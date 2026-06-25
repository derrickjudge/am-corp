"""
AM-Corp @Mention Router

Routes Discord @mentions to the correct agent and generates a channel-mode-
appropriate response. Designed to be extensible: adding a new watched channel
requires one line in build_channel_mode_map(); new agents are picked up
automatically from the AGENTS dict.

Channel modes:
    CASUAL    — #general: personality-driven casual response
    TECHNICAL — #agent-chat: technical, scan-context-aware response
"""

import asyncio
import random
import re
from enum import Enum
from typing import Any

from src.agents import AGENTS
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# CHANNEL MODES
# =============================================================================


class ChannelMode(str, Enum):
    """Response mode determined by which channel the mention appeared in."""

    CASUAL = "casual"
    TECHNICAL = "technical"


def build_channel_mode_map() -> dict[str, ChannelMode]:
    """
    Build a {channel_id: ChannelMode} mapping from config.

    To add a new watched channel, add one line here.
    """
    mapping: dict[str, ChannelMode] = {}
    if settings.discord_channel_general:
        mapping[settings.discord_channel_general] = ChannelMode.CASUAL
    if settings.discord_channel_agent_chat:
        mapping[settings.discord_channel_agent_chat] = ChannelMode.TECHNICAL
    return mapping


# Lazily populated after settings are loaded — do not access before first call
# to _ensure_channel_map().
_CHANNEL_MODE_MAP: dict[str, ChannelMode] = {}


def _ensure_channel_map() -> None:
    """Populate _CHANNEL_MODE_MAP on first use (settings are ready by then)."""
    global _CHANNEL_MODE_MAP
    if not _CHANNEL_MODE_MAP:
        _CHANNEL_MODE_MAP = build_channel_mode_map()


# =============================================================================
# MENTION PARSING
# =============================================================================


def parse_agent_mentions(
    message_content: str,
    agent_manager: Any,  # AgentBotManager — avoid circular import at type level
) -> list[str]:
    """
    Extract <@USER_ID> patterns and map them to agent_ids.

    Handles both <@123456> and <@!123456> (nickname) mention formats.
    Returns matched agent_ids in the order they appear, deduplicated.
    Iterates over AGENTS dict, so new agents are picked up automatically.
    """
    raw_ids = re.findall(r"<@!?(\d+)>", message_content)
    if not raw_ids:
        return []

    seen: set[str] = set()
    result: list[str] = []

    for user_id_str in raw_ids:
        user_id = int(user_id_str)
        for agent_id in AGENTS:
            if agent_id in seen:
                continue
            agent_user_id = agent_manager.get_user_id(agent_id)
            if agent_user_id == user_id:
                seen.add(agent_id)
                result.append(agent_id)
                break

    return result


# =============================================================================
# RESPONSE GENERATORS
# =============================================================================


async def _respond_casual(
    agent_id: str,
    message: str,
    author: str,
) -> None:
    """
    Generate a casual response and post it to #general via webhook.

    Reuses the existing CasualChatManager pipeline (personality + Gemini).
    Uses webhook rather than AgentBot because agent bots hold no reference
    to the general channel.
    """
    from src.discord_bot.casual_chat import ConversationType, get_casual_chat_manager
    from src.discord_bot.conversation_memory import get_conversation_memory
    from src.discord_bot.webhooks import get_webhook_client

    try:
        manager = get_casual_chat_manager()

        response_msg, _ = await manager.generate_message(
            agent_id=agent_id,
            conv_type=ConversationType.HUMAN_RESPONSE,
            context=message,
        )

        if not response_msg:
            logger.warning(f"Empty casual response generated for {agent_id}")
            return

        await get_webhook_client().post_agent_message(agent_id, response_msg, "general")

        # Track in conversation memory so future context is accurate
        agent_info = AGENTS[agent_id]
        get_conversation_memory().add_message(
            author=agent_info["name"],
            author_id=agent_id,
            content=response_msg[:500],
            is_agent=True,
            is_human=False,
            channel_id=settings.discord_channel_general,
        )

        logger.info("Casual mention response posted", agent=agent_id)

    except Exception as e:
        logger.error(f"Casual mention response failed for {agent_id}: {e}")


async def _respond_technical(
    agent_id: str,
    message: str,
    author: str,
    active_job: dict[str, Any] | None,
) -> None:
    """
    Generate a technical response and post it to #agent-chat.

    Builds a Gemini prompt with personality context + current scan state
    (if a scan is running). Posts via the agent's Discord bot user so it
    appears with their profile picture and username.
    """
    from google import genai
    from google.genai import types

    from src.agents.personality import get_personality_manager
    from src.discord_bot.agent_bots import get_agent_manager

    agent_info = AGENTS.get(agent_id)
    if not agent_info:
        return

    fallback = "On it. Will report back shortly."

    try:
        pm = get_personality_manager()
        personality_context = pm.get_prompt_context(agent_id)

        scan_context = ""
        if active_job:
            target = active_job.get("target", "unknown")
            phase = active_job.get("phase", "unknown")
            findings = active_job.get("findings", {})
            scan_context = (
                f"\nCURRENT SCAN CONTEXT:\n"
                f"Target: {target}\n"
                f"Phase: {phase}\n"
                f"Findings so far: {findings}"
            )

        system_instruction = (
            f"You are {agent_info['name']}, a cybersecurity specialist at AM-Corp "
            f"working in the team operations channel.\n\n"
            f"{personality_context}"
            f"{scan_context}\n\n"
            "RULES:\n"
            "- Write 2-3 complete sentences maximum\n"
            "- Be technical and work-focused — this is the operations channel\n"
            "- Answer the question based on your area of expertise\n"
            "- Reference the current scan context if it is relevant\n"
            "- Do not add emojis in the text\n"
            "- Do not start with greetings like 'Hey' or 'Sure'"
        )

        prompt = f'{author} is asking: "{message}"\n\nRespond with technical expertise.'

        client = genai.Client(api_key=settings.gemini_api_key)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.6,
                max_output_tokens=200,
            ),
        )

        reply = response.text.strip() if (response and response.text) else None
        if not reply or len(reply) < 10:
            reply = fallback

        await get_agent_manager().send_as_agent(agent_id, reply, channel="agent_chat")
        logger.info("Technical mention response posted", agent=agent_id)

    except Exception as e:
        logger.error(f"Technical mention response failed for {agent_id}: {e}")
        try:
            from src.discord_bot.agent_bots import get_agent_manager
            await get_agent_manager().send_as_agent(agent_id, fallback, channel="agent_chat")
        except Exception:
            pass


async def _staggered_respond(
    agent_id: str,
    delay: float,
    mode: ChannelMode,
    message_content: str,
    author_display: str,
    active_job: dict[str, Any] | None,
) -> None:
    """Sleep delay seconds, then dispatch the response based on channel mode."""
    if delay > 0:
        await asyncio.sleep(delay)
    if mode == ChannelMode.CASUAL:
        await _respond_casual(agent_id, message_content, author_display)
    else:
        await _respond_technical(agent_id, message_content, author_display, active_job)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


async def route_mentions(
    message_content: str,
    author_display: str,
    author_id: str,
    channel_id: str,
    active_job: dict[str, Any] | None,
    agent_manager: Any,  # AgentBotManager
) -> bool:
    """
    Check a message for agent @mentions and dispatch staggered responses.

    Returns True if at least one agent mention was found and handled,
    so the caller can suppress the normal (non-mention) chat handler.

    All mentioned agents respond, staggered by random.uniform(3, 6) seconds
    per agent to feel natural. Responses run as background tasks so this
    function returns immediately.
    """
    _ensure_channel_map()

    if channel_id not in _CHANNEL_MODE_MAP:
        return False

    agent_ids = parse_agent_mentions(message_content, agent_manager)
    if not agent_ids:
        return False

    mode = _CHANNEL_MODE_MAP[channel_id]

    for i, agent_id in enumerate(agent_ids):
        delay = i * random.uniform(3.0, 6.0)
        asyncio.create_task(
            _staggered_respond(
                agent_id=agent_id,
                delay=delay,
                mode=mode,
                message_content=message_content,
                author_display=author_display,
                active_job=active_job,
            )
        )

    logger.info(
        "Mention routing dispatched",
        agents=agent_ids,
        channel=channel_id,
        mode=mode.value,
    )
    return True
