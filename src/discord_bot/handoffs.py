"""
AM-Corp Agent Handoff Conversations

Manages conversational exchanges in #agent-chat when the scan pipeline
transitions from one agent to the next. Data still flows via Python return
values — this adds the visible Discord conversation around those transitions.
"""

import asyncio
import random
from dataclasses import dataclass
from typing import Any

from src.agents import AGENT_RANDY_RECON, AGENT_VICTOR_VULN, AGENT_IVY_INTEL, AGENTS
from src.agents.evolution import trigger_handoff
from src.agents.personality import get_personality_manager
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# HANDOFF CONTEXT
# =============================================================================


@dataclass
class HandoffContext:
    """Data describing a pipeline handoff between two agents."""

    from_agent: str
    to_agent: str
    target: str
    summary: dict[str, Any]


# =============================================================================
# FALLBACK MESSAGE POOLS
# =============================================================================

# Outgoing: keyed by (from_agent, to_agent)
_OUTGOING_FALLBACKS: dict[tuple[str, str], list[str]] = {
    (AGENT_RANDY_RECON, AGENT_VICTOR_VULN): [
        "{to_mention}, wrapped up recon on {target}. Found {port_count} open ports — a few look worth hitting. Your turn.",
        "{to_mention}, recon on {target} is done. Got {port_count} ports open, sending it your way.",
        "Finished the recon on {target}, {to_mention}. {port_count} ports showing — some interesting ones in there.",
        "{to_mention}, I've got {port_count} open ports on {target}. Handing this off to you.",
    ],
    (AGENT_VICTOR_VULN, AGENT_IVY_INTEL): [
        "{to_mention}, done on {target}. {critical} critical and {high} high findings. Passing the CVEs over.",
        "{to_mention}, got {critical} critical vulns on {target}. You'll want to dig into the threat intel on these.",
        "Vuln scan on {target} is wrapped, {to_mention}. {critical} critical findings — sending the CVE list your way.",
        "{to_mention}, {critical} critical on {target}. Some of these CVEs look nasty. Over to you.",
    ],
}

# Acknowledgments: keyed by to_agent
_INCOMING_FALLBACKS: dict[str, list[str]] = {
    AGENT_VICTOR_VULN: [
        "Got it. Firing up nuclei on {target} now.",
        "On it. Running the scanner — give me a few minutes.",
        "Thanks. Starting the vuln scan on {target}.",
        "Received. Nuclei's going up on {target}.",
    ],
    AGENT_IVY_INTEL: [
        "On it. Pulling threat intel on those CVEs now.",
        "Got the findings. Checking Shodan and VirusTotal.",
        "Thanks {from_mention}. Starting the intel lookup on {target}.",
        "Received. Spinning up the threat intel pipeline on {target}.",
    ],
}


# =============================================================================
# LLM MESSAGE GENERATION
# =============================================================================


async def _generate_handoff_message(
    agent_id: str,
    prompt: str,
    fallback: str,
) -> str:
    """
    Generate a short handoff message for agent_id via Gemini.

    Falls back to a pre-written message if generation fails so the scan
    pipeline is never blocked by an LLM error.
    """
    if not settings.gemini_api_key:
        return fallback

    try:
        from google import genai
        from google.genai import types

        pm = get_personality_manager()
        personality_context = pm.get_prompt_context(agent_id)
        agent_info = AGENTS[agent_id]

        system_instruction = f"""You are {agent_info['name']}, a cybersecurity specialist at AM-Corp.

{personality_context}

COMMUNICATION RULES FOR THIS MESSAGE:
- Write exactly 1-2 complete sentences
- Be conversational — you're talking to a colleague in team chat
- Stay in character per your personality above
- Do not add emojis (they are added automatically)
- Do not start with greetings like "Hey", "Alright", or "Sure"
- Do not repeat the agent's name in the message"""

        client = genai.Client(api_key=settings.gemini_api_key)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.8,
                max_output_tokens=120,
            ),
        )

        if response and response.text:
            text = response.text.strip()
            if len(text) >= 20:
                return text

    except Exception as e:
        logger.warning(f"Handoff message generation failed for {agent_id}: {e}")

    return fallback


# =============================================================================
# PROMPT BUILDERS
# =============================================================================


def _summary_to_text(summary: dict[str, Any]) -> str:
    """Convert a HandoffContext summary dict to readable bullet points."""
    parts: list[str] = []

    if "port_count" in summary:
        count = summary["port_count"]
        parts.append(f"Found {count} open ports")
        ports = summary.get("ports", [])
        if ports:
            port_strs = []
            for p in ports[:3]:
                if isinstance(p, dict):
                    svc = p.get("service", "")
                    port_strs.append(f"{p.get('port', '?')}" + (f"/{svc}" if svc else ""))
                else:
                    port_strs.append(str(p))
            parts.append(f"Key ports: {', '.join(port_strs)}")

    if "critical" in summary:
        parts.append(f"{summary['critical']} critical, {summary.get('high', 0)} high severity findings")
        cve_count = summary.get("cve_count", 0)
        if cve_count:
            parts.append(f"{cve_count} CVEs identified")

    return "\n".join(f"- {p}" for p in parts) if parts else "Work complete."


def _build_outgoing_prompt(ctx: HandoffContext, to_mention: str) -> str:
    """Prompt for the agent handing work off."""
    return f"""You just finished your work on {ctx.target} and are handing off to your colleague.

Your findings:
{_summary_to_text(ctx.summary)}

Write a 1-2 sentence handoff message in the team chat. Mention the key finding and pass the work to them.
Tag them using exactly: {to_mention}"""


def _build_incoming_prompt(ctx: HandoffContext, from_mention: str) -> str:
    """Prompt for the agent receiving work."""
    return f"""Your colleague just handed off work on {ctx.target} to you.

Their findings:
{_summary_to_text(ctx.summary)}

Write a 1-2 sentence acknowledgment. React briefly to one of their findings and confirm you are starting now."""


def _get_outgoing_fallback(ctx: HandoffContext, to_mention: str) -> str:
    """Return a formatted fallback from the pool for the outgoing message."""
    pool = _OUTGOING_FALLBACKS.get(
        (ctx.from_agent, ctx.to_agent),
        [f"{to_mention}, finished my work on {ctx.target}. Passing it to you."],
    )
    template = random.choice(pool)
    return template.format(
        to_mention=to_mention,
        target=ctx.target,
        port_count=ctx.summary.get("port_count", "several"),
        critical=ctx.summary.get("critical", 0),
        high=ctx.summary.get("high", 0),
    )


def _get_incoming_fallback(ctx: HandoffContext, from_mention: str) -> str:
    """Return a formatted fallback from the pool for the acknowledgment."""
    pool = _INCOMING_FALLBACKS.get(
        ctx.to_agent,
        [f"Got it. Starting my work on {ctx.target} now."],
    )
    template = random.choice(pool)
    return template.format(
        from_mention=from_mention,
        target=ctx.target,
        port_count=ctx.summary.get("port_count", "several"),
        critical=ctx.summary.get("critical", 0),
        high=ctx.summary.get("high", 0),
    )


# =============================================================================
# MAIN HANDOFF RUNNER
# =============================================================================


async def run_handoff(
    ctx: HandoffContext,
    pause_seconds: float | None = None,
) -> None:
    """
    Execute a two-message handoff exchange in #agent-chat.

    Posts the outgoing agent's farewell/summary, waits briefly, then posts
    the incoming agent's acknowledgment. Never raises — fallback messages
    are always available so the scan pipeline is never blocked.

    Args:
        ctx: Handoff context (agents, target, findings summary)
        pause_seconds: Override for settings.handoff_pause_seconds
    """
    from src.discord_bot.agent_bots import get_agent_manager

    manager = get_agent_manager()
    pause = pause_seconds if pause_seconds is not None else settings.handoff_pause_seconds

    to_mention = manager.get_mention(ctx.to_agent)
    from_mention = manager.get_mention(ctx.from_agent)

    try:
        # 1. Outgoing message (from_agent summarises and tags to_agent)
        outgoing_msg = await _generate_handoff_message(
            ctx.from_agent,
            _build_outgoing_prompt(ctx, to_mention),
            _get_outgoing_fallback(ctx, to_mention),
        )
        await manager.send_as_agent(ctx.from_agent, outgoing_msg, channel="agent_chat")

        # 2. Natural pause
        jitter = random.uniform(-0.5, 0.5)
        await asyncio.sleep(max(1.0, pause + jitter))

        # 3. Acknowledgment (to_agent responds before starting work)
        incoming_msg = await _generate_handoff_message(
            ctx.to_agent,
            _build_incoming_prompt(ctx, from_mention),
            _get_incoming_fallback(ctx, from_mention),
        )
        await manager.send_as_agent(ctx.to_agent, incoming_msg, channel="agent_chat")

        logger.info(
            "Handoff exchange complete",
            from_agent=ctx.from_agent,
            to_agent=ctx.to_agent,
            target=ctx.target,
        )

    except Exception as e:
        logger.error(
            f"Handoff conversation failed: {e}",
            from_agent=ctx.from_agent,
            to_agent=ctx.to_agent,
        )
        # Non-fatal — scan pipeline continues regardless

    # 4. Trigger personality evolution for both agents
    try:
        await trigger_handoff(
            from_agent=ctx.from_agent,
            to_agent=ctx.to_agent,
            handoff_type=f"{ctx.from_agent}_to_{ctx.to_agent}",
            context=ctx.summary,
        )
    except Exception as e:
        logger.warning(f"Evolution trigger failed for handoff: {e}")
