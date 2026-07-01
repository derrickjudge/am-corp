"""
Personality-rich message generation for the CrewAI pipeline.

Short, purpose-built messages (an opening line, a Victor handoff) voiced in the
agent's personality, generated through the SAME crew LLM as the agentic
reasoning (src/crew/llm.py). Routing the crew to a local Ollama model therefore
moves these messages too. A fallback string is always returned on failure, so
the scan pipeline is never blocked by an LLM error or an Ollama outage.
"""

import asyncio
from typing import Any, cast

from src.agents.personality import get_personality_manager
from src.crew.llm import get_llm
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


async def generate_agent_message(
    agent_id: str,
    character: str,
    prompt: str,
    fallback: str,
) -> str:
    """
    Generate a personality-rich message for an agent via the crew LLM.

    Args:
        agent_id:  Agent identifier (used to load live YAML state).
        character: The agent's fixed character/system description.
        prompt:    The user-turn prompt describing what to say.
        fallback:  Returned verbatim if generation is unavailable or fails.

    Returns:
        The generated message, or the fallback on any failure.
    """
    # Gemini needs a key; Ollama does not. If neither is available, skip to the
    # fallback so we never raise into the scan pipeline.
    if not settings.crew_llm_is_ollama and not settings.gemini_api_key:
        return fallback

    try:
        personality_context = get_personality_manager().get_prompt_context(agent_id)
        system_instruction = (
            f"{character}\n\n{personality_context}\n\n"
            "COMMUNICATION RULES FOR THIS MESSAGE:\n"
            "- Stay fully in character per your personality above.\n"
            "- Do not add emojis (they are added automatically).\n"
            "- Do not start with filler greetings like 'Hey', 'Alright', or 'Sure'.\n"
            "- Vary your phrasing — never sound templated."
        )
        # cast at the crewai boundary — LLM.call types messages as list[LLMMessage]
        messages = cast(
            Any,
            [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
        )

        # LLM.call is synchronous; run it off the event loop so Discord stays
        # responsive during the (possibly slow, local) generation.
        text = await asyncio.to_thread(get_llm().call, messages)
        if text and len(text.strip()) >= 10:
            return text.strip()

    except Exception as e:
        logger.warning(f"Personality message generation failed for {agent_id}: {e}")

    return fallback
