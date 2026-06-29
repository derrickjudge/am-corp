"""
Personality-rich message generation for the CrewAI pipeline.

This reuses the exact mechanism the hand-rolled agents and handoffs.py
use: a Gemini call whose system instruction carries the agent's full
character plus live personality state from the YAML. A fallback string is
always returned on failure so the scan pipeline is never blocked by an LLM
error.

Keeping this separate from the CrewAI Agent's own LLM lets us voice short,
purpose-built messages (an opening line, a Victor handoff) in the agent's
personality without depending on parsing CrewAI's internal step output.
"""

import asyncio

from src.agents import AGENTS
from src.agents.personality import get_personality_manager
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


async def generate_agent_message(
    agent_id: str,
    character: str,
    prompt: str,
    fallback: str,
    temperature: float = 0.85,
    max_output_tokens: int = 400,
) -> str:
    """
    Generate a personality-rich message for an agent via Gemini.

    Args:
        agent_id:          Agent identifier (used to load live YAML state).
        character:         The agent's fixed character/system description.
        prompt:            The user-turn prompt describing what to say.
        fallback:          Returned verbatim if generation is unavailable or fails.
        temperature:       Sampling temperature (higher = more varied voice).
        max_output_tokens: Cap on generated length.

    Returns:
        The generated message, or the fallback on any failure.
    """
    if not settings.gemini_api_key:
        return fallback

    try:
        from google import genai
        from google.genai import types

        personality_context = get_personality_manager().get_prompt_context(agent_id)
        system_instruction = (
            f"{character}\n\n{personality_context}\n\n"
            "COMMUNICATION RULES FOR THIS MESSAGE:\n"
            "- Stay fully in character per your personality above.\n"
            "- Do not add emojis (they are added automatically).\n"
            "- Do not start with filler greetings like 'Hey', 'Alright', or 'Sure'.\n"
            "- Vary your phrasing — never sound templated."
        )

        client = genai.Client(api_key=settings.gemini_api_key)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            ),
        )

        if response and response.text:
            text = response.text.strip()
            if len(text) >= 10:
                return text

    except Exception as e:
        logger.warning(f"Personality message generation failed for {agent_id}: {e}")

    return fallback
