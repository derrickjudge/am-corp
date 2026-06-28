"""
Shared CrewAI LLM instance.

CrewAI talks to Gemini through LiteLLM (bundled inside CrewAI).
LiteLLM uses the "gemini/" prefix to route to Google's API.

To swap to a local Ollama model later, change one line:
    model="ollama/llama3.2"
No other files need to change.
"""

from functools import lru_cache

from crewai import LLM

from src.utils.config import settings


@lru_cache(maxsize=1)
def get_llm() -> LLM:
    """
    Return the shared LLM instance used by all CrewAI agents.

    Cached so the object is built once and reused across agents and crews.
    Temperature 0.7 balances creativity with consistency for security analysis.
    max_tokens caps individual LLM responses to avoid runaway output.
    """
    return LLM(
        model=f"gemini/{settings.gemini_model}",
        api_key=settings.gemini_api_key,
        temperature=0.7,
        max_tokens=1024,
    )
