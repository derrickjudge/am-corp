"""
Shared CrewAI LLM instance for the crew path.

CrewAI talks to the model through LiteLLM (bundled inside CrewAI), which routes
by the model id's provider prefix:
    - "gemini/<model>"  -> Google Gemini (needs api_key)
    - "ollama/<model>"  -> a local Ollama server (needs base_url, no api_key)

The model id and optional base URL come from config (llm_model / llm_api_base),
so switching the whole crew between Gemini and a local Ollama model is a config
change — no code edit. See src/utils/config.py::crew_llm_model.
"""

from functools import lru_cache

from crewai import LLM

from src.utils.config import settings


@lru_cache(maxsize=1)
def get_llm() -> LLM:
    """
    Return the shared LLM instance used by all CrewAI agents and by the crew's
    personality messages (src/crew/personality_chat.py).

    Cached so the object is built once and reused. Temperature 0.7 balances
    creativity with consistency; max_tokens caps individual responses.

    The provider is chosen by settings.crew_llm_model: Gemini needs an api_key,
    Ollama needs a base_url instead. Passing an unused api_key to Ollama would
    be harmless, but we keep the arguments provider-appropriate for clarity.
    """
    return LLM(
        model=settings.crew_llm_model,
        # Gemini needs a key; Ollama needs a base_url instead. Passing None for
        # the one that doesn't apply is harmless.
        api_key=None if settings.crew_llm_is_ollama else settings.gemini_api_key,
        base_url=settings.llm_api_base or None,
        temperature=0.7,
        max_tokens=1024,
    )
