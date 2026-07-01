"""Tests for crew LLM routing: config resolution and the LLM factory.

Covers the provider-agnostic switch between Gemini and a local Ollama model.
No network is used — CrewAI's LLM object is constructed lazily and only its
resolved fields are inspected.
"""

from collections.abc import Iterator

import pytest

from src.crew import llm as llm_mod
from src.utils.config import Settings
from src.utils.config import settings as real_settings


@pytest.fixture(autouse=True)
def _clear_llm_cache() -> Iterator[None]:
    """get_llm is lru_cached; clear it around each test that rebuilds it."""
    llm_mod.get_llm.cache_clear()
    yield
    llm_mod.get_llm.cache_clear()


def test_crew_llm_model_defaults_to_gemini() -> None:
    """With llm_model unset, the crew model falls back to gemini/<gemini_model>."""
    s = Settings(llm_model="", gemini_model="gemini-2.5-flash-lite")
    assert s.crew_llm_model == "gemini/gemini-2.5-flash-lite"
    assert s.crew_llm_is_ollama is False


def test_crew_llm_model_uses_llm_model_when_set() -> None:
    """An explicit llm_model wins and is detected as Ollama by its prefix."""
    s = Settings(llm_model="ollama/qwen2.5")
    assert s.crew_llm_model == "ollama/qwen2.5"
    assert s.crew_llm_is_ollama is True


def test_get_llm_builds_ollama_llm_with_base_url(monkeypatch) -> None:
    """Ollama routing points the LLM at the configured local endpoint.

    (CrewAI strips the "ollama/" prefix from .model and normalises base_url to
    the OpenAI-compatible /v1 path, so we assert on substrings, not exact eq.)
    """
    monkeypatch.setattr(real_settings, "llm_model", "ollama/qwen2.5")
    monkeypatch.setattr(
        real_settings, "llm_api_base", "http://host.containers.internal:11434"
    )

    built = llm_mod.get_llm()

    assert "qwen2.5" in built.model
    assert built.base_url is not None
    assert "host.containers.internal:11434" in built.base_url


def test_get_llm_builds_gemini_llm_by_default(monkeypatch) -> None:
    """Gemini routing uses the gemini model and sets no base_url."""
    monkeypatch.setattr(real_settings, "llm_model", "")
    monkeypatch.setattr(real_settings, "gemini_model", "gemini-2.5-flash-lite")
    monkeypatch.setattr(real_settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(real_settings, "llm_api_base", None)

    built = llm_mod.get_llm()

    assert "flash-lite" in built.model
    assert built.base_url is None
