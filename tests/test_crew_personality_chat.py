"""Tests for crew personality message generation (src/crew/personality_chat.py).

The generator now routes through the shared crew LLM (get_llm().call). These
tests mock that call and the personality manager, so no network or model is
needed, and verify the fallback behaviour that keeps the pipeline unblocked.
"""

from types import SimpleNamespace

from src.crew import personality_chat as pc
from src.utils.config import settings as real_settings


async def test_returns_fallback_when_gemini_and_no_key(monkeypatch) -> None:
    """On Gemini with no API key, skip generation and return the fallback."""
    monkeypatch.setattr(real_settings, "llm_model", "")  # -> gemini routing
    monkeypatch.setattr(real_settings, "gemini_api_key", "")

    out = await pc.generate_agent_message("randy_recon", "char", "prompt", "FALLBACK")

    assert out == "FALLBACK"


async def test_returns_llm_text_when_generated(monkeypatch) -> None:
    """A successful LLM call is returned (stripped)."""
    monkeypatch.setattr(real_settings, "llm_model", "ollama/qwen2.5")  # no key needed
    monkeypatch.setattr(
        pc,
        "get_personality_manager",
        lambda: SimpleNamespace(get_prompt_context=lambda _agent: "ctx"),
    )
    fake_llm = SimpleNamespace(call=lambda _messages: "  Howdy partner, saddlin' up.  ")
    monkeypatch.setattr(pc, "get_llm", lambda: fake_llm)

    out = await pc.generate_agent_message("randy_recon", "char", "prompt", "FALLBACK")

    assert out == "Howdy partner, saddlin' up."


async def test_returns_fallback_on_llm_error(monkeypatch) -> None:
    """An LLM error (e.g. Ollama unreachable) degrades to the fallback."""
    monkeypatch.setattr(real_settings, "llm_model", "ollama/qwen2.5")
    monkeypatch.setattr(
        pc,
        "get_personality_manager",
        lambda: SimpleNamespace(get_prompt_context=lambda _agent: "ctx"),
    )

    def _boom(_messages):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(pc, "get_llm", lambda: SimpleNamespace(call=_boom))

    out = await pc.generate_agent_message("randy_recon", "char", "prompt", "FALLBACK")

    assert out == "FALLBACK"
