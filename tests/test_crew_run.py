"""Tests for run-orchestration helpers in src/crew/run.py.

Covers quota-error detection and the deterministic degraded fallback that
completes recon phases without the LLM.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.crew import run as run_mod
from src.crew import tools as tools_mod


@pytest.mark.parametrize(
    "message",
    [
        "429 RESOURCE_EXHAUSTED",
        "You exceeded your current quota",
        "rate limit reached, retry later",
        "RateLimitError: too many requests",
    ],
)
def test_is_quota_error_true(message: str) -> None:
    """Quota / rate-limit errors are recognised regardless of exact wording."""
    assert run_mod._is_quota_error(Exception(message)) is True


@pytest.mark.parametrize(
    "message",
    [
        "connection refused",
        "invalid API key",
        "ValueError: bad input",
        "nmap not found",
    ],
)
def test_is_quota_error_false(message: str) -> None:
    """Non-quota errors are not misclassified as quota errors."""
    assert run_mod._is_quota_error(Exception(message)) is False


async def test_complete_phases_runs_only_missing(monkeypatch) -> None:
    """The degraded fallback runs only the phases the agent did not reach."""
    # Arrange — DNS already done; WHOIS and ports still pending
    findings = SimpleNamespace(target="example.com", completed={"dns"})
    do_dns = AsyncMock()
    do_whois = AsyncMock()
    do_ports = AsyncMock()
    monkeypatch.setattr(tools_mod, "do_dns", do_dns)
    monkeypatch.setattr(tools_mod, "do_whois", do_whois)
    monkeypatch.setattr(tools_mod, "do_ports", do_ports)

    # Act
    await run_mod._complete_phases_deterministically(findings)

    # Assert
    do_dns.assert_not_called()
    do_whois.assert_awaited_once_with("example.com")
    do_ports.assert_awaited_once_with("example.com")


async def test_complete_phases_runs_all_when_nothing_done(monkeypatch) -> None:
    """With no phases completed, the fallback runs all three in order."""
    # Arrange
    findings = SimpleNamespace(target="example.com", completed=set())
    do_dns = AsyncMock()
    do_whois = AsyncMock()
    do_ports = AsyncMock()
    monkeypatch.setattr(tools_mod, "do_dns", do_dns)
    monkeypatch.setattr(tools_mod, "do_whois", do_whois)
    monkeypatch.setattr(tools_mod, "do_ports", do_ports)

    # Act
    await run_mod._complete_phases_deterministically(findings)

    # Assert
    do_dns.assert_awaited_once_with("example.com")
    do_whois.assert_awaited_once_with("example.com")
    do_ports.assert_awaited_once_with("example.com")
