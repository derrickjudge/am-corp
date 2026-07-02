"""Tests for the vuln phase function in src/crew/vuln_tools.py.

do_nuclei_scan() runs a scan, writes structured data to the findings store,
posts a structured #agent-chat message, and returns text for the LLM. The
external nuclei_scan call and the Discord-posting helpers are mocked, so these
are pure unit tests of the phase logic and message formatting.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.crew import findings as findings_mod
from src.crew import vuln_tools


def _result(success: bool = True, vulnerabilities: list | None = None, error: str = ""):
    """Build a stand-in for VulnResult with the attrs do_nuclei_scan() reads."""
    return SimpleNamespace(
        success=success,
        vulnerabilities=vulnerabilities or [],
        error=error,
    )


@pytest.fixture
def job(monkeypatch):
    """Register a findings store and capture chat/thoughts instead of posting."""
    chats: list[str] = []
    thoughts: list[tuple[str, str]] = []
    monkeypatch.setattr(vuln_tools, "_chat", lambda text: chats.append(text))
    monkeypatch.setattr(
        vuln_tools,
        "_think",
        lambda text, category="reasoning", confidence=None: thoughts.append(
            (category, text)
        ),
    )
    monkeypatch.setattr(vuln_tools, "_job_id", "test-job")
    store = findings_mod.init_vuln_run("test-job", "example.com")
    yield SimpleNamespace(store=store, chats=chats, thoughts=thoughts)
    findings_mod.clear_vuln_run("test-job")


async def test_do_nuclei_scan_with_ports_uses_smart_templates(job, monkeypatch) -> None:
    """With recon ports available, smart template selection drives the scan."""
    # Arrange
    ports = [{"port": 443, "service": "https"}]
    monkeypatch.setattr(
        vuln_tools, "select_templates_for_ports", lambda p: (["http", "ssl"], {})
    )
    scan = AsyncMock(
        return_value=_result(
            vulnerabilities=[
                {"severity": "critical", "name": "RCE", "cve_id": "CVE-2024-0001"}
            ]
        )
    )
    monkeypatch.setattr(vuln_tools, "nuclei_scan", scan)

    # Act
    out = await vuln_tools.do_nuclei_scan("example.com", ports)

    # Assert
    scan.assert_awaited_once()
    assert scan.await_args is not None
    assert scan.await_args.kwargs["templates"] == ["http", "ssl"]
    assert job.store.findings[0]["name"] == "RCE"
    assert "nuclei" in job.store.completed
    assert "CRITICAL" in out


async def test_do_nuclei_scan_without_ports_uses_default_templates(
    job, monkeypatch
) -> None:
    """With no recon data, default broad templates are used instead."""
    # Arrange
    monkeypatch.setattr(vuln_tools, "get_default_templates", lambda: ["cves"])
    scan = AsyncMock(return_value=_result(vulnerabilities=[]))
    monkeypatch.setattr(vuln_tools, "nuclei_scan", scan)

    # Act
    out = await vuln_tools.do_nuclei_scan("example.com", [])

    # Assert
    scan.assert_awaited_once()
    assert scan.await_args is not None
    assert scan.await_args.kwargs["templates"] == ["cves"]
    assert out == "No vulnerabilities found."
    assert "nuclei" in job.store.completed


async def test_do_nuclei_scan_failure_returns_error_and_skips_store(
    job, monkeypatch
) -> None:
    """A failed scan returns an error string and does not mark completed."""
    # Arrange
    monkeypatch.setattr(
        vuln_tools,
        "nuclei_scan",
        AsyncMock(return_value=_result(success=False, error="boom")),
    )

    # Act
    out = await vuln_tools.do_nuclei_scan("example.com", [])

    # Assert
    assert "Vuln scan failed" in out
    assert "nuclei" not in job.store.completed


async def test_do_nuclei_scan_flags_cves_for_ivy(job, monkeypatch) -> None:
    """Findings with CVEs post a chat message tagging Ivy for threat intel."""
    # Arrange
    monkeypatch.setattr(vuln_tools, "get_ivy_mention", lambda: "@Ivy")
    monkeypatch.setattr(
        vuln_tools,
        "nuclei_scan",
        AsyncMock(
            return_value=_result(
                vulnerabilities=[
                    {"severity": "high", "name": "SQLi", "cve_id": "CVE-2024-0002"}
                ]
            )
        ),
    )

    # Act
    await vuln_tools.do_nuclei_scan("example.com", [])

    # Assert
    assert any("@Ivy" in msg for msg in job.chats)
    assert any("CVE" in text for _category, text in job.thoughts)


def test_render_vuln_chat_no_findings_uses_fallback_pool() -> None:
    """A clean scan renders one of the NO_VULNS_FALLBACKS messages."""
    msg = vuln_tools._render_vuln_chat("example.com", [])
    assert "example.com" in msg


def test_render_vuln_chat_caps_bullets_at_five() -> None:
    """Only the top 5 critical/high findings are bulleted, to stay concise."""
    vulns = [{"severity": "critical", "name": f"vuln-{i}"} for i in range(8)]
    msg = vuln_tools._render_vuln_chat("example.com", vulns)
    assert msg.count("vuln-") == 5
