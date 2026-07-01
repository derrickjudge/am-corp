"""Tests for the recon phase functions in src/crew/tools.py.

Each do_*() runs a lookup, writes structured data to the findings store, posts
a structured #agent-chat message, and returns text for the LLM. External tool
calls (dig/whois/nmap) and the Discord-posting helpers are mocked, so these are
pure unit tests of the phase logic and message formatting.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.crew import findings as findings_mod
from src.crew import tools


def _result(
    success: bool = True, parsed: dict | None = None, output: str = "", error: str = ""
):
    """Build a stand-in for recon_tools.ToolResult with the attrs do_*() reads."""
    return SimpleNamespace(
        success=success,
        parsed_data=parsed or {},
        output=output,
        error=error,
    )


@pytest.fixture
def job(monkeypatch):
    """Register a findings store and capture chat/thoughts instead of posting."""
    chats: list[str] = []
    thoughts: list[tuple[str, str]] = []
    monkeypatch.setattr(tools, "_chat", lambda text: chats.append(text))
    monkeypatch.setattr(
        tools,
        "_think",
        lambda text, category="reasoning", confidence=None: thoughts.append(
            (category, text)
        ),
    )
    monkeypatch.setattr(tools, "_job_id", "test-job")
    store = findings_mod.init_run("test-job", "example.com")
    yield SimpleNamespace(store=store, chats=chats, thoughts=thoughts)
    findings_mod.clear_run("test-job")


async def test_do_dns_writes_findings_and_formats_bullets(job, monkeypatch) -> None:
    """do_dns stores records, returns raw output, and posts bulleted records."""
    # Arrange
    records = {"A": ["1.2.3.4"], "CNAME": ["example.com."]}
    monkeypatch.setattr(
        tools,
        "dig_lookup",
        AsyncMock(return_value=_result(parsed={"records": records}, output="raw dns")),
    )

    # Act
    out = await tools.do_dns("example.com")

    # Assert
    assert job.store.dns_records == records
    assert "dns" in job.store.completed
    assert out == "raw dns"
    assert job.chats, "expected an agent-chat message"
    msg = job.chats[0]
    assert "A: `1.2.3.4`" in msg
    assert "CNAME: `example.com.`" in msg


async def test_do_dns_failure_returns_error_and_skips_store(job, monkeypatch) -> None:
    """A failed DNS lookup returns an error string and does not mark completed."""
    # Arrange
    monkeypatch.setattr(
        tools,
        "dig_lookup",
        AsyncMock(return_value=_result(success=False, error="boom")),
    )

    # Act
    out = await tools.do_dns("example.com")

    # Assert
    assert "DNS lookup failed" in out
    assert "dns" not in job.store.completed


async def test_do_whois_writes_findings_and_formats_details(job, monkeypatch) -> None:
    """do_whois stores registration info and posts key registration details."""
    # Arrange
    info = {
        "registrar": "Dynadot",
        "creation_date": "1999-01-01",
        "name_servers": ["ns1.example", "ns2.example", "ns3.example"],
    }
    monkeypatch.setattr(
        tools,
        "whois_lookup",
        AsyncMock(return_value=_result(parsed=info, output="raw whois")),
    )

    # Act
    out = await tools.do_whois("example.com")

    # Assert
    assert job.store.whois_info == info
    assert "whois" in job.store.completed
    assert out == "raw whois"
    assert "Registrar" in job.chats[0]
    assert "Dynadot" in job.chats[0]


async def test_do_ports_formats_and_flags_risky_service(job, monkeypatch) -> None:
    """do_ports stores ports, tags Victor, and flags a risky service as a thought."""
    # Arrange
    ports = [{"port": 6379, "service": "redis", "version": "6.0"}]
    monkeypatch.setattr(
        tools, "nmap_scan", AsyncMock(return_value=_result(parsed={"ports": ports}))
    )
    monkeypatch.setattr(tools, "get_victor_mention", lambda: "@Victor")

    # Act
    await tools.do_ports("example.com")

    # Assert
    assert job.store.ports == ports
    assert "ports" in job.store.completed
    assert "6379" in job.chats[0]
    assert "@Victor" in job.chats[0]
    # A risky service (redis) produces an analytical finding thought for Victor.
    assert any("redis" in text.lower() for _category, text in job.thoughts)


async def test_do_ports_no_open_ports(job, monkeypatch) -> None:
    """No open ports still marks the phase completed and reports cleanly."""
    # Arrange
    monkeypatch.setattr(
        tools, "nmap_scan", AsyncMock(return_value=_result(parsed={"ports": []}))
    )

    # Act
    out = await tools.do_ports("example.com")

    # Assert
    assert out == "No open ports found."
    assert "ports" in job.store.completed
    assert job.store.open_port_count == 0
