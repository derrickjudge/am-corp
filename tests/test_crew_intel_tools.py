"""Tests for the intel phase functions in src/crew/intel_tools.py.

Each do_*() runs a lookup, writes structured data to the findings store, posts
a structured #agent-chat message, and returns text for the LLM. External API
calls (NVD/EPSS, Shodan, VirusTotal, SecurityTrails) are mocked, so these are
pure unit tests of the phase logic and message formatting.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.crew import findings as findings_mod
from src.crew import intel_tools
from src.tools.intel_tools import (
    CVEDetails,
    SecurityTrailsResult,
    ShodanResult,
    VirusTotalResult,
)


@pytest.fixture
def job(monkeypatch):
    """Register a findings store and capture chat/thoughts instead of posting."""
    chats: list[str] = []
    thoughts: list[tuple[str, str]] = []
    monkeypatch.setattr(intel_tools, "_chat", lambda text: chats.append(text))
    monkeypatch.setattr(
        intel_tools,
        "_think",
        lambda text, category="reasoning", confidence=None: thoughts.append(
            (category, text)
        ),
    )
    monkeypatch.setattr(intel_tools, "_job_id", "test-job")
    store = findings_mod.init_intel_run("test-job", "example.com")
    yield SimpleNamespace(store=store, chats=chats, thoughts=thoughts)
    findings_mod.clear_intel_run("test-job")


async def test_do_cve_enrichment_flags_high_risk_and_tags_victor(
    job, monkeypatch
) -> None:
    """A high-EPSS CVE is stored, thought about, and tags Victor in chat."""
    # Arrange
    cve = CVEDetails(cve_id="CVE-2024-0001", cvss_score=9.8, epss_score=0.75)
    monkeypatch.setattr(
        intel_tools, "lookup_multiple_cves", AsyncMock(return_value=[cve])
    )
    monkeypatch.setattr(intel_tools, "get_victor_mention", lambda: "@Victor")

    # Act
    out = await intel_tools.do_cve_enrichment(["CVE-2024-0001"])

    # Assert
    assert job.store.cve_enrichments == [cve]
    assert "cve" in job.store.completed
    assert any("@Victor" in msg for msg in job.chats)
    assert any("HIGH/CRITICAL" in text for _category, text in job.thoughts)
    assert "1 high-risk" in out


async def test_do_cve_enrichment_no_high_risk(job, monkeypatch) -> None:
    """Low-risk CVEs are stored but don't produce a finding thought or Victor tag."""
    # Arrange
    cve = CVEDetails(cve_id="CVE-2024-0002", cvss_score=3.0, epss_score=0.01)
    monkeypatch.setattr(
        intel_tools, "lookup_multiple_cves", AsyncMock(return_value=[cve])
    )

    # Act
    out = await intel_tools.do_cve_enrichment(["CVE-2024-0002"])

    # Assert
    assert "cve" in job.store.completed
    assert "0 high-risk" in out
    assert not any("finding" == category for category, _text in job.thoughts)


async def test_do_shodan_lookup_stores_and_flags_vulns(job, monkeypatch) -> None:
    """Shodan results with known vulns are stored and produce a finding thought."""
    # Arrange
    result = ShodanResult(ip="1.2.3.4", ports=[22, 443], vulns=["CVE-2020-1234"])
    monkeypatch.setattr(
        intel_tools, "shodan_host_lookup", AsyncMock(return_value=result)
    )

    # Act
    out = await intel_tools.do_shodan_lookup("1.2.3.4")

    # Assert
    assert job.store.shodan_result is result
    assert "shodan" in job.store.completed
    assert any("finding" == category for category, _text in job.thoughts)
    assert "1 known vuln" in out


async def test_do_shodan_lookup_handles_error(job, monkeypatch) -> None:
    """A Shodan error (e.g. no API key) is reported and does not mark completed."""
    # Arrange
    result = ShodanResult(ip="1.2.3.4", error="Shodan API key not configured")
    monkeypatch.setattr(
        intel_tools, "shodan_host_lookup", AsyncMock(return_value=result)
    )

    # Act
    out = await intel_tools.do_shodan_lookup("1.2.3.4")

    # Assert
    assert "Shodan lookup failed" in out
    assert "shodan" not in job.store.completed


async def test_do_virustotal_lookup_flags_malicious(job, monkeypatch) -> None:
    """Malicious VirusTotal detections are stored and produce a finding thought."""
    # Arrange
    result = VirusTotalResult(
        target="example.com",
        target_type="domain",
        malicious_count=3,
        suspicious_count=1,
    )
    monkeypatch.setattr(
        intel_tools, "virustotal_lookup", AsyncMock(return_value=result)
    )

    # Act
    out = await intel_tools.do_virustotal_lookup("example.com")

    # Assert
    assert job.store.virustotal_result is result
    assert "virustotal" in job.store.completed
    assert any("finding" == category for category, _text in job.thoughts)
    assert "3 malicious" in out


async def test_do_securitytrails_lookup_stores_subdomains(job, monkeypatch) -> None:
    """SecurityTrails subdomain data is stored and posted as a structured chat."""
    # Arrange
    result = SecurityTrailsResult(domain="example.com", subdomain_count=12)
    monkeypatch.setattr(
        intel_tools, "securitytrails_lookup", AsyncMock(return_value=result)
    )

    # Act
    out = await intel_tools.do_securitytrails_lookup("example.com")

    # Assert
    assert job.store.securitytrails_result is result
    assert "securitytrails" in job.store.completed
    assert "12 subdomain" in out


def test_render_cve_chat_no_valid_cves() -> None:
    """All-errored CVEs render a rate-limit/invalid-ID message."""
    cves = [CVEDetails(cve_id="CVE-2024-0001", error="not found")]
    msg = intel_tools._render_cve_chat(cves)
    assert "Couldn't get CVE details" in msg


def test_render_cve_chat_caps_bullets_at_three() -> None:
    """Only the top 3 high-risk CVEs are bulleted, to stay concise."""
    cves = [
        CVEDetails(cve_id=f"CVE-2024-{i:04d}", epss_score=0.9) for i in range(6)
    ]
    msg = intel_tools._render_cve_chat(cves)
    assert msg.count("CVE-2024-") == 3
