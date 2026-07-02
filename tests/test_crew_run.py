"""Tests for run-orchestration helpers in src/crew/run.py.

Covers quota-error detection and the deterministic degraded fallback that
completes recon phases without the LLM.
"""

from unittest.mock import AsyncMock

import pytest

from src.crew import intel_tools as intel_tools_mod
from src.crew import run as run_mod
from src.crew import tools as tools_mod
from src.crew import vuln_tools as vuln_tools_mod
from src.crew.findings import IntelFindings, ReconFindings, VulnFindings


@pytest.mark.parametrize(
    "message",
    [
        # Quota / rate limit (Gemini)
        "429 RESOURCE_EXHAUSTED",
        "You exceeded your current quota",
        "rate limit reached, retry later",
        "RateLimitError: too many requests",
        # LLM server unreachable (e.g. local Ollama outage)
        "APIConnectionError: Connection refused",
        "Max retries exceeded with url",
        "litellm.APIError: failed to connect to ollama",
        "Read timed out",
    ],
)
def test_should_degrade_true(message: str) -> None:
    """Quota AND unreachable-LLM errors both trigger the deterministic fallback."""
    assert run_mod._should_degrade(Exception(message)) is True


@pytest.mark.parametrize(
    "message",
    [
        "invalid API key",
        "ValueError: bad input",
        "KeyError: 'target'",
    ],
)
def test_should_degrade_false(message: str) -> None:
    """Genuine bugs / config errors are not degraded — they should re-raise."""
    assert run_mod._should_degrade(Exception(message)) is False


async def test_complete_phases_runs_only_missing(monkeypatch) -> None:
    """The degraded fallback runs only the phases the agent did not reach."""
    # Arrange — DNS already done; WHOIS and ports still pending
    findings = ReconFindings(target="example.com", completed={"dns"})
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
    findings = ReconFindings(target="example.com", completed=set())
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


async def test_complete_vuln_phases_runs_when_missing(monkeypatch) -> None:
    """The vuln degraded fallback runs the nuclei phase when not yet completed."""
    # Arrange
    findings = VulnFindings(
        target="example.com", ports=[{"port": 443}], completed=set()
    )
    do_nuclei_scan = AsyncMock()
    monkeypatch.setattr(vuln_tools_mod, "do_nuclei_scan", do_nuclei_scan)

    # Act
    await run_mod._complete_vuln_phases_deterministically(findings)

    # Assert
    do_nuclei_scan.assert_awaited_once_with("example.com", [{"port": 443}])


async def test_complete_vuln_phases_skips_when_already_done(monkeypatch) -> None:
    """The vuln degraded fallback is a no-op if the agent already ran the scan."""
    # Arrange
    findings = VulnFindings(target="example.com", ports=[], completed={"nuclei"})
    do_nuclei_scan = AsyncMock()
    monkeypatch.setattr(vuln_tools_mod, "do_nuclei_scan", do_nuclei_scan)

    # Act
    await run_mod._complete_vuln_phases_deterministically(findings)

    # Assert
    do_nuclei_scan.assert_not_called()


async def test_complete_intel_phases_runs_available_sources(monkeypatch) -> None:
    """Each available, not-yet-completed source is run; unavailable ones are skipped."""
    # Arrange — CVEs and an IP available; only Shodan+VirusTotal capable (no key
    # for SecurityTrails); nothing completed yet.
    findings = IntelFindings(
        target="example.com", cves=["CVE-2024-0001"], ips=["1.2.3.4"], completed=set()
    )
    capabilities = {"shodan": True, "virustotal": True, "securitytrails": False}
    do_cve = AsyncMock()
    do_shodan = AsyncMock()
    do_vt = AsyncMock()
    do_st = AsyncMock()
    monkeypatch.setattr(intel_tools_mod, "do_cve_enrichment", do_cve)
    monkeypatch.setattr(intel_tools_mod, "do_shodan_lookup", do_shodan)
    monkeypatch.setattr(intel_tools_mod, "do_virustotal_lookup", do_vt)
    monkeypatch.setattr(intel_tools_mod, "do_securitytrails_lookup", do_st)

    # Act
    await run_mod._complete_intel_phases_deterministically(findings, capabilities)

    # Assert
    do_cve.assert_awaited_once_with(["CVE-2024-0001"])
    do_shodan.assert_awaited_once_with("1.2.3.4")
    do_vt.assert_awaited_once_with("example.com")
    do_st.assert_not_called()


async def test_complete_intel_phases_skips_already_completed(monkeypatch) -> None:
    """Sources already marked completed by the agent are not re-run."""
    # Arrange
    findings = IntelFindings(
        target="example.com",
        cves=["CVE-2024-0001"],
        ips=["1.2.3.4"],
        completed={"cve", "shodan", "virustotal"},
    )
    capabilities = {"shodan": True, "virustotal": True, "securitytrails": True}
    do_cve = AsyncMock()
    do_shodan = AsyncMock()
    do_vt = AsyncMock()
    do_st = AsyncMock()
    monkeypatch.setattr(intel_tools_mod, "do_cve_enrichment", do_cve)
    monkeypatch.setattr(intel_tools_mod, "do_shodan_lookup", do_shodan)
    monkeypatch.setattr(intel_tools_mod, "do_virustotal_lookup", do_vt)
    monkeypatch.setattr(intel_tools_mod, "do_securitytrails_lookup", do_st)

    # Act
    await run_mod._complete_intel_phases_deterministically(findings, capabilities)

    # Assert
    do_cve.assert_not_called()
    do_shodan.assert_not_called()
    do_vt.assert_not_called()
    do_st.assert_awaited_once_with("example.com")


async def test_complete_intel_phases_skips_cve_when_no_cves(monkeypatch) -> None:
    """CVE enrichment is skipped entirely when Victor found no CVEs to check."""
    # Arrange
    findings = IntelFindings(target="example.com", cves=[], ips=[], completed=set())
    capabilities = {"shodan": False, "virustotal": False, "securitytrails": False}
    do_cve = AsyncMock()
    monkeypatch.setattr(intel_tools_mod, "do_cve_enrichment", do_cve)

    # Act
    await run_mod._complete_intel_phases_deterministically(findings, capabilities)

    # Assert
    do_cve.assert_not_called()
