"""Tests for the run-scoped intel findings store (src/crew/findings.py)."""

from src.crew import findings as f
from src.tools.intel_tools import CVEDetails


def test_init_get_clear_lifecycle() -> None:
    """init_intel_run stores an object; get/clear_intel_run retrieve/remove it."""
    # Arrange / Act
    obj = f.init_intel_run(
        "job-1", "example.com", cves=["CVE-2024-0001"], ips=["1.2.3.4"]
    )

    # Assert
    assert f.get_intel_findings("job-1") is obj
    assert obj.target == "example.com"
    assert obj.cves == ["CVE-2024-0001"]
    assert obj.ips == ["1.2.3.4"]

    f.clear_intel_run("job-1")
    assert f.get_intel_findings("job-1") is None


def test_init_defaults_cves_and_ips_to_empty_list() -> None:
    """Omitting cves/ips (e.g. standalone intel scan) defaults to []."""
    obj = f.init_intel_run("job-2", "example.com")
    assert obj.cves == []
    assert obj.ips == []
    f.clear_intel_run("job-2")


def test_setters_populate_and_track_completed() -> None:
    """Each setter stores its result and records the source as completed."""
    # Arrange
    obj = f.init_intel_run("job-3", "example.com")
    cve = CVEDetails(cve_id="CVE-2024-0001", cvss_score=9.5, epss_score=0.7)

    # Act
    obj.set_cve_enrichments([cve])

    # Assert
    assert obj.cve_enrichments == [cve]
    assert "cve" in obj.completed

    f.clear_intel_run("job-3")


def test_high_risk_cve_count() -> None:
    """high_risk_cve_count counts only CRITICAL/HIGH, non-errored CVEs."""
    # Arrange
    obj = f.init_intel_run("job-4", "example.com")
    obj.set_cve_enrichments(
        [
            CVEDetails(cve_id="CVE-1", epss_score=0.7),  # CRITICAL (>=0.5)
            CVEDetails(cve_id="CVE-2", epss_score=0.3),  # HIGH (>=0.2)
            CVEDetails(cve_id="CVE-3", epss_score=0.01),  # LOW
            CVEDetails(cve_id="CVE-4", epss_score=0.9, error="not found"),  # excluded
        ]
    )

    # Assert
    assert obj.high_risk_cve_count == 2

    f.clear_intel_run("job-4")


def test_clear_intel_run_is_idempotent() -> None:
    """Clearing a job id that was never registered does not raise."""
    f.clear_intel_run("never-existed")
