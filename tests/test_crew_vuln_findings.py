"""Tests for the run-scoped vuln findings store (src/crew/findings.py)."""

from src.crew import findings as f


def test_init_get_clear_lifecycle() -> None:
    """init_vuln_run stores an object; get/clear_vuln_run retrieve/remove it."""
    # Arrange / Act
    obj = f.init_vuln_run("job-1", "example.com", ports=[{"port": 80}])

    # Assert
    assert f.get_vuln_findings("job-1") is obj
    assert obj.target == "example.com"
    assert obj.ports == [{"port": 80}]

    f.clear_vuln_run("job-1")
    assert f.get_vuln_findings("job-1") is None


def test_init_defaults_ports_to_empty_list() -> None:
    """Omitting ports (e.g. standalone vuln scan with no recon) defaults to []."""
    obj = f.init_vuln_run("job-2", "example.com")
    assert obj.ports == []
    f.clear_vuln_run("job-2")


def test_set_findings_populates_and_tracks_completed() -> None:
    """set_findings stores results, templates used, and marks the phase completed."""
    # Arrange
    obj = f.init_vuln_run("job-3", "example.com")
    vulns = [
        {"severity": "critical", "name": "RCE", "cve_id": "CVE-2024-0001"},
        {"severity": "high", "name": "SQLi"},
        {"severity": "medium", "name": "Misconfig"},
    ]

    # Act
    obj.set_findings(vulns, templates=["cves", "http"])

    # Assert
    assert obj.findings == vulns
    assert obj.templates_used == ["cves", "http"]
    assert "nuclei" in obj.completed

    f.clear_vuln_run("job-3")


def test_severity_counts_and_cve_ids() -> None:
    """Severity counts and cve_ids are computed from the stored findings."""
    # Arrange
    obj = f.init_vuln_run("job-4", "example.com")
    obj.set_findings(
        [
            {"severity": "critical", "name": "a", "cve_id": "CVE-1"},
            {"severity": "critical", "name": "b"},
            {"severity": "high", "name": "c", "cve_id": "CVE-2"},
            {"severity": "medium", "name": "d"},
            {"severity": "low", "name": "e"},
            {"severity": "info", "name": "f"},
        ],
        templates=["cves"],
    )

    # Assert
    assert obj.critical_count == 2
    assert obj.high_count == 1
    assert obj.medium_count == 1
    assert obj.low_count == 1
    assert obj.info_count == 1
    assert obj.cve_ids == ["CVE-1", "CVE-2"]

    f.clear_vuln_run("job-4")


def test_empty_findings_are_still_marked_completed() -> None:
    """A clean scan (no vulns) is still marked completed (attempted)."""
    obj = f.init_vuln_run("job-5", "example.com")
    obj.set_findings([], templates=["cves"])

    assert obj.critical_count == 0
    assert "nuclei" in obj.completed

    f.clear_vuln_run("job-5")


def test_clear_vuln_run_is_idempotent() -> None:
    """Clearing a job id that was never registered does not raise."""
    f.clear_vuln_run("never-existed")
