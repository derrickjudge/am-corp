"""Tests for the run-scoped report findings store (src/crew/findings.py)."""

from src.agents.ivy_intel import IntelScanResult
from src.agents.randy_recon import ReconResult
from src.agents.rita_report import ReportResult
from src.agents.victor_vuln import VulnScanResult
from src.crew import findings as f


def test_init_get_clear_lifecycle() -> None:
    """init_report_run stores an object; get/clear_report_run retrieve/remove it."""
    # Arrange / Act
    obj = f.init_report_run("job-1", "example.com")

    # Assert
    assert f.get_report_findings("job-1") is obj
    assert obj.target == "example.com"
    assert obj.report is None
    assert obj.completed == set()

    f.clear_report_run("job-1")
    assert f.get_report_findings("job-1") is None


def test_init_stores_upstream_agent_results() -> None:
    """The recon/vuln/intel inputs from the other agents are stored verbatim."""
    recon_result = ReconResult(target="example.com")
    vuln_result = VulnScanResult(target="example.com")
    intel_result = IntelScanResult(target="example.com")

    obj = f.init_report_run(
        "job-2",
        "example.com",
        recon_result=recon_result,
        vuln_result=vuln_result,
        intel_result=intel_result,
    )

    assert obj.recon_result is recon_result
    assert obj.vuln_result is vuln_result
    assert obj.intel_result is intel_result

    f.clear_report_run("job-2")


def test_set_report_populates_and_tracks_completed() -> None:
    """set_report stores the compiled report and marks the phase completed."""
    # Arrange
    obj = f.init_report_run("job-3", "example.com")
    report = ReportResult(
        target="example.com",
        scan_timestamp="2026-01-01T00:00:00+00:00",
        overall_risk="LOW",
        executive_summary="All clear.",
    )

    # Act
    obj.set_report(report)

    # Assert
    assert obj.report is report
    assert "report" in obj.completed

    f.clear_report_run("job-3")


def test_clear_report_run_is_idempotent() -> None:
    """Clearing a job id that was never registered does not raise."""
    f.clear_report_run("never-existed")
