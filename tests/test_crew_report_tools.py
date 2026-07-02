"""Tests for the report phase function in src/crew/report_tools.py.

do_compile_report() runs Rita's existing deterministic aggregation (reused,
not rewritten), generates an executive summary via the crew LLM, writes the
result to the findings store, posts a structured #agent-chat message, and
returns text for the LLM. The LLM call and Discord-posting helpers are
mocked, so these are pure unit tests of the aggregation + wiring.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.agents.ivy_intel import IntelScanResult
from src.agents.randy_recon import ReconResult
from src.agents.victor_vuln import VulnScanResult
from src.crew import findings as findings_mod
from src.crew import report_tools


@pytest.fixture
def job(monkeypatch):
    """Register a findings store and capture chat/thoughts instead of posting."""
    chats: list[str] = []
    thoughts: list[tuple[str, str]] = []
    monkeypatch.setattr(report_tools, "_chat", lambda text: chats.append(text))
    monkeypatch.setattr(
        report_tools,
        "_think",
        lambda text, category="reasoning", confidence=None: thoughts.append(
            (category, text)
        ),
    )
    monkeypatch.setattr(report_tools, "_job_id", "test-job")
    store = findings_mod.init_report_run("test-job", "example.com")
    yield SimpleNamespace(store=store, chats=chats, thoughts=thoughts)
    findings_mod.clear_report_run("test-job")


async def test_do_compile_report_writes_findings_and_marks_completed(
    job, monkeypatch
) -> None:
    """A full compile stores a ReportResult and posts a completion message."""
    # Arrange
    monkeypatch.setattr(
        report_tools, "generate_agent_message", AsyncMock(return_value="Summary text.")
    )
    vuln_result = VulnScanResult(target="example.com", critical_count=2)

    # Act
    out = await report_tools.do_compile_report(
        "example.com", recon_result=None, vuln_result=vuln_result, intel_result=None
    )

    # Assert
    assert job.store.report is not None
    assert job.store.report.overall_risk == "CRITICAL"
    assert job.store.report.executive_summary == "Summary text."
    assert "report" in job.store.completed
    assert job.chats, "expected a completion message in #agent-chat"
    assert "CRITICAL" in out


async def test_do_compile_report_clean_scan(job, monkeypatch) -> None:
    """No findings from any agent still produces a CLEAN report, not an error."""
    # Arrange
    monkeypatch.setattr(
        report_tools, "generate_agent_message", AsyncMock(return_value="Clean summary.")
    )

    # Act
    out = await report_tools.do_compile_report(
        "example.com", recon_result=None, vuln_result=None, intel_result=None
    )

    # Assert
    assert job.store.report is not None
    assert job.store.report.overall_risk == "CLEAN"
    assert "CLEAN" in out


async def test_do_compile_report_includes_port_and_intel_context(
    job, monkeypatch
) -> None:
    """Recon ports and intel highlights flow into the compiled report."""
    # Arrange
    generate = AsyncMock(return_value="Summary text.")
    monkeypatch.setattr(report_tools, "generate_agent_message", generate)
    recon_result = ReconResult(
        target="example.com", raw_findings={"ports": [{"port": 443}]}
    )
    intel_result = IntelScanResult(target="example.com")

    # Act
    await report_tools.do_compile_report(
        "example.com",
        recon_result=recon_result,
        vuln_result=None,
        intel_result=intel_result,
    )

    # Assert
    assert job.store.report is not None
    assert job.store.report.open_ports == [{"port": 443}]
    # The prompt sent to the LLM should reference the port data.
    assert generate.await_args is not None
    prompt = generate.await_args.kwargs["prompt"]
    assert "1 open port" in prompt
