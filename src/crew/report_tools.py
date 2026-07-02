"""
CrewAI tool wrapper for Rita's report compilation.

WHY RITA IS DIFFERENT FROM RANDY/VICTOR/IVY:
  Every other converted agent has an LLM deciding WHICH tool to call (dig vs
  whois vs nmap; which of four intel sources to check). That tool-choice
  decision is the actual value of a CrewAI Agent. Rita has no such decision —
  she takes data the other agents already collected, runs deterministic
  Python to prioritize it (reused as-is from RitaReport, never rewritten),
  and makes exactly one LLM call to write an executive-summary paragraph.

  So this is a single-tool wrapper, not a multi-tool orchestration. The
  payoff is narrower than for the other three: mainly getting Rita's
  executive-summary generation onto the shared crew_llm routing (so it runs
  on Ollama when the crew is configured for local inference, instead of
  being hardcoded to Gemini like the hand-rolled
  RitaReport._generate_executive_summary).

Mirrors src/crew/tools.py's pattern otherwise (sync<->async bridge, one
do_*()-two-callers). Separate module because Rita's bridge state is
independent of the other three agents'.
"""

import asyncio
import random
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from crewai.tools import tool

from src.agents import AGENT_RITA_REPORT
from src.agents.rita_report import (
    POSTING_FALLBACKS,
    RITA_SYSTEM_PROMPT,
    SUMMARY_FALLBACKS,
    ReportResult,
    get_rita,
)
from src.crew.narration import push_agent_chat, push_thought
from src.crew.personality_chat import generate_agent_message
from src.utils.logging import get_logger

if TYPE_CHECKING:
    from src.agents.ivy_intel import IntelScanResult
    from src.agents.randy_recon import ReconResult
    from src.agents.rita_report import RiskItem
    from src.agents.victor_vuln import VulnScanResult

logger = get_logger(__name__)

# Injected at crew kickoff alongside the event loop
_job_id: str | None = None

# The bot's running event loop — set once at crew kickoff via set_event_loop()
_bot_loop: asyncio.AbstractEventLoop | None = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Register the bot's event loop so sync tools can submit async work."""
    global _bot_loop
    _bot_loop = loop


def set_job_id(job_id: str) -> None:
    """Register the current job ID so tools can write to the findings store."""
    global _job_id
    _job_id = job_id


def _run_async(coro: Any, timeout: int = 120) -> str:
    """
    Run an async coroutine from a sync context using the bot's event loop.

    Raises RuntimeError if the event loop was never registered (i.e.
    set_event_loop() was not called before running the crew).
    """
    if _bot_loop is None:
        raise RuntimeError(
            "Bot event loop not registered. Call set_event_loop() "
            "before running the crew."
        )
    future = asyncio.run_coroutine_threadsafe(coro, _bot_loop)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        future.cancel()
        raise TimeoutError(f"Async tool timed out after {timeout}s") from None


def _think(
    text: str, category: str = "reasoning", confidence: float | None = None
) -> None:
    """Post a data-driven thought to #thoughts (no-op if loop not registered)."""
    if _bot_loop is not None:
        push_thought(
            _bot_loop, AGENT_RITA_REPORT, text, category=category, confidence=confidence
        )


def _chat(text: str) -> None:
    """Post a per-phase update to #agent-chat (no-op if loop unset)."""
    if _bot_loop is not None:
        push_agent_chat(_bot_loop, AGENT_RITA_REPORT, text)


def _store_findings() -> Any:
    """Return the report findings store for the current job, or None."""
    if not _job_id:
        return None
    from src.crew.findings import get_report_findings

    return get_report_findings(_job_id)


def _report_inputs_from_findings() -> (
    tuple["ReconResult | None", "VulnScanResult | None", "IntelScanResult | None"]
):
    """Read the recon/vuln/intel results fed into this run at init_report_run()."""
    store = _store_findings()
    if not store:
        return None, None, None
    return store.recon_result, store.vuln_result, store.intel_result


async def _generate_executive_summary(
    target: str,
    overall_risk: str,
    recon_result: "ReconResult | None",
    vuln_result: "VulnScanResult | None",
    intel_result: "IntelScanResult | None",
    risk_items: list["RiskItem"],
) -> str:
    """
    Generate the executive summary paragraph via the shared crew LLM.

    Reuses the exact scan-data framing from RitaReport._generate_executive_summary
    but routes the actual generation through generate_agent_message() (the
    crew_llm, e.g. Ollama) instead of a hardcoded Gemini client — that's the
    whole point of Rita's conversion.
    """
    vuln_summary = ""
    if vuln_result:
        vuln_summary = (
            f"Nuclei found {vuln_result.critical_count} critical, "
            f"{vuln_result.high_count} high, "
            f"{vuln_result.medium_count} medium findings."
        )

    intel_summary = ""
    if intel_result and intel_result.cve_enrichments:
        max_epss_cve = max(
            intel_result.cve_enrichments, key=lambda c: c.epss_score or 0
        )
        epss_pct = (max_epss_cve.epss_score or 0) * 100
        intel_summary = (
            f"Ivy enriched {len(intel_result.cve_enrichments)} CVE(s). "
            f"Highest EPSS: {max_epss_cve.cve_id} at {epss_pct:.1f}%."
        )

    port_summary = ""
    if recon_result and recon_result.raw_findings.get("ports"):
        ports = recon_result.raw_findings["ports"]
        port_summary = f"Randy identified {len(ports)} open port(s)."

    top_risks = "\n".join(
        f"- [{i.severity}] {i.title}: {i.description[:100]}" for i in risk_items[:4]
    )

    prompt = f"""Write a 2-paragraph executive summary for a security \
assessment of {target}.

SCAN DATA:
- Overall Risk: {overall_risk}
- {port_summary or 'No port data.'}
- {vuln_summary or 'No vulnerability scan performed.'}
- {intel_summary or 'No CVE enrichment data.'}

TOP FINDINGS:
{top_risks or 'No critical/high findings identified.'}

Be direct and actionable. First paragraph: what was found and the risk level.
Second paragraph: top 2-3 recommendations. Do not use markdown headers. Keep
it under 200 words total."""

    finding_headline = (
        vuln_summary or intel_summary or f"overall risk rated {overall_risk}"
    )
    fallback = random.choice(SUMMARY_FALLBACKS).format(
        finding_headline=finding_headline
    )

    return await generate_agent_message(
        agent_id=AGENT_RITA_REPORT,
        character=RITA_SYSTEM_PROMPT,
        prompt=prompt,
        fallback=fallback,
    )


# =============================================================================
# Phase logic — shared by the @tool wrapper and the deterministic fallback
# =============================================================================


async def do_compile_report(
    target: str,
    recon_result: "ReconResult | None",
    vuln_result: "VulnScanResult | None",
    intel_result: "IntelScanResult | None",
) -> str:
    """Compile the report: write findings, post chat + thoughts, return LLM text."""
    _think(
        "Pulling together everything the team found - context first, then "
        "findings, then recommendations.",
        category="reasoning",
    )

    # Deterministic aggregation logic, reused as-is from RitaReport (never
    # rewritten — see module docstring).
    rita = get_rita()
    overall_risk = rita._compute_overall_risk(vuln_result, intel_result)
    risk_items = rita._build_risk_items(vuln_result, intel_result)
    intel_highlights = rita._extract_intel_highlights(intel_result)

    open_ports: list[dict[str, Any]] = []
    if recon_result and recon_result.raw_findings.get("ports"):
        open_ports = recon_result.raw_findings["ports"][:15]

    vuln_counts: dict[str, int] = {}
    if vuln_result:
        vuln_counts = {
            "critical": vuln_result.critical_count,
            "high": vuln_result.high_count,
            "medium": vuln_result.medium_count,
            "low": vuln_result.low_count,
        }

    shodan_exposure = ""
    virustotal_status = ""
    if intel_result:
        if intel_result.shodan_result and not intel_result.shodan_result.error:
            s = intel_result.shodan_result
            shodan_exposure = f"{len(s.ports)} ports / {s.org or 'unknown'}"
        if intel_result.virustotal_result and not intel_result.virustotal_result.error:
            vt = intel_result.virustotal_result
            virustotal_status = (
                f"{vt.malicious_count} malicious" if vt.malicious_count > 0 else "Clean"
            )

    executive_summary = await _generate_executive_summary(
        target, overall_risk, recon_result, vuln_result, intel_result, risk_items
    )

    report = ReportResult(
        target=target,
        scan_timestamp=datetime.now(UTC).isoformat(),
        overall_risk=overall_risk,
        executive_summary=executive_summary,
        risk_items=risk_items,
        open_ports=open_ports,
        vuln_counts=vuln_counts,
        intel_highlights=intel_highlights,
        shodan_exposure=shodan_exposure,
        virustotal_status=virustotal_status,
    )

    store = _store_findings()
    if store:
        store.set_report(report)

    _chat(random.choice(POSTING_FALLBACKS))
    _think(
        f"Report compiled. Overall risk: {overall_risk}. "
        f"{len(risk_items)} prioritized item(s).",
        category="finding",
        confidence=0.9,
    )

    return f"Report compiled. Overall risk: {overall_risk}."


# =============================================================================
# Rita's one CrewAI tool — thin sync wrapper over do_compile_report()
# =============================================================================


@tool("Compile Security Report")
def compile_report_tool(target: str) -> str:
    """
    Compile the team's findings into a prioritized security assessment report
    with an executive summary.

    Call this once, after the team's scans are complete. Automatically reads
    Randy's, Victor's, and Ivy's findings — no need to pass them in.
    Returns a one-line confirmation the report was compiled.
    """
    recon_result, vuln_result, intel_result = _report_inputs_from_findings()
    return _run_async(
        do_compile_report(target, recon_result, vuln_result, intel_result), timeout=60
    )


def get_report_tools() -> list[Any]:
    """Return all report tools for use in a CrewAI Agent definition."""
    return [compile_report_tool]
