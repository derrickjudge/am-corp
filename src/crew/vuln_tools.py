"""
CrewAI tool wrappers for Victor's vulnerability scanning.

Mirrors src/crew/tools.py's pattern (see that module's docstring for the full
rationale on the sync<->async bridge and the one-do_*()-two-callers shape).
This is a separate module rather than an addition to tools.py because Victor's
bridge state (event loop, job id) is independent of Randy's — the two agents
can run in the same process without sharing globals.
"""

import asyncio
import random
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from crewai.tools import tool

from src.agents import AGENT_VICTOR_VULN
from src.agents.victor_vuln import (
    FINDING_REACTIONS,
    NO_VULNS_FALLBACKS,
    SCANNING_NO_RECON_FALLBACKS,
    SCANNING_WITH_RECON_FALLBACKS,
    _random_fallback,
)
from src.crew.narration import push_agent_chat, push_thought
from src.discord_bot.agent_bots import get_ivy_mention
from src.tools.vuln_tools import (
    get_default_templates,
    nuclei_scan,
    select_templates_for_ports,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Injected at crew kickoff alongside the event loop
_job_id: str | None = None

# The bot's running event loop — set once at crew kickoff via set_event_loop()
_bot_loop: asyncio.AbstractEventLoop | None = None

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


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
            _bot_loop, AGENT_VICTOR_VULN, text, category=category, confidence=confidence
        )


def _chat(text: str) -> None:
    """Post a per-phase update to #agent-chat (no-op if loop unset)."""
    if _bot_loop is not None:
        push_agent_chat(_bot_loop, AGENT_VICTOR_VULN, text)


def _store_findings() -> Any:
    """Return the vuln findings store for the current job, or None."""
    if not _job_id:
        return None
    from src.crew.findings import get_vuln_findings

    return get_vuln_findings(_job_id)


def _ports_from_findings() -> list[dict[str, Any]]:
    """Read the recon ports fed into this run at init_vuln_run()."""
    store = _store_findings()
    return store.ports if store else []


def _render_vuln_chat(target: str, vulns: list[dict[str, Any]]) -> str:
    """Build the deterministic, structured #agent-chat message for a scan result."""
    if not vulns:
        return _random_fallback(NO_VULNS_FALLBACKS, target=target)

    counts = {
        sev: sum(1 for v in vulns if v.get("severity") == sev)
        for sev in ("critical", "high", "medium", "low")
    }
    count_line = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)

    top = [v for v in vulns if v.get("severity") in ("critical", "high")][:5]
    bullets = []
    for v in top:
        emoji = _SEVERITY_EMOJI.get(v.get("severity", ""), "⚪")
        cve = v.get("cve_id")
        cve_suffix = f" ({cve})" if cve else ""
        bullets.append(f"  {emoji} {v.get('name', 'Unknown')}{cve_suffix}")

    msg = f"{random.choice(FINDING_REACTIONS)} {count_line} on {target}."
    if bullets:
        msg += "\n" + "\n".join(bullets)
    if any(v.get("cve_id") for v in vulns):
        msg += (
            f"\n\n{get_ivy_mention()}, some CVEs in here worth checking against "
            "threat intel."
        )

    return msg


# =============================================================================
# Phase logic — shared by the @tool wrapper and the deterministic fallback
# =============================================================================


async def do_nuclei_scan(target: str, ports: list[dict[str, Any]]) -> str:
    """Run a Nuclei scan: write findings, post chat + thoughts, return LLM text."""
    if ports:
        _think(
            f"Got {len(ports)} ports from Randy's recon. Going with smart template "
            "selection instead of spraying everything.",
            category="decision",
            confidence=0.85,
        )
        templates, _reasoning = select_templates_for_ports(ports)
        _chat(
            _random_fallback(
                SCANNING_WITH_RECON_FALLBACKS,
                templates=len(templates),
                ports=len(ports),
            )
        )
    else:
        _think(
            "No recon data to work with. Going broad with default templates.",
            category="reasoning",
            confidence=0.6,
        )
        templates = get_default_templates()
        _chat(_random_fallback(SCANNING_NO_RECON_FALLBACKS))

    result = await nuclei_scan(
        target, templates=templates, severity=["critical", "high", "medium"]
    )
    if not result.success:
        _think(f"Nuclei scan on {target} failed: {result.error}", category="detail")
        _chat(f"Vuln scan on {target} hit a snag: {result.error}")
        return f"Vuln scan failed: {result.error}"

    vulns = result.vulnerabilities

    store = _store_findings()
    if store:
        store.set_findings(vulns, templates)

    _chat(_render_vuln_chat(target, vulns))

    critical = [v for v in vulns if v.get("severity") == "critical"]
    high = [v for v in vulns if v.get("severity") == "high"]
    cve_vulns = [v for v in vulns if v.get("cve_id")]
    if critical:
        _think(
            f"Found {len(critical)} CRITICAL vuln(s). Need to verify these aren't "
            "false positives before reporting.",
            category="finding",
            confidence=0.75,
        )
    elif high:
        _think(
            f"Got {len(high)} HIGH severity finding(s). Definitely needs attention.",
            category="finding",
            confidence=0.8,
        )
    if cve_vulns:
        _think(
            f"Found {len(cve_vulns)} CVE-related finding(s). Ivy should check "
            "exploitation probability and threat intel.",
            category="reasoning",
        )

    if not vulns:
        return "No vulnerabilities found."
    lines = [f"Found {len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'}:"]
    for v in vulns[:10]:
        severity = v.get("severity", "unknown").upper()
        lines.append(f"  {severity}: {v.get('name', 'Unknown')}")
    return "\n".join(lines)


# =============================================================================
# Victor's CrewAI tool — thin sync wrapper over do_nuclei_scan()
# =============================================================================


@tool("Nuclei Vulnerability Scanner")
def nuclei_scan_tool(target: str) -> str:
    """
    Run a Nuclei vulnerability scan against the target.

    Automatically uses smart template selection based on any open ports
    already discovered during reconnaissance (falls back to broad default
    templates when none are available). Call this once per target — it runs
    the complete scan in a single pass.
    Returns a summary of vulnerabilities found, grouped by severity.
    """
    return _run_async(do_nuclei_scan(target, _ports_from_findings()), timeout=600)


def get_vuln_tools() -> list[Any]:
    """Return all vuln tools for use in a CrewAI Agent definition."""
    return [nuclei_scan_tool]
