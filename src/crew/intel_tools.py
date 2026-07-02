"""
CrewAI tool wrappers for Ivy's threat intelligence gathering.

Mirrors src/crew/tools.py's pattern (see that module's docstring for the full
rationale on the sync<->async bridge and the one-do_*()-two-callers shape).
This is a separate module because Ivy's bridge state (event loop, job id) is
independent of Randy's/Victor's.

Unlike Randy (3 sequential phases, all always run) and Victor (1 phase),
Ivy's four sources are each independently optional: CVE enrichment only
matters if Victor found CVEs, and Shodan/VirusTotal/SecurityTrails each
require their own API key. Each tool checks its own precondition and returns
a clear "skipped" message rather than erroring, so the LLM gets useful
feedback regardless of what it decides to call.
"""

import asyncio
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from crewai.tools import tool

from src.agents import AGENT_IVY_INTEL
from src.agents.ivy_intel import (
    SECURITYTRAILS_FALLBACKS,
    SHODAN_FALLBACKS,
    VT_CLEAN_FALLBACKS,
    VT_DIRTY_FALLBACKS,
    _random_fallback,
)
from src.crew.narration import push_agent_chat, push_thought
from src.discord_bot.agent_bots import get_victor_mention
from src.tools.intel_tools import (
    assess_exploitation_risk,
    lookup_multiple_cves,
    securitytrails_lookup,
    shodan_host_lookup,
    virustotal_lookup,
)
from src.utils.logging import get_logger

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
            _bot_loop, AGENT_IVY_INTEL, text, category=category, confidence=confidence
        )


def _chat(text: str) -> None:
    """Post a per-phase update to #agent-chat (no-op if loop unset)."""
    if _bot_loop is not None:
        push_agent_chat(_bot_loop, AGENT_IVY_INTEL, text)


def _store_findings() -> Any:
    """Return the intel findings store for the current job, or None."""
    if not _job_id:
        return None
    from src.crew.findings import get_intel_findings

    return get_intel_findings(_job_id)


def _cves_from_findings() -> list[str]:
    """Read the CVE IDs fed into this run at init_intel_run()."""
    store = _store_findings()
    return store.cves if store else []


def _ips_from_findings() -> list[str]:
    """Read the IPs fed into this run at init_intel_run()."""
    store = _store_findings()
    return store.ips if store else []


def _render_cve_chat(cves: list[Any]) -> str:
    """Build the deterministic, structured #agent-chat message for CVE enrichment."""
    valid = [c for c in cves if not c.error]
    if not valid:
        return (
            "Couldn't get CVE details back — NVD may be rate-limiting or the "
            "IDs were invalid."
        )

    high_risk = [(c, assess_exploitation_risk(c)) for c in valid]
    high_risk = [(c, r) for c, r in high_risk if r in ("CRITICAL", "HIGH")]

    if not high_risk:
        return f"Checked {len(valid)} CVE(s). Nothing critical in the wild. For now."

    bullets = []
    for cve, risk in high_risk[:3]:
        epss_pct = (
            f"{cve.epss_score * 100:.1f}%" if cve.epss_score is not None else "unknown"
        )
        bullets.append(f"  • {cve.cve_id}: {risk} risk, {epss_pct} EPSS")

    msg = (
        f"Checked {len(valid)} CVE(s), {len(high_risk)} with HIGH/CRITICAL "
        "exploitation risk."
    )
    msg += "\n" + "\n".join(bullets)
    msg += f"\n\n{get_victor_mention()}, worth bumping priority on these."
    return msg


# =============================================================================
# Phase logic — shared by the @tool wrappers and the deterministic fallback
# =============================================================================


async def do_cve_enrichment(cves: list[str]) -> str:
    """Enrich CVEs with NVD/EPSS: write findings, post chat + thoughts, return text."""
    _think(
        f"Got {len(cves)} CVE(s) to check. CVSS is one thing, but EPSS is what "
        "matters - who's actually exploiting these in the wild.",
        category="reasoning",
    )

    enriched = await lookup_multiple_cves(cves)

    store = _store_findings()
    if store:
        store.set_cve_enrichments(enriched)

    _chat(_render_cve_chat(enriched))

    high_risk = [
        c
        for c in enriched
        if not c.error and assess_exploitation_risk(c) in ("CRITICAL", "HIGH")
    ]
    if high_risk:
        _think(
            f"Found {len(high_risk)} CVE(s) with HIGH/CRITICAL exploitation risk. "
            "These aren't theoretical — priority bump needed.",
            category="finding",
            confidence=0.85,
        )

    lines = [f"Enriched {len(enriched)} CVE(s), {len(high_risk)} high-risk."]
    return "\n".join(lines)


async def do_shodan_lookup(ip: str) -> str:
    """Check Shodan: write findings, post chat + thoughts, return LLM text."""
    _think(f"Checking Shodan for exposure history on {ip}.", category="reasoning")

    result = await shodan_host_lookup(ip)

    if result.error:
        _chat(f"Shodan: {result.error}")
        return f"Shodan lookup failed: {result.error}"

    store = _store_findings()
    if store:
        store.set_shodan_result(result)

    if result.vulns:
        _think(
            f"Shodan flags {len(result.vulns)} known vuln(s) on {ip}. "
            "Been exposed a while.",
            category="finding",
            confidence=0.75,
        )
        _chat(
            f"Bit concerning - Shodan's got {len(result.vulns)} vuln(s) flagged on "
            f"{ip}. Been exposed since at least {result.last_update or 'unknown'}."
        )
    elif result.ports:
        _chat(
            _random_fallback(
                SHODAN_FALLBACKS,
                date=result.last_update or "unknown",
                ports=len(result.ports),
            )
        )
    else:
        _chat(f"Not much on Shodan for {ip}. That's either good news or good OPSEC.")

    if not result.vulns and not result.ports:
        return "No Shodan exposure data found."
    return (
        f"Shodan: {len(result.ports)} port(s) exposed, "
        f"{len(result.vulns)} known vuln(s)."
    )


async def do_virustotal_lookup(target: str) -> str:
    """Check VirusTotal: write findings, post chat + thoughts, return LLM text."""
    _think(f"Checking VirusTotal reputation for {target}.", category="reasoning")

    result = await virustotal_lookup(target, "domain")

    if result.error:
        _chat(f"VirusTotal: {result.error}")
        return f"VirusTotal lookup failed: {result.error}"

    store = _store_findings()
    if store:
        store.set_virustotal_result(result)

    if result.malicious_count > 0 or result.suspicious_count > 0:
        _think(
            f"VirusTotal flags {result.malicious_count} malicious, "
            f"{result.suspicious_count} suspicious on {target}.",
            category="finding",
            confidence=0.8,
        )
        _chat(
            _random_fallback(
                VT_DIRTY_FALLBACKS,
                malicious=result.malicious_count,
                suspicious=result.suspicious_count,
            )
        )
    elif result.reputation < -10:
        _chat(
            f"VirusTotal shows negative reputation ({result.reputation}) for "
            f"{target}. Worth a closer look."
        )
    else:
        _chat(_random_fallback(VT_CLEAN_FALLBACKS))

    return (
        f"VirusTotal: reputation {result.reputation}, {result.malicious_count} "
        f"malicious, {result.suspicious_count} suspicious detection(s)."
    )


async def do_securitytrails_lookup(target: str) -> str:
    """Check SecurityTrails: write findings, post chat + thoughts, return text."""
    _think(
        f"Checking SecurityTrails for domain intel on {target}.",
        category="reasoning",
    )

    result = await securitytrails_lookup(target)

    if result.error:
        _chat(f"SecurityTrails: {result.error}")
        return f"SecurityTrails lookup failed: {result.error}"

    store = _store_findings()
    if store:
        store.set_securitytrails_result(result)

    if result.subdomain_count > 0:
        _think(
            f"{result.subdomain_count} subdomain(s) on {target}. Each one's a "
            "potential entry point.",
            category="detail",
        )
        _chat(
            _random_fallback(
                SECURITYTRAILS_FALLBACKS, subdomains=result.subdomain_count
            )
        )
    else:
        _chat(
            f"SecurityTrails shows limited data for {target}. "
            "May be newer or less prominent."
        )

    return (
        f"SecurityTrails: {result.subdomain_count} subdomain(s), "
        f"{len(result.associated_domains)} associated domain(s)."
    )


# =============================================================================
# Ivy's four CrewAI tools — thin sync wrappers over the do_*() functions
# =============================================================================


@tool("CVE & EPSS Enrichment")
def cve_enrichment_tool(target: str) -> str:
    """
    Enrich known CVEs for this target with NVD details and EPSS exploitation scores.

    Reads the CVE IDs discovered during vulnerability scanning. Call this
    first if CVEs are available — EPSS tells you real-world exploitation
    likelihood, not just theoretical CVSS severity.
    Returns CVE risk details, or a message if no CVEs are available to enrich.
    """
    cves = _cves_from_findings()
    if not cves:
        return "No CVEs available to enrich for this target."
    return _run_async(do_cve_enrichment(cves), timeout=180)


@tool("Shodan Host Lookup")
def shodan_lookup_tool(target: str) -> str:
    """
    Check Shodan for internet-exposure history on this target's IP.

    Only useful if an IP was discovered during recon/vuln scanning and
    SHODAN_API_KEY is configured. Returns exposure history, open ports, and
    known vulnerabilities Shodan has flagged, or a message explaining why the
    lookup was skipped.
    """
    ips = _ips_from_findings()
    if not ips:
        return "No IP address available for Shodan lookup."
    return _run_async(do_shodan_lookup(ips[0]), timeout=60)


@tool("VirusTotal Reputation Lookup")
def virustotal_lookup_tool(target: str) -> str:
    """
    Check VirusTotal for domain reputation and malicious detections.

    Only useful if VIRUSTOTAL_API_KEY is configured.
    Returns reputation score and malicious/suspicious detection counts.
    """
    return _run_async(do_virustotal_lookup(target), timeout=60)


@tool("SecurityTrails Domain Intel")
def securitytrails_lookup_tool(target: str) -> str:
    """
    Check SecurityTrails for subdomain enumeration and associated domains.

    Only useful if SECURITYTRAILS_API_KEY is configured.
    Returns subdomain count and attack-surface details.
    """
    return _run_async(do_securitytrails_lookup(target), timeout=60)


def get_intel_tools() -> list[Any]:
    """Return all intel tools for use in a CrewAI Agent definition."""
    return [
        cve_enrichment_tool,
        shodan_lookup_tool,
        virustotal_lookup_tool,
        securitytrails_lookup_tool,
    ]
