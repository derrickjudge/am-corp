"""
CrewAI tool wrappers for Randy's recon tools.

KEY CONCEPT — why wrappers exist:
  CrewAI calls tools synchronously (from a worker thread it manages).
  Our actual tools (dig_lookup, whois_lookup, nmap_scan) are async.
  The bridge: asyncio.run_coroutine_threadsafe() submits the coroutine
  to the Discord bot's running event loop and blocks until it finishes.

  The event loop reference is injected at crew kickoff time via
  set_event_loop(). This avoids a circular import and keeps tools
  testable independently.

KEY CONCEPT — the @tool decorator:
  The docstring IS the tool description the LLM reads to decide when
  to use this tool. Write it for the LLM, not for a human developer.
  Be specific: what does it return, when should the agent use it?
"""

import asyncio
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Optional

from crewai.tools import tool

from src.tools.recon_tools import dig_lookup, nmap_scan, whois_lookup
from src.utils.logging import get_logger

# Injected at crew kickoff alongside the event loop
_job_id: Optional[str] = None

logger = get_logger(__name__)

# The bot's running event loop — set once at crew kickoff via set_event_loop()
_bot_loop: Optional[asyncio.AbstractEventLoop] = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Register the bot's event loop so sync tools can submit async work."""
    global _bot_loop
    _bot_loop = loop


def set_job_id(job_id: str) -> None:
    """Register the current job ID so tools can write to the findings store."""
    global _job_id
    _job_id = job_id


def _run_async(coro, timeout: int = 120):
    """
    Run an async coroutine from a sync context using the bot's event loop.

    Raises RuntimeError if the event loop was never registered (i.e.
    set_event_loop() was not called before running the crew).
    """
    if _bot_loop is None:
        raise RuntimeError(
            "Bot event loop not registered. Call set_event_loop() before running the crew."
        )
    future = asyncio.run_coroutine_threadsafe(coro, _bot_loop)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        future.cancel()
        raise TimeoutError(f"Async tool timed out after {timeout}s")


# =============================================================================
# Randy's three tools
# =============================================================================

@tool("DNS Lookup")
def dns_lookup_tool(target: str) -> str:
    """
    Perform a DNS lookup on the target using dig.

    Use this tool first when starting reconnaissance on any target.
    Returns A, AAAA, MX, NS, TXT, and CNAME records.
    Call this with the bare domain name (e.g. 'example.com', not 'https://example.com').
    Returns a text summary of all DNS records found, or an error message.
    """
    result = _run_async(dig_lookup(target))
    if not result.success:
        return f"DNS lookup failed: {result.error}"

    # Write structured data to the findings store for downstream consumers
    if _job_id and result.parsed_data:
        from src.crew.findings import get_findings
        findings = get_findings(_job_id)
        if findings:
            findings.set_dns(result.parsed_data.get("records", {}))

    return result.output or "No DNS records found."


@tool("WHOIS Lookup")
def whois_lookup_tool(target: str) -> str:
    """
    Perform a WHOIS lookup on the target domain to gather registration information.

    Use this tool to identify registrar, registration/expiry dates, name servers,
    and registrant organization. Useful for understanding who owns the target
    and how long they have maintained it.
    Call this with the base domain (e.g. 'example.com', not a subdomain).
    Returns registrar name, dates, and name server information.
    """
    result = _run_async(whois_lookup(target))
    if not result.success:
        return f"WHOIS lookup failed: {result.error}"

    if _job_id and result.parsed_data:
        from src.crew.findings import get_findings
        findings = get_findings(_job_id)
        if findings:
            findings.set_whois(result.parsed_data)

    return result.output or "No WHOIS data found."


@tool("Port Scanner")
def port_scan_tool(target: str) -> str:
    """
    Run an nmap port scan on the target to discover open ports and services.

    Use this tool after DNS lookup to identify what services are exposed.
    Scans the top 500 ports using TCP connect scan (-sT) with service version
    detection (-sV). Safe for authorized targets — does not attempt exploitation.
    Returns a list of open ports with service names and version info.
    Only scan targets you have explicit authorization to scan.
    """
    result = _run_async(nmap_scan(target), timeout=360)
    if not result.success:
        return f"Port scan failed: {result.error}"

    ports = result.parsed_data.get("ports", [])

    # Write structured port list to findings store — Victor reads this
    if _job_id:
        from src.crew.findings import get_findings
        findings = get_findings(_job_id)
        if findings:
            findings.set_ports(ports)

    if not ports:
        return "No open ports found."

    lines = [f"Found {len(ports)} open port(s):"]
    for p in ports:
        port = p.get("port", "?")
        service = p.get("service", p.get("name", "unknown"))
        version = p.get("version", "")
        lines.append(f"  {port}/tcp  {service}  {version}".rstrip())
    return "\n".join(lines)


def get_recon_tools() -> list:
    """Return all recon tools for use in a CrewAI Agent definition."""
    return [dns_lookup_tool, whois_lookup_tool, port_scan_tool]
