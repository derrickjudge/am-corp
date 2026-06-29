"""
CrewAI tool wrappers for Randy's recon tools.

KEY CONCEPT — why wrappers exist:
  CrewAI calls tools synchronously (from a worker thread it manages).
  Our actual tools (dig_lookup, whois_lookup, nmap_scan) are async.
  The bridge: asyncio.run_coroutine_threadsafe() submits the coroutine
  to the Discord bot's running event loop and blocks until it finishes.

KEY CONCEPT — one implementation, two callers:
  Each phase's logic lives in an async do_*() function: run the lookup,
  write structured data to the findings store, post a structured per-phase
  update to #agent-chat, and post analytical thoughts to #thoughts. It then
  returns a concise text summary for the LLM.
    - The @tool wrapper runs do_*() via the sync->async bridge (agentic path).
    - run.py awaits do_*() directly when the LLM is unavailable (the
      degraded, deterministic fallback). Same output either way.

KEY CONCEPT — display is deterministic:
  The structured #agent-chat messages are built from the findings (with the
  Texan fallback pools for voice), NOT from the LLM's prose. That keeps the
  output tidy and bulleted, and means it still works when quota is exhausted.
"""

import asyncio
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Optional

from crewai.tools import tool

from src.agents import AGENT_RANDY_RECON
from src.agents.randy_recon import (
    DNS_FALLBACKS,
    NO_PORTS_FALLBACKS,
    PORTSCAN_DONE_FALLBACKS,
    WHOIS_FALLBACKS,
    _random_fallback,
)
from src.crew.narration import push_agent_chat, push_thought
from src.discord_bot.agent_bots import get_victor_mention
from src.tools.recon_tools import dig_lookup, nmap_scan, whois_lookup
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Injected at crew kickoff alongside the event loop
_job_id: Optional[str] = None

# The bot's running event loop — set once at crew kickoff via set_event_loop()
_bot_loop: Optional[asyncio.AbstractEventLoop] = None

# Services worth flagging for Victor, with why they matter
_RISKY_SERVICES = {
    "elasticsearch": "Elasticsearch is often exposed without auth",
    "mongodb": "MongoDB without auth is a common breach vector",
    "redis": "Exposed Redis can lead to RCE",
    "mysql": "Database exposed to the internet",
    "postgresql": "Database exposed to the internet",
    "ftp": "FTP is a legacy protocol, often insecure",
    "telnet": "Telnet is cleartext and insecure",
    "vnc": "VNC exposed remotely is risky",
    "rdp": "RDP exposed remotely is a frequent attack target",
}
_RISKY_PORTS = {
    9200: "elasticsearch",
    27017: "mongodb",
    6379: "redis",
    3306: "mysql",
    5432: "postgresql",
    21: "ftp",
    23: "telnet",
    5900: "vnc",
    3389: "rdp",
}


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


def _think(text: str, category: str = "reasoning", confidence: Optional[float] = None) -> None:
    """Post a data-driven thought to #thoughts (no-op if loop not registered)."""
    if _bot_loop is not None:
        push_thought(_bot_loop, AGENT_RANDY_RECON, text, category=category, confidence=confidence)


def _chat(text: str) -> None:
    """Post a structured per-phase update to #agent-chat (no-op if loop not registered)."""
    if _bot_loop is not None:
        push_agent_chat(_bot_loop, AGENT_RANDY_RECON, text)


def _store_findings():
    """Return the findings store for the current job, or None."""
    if not _job_id:
        return None
    from src.crew.findings import get_findings
    return get_findings(_job_id)


# =============================================================================
# Phase logic — shared by the @tool wrappers and the deterministic fallback
# =============================================================================

async def do_dns(target: str) -> str:
    """Run DNS lookup: write findings, post structured chat + thoughts, return LLM text."""
    _think(
        f"Starting passive recon on {target} with DNS enumeration — it won't "
        "trip any alerts. Looking for subdomains, mail servers, and anything unusual.",
        category="reasoning",
    )

    result = await dig_lookup(target)
    if not result.success:
        _think(f"DNS lookup on {target} came back empty or errored. Pressing on.", category="detail")
        return f"DNS lookup failed: {result.error}"

    records = (result.parsed_data or {}).get("records", {})

    store = _store_findings()
    if store:
        store.set_dns(records)

    # Structured #agent-chat message: Texan line + bulleted records
    total = sum(len(v) for v in records.values())
    line = _random_fallback(DNS_FALLBACKS, count=total, target=target)
    bullets = [f"  • {rtype}: `{val}`" for rtype, values in records.items() for val in values]
    _chat(line + ("\n" + "\n".join(bullets) if bullets else ""))

    # Analytical thoughts (deterministic, not LLM)
    ns_records = records.get("NS", [])
    mx_records = records.get("MX", [])
    txt_records = records.get("TXT", [])
    if len(ns_records) >= 4:
        _think(
            f"{len(ns_records)} name servers in play. Could be CDN plus origin, "
            "or a migration that left old records around. Worth noting.",
            category="finding", confidence=0.7,
        )
    if len(mx_records) >= 3:
        _think(f"Multiple MX records ({len(mx_records)}) — redundant or split email handling.", category="detail")
    if txt_records and not any("spf" in t.lower() for t in txt_records):
        _think(
            "TXT records present but no SPF that I can see. Could be a mail "
            "security gap — medium confidence, might be intentional.",
            category="uncertainty", confidence=0.6,
        )

    return result.output or "No DNS records found."


async def do_whois(target: str) -> str:
    """Run WHOIS lookup: write findings, post structured chat + thoughts, return LLM text."""
    _think(
        "Moving to WHOIS — want to see who owns this, when it was registered, "
        "and whether the registrar tells us anything.",
        category="reasoning",
    )

    result = await whois_lookup(target)
    if not result.success:
        _think(f"WHOIS on {target} didn't return much. Moving along.", category="detail")
        return f"WHOIS lookup failed: {result.error}"

    info = result.parsed_data or {}

    store = _store_findings()
    if store:
        store.set_whois(info)

    # Structured #agent-chat message: Texan line + key registration details
    line = _random_fallback(WHOIS_FALLBACKS, target=target)
    details = []
    if info.get("registrar"):
        details.append(f"  • Registrar: `{info['registrar']}`")
    if info.get("creation_date"):
        details.append(f"  • Created: `{info['creation_date']}`")
    if info.get("expiry_date"):
        details.append(f"  • Expires: `{info['expiry_date']}`")
    if info.get("name_servers"):
        details.append(f"  • Name Servers: `{', '.join(info['name_servers'][:3])}`")
    if info.get("registrant_org"):
        details.append(f"  • Organization: `{info['registrant_org']}`")
    _chat(line + ("\n" + "\n".join(details) if details else ""))

    creation_date = str(info.get("creation_date", ""))
    if any(year in creation_date for year in ("2024", "2025", "2026")):
        _think(
            f"Domain looks fairly new (created {creation_date}). Young domains "
            "sometimes mean less mature security practices.",
            category="finding", confidence=0.6,
        )
    if "privacy" in str(info.get("registrant_org", "")).lower():
        _think("WHOIS privacy protection is on — can't see the real owner from here.", category="detail")

    return result.output or "No WHOIS data found."


async def do_ports(target: str) -> str:
    """Run nmap port scan: write findings, post structured chat + thoughts, return LLM text."""
    _think(
        "Passive recon's done. Moving to active port scanning now — this may "
        "show up in their logs, but we've already got good intel.",
        category="decision", confidence=0.85,
    )

    result = await nmap_scan(target)
    if not result.success:
        _think(f"Port scan on {target} failed: {result.error}", category="detail")
        _chat(f"Port scan on {target} hit a snag and didn't complete. {result.error}")
        return f"Port scan failed: {result.error}"

    ports = (result.parsed_data or {}).get("ports", [])

    store = _store_findings()
    if store:
        store.set_ports(ports)

    if not ports:
        _chat(_random_fallback(NO_PORTS_FALLBACKS, target=target))
        _think(
            f"No open ports on {target} from the common ones I checked. Either "
            "tight security or services on non-standard ports.",
            category="finding",
        )
        return "No open ports found."

    # Structured #agent-chat message: Texan line + bulleted ports + Victor handoff
    line = _random_fallback(PORTSCAN_DONE_FALLBACKS, count=len(ports))
    bullets = []
    for p in ports:
        port = p.get("port", "?")
        service = p.get("service", p.get("name", "unknown"))
        version = p.get("version", "")
        version_str = f" ({version})" if version else ""
        bullets.append(f"  • Port `{port}`: {service}{version_str}")
    victor = get_victor_mention()
    msg = f"{line}\n" + "\n".join(bullets) + f"\n\n{victor}, reckon you'll want to poke at these."
    _chat(msg)

    # Analytical thoughts: flag risky services and version info for Victor
    for p in ports:
        service = str(p.get("service", "")).lower()
        port_num = p.get("port", 0)
        version = p.get("version", "")
        significance = _RISKY_SERVICES.get(service) or _RISKY_SERVICES.get(_RISKY_PORTS.get(port_num, ""))
        if significance:
            _think(
                f"Found {service or 'a service'} on port {port_num}. {significance}. "
                "Victor will want to look at this one.",
                category="finding", confidence=0.8,
            )
        if version:
            _think(
                f"Got version info — {service} {version} on port {port_num}. "
                "Victor can check that against known CVEs.",
                category="detail",
            )

    lines = [f"Found {len(ports)} open port(s):"]
    for p in ports:
        lines.append(
            f"  {p.get('port', '?')}/tcp  {p.get('service', p.get('name', 'unknown'))}  "
            f"{p.get('version', '')}".rstrip()
        )
    return "\n".join(lines)


# =============================================================================
# Randy's three CrewAI tools — thin sync wrappers over the do_*() functions
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
    return _run_async(do_dns(target))


@tool("WHOIS Lookup")
def whois_lookup_tool(target: str) -> str:
    """
    Perform a WHOIS lookup on the target domain to gather registration information.

    Use this tool to identify registrar, registration/expiry dates, name servers,
    and registrant organization. Useful for understanding who owns the target.
    Call this with the base domain (e.g. 'example.com', not a subdomain).
    Returns registrar name, dates, and name server information.
    """
    return _run_async(do_whois(target))


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
    return _run_async(do_ports(target), timeout=360)


def get_recon_tools() -> list:
    """Return all recon tools for use in a CrewAI Agent definition."""
    return [dns_lookup_tool, whois_lookup_tool, port_scan_tool]
