"""
AM-Corp Reconnaissance Tools

Tool wrappers for dig, whois, and nmap that Randy Recon uses.
These execute locally for now, with Docker containerization planned.
"""

import asyncio
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


@dataclass
class ToolResult:
    """Result from a recon tool execution."""
    
    tool: str
    target: str
    success: bool
    output: str
    parsed_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    execution_time: float = 0.0


def _check_tool_available(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(tool_name) is not None


async def run_command(
    cmd: list[str], 
    timeout: int = 30,
    agent: str | None = None,
) -> tuple[bool, str, str]:
    """
    Run a shell command asynchronously with timeout.
    
    Args:
        cmd: Command and arguments to execute
        timeout: Timeout in seconds
        agent: Agent ID for debug logging
    
    Returns:
        Tuple of (success, stdout, stderr)
    """
    import time
    from src.utils.debug import debug_command, debug_result, is_debug_enabled
    
    cmd_str = " ".join(cmd)
    logger.info(f"[CMD] Executing: {cmd_str}")
    
    # Post to debug channel
    if is_debug_enabled():
        await debug_command(cmd_str, agent=agent)
    
    start_time = time.time()
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        logger.info(f"[CMD] Process started (PID: {process.pid}), waiting up to {timeout}s...")
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        
        duration = time.time() - start_time
        success = process.returncode == 0
        stdout_decoded = stdout.decode("utf-8", errors="replace")
        stderr_decoded = stderr.decode("utf-8", errors="replace")
        
        logger.info(f"[CMD] Completed with exit code {process.returncode}")
        if stdout_decoded:
            logger.debug(f"[CMD] stdout: {stdout_decoded[:200]}...")
        if stderr_decoded:
            logger.debug(f"[CMD] stderr: {stderr_decoded[:200]}...")
        
        # Post result to debug channel
        if is_debug_enabled():
            output_preview = stdout_decoded or stderr_decoded
            await debug_result(
                cmd[0],  # Just the command name
                process.returncode,
                duration,
                agent=agent,
                output_preview=output_preview[:100] if output_preview else None,
            )
        
        return success, stdout_decoded, stderr_decoded
        
    except asyncio.TimeoutError:
        duration = time.time() - start_time
        logger.error(f"[CMD] Timed out after {timeout}s: {cmd_str}")
        process.kill()
        
        if is_debug_enabled():
            await debug_result(cmd[0], -1, duration, agent=agent, output_preview="TIMEOUT")
        
        return False, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"[CMD] Failed: {cmd_str} - {e}")
        
        if is_debug_enabled():
            from src.utils.debug import debug_error
            await debug_error(f"Command failed: {cmd_str}", agent=agent, exception=e)
        
        return False, "", str(e)


# =============================================================================
# DIG Tool - DNS Lookups
# =============================================================================

async def dig_lookup(target: str, record_types: list[str] | None = None) -> ToolResult:
    """
    Perform DNS lookups using dig.
    
    Args:
        target: Domain to look up
        record_types: List of record types (A, AAAA, MX, NS, TXT, etc.)
                     Defaults to common types if not specified.
    """
    import time
    start_time = time.time()
    
    if not _check_tool_available("dig"):
        return ToolResult(
            tool="dig",
            target=target,
            success=False,
            output="",
            error="dig is not installed on this system",
        )
    
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    
    all_output = []
    parsed_records: dict[str, list[str]] = {}
    
    for rtype in record_types:
        cmd = ["dig", "+short", target, rtype]
        success, stdout, stderr = await run_command(cmd, timeout=10)
        
        if stdout.strip():
            all_output.append(f"# {rtype} Records:")
            all_output.append(stdout.strip())
            all_output.append("")
            
            # Parse the records
            records = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
            if records:
                parsed_records[rtype] = records
    
    execution_time = time.time() - start_time
    output = "\n".join(all_output) if all_output else "No DNS records found"
    
    audit_log(
        action="dig_lookup",
        user="randy_recon",
        target=target,
        result="success" if parsed_records else "no_records",
        record_count=sum(len(v) for v in parsed_records.values()),
    )
    
    logger.info(
        "DNS lookup completed",
        tool="dig",
        target=target,
        record_count=sum(len(v) for v in parsed_records.values()),
    )
    
    return ToolResult(
        tool="dig",
        target=target,
        success=True,
        output=output,
        parsed_data={"records": parsed_records},
        execution_time=execution_time,
    )


# =============================================================================
# WHOIS Tool - Domain Registration Info
# =============================================================================

def _extract_base_domain(target: str) -> str:
    """
    Extract the base domain from a target (removes subdomains).
    
    Examples:
        scanme.nmap.org -> nmap.org
        www.example.com -> example.com
        example.co.uk -> example.co.uk (handles known TLDs)
    """
    # Remove protocol if present
    if "://" in target:
        target = target.split("://")[1]
    
    # Remove path if present
    target = target.split("/")[0]
    
    # Remove port if present
    target = target.split(":")[0]
    
    parts = target.split(".")
    
    # Handle common multi-part TLDs
    multi_part_tlds = {"co.uk", "com.au", "co.nz", "org.uk", "gov.uk", "ac.uk"}
    
    if len(parts) >= 3:
        possible_tld = ".".join(parts[-2:])
        if possible_tld in multi_part_tlds:
            return ".".join(parts[-3:])
    
    # Standard case: return last two parts
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    
    return target


async def whois_lookup(target: str) -> ToolResult:
    """
    Perform WHOIS lookup for domain registration info.
    
    Args:
        target: Domain to look up (subdomains will be stripped)
    """
    import time
    start_time = time.time()
    
    if not _check_tool_available("whois"):
        return ToolResult(
            tool="whois",
            target=target,
            success=False,
            output="",
            error="whois is not installed on this system",
        )
    
    # WHOIS only works on base domains, not subdomains
    base_domain = _extract_base_domain(target)
    logger.info(f"[WHOIS] Querying base domain: {base_domain} (from {target})")
    
    cmd = ["whois", base_domain]
    success, stdout, stderr = await run_command(cmd, timeout=15)
    
    if not success:
        return ToolResult(
            tool="whois",
            target=target,
            success=False,
            output="",
            error=stderr or "WHOIS lookup failed",
            execution_time=time.time() - start_time,
        )
    
    # Parse key WHOIS fields
    parsed_data = _parse_whois_output(stdout)
    
    execution_time = time.time() - start_time
    
    audit_log(
        action="whois_lookup",
        user="randy_recon",
        target=target,
        result="success",
    )
    
    logger.info(
        "WHOIS lookup completed",
        tool="whois",
        target=target,
        registrar=parsed_data.get("registrar", "unknown"),
    )
    
    return ToolResult(
        tool="whois",
        target=target,
        success=True,
        output=stdout,
        parsed_data=parsed_data,
        execution_time=execution_time,
    )


def _parse_whois_output(output: str) -> dict[str, Any]:
    """Parse WHOIS output to extract key fields."""
    parsed = {}
    
    # Common WHOIS field patterns
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"(?:Registry Expiry Date|Expiration Date):\s*(.+)",
        "updated_date": r"Updated Date:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
    }
    
    for field_name, pattern in patterns.items():
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            if field_name == "name_servers":
                parsed[field_name] = [m.strip().lower() for m in matches]
            else:
                parsed[field_name] = matches[0].strip()
    
    return parsed


# =============================================================================
# NMAP Tool - Port Scanning
# =============================================================================

async def nmap_scan(
    target: str,
    top_ports: int = 500,
) -> ToolResult:
    """
    Perform port scan using nmap.
    
    Args:
        target: Host to scan (IP or domain)
        top_ports: Number of top ports to scan (default: 500)
    """
    import time
    start_time = time.time()
    
    if not _check_tool_available("nmap"):
        return ToolResult(
            tool="nmap",
            target=target,
            success=False,
            output="",
            error="nmap is not installed on this system",
        )
    
    # Build nmap command
    # -sT: TCP connect scan (doesn't require root, works everywhere)
    # -T4: Aggressive timing
    # --top-ports: Scan most common ports
    # -sV: Service version detection
    # -n: No DNS resolution (faster)
    # -Pn: Skip host discovery (assume host is up)
    # --open: Only show open ports
    cmd = [
        "nmap",
        "-sT",                      # TCP connect scan
        "-T4",                      # Aggressive timing
        f"--top-ports", str(top_ports),  # Top N ports
        "-sV",                      # Service version detection
        "-n",                       # No DNS resolution
        "-Pn",                      # No ping
        "--open",                   # Only open ports
        "-oG", "-",                 # Greppable output to stdout
        target,
    ]
    
    # Version detection takes longer, increase timeout
    success, stdout, stderr = await run_command(cmd, timeout=300)
    
    if not success:
        return ToolResult(
            tool="nmap",
            target=target,
            success=False,
            output="",
            error=stderr or "Nmap scan failed",
            execution_time=time.time() - start_time,
        )
    
    # Parse nmap greppable output
    parsed_data = _parse_nmap_output(stdout)
    
    execution_time = time.time() - start_time
    
    audit_log(
        action="nmap_scan",
        user="randy_recon",
        target=target,
        result="success",
        open_ports=len(parsed_data.get("ports", [])),
    )
    
    logger.info(
        "Nmap scan completed",
        tool="nmap",
        target=target,
        open_ports=len(parsed_data.get("ports", [])),
        execution_time=f"{execution_time:.2f}s",
    )
    
    return ToolResult(
        tool="nmap",
        target=target,
        success=True,
        output=stdout,
        parsed_data=parsed_data,
        execution_time=execution_time,
    )


def _parse_nmap_output(output: str) -> dict[str, Any]:
    """Parse nmap greppable output to extract port info."""
    parsed: dict[str, Any] = {"ports": [], "host_status": "unknown"}
    
    for line in output.split("\n"):
        # Parse host status
        if line.startswith("Host:"):
            if "Status: Up" in line:
                parsed["host_status"] = "up"
            elif "Status: Down" in line:
                parsed["host_status"] = "down"
            
            # Parse ports from the Ports: section
            if "Ports:" in line:
                ports_section = line.split("Ports:")[1]
                port_entries = ports_section.split(",")
                
                for entry in port_entries:
                    entry = entry.strip()
                    if not entry or entry.startswith("Ignored"):
                        continue
                    
                    # Format: port/state/protocol/owner/service/...
                    parts = entry.split("/")
                    if len(parts) >= 5:
                        port_info = {
                            "port": int(parts[0]),
                            "state": parts[1],
                            "protocol": parts[2],
                            "service": parts[4] if parts[4] else "unknown",
                        }
                        # Add version if available
                        if len(parts) > 6 and parts[6]:
                            port_info["version"] = parts[6]
                        
                        parsed["ports"].append(port_info)
    
    return parsed


# =============================================================================
# Tool Registry
# =============================================================================

RECON_TOOLS = {
    "dig": dig_lookup,
    "whois": whois_lookup,
    "nmap": nmap_scan,
}


def get_available_tools() -> list[str]:
    """Get list of tools that are available on this system."""
    available = []
    for tool in ["dig", "whois", "nmap"]:
        if _check_tool_available(tool):
            available.append(tool)
    return available


async def check_all_tools() -> dict[str, bool]:
    """Check availability of all recon tools."""
    return {
        "dig": _check_tool_available("dig"),
        "whois": _check_tool_available("whois"),
        "nmap": _check_tool_available("nmap"),
    }

