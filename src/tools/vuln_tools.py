"""
AM-Corp Vulnerability Scanning Tools

Tool wrappers for vulnerability scanning that Victor Vuln uses.
"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from typing import Any

from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


@dataclass
class VulnResult:
    """Result from a vulnerability scan."""
    
    tool: str
    target: str
    success: bool
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    output: str = ""
    error: str | None = None
    execution_time: float = 0.0


def _check_tool_available(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(tool_name) is not None


async def run_command(
    cmd: list[str], 
    timeout: int = 300,
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
                cmd[0],
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
# Nuclei Tool - Template-based Vulnerability Scanning
# =============================================================================

async def _ensure_nuclei_templates() -> tuple[bool, str]:
    """
    Ensure Nuclei templates are downloaded.
    
    Returns:
        Tuple of (success, templates_dir_path)
    """
    import os
    
    # Use /app/nuclei-templates as the primary location (inside container, not mounted)
    templates_dir = "/app/nuclei-templates"
    
    # Check if templates already exist
    if os.path.isdir(templates_dir) and len(os.listdir(templates_dir)) > 10:
        logger.info(f"[NUCLEI] Found templates at: {templates_dir}")
        return True, templates_dir
    
    # Create directory if it doesn't exist
    os.makedirs(templates_dir, exist_ok=True)
    
    logger.info("[NUCLEI] Templates not found, downloading...")
    
    # Download templates to specific directory
    success, stdout, stderr = await run_command(
        ["nuclei", "-update-templates", "-ud", templates_dir],
        timeout=600,  # 10 min timeout for download
    )
    
    # Log the output regardless
    if stdout:
        logger.info(f"[NUCLEI] Download output: {stdout[:300]}")
    if stderr:
        logger.info(f"[NUCLEI] Download stderr: {stderr[:300]}")
    
    # Check if templates were downloaded
    if os.path.isdir(templates_dir) and len(os.listdir(templates_dir)) > 10:
        template_count = sum(1 for _ in os.walk(templates_dir))
        logger.info(f"[NUCLEI] Templates downloaded to: {templates_dir} ({template_count} dirs)")
        return True, templates_dir
    
    # Try alternative: download from github
    logger.info("[NUCLEI] Trying curl download fallback...")
    success, stdout, stderr = await run_command(
        ["curl", "-sL", "https://github.com/projectdiscovery/nuclei-templates/archive/main.tar.gz", 
         "-o", "/tmp/nuclei-templates.tar.gz"],
        timeout=300,
    )
    
    if success:
        # Extract directly to templates_dir with strip-components to remove the top-level folder
        # First ensure the target directory exists
        os.makedirs(templates_dir, exist_ok=True)
        
        # Extract templates directly, stripping the top-level "nuclei-templates-main" folder
        success, stdout, stderr = await run_command(
            ["tar", "-xzf", "/tmp/nuclei-templates.tar.gz", "-C", templates_dir, "--strip-components=1"],
            timeout=120,
        )
        
        if success:
            logger.info(f"[NUCLEI] Templates extracted to: {templates_dir}")
        else:
            logger.error(f"[NUCLEI] Tar extraction failed: {stderr}")
    
    # Final check
    if os.path.isdir(templates_dir) and len(os.listdir(templates_dir)) > 10:
        logger.info(f"[NUCLEI] Templates available at: {templates_dir}")
        return True, templates_dir
    
    logger.error(f"[NUCLEI] Failed to download templates after all attempts")
    return False, ""


async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: list[str] | None = None,
    rate_limit: int = 150,
    timeout_minutes: int = 10,
) -> VulnResult:
    """
    Perform vulnerability scan using Nuclei.
    
    Args:
        target: Host to scan (URL, IP, or domain)
        templates: Template categories to use (cves, vulnerabilities, etc.)
        severity: Severity levels to include (critical, high, medium, low, info)
        rate_limit: Requests per second limit
        timeout_minutes: Maximum scan time in minutes
    """
    import time
    start_time = time.time()
    
    if not _check_tool_available("nuclei"):
        return VulnResult(
            tool="nuclei",
            target=target,
            success=False,
            error="nuclei is not installed on this system",
        )
    
    # Ensure templates are downloaded
    templates_ok, templates_dir = await _ensure_nuclei_templates()
    if not templates_ok:
        return VulnResult(
            tool="nuclei",
            target=target,
            success=False,
            error="Failed to download Nuclei templates. Check network connectivity.",
        )
    
    # Default to common vulnerability templates
    if templates is None:
        templates = ["cves", "vulnerabilities", "misconfigurations", "exposures"]
    
    # Default to medium and above
    if severity is None:
        severity = ["critical", "high", "medium"]
    
    # Ensure target has protocol for web scanning
    scan_target = target
    if not target.startswith(("http://", "https://")):
        scan_target = f"https://{target}"
    
    # Build nuclei command
    cmd = [
        "nuclei",
        "-u", scan_target,
        "-jsonl",                           # JSON Lines output for parsing
        "-silent",                          # Reduce noise
        "-nc",                              # No color
        "-rate-limit", str(rate_limit),     # Rate limiting
        "-timeout", "10",                   # Per-request timeout
        "-retries", "1",                    # Retry count
        "-severity", ",".join(severity),    # Severity filter
    ]
    
    # Explicitly specify templates directory if we found one
    if templates_dir:
        cmd.extend(["-t", templates_dir])
    
    # Add template tags if specified (otherwise use all templates)
    if templates:
        cmd.extend(["-tags", ",".join(templates)])
    
    logger.info(f"[NUCLEI] Starting scan on {target} with templates: {templates}")
    
    success, stdout, stderr = await run_command(cmd, timeout=timeout_minutes * 60)
    
    # Parse even if exit code is non-zero (nuclei returns 1 when vulns found)
    vulnerabilities = _parse_nuclei_output(stdout)
    
    execution_time = time.time() - start_time
    
    # Consider it successful if we got output (even with exit code 1)
    scan_success = bool(stdout) or success
    
    audit_log(
        action="nuclei_scan",
        user="victor_vuln",
        target=target,
        result="success" if scan_success else "failed",
        vuln_count=len(vulnerabilities),
    )
    
    logger.info(
        f"[NUCLEI] Scan completed",
        target=target,
        vulnerabilities_found=len(vulnerabilities),
        execution_time=f"{execution_time:.2f}s",
    )
    
    return VulnResult(
        tool="nuclei",
        target=target,
        success=scan_success,
        vulnerabilities=vulnerabilities,
        output=stdout,
        error=stderr if not scan_success else None,
        execution_time=execution_time,
    )


def _parse_nuclei_output(output: str) -> list[dict[str, Any]]:
    """Parse Nuclei JSONL output into structured vulnerability list."""
    vulnerabilities = []
    
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        
        try:
            finding = json.loads(line)
            
            vuln = {
                "template_id": finding.get("template-id", "unknown"),
                "name": finding.get("info", {}).get("name", "Unknown Vulnerability"),
                "severity": finding.get("info", {}).get("severity", "unknown"),
                "description": finding.get("info", {}).get("description", ""),
                "matched_at": finding.get("matched-at", ""),
                "matcher_name": finding.get("matcher-name", ""),
                "type": finding.get("type", ""),
                "host": finding.get("host", ""),
                "tags": finding.get("info", {}).get("tags", []),
                "reference": finding.get("info", {}).get("reference", []),
                "cve_id": _extract_cve_id(finding),
                "cvss_score": _extract_cvss_score(finding),
            }
            
            vulnerabilities.append(vuln)
            
        except json.JSONDecodeError:
            # Skip non-JSON lines
            continue
    
    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    vulnerabilities.sort(key=lambda v: severity_order.get(v.get("severity", "unknown"), 5))
    
    return vulnerabilities


def _extract_cve_id(finding: dict) -> str | None:
    """Extract CVE ID from Nuclei finding."""
    # Check template ID first
    template_id = finding.get("template-id", "")
    if template_id.upper().startswith("CVE-"):
        return template_id.upper()
    
    # Check tags
    tags = finding.get("info", {}).get("tags", [])
    for tag in tags:
        if tag.upper().startswith("CVE-"):
            return tag.upper()
    
    # Check references
    refs = finding.get("info", {}).get("reference", [])
    for ref in refs:
        if "cve" in ref.lower():
            # Try to extract CVE ID from URL
            import re
            match = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
            if match:
                return match.group().upper()
    
    return None


def _extract_cvss_score(finding: dict) -> float | None:
    """Extract CVSS score from Nuclei finding."""
    info = finding.get("info", {})
    
    # Check classification
    classification = info.get("classification", {})
    if "cvss-score" in classification:
        try:
            return float(classification["cvss-score"])
        except (ValueError, TypeError):
            pass
    
    # Estimate from severity if no CVSS
    severity = info.get("severity", "").lower()
    severity_to_cvss = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.0,
    }
    return severity_to_cvss.get(severity)


# =============================================================================
# Smart Template Selection
# =============================================================================

# Comprehensive service-to-template mapping based on ADR-003
SERVICE_TEMPLATE_MAP: dict[str, list[str]] = {
    # Web services
    "http": ["http", "cves", "exposures", "misconfigurations"],
    "https": ["http", "ssl", "cves", "exposures", "misconfigurations"],
    "http-proxy": ["http", "cves", "exposures"],
    "ssl/http": ["http", "ssl", "cves", "exposures"],
    "ssl/https": ["http", "ssl", "cves", "exposures"],
    
    # SSH
    "ssh": ["ssh", "network", "cves"],
    "openssh": ["ssh", "network", "cves"],
    
    # FTP
    "ftp": ["ftp", "network", "cves"],
    "ftp-data": ["ftp", "network", "cves"],
    
    # Databases
    "mysql": ["mysql", "network", "cves"],
    "mariadb": ["mysql", "network", "cves"],
    "postgresql": ["postgres", "network", "cves"],
    "postgres": ["postgres", "network", "cves"],
    "mongodb": ["mongodb", "network", "cves"],
    "redis": ["redis", "network", "cves"],
    "memcached": ["network", "cves"],
    "elasticsearch": ["elasticsearch", "network", "cves", "exposures"],
    "cassandra": ["network", "cves"],
    
    # Windows services
    "smb": ["smb", "network", "cves"],
    "microsoft-ds": ["smb", "network", "cves"],
    "netbios-ssn": ["smb", "network", "cves"],
    "rdp": ["rdp", "network", "cves"],
    "ms-wbt-server": ["rdp", "network", "cves"],
    
    # Mail
    "smtp": ["network", "cves"],
    "imap": ["network", "cves"],
    "pop3": ["network", "cves"],
    
    # DNS
    "domain": ["dns", "network", "cves"],
    "dns": ["dns", "network", "cves"],
    
    # Other common services
    "telnet": ["network", "cves"],
    "vnc": ["network", "cves"],
    "ldap": ["network", "cves"],
    "nfs": ["network", "cves"],
    "docker": ["network", "cves", "exposures"],
    "kubernetes": ["network", "cves", "exposures"],
}

# Port-based fallback mapping (when service name is unknown)
PORT_TEMPLATE_MAP: dict[int, list[str]] = {
    21: ["ftp", "network", "cves"],
    22: ["ssh", "network", "cves"],
    23: ["network", "cves"],  # telnet
    25: ["network", "cves"],  # smtp
    53: ["dns", "network", "cves"],
    80: ["http", "cves", "exposures", "misconfigurations"],
    110: ["network", "cves"],  # pop3
    143: ["network", "cves"],  # imap
    443: ["http", "ssl", "cves", "exposures", "misconfigurations"],
    445: ["smb", "network", "cves"],
    993: ["network", "cves"],  # imaps
    995: ["network", "cves"],  # pop3s
    1433: ["network", "cves"],  # mssql
    1521: ["network", "cves"],  # oracle
    3306: ["mysql", "network", "cves"],
    3389: ["rdp", "network", "cves"],
    5432: ["postgres", "network", "cves"],
    5900: ["network", "cves"],  # vnc
    6379: ["redis", "network", "cves"],
    8080: ["http", "cves", "exposures"],
    8443: ["http", "ssl", "cves", "exposures"],
    9200: ["elasticsearch", "network", "cves", "exposures"],
    27017: ["mongodb", "network", "cves"],
}


def select_templates_for_ports(
    ports: list[dict],
    include_baseline: bool = True,
) -> tuple[list[str], dict[str, list[str]]]:
    """
    Select Nuclei templates based on discovered ports/services.
    
    Args:
        ports: List of port dicts from Randy's recon 
               (each with 'port', 'service', optionally 'version')
        include_baseline: Always include baseline 'cves' templates
    
    Returns:
        Tuple of (selected_templates, selection_reasoning)
        - selected_templates: Deduplicated list of template tags
        - selection_reasoning: Dict mapping service/port to selected templates
    """
    selected: set[str] = set()
    reasoning: dict[str, list[str]] = {}
    
    if include_baseline:
        selected.add("cves")
        reasoning["baseline"] = ["cves"]
    
    for port_info in ports:
        port = port_info.get("port")
        service = port_info.get("service", "").lower()
        
        # Try service name first
        if service and service in SERVICE_TEMPLATE_MAP:
            templates = SERVICE_TEMPLATE_MAP[service]
            selected.update(templates)
            reasoning[f"{port}/{service}"] = templates
        # Fall back to port number
        elif port and port in PORT_TEMPLATE_MAP:
            templates = PORT_TEMPLATE_MAP[port]
            selected.update(templates)
            reasoning[f"{port}/unknown"] = templates
        # Generic fallback
        elif port:
            # Check if it's likely a web port
            if port in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]:
                templates = ["http", "cves", "exposures"]
            else:
                templates = ["network", "cves"]
            selected.update(templates)
            reasoning[f"{port}/generic"] = templates
    
    return sorted(list(selected)), reasoning


def get_default_templates() -> list[str]:
    """Get default templates when no recon data is available."""
    return ["cves", "vulnerabilities", "misconfigurations", "exposures"]


# =============================================================================
# Service-specific scanning
# =============================================================================

async def scan_http_service(target: str, port: int = 443) -> VulnResult:
    """
    Scan an HTTP/HTTPS service for vulnerabilities.
    
    Args:
        target: Hostname or IP
        port: Port number (443 for HTTPS, 80 for HTTP)
    """
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}:{port}"
    
    return await nuclei_scan(
        target=url,
        templates=["cves", "vulnerabilities", "misconfigurations", "exposures", "technologies"],
        severity=["critical", "high", "medium"],
    )


async def scan_service_by_port(target: str, port: int, service: str) -> VulnResult:
    """
    Scan a service based on its port and detected service name.
    
    Args:
        target: Hostname or IP
        port: Port number
        service: Service name (e.g., 'ssh', 'mysql', 'elasticsearch')
    """
    # Map services to appropriate template tags
    service_templates = {
        "http": ["cves", "vulnerabilities", "misconfigurations", "exposures"],
        "https": ["cves", "vulnerabilities", "misconfigurations", "exposures"],
        "ssh": ["cves", "network", "ssh"],
        "ftp": ["cves", "network", "ftp"],
        "mysql": ["cves", "network", "mysql"],
        "postgresql": ["cves", "network", "postgres"],
        "elasticsearch": ["cves", "network", "elasticsearch", "exposures"],
        "redis": ["cves", "network", "redis"],
        "mongodb": ["cves", "network", "mongodb"],
        "smb": ["cves", "network", "smb"],
        "rdp": ["cves", "network", "rdp"],
    }
    
    # Get templates for this service
    templates = service_templates.get(service.lower(), ["cves", "vulnerabilities"])
    
    # Determine if it's a web service
    web_services = {"http", "https", "http-proxy", "ssl/http", "ssl/https"}
    is_web = service.lower() in web_services or port in [80, 443, 8080, 8443]
    
    if is_web:
        protocol = "https" if port in [443, 8443] or "ssl" in service.lower() else "http"
        url = f"{protocol}://{target}:{port}"
        return await nuclei_scan(target=url, templates=templates)
    else:
        # For non-web services, use host:port format
        return await nuclei_scan(
            target=f"{target}:{port}",
            templates=templates,
        )


# =============================================================================
# Tool Registry
# =============================================================================

VULN_TOOLS = {
    "nuclei": nuclei_scan,
}


def get_available_vuln_tools() -> list[str]:
    """Get list of vulnerability scanning tools available on this system."""
    available = []
    if _check_tool_available("nuclei"):
        available.append("nuclei")
    return available


async def check_all_vuln_tools() -> dict[str, bool]:
    """Check availability of all vulnerability scanning tools."""
    return {
        "nuclei": _check_tool_available("nuclei"),
    }

