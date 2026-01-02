"""
AM-Corp Threat Intelligence Tools

Tool wrappers for threat intelligence gathering that Ivy Intel uses.
Provides CVE enrichment, exploitation probability, and external intel sources.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)

# API Endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
SHODAN_API_URL = "https://api.shodan.io"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1"


@dataclass
class CVEDetails:
    """Detailed CVE information from NVD."""
    
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity: str = "unknown"
    published_date: str = ""
    last_modified: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploitability: str = ""
    epss_score: float | None = None
    epss_percentile: float | None = None
    known_exploited: bool = False
    error: str | None = None


@dataclass 
class ShodanResult:
    """Shodan host lookup result."""
    
    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    org: str = ""
    isp: str = ""
    country: str = ""
    city: str = ""
    last_update: str = ""
    vulns: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    first_seen: str = ""
    error: str | None = None


@dataclass
class VirusTotalResult:
    """VirusTotal domain/IP analysis result."""
    
    target: str
    target_type: str  # "domain" or "ip"
    reputation: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    categories: list[str] = field(default_factory=list)
    last_analysis_date: str = ""
    whois_info: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class SecurityTrailsResult:
    """SecurityTrails domain intelligence result."""
    
    domain: str
    current_dns: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    subdomain_count: int = 0
    associated_domains: list[str] = field(default_factory=list)
    alexa_rank: int | None = None
    hostname_count: int = 0
    apex_domain: str = ""
    error: str | None = None


@dataclass
class IntelResult:
    """Combined intelligence result."""
    
    target: str
    cve_details: list[CVEDetails] = field(default_factory=list)
    shodan_result: ShodanResult | None = None
    virustotal_result: VirusTotalResult | None = None
    securitytrails_result: SecurityTrailsResult | None = None
    risk_assessment: str = ""
    recommendations: list[str] = field(default_factory=list)


async def lookup_cve(cve_id: str) -> CVEDetails:
    """
    Look up CVE details from the National Vulnerability Database.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    
    Returns:
        CVEDetails with vulnerability information
    """
    # Normalize CVE ID format
    cve_id = cve_id.upper().strip()
    if not re.match(r"CVE-\d{4}-\d+", cve_id):
        return CVEDetails(cve_id=cve_id, error=f"Invalid CVE format: {cve_id}")
    
    logger.info(f"[INTEL] Looking up CVE: {cve_id}")
    
    result = CVEDetails(cve_id=cve_id)
    
    try:
        async with aiohttp.ClientSession() as session:
            # Query NVD API
            params = {"cveId": cve_id}
            async with session.get(
                NVD_API_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    vulns = data.get("vulnerabilities", [])
                    
                    if vulns:
                        cve_data = vulns[0].get("cve", {})
                        result = _parse_nvd_cve(cve_data)
                    else:
                        result.error = f"CVE {cve_id} not found in NVD"
                elif response.status == 403:
                    result.error = "NVD API rate limited. Try again later."
                else:
                    result.error = f"NVD API returned {response.status}"
        
        # Get EPSS score if CVE was found
        if not result.error:
            epss = await lookup_epss(cve_id)
            if epss:
                result.epss_score = epss.get("epss")
                result.epss_percentile = epss.get("percentile")
                
    except asyncio.TimeoutError:
        result.error = "NVD API request timed out"
    except aiohttp.ClientError as e:
        result.error = f"Network error: {str(e)}"
    except Exception as e:
        logger.error(f"CVE lookup failed: {e}")
        result.error = str(e)
    
    return result


def _parse_nvd_cve(cve_data: dict) -> CVEDetails:
    """Parse NVD CVE response into CVEDetails."""
    cve_id = cve_data.get("id", "")
    
    # Get description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")
    
    # Get CVSS metrics (try v3.1 first, then v3.0, then v2.0)
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_vector = ""
    severity = "unknown"
    
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            cvss_data = metrics[version][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "unknown")
            break
    
    # Get dates
    published = cve_data.get("published", "")
    modified = cve_data.get("lastModified", "")
    
    # Get references
    references = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append(url)
    
    # Get CWE IDs
    cwe_ids = []
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_value = desc.get("value", "")
            if cwe_value.startswith("CWE-"):
                cwe_ids.append(cwe_value)
    
    # Check if in CISA KEV (Known Exploited Vulnerabilities)
    # This would require a separate API call, for now check via configurations
    known_exploited = False
    configs = cve_data.get("configurations", [])
    
    return CVEDetails(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity.upper() if severity else "UNKNOWN",
        published_date=published[:10] if published else "",
        last_modified=modified[:10] if modified else "",
        references=references[:5],  # Limit to top 5
        cwe_ids=cwe_ids,
        known_exploited=known_exploited,
    )


async def lookup_epss(cve_id: str) -> dict | None:
    """
    Look up EPSS (Exploit Prediction Scoring System) score for a CVE.
    
    EPSS provides a probability score (0-1) indicating likelihood of
    exploitation in the next 30 days.
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        Dict with 'epss' score and 'percentile', or None if not found
    """
    logger.info(f"[INTEL] Looking up EPSS score for: {cve_id}")
    
    try:
        async with aiohttp.ClientSession() as session:
            params = {"cve": cve_id}
            async with session.get(
                EPSS_API_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    epss_data = data.get("data", [])
                    
                    if epss_data:
                        return {
                            "epss": float(epss_data[0].get("epss", 0)),
                            "percentile": float(epss_data[0].get("percentile", 0)),
                        }
    except Exception as e:
        logger.warning(f"EPSS lookup failed for {cve_id}: {e}")
    
    return None


async def lookup_multiple_cves(cve_ids: list[str]) -> list[CVEDetails]:
    """
    Look up multiple CVEs with rate limiting.
    
    NVD has rate limits, so we add delays between requests.
    """
    results = []
    
    for i, cve_id in enumerate(cve_ids[:10]):  # Limit to 10 CVEs
        result = await lookup_cve(cve_id)
        results.append(result)
        
        # NVD rate limit: 5 requests per 30 seconds without API key
        if i < len(cve_ids) - 1:
            await asyncio.sleep(6)  # 6 seconds between requests
    
    return results


async def shodan_host_lookup(ip: str) -> ShodanResult:
    """
    Look up host information from Shodan.
    
    Requires SHODAN_API_KEY to be configured.
    
    Args:
        ip: IP address to look up
    
    Returns:
        ShodanResult with host information
    """
    result = ShodanResult(ip=ip)
    
    api_key = settings.shodan_api_key
    if not api_key:
        result.error = "Shodan API key not configured"
        return result
    
    logger.info(f"[INTEL] Shodan lookup for: {ip}")
    
    try:
        async with aiohttp.ClientSession() as session:
            url = f"{SHODAN_API_URL}/shodan/host/{ip}"
            params = {"key": api_key}
            
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    result.hostnames = data.get("hostnames", [])
                    result.ports = data.get("ports", [])
                    result.org = data.get("org", "")
                    result.isp = data.get("isp", "")
                    result.country = data.get("country_name", "")
                    result.city = data.get("city", "")
                    result.last_update = data.get("last_update", "")
                    result.vulns = data.get("vulns", [])
                    
                    # Parse services
                    for service in data.get("data", [])[:10]:
                        result.services.append({
                            "port": service.get("port"),
                            "transport": service.get("transport"),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "banner": service.get("data", "")[:200],
                        })
                        
                elif response.status == 404:
                    result.error = "IP not found in Shodan database"
                elif response.status == 401:
                    result.error = "Invalid Shodan API key"
                else:
                    result.error = f"Shodan API returned {response.status}"
                    
    except asyncio.TimeoutError:
        result.error = "Shodan API request timed out"
    except Exception as e:
        logger.error(f"Shodan lookup failed: {e}")
        result.error = str(e)
    
    audit_log(
        action="shodan_lookup",
        user="ivy_intel",
        target=ip,
        result="success" if not result.error else "error",
    )
    
    return result


async def virustotal_lookup(target: str, target_type: str = "domain") -> VirusTotalResult:
    """
    Look up domain or IP reputation from VirusTotal.
    
    Requires VIRUSTOTAL_API_KEY to be configured.
    
    Args:
        target: Domain or IP to look up
        target_type: "domain" or "ip"
    
    Returns:
        VirusTotalResult with reputation information
    """
    result = VirusTotalResult(target=target, target_type=target_type)
    
    api_key = settings.virustotal_api_key
    if not api_key:
        result.error = "VirusTotal API key not configured"
        return result
    
    logger.info(f"[INTEL] VirusTotal lookup for: {target} ({target_type})")
    
    try:
        async with aiohttp.ClientSession() as session:
            if target_type == "domain":
                url = f"{VIRUSTOTAL_API_URL}/domains/{target}"
            else:
                url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{target}"
            
            headers = {"x-apikey": api_key}
            
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    
                    result.reputation = attrs.get("reputation", 0)
                    
                    # Parse analysis stats
                    stats = attrs.get("last_analysis_stats", {})
                    result.malicious_count = stats.get("malicious", 0)
                    result.suspicious_count = stats.get("suspicious", 0)
                    result.harmless_count = stats.get("harmless", 0)
                    result.undetected_count = stats.get("undetected", 0)
                    
                    # Categories
                    cats = attrs.get("categories", {})
                    result.categories = list(cats.values())[:5]
                    
                    # Last analysis date
                    last_analysis = attrs.get("last_analysis_date")
                    if last_analysis:
                        result.last_analysis_date = datetime.fromtimestamp(
                            last_analysis
                        ).strftime("%Y-%m-%d")
                        
                elif response.status == 404:
                    result.error = f"{target_type.capitalize()} not found in VirusTotal"
                elif response.status == 401:
                    result.error = "Invalid VirusTotal API key"
                elif response.status == 429:
                    result.error = "VirusTotal rate limit exceeded"
                else:
                    result.error = f"VirusTotal API returned {response.status}"
                    
    except asyncio.TimeoutError:
        result.error = "VirusTotal API request timed out"
    except Exception as e:
        logger.error(f"VirusTotal lookup failed: {e}")
        result.error = str(e)
    
    audit_log(
        action="virustotal_lookup",
        user="ivy_intel",
        target=target,
        result="success" if not result.error else "error",
    )
    
    return result


async def securitytrails_lookup(domain: str) -> SecurityTrailsResult:
    """
    Look up domain intelligence from SecurityTrails.
    
    Provides subdomain enumeration, DNS history, and associated domains.
    Requires SECURITYTRAILS_API_KEY to be configured.
    
    Args:
        domain: Domain to look up
    
    Returns:
        SecurityTrailsResult with domain intelligence
    """
    result = SecurityTrailsResult(domain=domain)
    
    api_key = settings.securitytrails_api_key
    if not api_key:
        result.error = "SecurityTrails API key not configured"
        return result
    
    logger.info(f"[INTEL] SecurityTrails lookup for: {domain}")
    
    try:
        async with aiohttp.ClientSession() as session:
            headers = {"APIKEY": api_key}
            
            # Get domain details
            url = f"{SECURITYTRAILS_API_URL}/domain/{domain}"
            
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    result.apex_domain = data.get("apex_domain", domain)
                    result.hostname_count = data.get("hostname_count", 0)
                    result.alexa_rank = data.get("alexa_rank")
                    
                    # Current DNS records
                    current_dns = data.get("current_dns", {})
                    result.current_dns = {
                        "a": [r.get("ip") for r in current_dns.get("a", {}).get("values", [])],
                        "aaaa": [r.get("ipv6") for r in current_dns.get("aaaa", {}).get("values", [])],
                        "mx": [r.get("hostname") for r in current_dns.get("mx", {}).get("values", [])],
                        "ns": [r.get("nameserver") for r in current_dns.get("ns", {}).get("values", [])],
                        "txt": [r.get("value") for r in current_dns.get("txt", {}).get("values", [])],
                    }
                    
                elif response.status == 401:
                    result.error = "Invalid SecurityTrails API key"
                    return result
                elif response.status == 429:
                    result.error = "SecurityTrails rate limit exceeded"
                    return result
                elif response.status == 404:
                    result.error = f"Domain {domain} not found in SecurityTrails"
                    return result
                else:
                    result.error = f"SecurityTrails API returned {response.status}"
                    return result
            
            # Get subdomains (separate API call)
            subdomain_url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/subdomains"
            
            async with session.get(
                subdomain_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = data.get("subdomains", [])
                    result.subdomains = subdomains[:20]  # Limit to 20
                    result.subdomain_count = len(subdomains)
            
            # Get associated domains (separate API call)
            assoc_url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/associated"
            
            async with session.get(
                assoc_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    records = data.get("records", [])
                    result.associated_domains = [
                        r.get("hostname", "") for r in records[:10]
                    ]
                    
    except asyncio.TimeoutError:
        result.error = "SecurityTrails API request timed out"
    except Exception as e:
        logger.error(f"SecurityTrails lookup failed: {e}")
        result.error = str(e)
    
    audit_log(
        action="securitytrails_lookup",
        user="ivy_intel",
        target=domain,
        result="success" if not result.error else "error",
    )
    
    return result


def assess_exploitation_risk(cve_details: CVEDetails) -> str:
    """
    Assess exploitation risk based on CVE details and EPSS score.
    
    Returns risk level: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN
    """
    # If EPSS score is available, use it as primary indicator
    if cve_details.epss_score is not None:
        if cve_details.epss_score >= 0.5:
            return "CRITICAL"  # 50%+ chance of exploitation
        elif cve_details.epss_score >= 0.2:
            return "HIGH"  # 20-50% chance
        elif cve_details.epss_score >= 0.05:
            return "MEDIUM"  # 5-20% chance
        else:
            return "LOW"  # <5% chance
    
    # Fall back to CVSS severity
    if cve_details.severity in ["CRITICAL", "HIGH"]:
        return cve_details.severity
    elif cve_details.severity == "MEDIUM":
        return "MEDIUM"
    elif cve_details.severity == "LOW":
        return "LOW"
    
    return "UNKNOWN"


def format_cve_summary(cve: CVEDetails) -> str:
    """Format a CVE for Discord message."""
    lines = [f"**{cve.cve_id}**"]
    
    if cve.error:
        lines.append(f"  ⚠️ {cve.error}")
        return "\n".join(lines)
    
    if cve.cvss_score:
        lines.append(f"  • CVSS: {cve.cvss_score} ({cve.severity})")
    
    if cve.epss_score is not None:
        pct = cve.epss_score * 100
        percentile = cve.epss_percentile * 100 if cve.epss_percentile else 0
        lines.append(f"  • EPSS: {pct:.1f}% exploitation probability (top {100-percentile:.0f}%)")
    
    if cve.description:
        desc = cve.description[:150] + "..." if len(cve.description) > 150 else cve.description
        lines.append(f"  • {desc}")
    
    if cve.published_date:
        lines.append(f"  • Published: {cve.published_date}")
    
    if cve.known_exploited:
        lines.append("  • ⚠️ **Known Exploited Vulnerability (CISA KEV)**")
    
    return "\n".join(lines)


def get_intel_capabilities() -> dict:
    """
    Get available intelligence capabilities based on configured API keys.
    """
    return {
        "nvd_cve_lookup": True,  # Always available (free)
        "epss_scores": True,  # Always available (free)
        "shodan": bool(settings.shodan_api_key),
        "virustotal": bool(settings.virustotal_api_key),
        "securitytrails": bool(settings.securitytrails_api_key),
    }

