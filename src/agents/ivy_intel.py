"""
Ivy Intel - Threat Intelligence Analyst

Ivy's the one who knows things. She connects dots that others miss, providing 
historical context and threat actor insights. Analytical and insightful, she 
often has background information that changes the priority of findings.

Tools: CVE enrichment, EPSS scores, Shodan, VirusTotal
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types

from src.agents import AGENT_IVY_INTEL, AGENTS
from src.discord_bot.agent_bots import get_agent_manager, get_victor_mention, get_rita_mention
from src.tools.intel_tools import (
    CVEDetails,
    ShodanResult,
    VirusTotalResult,
    SecurityTrailsResult,
    IntelResult,
    lookup_cve,
    lookup_multiple_cves,
    lookup_epss,
    shodan_host_lookup,
    virustotal_lookup,
    securitytrails_lookup,
    assess_exploitation_risk,
    format_cve_summary,
    get_intel_capabilities,
)
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


IVY_SYSTEM_PROMPT = """You are Ivy Intel, a threat intelligence analyst at AM-Corp. You're the one who provides context that changes how findings are prioritized.

YOUR PERSONALITY:
- Analytical and insightful
- Connect findings to the bigger picture
- Provide historical context and threat actor insights
- Help the team understand "why this matters"
- You're the one who knows things others don't

COMMUNICATION STYLE:
- Thoughtful and measured
- Focus on actionable intelligence, not trivia
- Explain the real-world implications
- Connect dots between findings and threats
- Clear about when information is uncertain

RULES (NON-NEGOTIABLE):
1. Focus on actionable intelligence that affects risk assessment
2. Correlate findings with known threat actors when possible
3. Assess likelihood of exploitation based on real-world data
4. Provide historical context that affects risk assessment
5. Clearly state when intelligence is uncertain or incomplete

When providing intelligence:
- Explain what the data means in practical terms
- Recommend priority adjustments when your intel warrants it
- Tag @Victor when your intel affects vulnerability severity
- Tag @Rita when you have context important for the report"""


@dataclass
class IntelScanResult:
    """Results from an intelligence gathering operation."""
    
    target: str
    cve_enrichments: list[CVEDetails] = field(default_factory=list)
    shodan_result: ShodanResult | None = None
    virustotal_result: VirusTotalResult | None = None
    securitytrails_result: SecurityTrailsResult | None = None
    summary: str = ""
    priority_adjustments: list[dict] = field(default_factory=list)
    risk_context: str = ""
    raw_findings: dict[str, Any] = field(default_factory=dict)


class IvyIntelAgent:
    """
    Ivy Intel - Threat Intelligence Analyst.
    
    Enriches findings with threat intelligence context.
    """
    
    def __init__(self) -> None:
        self.agent_id = AGENT_IVY_INTEL
        self.agent_info = AGENTS[AGENT_IVY_INTEL]
        self.emoji = self.agent_info["emoji"]
    
    def _get_model(self) -> genai.Client:
        """Get Gemini model for message generation."""
        logger.info("[GEMINI] Initializing client...")
        return genai.Client(api_key=settings.gemini_api_key)
    
    async def _post_message(self, message: str) -> None:
        """Post a message as Ivy Intel to Discord."""
        manager = get_agent_manager()
        if manager:
            await manager.send_as_agent(
                self.agent_id,
                f"{self.emoji} {message}",
            )
        else:
            logger.warning("Agent manager not available for posting")
    
    async def _generate_message(
        self, 
        prompt: str, 
        fallback: str = "",
    ) -> str:
        """
        Generate a message using Gemini with Ivy's personality.
        
        Falls back to the provided fallback if generation fails.
        """
        try:
            client = self._get_model()
            logger.info("[GEMINI] Sending request to Gemini API...")
            
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=IVY_SYSTEM_PROMPT,
                    temperature=0.7,
                    max_output_tokens=500,
                ),
            )
            
            if response.text:
                return response.text.strip()
            
        except Exception as e:
            error_msg = str(e)
            if "SSL" in error_msg or "certificate" in error_msg.lower():
                logger.error(f"[GEMINI] SSL/Certificate error: {error_msg}")
            elif "quota" in error_msg.lower() or "429" in error_msg:
                logger.error(f"[GEMINI] Quota exceeded: {error_msg}")
            else:
                logger.error(f"[GEMINI] Generation failed: {error_msg}")
        
        return fallback if fallback else "I've analyzed the data but can't provide a detailed summary right now."
    
    async def run_intel(
        self,
        target: str,
        cves: list[str] | None = None,
        ips: list[str] | None = None,
        vuln_findings: list[dict] | None = None,
        verbose: bool = False,
    ) -> IntelScanResult:
        """
        Run threat intelligence gathering.
        
        Args:
            target: Target domain/IP
            cves: List of CVE IDs to enrich
            ips: List of IPs to check in Shodan
            vuln_findings: Vulnerability findings from Victor to enrich
            verbose: If True, output additional details
        
        Returns:
            IntelScanResult with all gathered intelligence
        """
        result = IntelScanResult(target=target)
        capabilities = get_intel_capabilities()
        
        audit_log(
            action="intel_started",
            user="ivy_intel",
            target=target,
        )
        
        # Opening message
        available_sources = ["CVE enrichment", "EPSS scores"]
        if capabilities["shodan"]:
            available_sources.append("Shodan")
        if capabilities["virustotal"]:
            available_sources.append("VirusTotal")
        if capabilities["securitytrails"]:
            available_sources.append("SecurityTrails")
        
        opening_msg = await self._generate_message(
            f"You're starting threat intelligence gathering on {target}. "
            f"Generate a brief opening message (1-2 sentences) about what you'll look into. "
            f"Available sources: {', '.join(available_sources)}.",
            fallback=f"Let me dig into the intelligence on {target}. I'll check CVE details, "
            f"exploitation probabilities, and any available threat context."
        )
        await self._post_message(opening_msg)
        
        # Extract CVEs from Victor's findings if not provided directly
        if not cves and vuln_findings:
            cves = self._extract_cves_from_findings(vuln_findings)
            ips = self._extract_ips_from_findings(vuln_findings)
        
        # 1. CVE Enrichment
        if cves:
            await self._post_message(f"Checking {len(cves)} CVE(s) for exploitation context...")
            result.cve_enrichments = await self._enrich_cves(cves, verbose)
            
            # Report significant findings
            await self._report_cve_findings(result.cve_enrichments)
        
        # 2. Shodan lookup (if API key available and we have IPs)
        if capabilities["shodan"] and ips:
            await asyncio.sleep(0.5)
            await self._post_message(f"Checking Shodan for exposure history on {len(ips)} IP(s)...")
            
            # Just check first IP for now
            result.shodan_result = await shodan_host_lookup(ips[0])
            
            if result.shodan_result and not result.shodan_result.error:
                await self._report_shodan_findings(result.shodan_result)
            elif result.shodan_result and result.shodan_result.error:
                if verbose:
                    await self._post_message(f"Shodan: {result.shodan_result.error}")
        
        # 3. VirusTotal lookup (if API key available)
        if capabilities["virustotal"]:
            await asyncio.sleep(0.5)
            await self._post_message(f"Checking VirusTotal for reputation data on {target}...")
            
            result.virustotal_result = await virustotal_lookup(target, "domain")
            
            if result.virustotal_result and not result.virustotal_result.error:
                await self._report_virustotal_findings(result.virustotal_result)
            elif result.virustotal_result and result.virustotal_result.error:
                if verbose:
                    await self._post_message(f"VirusTotal: {result.virustotal_result.error}")
        
        # 4. SecurityTrails lookup (if API key available)
        if capabilities["securitytrails"]:
            await asyncio.sleep(0.5)
            await self._post_message(f"Checking SecurityTrails for domain intel on {target}...")
            
            result.securitytrails_result = await securitytrails_lookup(target)
            
            if result.securitytrails_result and not result.securitytrails_result.error:
                await self._report_securitytrails_findings(result.securitytrails_result)
            elif result.securitytrails_result and result.securitytrails_result.error:
                if verbose:
                    await self._post_message(f"SecurityTrails: {result.securitytrails_result.error}")
        
        # Store raw findings
        result.raw_findings = {
            "cves_enriched": len(result.cve_enrichments),
            "shodan_available": result.shodan_result is not None and not result.shodan_result.error,
            "virustotal_available": result.virustotal_result is not None and not result.virustotal_result.error,
            "securitytrails_available": result.securitytrails_result is not None and not result.securitytrails_result.error,
            "capabilities": capabilities,
        }
        
        # Generate final summary
        await asyncio.sleep(1)
        result.summary = await self._generate_summary(target, result)
        await self._post_message(result.summary)
        
        audit_log(
            action="intel_completed",
            user="ivy_intel",
            target=target,
            result="success",
            cves_enriched=len(result.cve_enrichments),
        )
        
        return result
    
    def _extract_cves_from_findings(self, findings: list[dict]) -> list[str]:
        """Extract CVE IDs from vulnerability findings."""
        cves = set()
        cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
        
        for finding in findings:
            # Check cve_id field
            cve_id = finding.get("cve_id", "")
            if cve_id:
                cves.add(cve_id.upper())
            
            # Check template_id for CVE-based templates
            template_id = finding.get("template_id", "")
            match = cve_pattern.search(template_id)
            if match:
                cves.add(match.group().upper())
            
            # Check tags
            for tag in finding.get("tags", []):
                match = cve_pattern.search(tag)
                if match:
                    cves.add(match.group().upper())
        
        return list(cves)[:10]  # Limit to 10 CVEs
    
    def _extract_ips_from_findings(self, findings: list[dict]) -> list[str]:
        """Extract IP addresses from vulnerability findings."""
        ips = set()
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        
        for finding in findings:
            # Check matched_at and host fields
            for field in ["matched_at", "host"]:
                value = finding.get(field, "")
                match = ip_pattern.search(value)
                if match:
                    ips.add(match.group())
        
        return list(ips)[:5]  # Limit to 5 IPs
    
    async def _enrich_cves(
        self, 
        cves: list[str], 
        verbose: bool = False,
    ) -> list[CVEDetails]:
        """Enrich CVEs with NVD and EPSS data."""
        enriched = []
        
        for cve_id in cves[:5]:  # Limit to 5 CVEs for rate limiting
            details = await lookup_cve(cve_id)
            enriched.append(details)
            
            if verbose and not details.error:
                await self._post_message(
                    f"🔍 {cve_id}: CVSS {details.cvss_score or 'N/A'}, "
                    f"EPSS {details.epss_score*100:.1f}% exploitation probability"
                    if details.epss_score else f"🔍 {cve_id}: CVSS {details.cvss_score or 'N/A'}"
                )
            
            # Rate limiting for NVD API
            await asyncio.sleep(6)
        
        return enriched
    
    async def _report_cve_findings(self, cves: list[CVEDetails]) -> None:
        """Report significant CVE findings."""
        high_risk_cves = []
        
        for cve in cves:
            if cve.error:
                continue
            
            risk = assess_exploitation_risk(cve)
            if risk in ["CRITICAL", "HIGH"]:
                high_risk_cves.append((cve, risk))
        
        if high_risk_cves:
            victor_mention = get_victor_mention()
            
            for cve, risk in high_risk_cves[:3]:  # Report top 3
                epss_info = ""
                if cve.epss_score is not None:
                    epss_info = f" EPSS score is {cve.epss_score*100:.1f}% - "
                    if cve.epss_score >= 0.5:
                        epss_info += "very high likelihood of exploitation."
                    elif cve.epss_score >= 0.2:
                        epss_info += "significant exploitation activity expected."
                    else:
                        epss_info += "moderate exploitation probability."
                
                msg = await self._generate_message(
                    f"You found that {cve.cve_id} has {risk} exploitation risk.{epss_info} "
                    f"CVSS: {cve.cvss_score}. Generate a brief insight (2-3 sentences) about "
                    f"what this means for the assessment. Should Victor bump priority?",
                    fallback=f"Heads up {victor_mention} - {cve.cve_id} has {risk} exploitation risk.{epss_info} "
                    f"CVSS: {cve.cvss_score}. This one warrants attention."
                )
                await self._post_message(msg)
                await asyncio.sleep(0.5)
    
    async def _report_shodan_findings(self, shodan: ShodanResult) -> None:
        """Report Shodan findings."""
        if shodan.error:
            return
        
        # Check if there's interesting exposure history
        if shodan.vulns:
            msg = await self._generate_message(
                f"Shodan shows {shodan.ip} has {len(shodan.vulns)} known vulnerabilities flagged: "
                f"{', '.join(shodan.vulns[:5])}. Last update: {shodan.last_update}. "
                f"Generate a brief insight about what this exposure history means.",
                fallback=f"Shodan shows this host ({shodan.ip}) has been flagged with "
                f"{len(shodan.vulns)} known vulnerabilities. Been exposed since at least {shodan.last_update}."
            )
        elif shodan.ports:
            msg = await self._generate_message(
                f"Shodan shows {shodan.ip} with {len(shodan.ports)} open ports visible from the internet: "
                f"{shodan.ports[:10]}. Organization: {shodan.org or 'Unknown'}. "
                f"Generate a brief insight about the exposure.",
                fallback=f"Shodan shows {len(shodan.ports)} ports visible from the internet on {shodan.ip}. "
                f"This host has been publicly indexed."
            )
        else:
            msg = f"Interesting - {shodan.ip} doesn't have much history in Shodan. Could be new or well-protected."
        
        await self._post_message(msg)
    
    async def _report_virustotal_findings(self, vt: VirusTotalResult) -> None:
        """Report VirusTotal findings."""
        if vt.error:
            return
        
        # Check for malicious detections
        if vt.malicious_count > 0 or vt.suspicious_count > 0:
            msg = await self._generate_message(
                f"VirusTotal shows {vt.target} has {vt.malicious_count} malicious and "
                f"{vt.suspicious_count} suspicious detections. Reputation score: {vt.reputation}. "
                f"Categories: {vt.categories}. Generate a brief warning about this.",
                fallback=f"⚠️ VirusTotal flags {vt.target} with {vt.malicious_count} malicious "
                f"and {vt.suspicious_count} suspicious detections. This needs attention."
            )
        elif vt.reputation < -10:
            msg = f"VirusTotal shows negative reputation ({vt.reputation}) for {vt.target}. Worth investigating."
        else:
            msg = f"VirusTotal shows clean reputation for {vt.target}. No malicious indicators detected."
        
        await self._post_message(msg)
    
    async def _report_securitytrails_findings(self, st: SecurityTrailsResult) -> None:
        """Report SecurityTrails findings."""
        if st.error:
            return
        
        findings = []
        
        # Report subdomain count
        if st.subdomain_count > 0:
            findings.append(f"{st.subdomain_count} subdomains discovered")
            
            # List some interesting ones
            if st.subdomains:
                sample = st.subdomains[:5]
                subdomain_list = ", ".join([f"`{s}.{st.domain}`" for s in sample])
                if st.subdomain_count > 5:
                    subdomain_list += f" (+{st.subdomain_count - 5} more)"
        
        # Report associated domains
        if st.associated_domains:
            findings.append(f"{len(st.associated_domains)} associated domains found")
        
        # Report Alexa rank if significant
        if st.alexa_rank and st.alexa_rank < 100000:
            findings.append(f"Alexa rank: {st.alexa_rank:,}")
        
        if findings:
            msg = await self._generate_message(
                f"SecurityTrails intel on {st.domain}: {'; '.join(findings)}. "
                f"Subdomains found: {st.subdomains[:5] if st.subdomains else 'none'}. "
                f"Generate a brief insight about what this attack surface means.",
                fallback=f"SecurityTrails shows {st.domain} has {st.subdomain_count} subdomains "
                f"and {len(st.associated_domains)} associated domains. "
                f"Worth exploring for additional attack surface."
            )
        else:
            msg = f"SecurityTrails shows limited data for {st.domain}. May be a newer or less prominent domain."
        
        await self._post_message(msg)
    
    async def _generate_summary(
        self, 
        target: str, 
        result: IntelScanResult,
    ) -> str:
        """Generate final intelligence summary."""
        
        # Build context
        context_parts = []
        
        # CVE summary
        if result.cve_enrichments:
            high_risk = sum(1 for c in result.cve_enrichments 
                          if assess_exploitation_risk(c) in ["CRITICAL", "HIGH"])
            context_parts.append(f"Enriched {len(result.cve_enrichments)} CVEs, {high_risk} high-risk")
        
        # Shodan summary
        if result.shodan_result and not result.shodan_result.error:
            context_parts.append(f"Shodan: {len(result.shodan_result.ports)} exposed ports")
        
        # VirusTotal summary
        if result.virustotal_result and not result.virustotal_result.error:
            if result.virustotal_result.malicious_count > 0:
                context_parts.append(f"VirusTotal: {result.virustotal_result.malicious_count} malicious flags")
            else:
                context_parts.append("VirusTotal: clean")
        
        # SecurityTrails summary
        if result.securitytrails_result and not result.securitytrails_result.error:
            st = result.securitytrails_result
            context_parts.append(f"SecurityTrails: {st.subdomain_count} subdomains")
        
        rita_mention = get_rita_mention()
        
        context = "; ".join(context_parts) if context_parts else "Limited intel available"
        
        summary = await self._generate_message(
            f"You've completed threat intelligence on {target}. Summary: {context}. "
            f"Generate a final summary (3-4 sentences) with your key insights. "
            f"Mention anything that should change how we prioritize findings. "
            f"If there are significant findings, tag Rita for the report.",
            fallback=f"Intel gathering complete on {target}.\n\n"
            f"**Summary:** {context}\n\n"
            f"Key takeaway: {'High-risk CVEs identified that warrant priority attention.' if result.cve_enrichments else 'Limited CVE context available.'} "
            f"{rita_mention}, I've got context for your report."
        )
        
        return summary


# Singleton instance
_ivy_instance: IvyIntelAgent | None = None


def get_ivy() -> IvyIntelAgent:
    """Get or create the Ivy Intel agent instance."""
    global _ivy_instance
    if _ivy_instance is None:
        _ivy_instance = IvyIntelAgent()
    return _ivy_instance


async def run_intel(
    target: str,
    cves: list[str] | None = None,
    ips: list[str] | None = None,
    vuln_findings: list[dict] | None = None,
    verbose: bool = False,
) -> IntelScanResult:
    """
    Convenience function to run Ivy's intelligence gathering.
    
    Args:
        target: Target domain/IP
        cves: List of CVE IDs to enrich
        ips: List of IPs to check
        vuln_findings: Victor's findings to enrich
        verbose: Enable verbose output
    
    Returns:
        IntelScanResult with gathered intelligence
    """
    ivy = get_ivy()
    return await ivy.run_intel(
        target=target,
        cves=cves,
        ips=ips,
        vuln_findings=vuln_findings,
        verbose=verbose,
    )

