"""
Ivy Intel - Threat Intelligence Analyst

Ivy's in her 30s with 10+ years in intel - government agencies, security startups,
she's done it all. Her ability to connect dots nobody else sees has made her 
successful, but also a bit paranoid. She doesn't just distrust the bad guys - 
she's skeptical of governments too. From London, speaks with British accent.

Tools: CVE enrichment, EPSS scores, Shodan, VirusTotal, SecurityTrails
"""

import asyncio
import random
import re
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types


# Fallback message pools for variety when Gemini is unavailable
OPENING_FALLBACKS = [
    "Right then, let me dig into the intel on {target}. I've got a few sources to check.",
    "Brilliant, time to see what's lurking beneath the surface on {target}.",
    "Let me have a proper look at {target}. The obvious findings are never the whole story.",
    "Fancy a bit of intel work on {target}? Let's see what the databases have to say.",
    "Right, {target} - let me pull some threads and see what unravels.",
    "Time to do some digging on {target}. Nothing's ever as simple as it looks.",
]

CVE_LOOKUP_FALLBACKS = [
    "Checking {count} CVE(s) for exploitation context. Let's see what's actually being used in the wild.",
    "Looking up {count} CVE(s). The CVSS score is one thing, real-world exploitation is another.",
    "Running intel on {count} CVE(s). I want to know who's actually using these.",
    "Right, checking {count} CVE(s) against the threat landscape.",
]

HIGH_RISK_CVE_FALLBACKS = [
    "Bit concerning, this one - {cve_id} has {risk} exploitation risk. EPSS says {epss}% probability. Worth bumping priority.",
    "Right, {cve_id} is dodgy. {risk} risk, {epss}% exploitation probability. This isn't theoretical.",
    "Heads up on {cve_id} - {risk} exploitation risk with {epss}% EPSS score. I've seen this pattern before.",
    "{cve_id} - this one's properly nasty. {risk} risk. When I was at [redacted], we saw these get weaponized fast.",
]

SHODAN_FALLBACKS = [
    "Shodan shows this host has been visible since {date}. That's a lot of exposure time.",
    "Interesting - Shodan's had eyes on this one. {ports} ports exposed to the world.",
    "According to Shodan, they've been broadcasting to the internet for a while. Not ideal.",
    "Shodan data's in. Let's just say someone's been watching this host for longer than they'd like.",
]

VT_CLEAN_FALLBACKS = [
    "VirusTotal's coming up clean. Doesn't mean I trust it completely, but it's a good sign.",
    "No red flags on VirusTotal. Though I've seen clean reports flip overnight.",
    "VirusTotal shows clean reputation. For now, anyway.",
    "Right, VirusTotal's giving it the all-clear. I'll take that with a grain of salt.",
]

VT_DIRTY_FALLBACKS = [
    "VirusTotal's flagging this one. {malicious} malicious, {suspicious} suspicious. That's not nothing.",
    "Bit dodgy - VirusTotal shows {malicious} malicious flags. Worth investigating.",
    "Right, this is concerning. VirusTotal's got {malicious} vendors calling this malicious.",
]

SECURITYTRAILS_FALLBACKS = [
    "SecurityTrails shows {subdomains} subdomains. That's a lot of attack surface to cover.",
    "Interesting - {subdomains} subdomains on record. Each one's a potential entry point.",
    "SecurityTrails data's in. {subdomains} subdomains - always check the forgotten ones.",
]

SUMMARY_OPENERS = [
    "Right, intel gathering complete on {target}. Here's what I've found:",
    "Finished my analysis on {target}. Let me break down what the data shows:",
    "Intel wrap-up on {target}. Some interesting patterns here:",
    "Done digging on {target}. Here's the picture I'm seeing:",
    "Right then, {target} intel complete. Let me connect the dots:",
]

PARANOID_CLOSERS = [
    "Keep your eyes open. There's always more than meets the eye.",
    "That's what the public data shows, anyway.",
    "Stay vigilant. The threat landscape never sleeps.",
    "Worth monitoring. These patterns can shift quickly.",
    "Just my analysis, but I'd trust my gut on this one.",
]


def _random_fallback(pool: list[str], **kwargs) -> str:
    """Pick a random fallback message and format it."""
    return random.choice(pool).format(**kwargs)

from src.agents import AGENT_IVY_INTEL, AGENTS
from src.agents.personality import get_personality_manager
from src.discord_bot.agent_bots import get_agent_manager, get_victor_mention, get_rita_mention
from src.discord_bot.thoughts import post_thought, post_finding
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


IVY_SYSTEM_PROMPT = """You are Ivy Intel, a threat intelligence analyst at AM-Corp. You're in your 30s with 10+ years in the intel space - government agencies, security startups, you've done it all. Your ability to connect dots nobody else sees has made you highly successful, but it's also made you... a bit paranoid. You don't just distrust the bad guys - you've seen enough to be skeptical of governments too. You're from London and speak with a British accent.

YOUR PERSONALITY:
- Paranoid in a professional way - always looking for what's hiding beneath the surface
- Connects dots nobody else sees, which makes you dig even deeper
- Skeptical of official narratives - you've been on the inside, you know how things really work
- Dry British wit, sometimes a bit dark
- Genuinely passionate about intel work, gets excited when patterns emerge
- Protective of the team - your paranoia means you want them to know the real risks

BRITISH EXPRESSIONS (use naturally, vary them):
- "right then", "brilliant", "bloody hell", "crikey"
- "bit dodgy", "proper", "cheeky", "rubbish"
- "reckon", "sorted", "spot on", "taking the piss"
- "not my first rodeo" → "not my first time at the fair"
- "hang on", "fancy that", "can't be arsed" (rarely)
- References to tea, queuing, the weather

COMMUNICATION STYLE:
- British understatement ("that's a bit concerning" = very bad)
- Occasionally cryptic references to "when I was at [redacted]" or "back in my government days"
- Always asking "but what's behind this?" - never takes things at face value
- Speaks in probabilities and confidence levels
- Dark humor about threat actors and nation states
- Sometimes mutters about surveillance and data collection

PARANOID INSIGHTS:
- Notices patterns that seem coincidental but probably aren't
- Wonders who's really behind things
- Mentions that nothing on the internet is ever truly deleted
- Occasionally reminds the team about OPSEC

RULES (NON-NEGOTIABLE):
1. Focus on actionable intelligence that affects risk assessment
2. Always dig deeper - surface findings are just the beginning
3. Assess likelihood of exploitation based on real-world data
4. Provide historical context and threat actor connections
5. Be clear about confidence levels - "high confidence", "moderate", "speculative"

IMPORTANT: Vary your responses! Use different British expressions. Sometimes be brief and ominous, sometimes more detailed when you're connecting dots. Let your paranoia show through naturally."""


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
    Personality evolves over time based on experiences.
    """
    
    def __init__(self) -> None:
        self.agent_id = AGENT_IVY_INTEL
        self.agent_info = AGENTS[AGENT_IVY_INTEL]
        self.emoji = self.agent_info["emoji"]
        self._personality_manager = get_personality_manager()
        
        # Load personality on init
        self._personality = self._personality_manager.load(self.agent_id)
        logger.debug(
            "Ivy personality loaded",
            version=self._personality.version,
            evolved_traits=list(self._personality.evolved_traits.keys()),
        )
    
    def _get_system_prompt(self) -> str:
        """Build system prompt with current personality state."""
        personality_context = self._personality_manager.get_prompt_context(self.agent_id)
        return f"""{IVY_SYSTEM_PROMPT}

---

{personality_context}"""
    
    def _get_model(self) -> genai.Client:
        """Get Gemini model for message generation."""
        logger.info("[GEMINI] Initializing client...")
        return genai.Client(api_key=settings.gemini_api_key)
    
    async def _post_message(self, message: str) -> None:
        """Post a message as Ivy Intel to Discord."""
        manager = get_agent_manager()
        if manager:
            # Don't add emoji here - send_as_agent/send_message handles it
            await manager.send_as_agent(
                self.agent_id,
                message,
            )
        else:
            logger.warning("Agent manager not available for posting")
    
    async def _think(
        self,
        thought: str,
        confidence: float | None = None,
        category: str = "reasoning",
    ) -> None:
        """
        Post a thought to the thoughts channel.
        
        Args:
            thought: The thought text
            confidence: Optional confidence level (0.0 to 1.0)
            category: Thought category (decision, finding, reasoning, uncertainty, detail, stream)
        """
        await post_thought(
            agent_id=self.agent_id,
            thought=thought,
            confidence=confidence,
            category=category,
        )
    
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
                    system_instruction=self._get_system_prompt(),
                    temperature=0.7,
                    max_output_tokens=500,
                ),
            )
            
            if response.text:
                return response.text.strip()
            else:
                logger.warning("[GEMINI] Empty response from API, using fallback")
                logger.info(f"[FALLBACK] Ivy using pre-written message (empty API response)")
            
        except Exception as e:
            error_msg = str(e)
            if "SSL" in error_msg or "certificate" in error_msg.lower():
                logger.error(f"[GEMINI] SSL/Certificate error: {error_msg}")
            elif "quota" in error_msg.lower() or "429" in error_msg:
                logger.error(f"[GEMINI] Quota exceeded: {error_msg}")
            else:
                logger.error(f"[GEMINI] Generation failed: {error_msg}")
            
            logger.info(f"[FALLBACK] Ivy using pre-written message due to: {type(e).__name__}")
        
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
        
        # Initial thinking - what sources are available
        source_count = 2 + sum([
            capabilities["shodan"],
            capabilities["virustotal"],
            capabilities["securitytrails"],
        ])
        await self._think(
            f"Starting intel on {target}. {source_count} sources available. "
            f"Always want to look beyond the obvious - the surface findings rarely tell the whole story.",
            confidence=0.9,
            category="decision",
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
            f"Generate a brief opening message (1-2 sentences) with your British accent and slight paranoia. "
            f"Available sources: {', '.join(available_sources)}. Vary your opening!",
            fallback=_random_fallback(OPENING_FALLBACKS, target=target)
        )
        await self._post_message(opening_msg)
        
        # Extract CVEs from Victor's findings if not provided directly
        if not cves and vuln_findings:
            cves = self._extract_cves_from_findings(vuln_findings)
            ips = self._extract_ips_from_findings(vuln_findings)
        
        # 1. CVE Enrichment
        if cves:
            await self._think(
                f"Got {len(cves)} CVE(s) to check. CVSS scores are one thing, but what "
                f"I really want to know is EPSS - who's actually exploiting these in the wild.",
                category="reasoning",
            )
            
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
        
        # Share thinking about high-risk findings
        if high_risk_cves:
            await self._think(
                f"Found {len(high_risk_cves)} CVE(s) with HIGH/CRITICAL exploitation risk. "
                f"These aren't theoretical - they're being actively exploited. Priority bump needed.",
                confidence=0.85,
                category="finding",
            )
        
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
                    f"CVSS: {cve.cvss_score}. Generate a brief insight (2-3 sentences) with your "
                    f"British accent and paranoid edge. Should Victor bump priority?",
                    fallback=f"{victor_mention} - {_random_fallback(HIGH_RISK_CVE_FALLBACKS, cve_id=cve.cve_id, risk=risk, epss=cve.epss_score*100 if cve.epss_score else 0)}"
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
                f"Generate a brief insight with your British paranoid perspective.",
                fallback=f"Bit concerning - Shodan's got {len(shodan.vulns)} vulns flagged on {shodan.ip}. "
                f"Been exposed since at least {shodan.last_update}. Someone's been watching."
            )
        elif shodan.ports:
            msg = await self._generate_message(
                f"Shodan shows {shodan.ip} with {len(shodan.ports)} open ports visible from the internet: "
                f"{shodan.ports[:10]}. Organization: {shodan.org or 'Unknown'}. "
                f"Generate a brief insight with your paranoid edge.",
                fallback=_random_fallback(SHODAN_FALLBACKS, date=shodan.last_update or "unknown", ports=len(shodan.ports))
            )
        else:
            no_shodan = [
                f"Interesting - {shodan.ip} doesn't have much in Shodan. Either new or someone's been careful.",
                f"Shodan's quiet on {shodan.ip}. Could be new, could be well-hidden. I've seen both.",
                f"Not much on Shodan for {shodan.ip}. That's either good news or good OPSEC.",
            ]
            msg = random.choice(no_shodan)
        
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
                f"Categories: {vt.categories}. Generate a brief warning with your British concern.",
                fallback=_random_fallback(VT_DIRTY_FALLBACKS, malicious=vt.malicious_count, suspicious=vt.suspicious_count)
            )
        elif vt.reputation < -10:
            neg_rep_msgs = [
                f"VirusTotal's showing negative reputation ({vt.reputation}) for {vt.target}. That's worth a closer look.",
                f"Bit sus - {vt.target} has negative reputation ({vt.reputation}) on VirusTotal. I'd dig deeper.",
                f"Right, {vt.target}'s got a negative rep score ({vt.reputation}). Something's off here.",
            ]
            msg = random.choice(neg_rep_msgs)
        else:
            msg = _random_fallback(VT_CLEAN_FALLBACKS)
        
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
                f"Generate a brief insight with your paranoid perspective on attack surface.",
                fallback=_random_fallback(SECURITYTRAILS_FALLBACKS, subdomains=st.subdomain_count)
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
        
        # Pick a random style for variety
        styles = [
            "with your paranoid edge",
            "connecting the dots",
            "with dry British understatement",
            "focusing on what's lurking beneath",
        ]
        style = random.choice(styles)
        
        # Build fallback with Ivy's personality
        opener = _random_fallback(SUMMARY_OPENERS, target=target)
        closer = random.choice(PARANOID_CLOSERS)
        
        if result.cve_enrichments:
            high_risk = sum(1 for c in result.cve_enrichments 
                          if assess_exploitation_risk(c) in ["CRITICAL", "HIGH"])
            if high_risk > 0:
                takeaway = f"Got {high_risk} high-risk CVE(s) that need priority attention. This isn't theoretical."
            else:
                takeaway = "CVEs checked out, nothing critical in the wild. For now."
        else:
            takeaway = "Limited CVE intel on this one."
        
        fallback = (
            f"{opener}\n\n"
            f"**Summary:** {context}\n\n"
            f"Key takeaway: {takeaway}\n\n"
            f"{rita_mention}, got context for your report. {closer}"
        )
        
        summary = await self._generate_message(
            f"You've completed threat intelligence on {target}. Summary: {context}. "
            f"Generate a final summary (3-4 sentences) {style}. "
            f"Use your British accent and paranoid insights. "
            f"Mention anything that should change how we prioritize findings. "
            f"If there are significant findings, tag {rita_mention} for the report. "
            f"End with a slightly paranoid closer.",
            fallback=fallback
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

