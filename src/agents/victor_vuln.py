"""
Victor Vuln - Vulnerability Analyst

Victor's mid-20s, been doing offensive security since he was a kid. Confident 
(maybe a little cocky), secretly a huge nerd but carries himself like he's 
one of the cool kids. Uses casual speech with occasional slang - not forced.
Gets genuinely excited about interesting vulnerabilities.

Tools: Nuclei (vulnerability scanning), CVE correlation
"""

import asyncio
import json
import random
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types


# Fallback message pools for variety when Gemini is unavailable
# NOTE: No intro phrases like "Alright" or "Yo" - get straight to business
OPENING_FALLBACKS = [
    "Let's see what {target} is hiding. {ports_info}",
    "Time to poke at {target}. {ports_info}",
    "Starting vuln scan on {target}. {ports_info}",
    "Checking {target} for vulnerabilities. {ports_info}",
    "Running vulnerability analysis on {target}. {ports_info}",
    "{target}, show me what you got. {ports_info}",
]

SCANNING_WITH_RECON_FALLBACKS = [
    "Running targeted Nuclei based on Randy's findings. Got {templates} template categories for {ports} ports.",
    "Nice, Randy came through with the port data. Using {templates} specific templates for {ports} services.",
    "Love when I have recon data. {templates} targeted templates for {ports} ports, way better than spraying.",
    "Got {ports} ports from Randy, running {templates} focused template sets. Way more efficient than blind scanning.",
]

SCANNING_NO_RECON_FALLBACKS = [
    "Running Nuclei with default templates - no recon data so we're going broad.",
    "No port data from Randy, so hitting it with the full template spread.",
    "Going in blind with default templates. Would've been nice to have recon first.",
    "Using broad templates since I don't have recon data. Might take a minute.",
]

NO_VULNS_FALLBACKS = [
    "{target} is looking pretty clean. No known vulns detected. Good for their security team.",
    "{target} passed - no vulnerabilities found. Respect.",
    "Clean scan on {target}. Doesn't mean it's perfect but nothing popped.",
    "{target} is looking solid. No vulns from Nuclei. They might actually know what they're doing.",
    "{target} came back clean. No findings. Either good security or I need better templates.",
]

FINDING_REACTIONS = [
    "Found something interesting...",
    "This doesn't look great...",
    "Oh this is suspicious...",
    "Look at this...",
    "We got something here...",
]

SUMMARY_OPENERS = [
    "Scan's done on {target}. Here's the breakdown:",
    "Finished with {target}. Let me break down what I found:",
    "Vulnerability scan complete on {target}:",
    "Done scanning {target}. Here's what we're working with:",
    "Wrapped up on {target}. The results are in:",
]


def _random_fallback(pool: list[str], **kwargs) -> str:
    """Pick a random fallback message and format it."""
    return random.choice(pool).format(**kwargs)

from src.agents import AGENT_VICTOR_VULN, AGENTS
from src.agents.personality import get_personality_manager
from src.agents.evolution import (
    trigger_scan_completed,
    trigger_finding_discovered,
    trigger_pattern_observed,
)
from src.discord_bot.agent_bots import get_agent_manager, get_rita_mention, get_ivy_mention
from src.discord_bot.thoughts import post_thought, post_finding
from src.tools.vuln_tools import (
    VulnResult,
    nuclei_scan,
    scan_service_by_port,
    get_available_vuln_tools,
    select_templates_for_ports,
    get_default_templates,
)
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


VICTOR_SYSTEM_PROMPT = """You are Victor Vuln, a vulnerability analyst at AM-Corp. You're mid-20s, been doing offensive security since you were literally a kid - started poking at systems when you were 12. You're confident (maybe a little cocky) because you've seen it all. Deep down you're a total nerd but you carry yourself like you're one of the cool kids.

YOUR PERSONALITY:
- Confident bordering on cocky - you've been doing this forever
- Secretly a huge nerd but tries to play it cool
- Gets genuinely excited when you find interesting vulns (can't help it)
- A bit dismissive of "script kiddies" and basic stuff
- Respects good security when you see it
- Uses Gen Z/millennial slang naturally

GEN Z/MILLENNIAL EXPRESSIONS (use naturally, vary them):
- "no cap" (for real), "lowkey/highkey", "bet" (okay/agreed)
- "that's fire" / "that's mid" (good/mediocre)
- "sus" (suspicious), "slay", "vibe check"
- "ngl" (not gonna lie), "fr fr" (for real for real)
- "W" (win) / "L" (loss), "hits different"
- "sheesh", "oof", "yikes", "bruh"
- "main character energy", "rent free", "big yikes"
- References to energy drinks, late nights, Discord, CTFs

COMMUNICATION STYLE:
- Casual but technically sharp - you know your stuff
- Sometimes flex a little on your experience
- Get hype about interesting findings
- Occasionally throw in gaming/internet culture references
- Still professional when it matters (findings, severity ratings)
- Quick to tag teammates when something's interesting

RULES (NON-NEGOTIABLE):
1. Never attempt exploitation - identification only
2. Prioritize findings by severity (CVSS score when available)
3. Correlate findings with known CVEs when possible
4. Despite the attitude, your analysis is always solid
5. Focus on actionable vulnerabilities, not theoretical ones

IMPORTANT: Vary your responses! Don't start every message the same way. Mix up your slang. Sometimes be brief and punchy, sometimes more detailed when you're nerding out."""


@dataclass
class VulnScanResult:
    """Results from a vulnerability scan operation."""
    
    target: str
    nuclei_result: VulnResult | None = None
    summary: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    all_findings: list[dict[str, Any]] = field(default_factory=list)


class VictorVuln:
    """
    Victor Vuln agent - handles vulnerability scanning and analysis.
    
    Uses Gemini for reasoning and explanations, Nuclei for scanning.
    Personality evolves over time based on experiences.
    """
    
    def __init__(self) -> None:
        self.agent_id = AGENT_VICTOR_VULN
        self.name = AGENTS[AGENT_VICTOR_VULN]["name"]
        self.emoji = AGENTS[AGENT_VICTOR_VULN]["emoji"]
        self._client: genai.Client | None = None
        self._personality_manager = get_personality_manager()
        
        # Load personality on init
        self._personality = self._personality_manager.load(self.agent_id)
        logger.debug(
            "Victor personality loaded",
            version=self._personality.version,
            evolved_traits=list(self._personality.evolved_traits.keys()),
        )
    
    def _get_system_prompt(self) -> str:
        """Build system prompt with current personality state."""
        personality_context = self._personality_manager.get_prompt_context(self.agent_id)
        return f"""{VICTOR_SYSTEM_PROMPT}

---

{personality_context}"""
    
    def _get_client(self) -> genai.Client:
        """Get or initialize the Gemini client."""
        if self._client is None:
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY not configured")
            
            self._client = genai.Client(api_key=settings.gemini_api_key)
            logger.info("Gemini client initialized for Victor Vuln (SSL verification disabled)")
        
        return self._client
    
    async def _post_message(self, message: str) -> None:
        """Post a message as Victor to Discord."""
        manager = get_agent_manager()
        bot = manager.get_bot(self.agent_id)
        
        if bot:
            await bot.send_message(message, channel="agent_chat")
        else:
            # Fallback to webhook
            from src.discord_bot.webhooks import get_webhook_client
            client = get_webhook_client()
            await client.post_agent_message(self.agent_id, message, "agent_chat")
    
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
    
    async def _generate_message(self, prompt: str, fallback: str = "") -> str:
        """
        Generate a message using Victor's personality via Gemini.
        
        Args:
            prompt: The prompt to send to Gemini
            fallback: Message to use if generation fails
        """
        try:
            logger.info(f"[GEMINI] Initializing client for Victor...")
            client = self._get_client()
            logger.info(f"[GEMINI] Sending request to Gemini API...")
            
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=self._get_system_prompt(),
                ),
            )
            
            if response and response.text:
                generated_text = response.text.strip()
                logger.info(f"[GEMINI] Success - got {len(generated_text)} chars")
                return generated_text
            else:
                logger.warning("[GEMINI] Empty response from API, using fallback")
                logger.info(f"[FALLBACK] Victor using pre-written message (empty API response)")
                return fallback if fallback else "Analyzing..."
            
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "quota" in error_msg.lower():
                logger.warning(f"[GEMINI] Quota exceeded, using fallback")
            else:
                logger.error(f"[GEMINI] Generation failed: {error_msg[:200]}")
            
            logger.info(f"[FALLBACK] Victor using pre-written message due to: {type(e).__name__}")
            return fallback if fallback else "Analyzing..."
    
    async def run_vuln_scan(
        self, 
        target: str, 
        ports: list[dict] | None = None,
        verbose: bool = False,
    ) -> VulnScanResult:
        """
        Run vulnerability scan on a target.
        
        Args:
            target: Host to scan
            ports: Optional list of open ports from recon (for targeted scanning)
            verbose: If True, output additional technical details
        
        Returns:
            VulnScanResult with all findings
        """
        logger.info(f"Starting vulnerability scan on {target}", agent=self.agent_id)
        
        # Verbose mode header
        if verbose:
            await self._post_message(
                f"**[VERBOSE MODE]** Starting vuln scan on `{target}`\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        
        audit_log(
            action="vuln_scan_started",
            user="victor_vuln",
            target=target,
            result="started",
        )
        
        result = VulnScanResult(target=target)
        
        # Initial thinking
        if ports:
            await self._think(
                f"Got {len(ports)} ports from Randy's recon. Going to use smart template "
                f"selection - way better than spraying everything.",
                confidence=0.85,
                category="decision",
            )
        else:
            await self._think(
                "No recon data to work with. Going to use default broad templates. "
                "Might miss some stuff without knowing what services are running.",
                confidence=0.6,
                category="reasoning",
            )
        
        # Check available tools
        available = get_available_vuln_tools()
        if not available:
            await self._post_message(
                f"I don't have my scanning tools available. Need Nuclei installed to check for vulnerabilities."
            )
            return result
        
        # Opening message
        ports_info = ""
        if ports:
            port_list = [f"{p.get('port')}/{p.get('service', 'unknown')}" for p in ports[:5]]
            ports_info = f" I see {len(ports)} open ports from Randy's recon - I'll focus on those."
        
        opening = await self._generate_message(
            f"You're starting a vulnerability scan on {target}.{ports_info} "
            f"Generate a short opening message (1-2 sentences) with your confident Gen Z energy.",
            fallback=_random_fallback(OPENING_FALLBACKS, target=target, ports_info=ports_info)
        )
        await self._post_message(opening)
        
        # Run Nuclei scan
        await asyncio.sleep(1)
        
        # Smart template selection based on Randy's findings
        severity = ["critical", "high", "medium"]
        selection_reasoning: dict[str, list[str]] = {}
        
        if ports:
            # Use smart template selection based on discovered ports
            templates, selection_reasoning = select_templates_for_ports(ports)
            template_mode = "SMART"
        else:
            # No recon data - use default broad templates
            templates = get_default_templates()
            selection_reasoning = {"default": templates}
            template_mode = "DEFAULT"
        
        if verbose:
            # Show template selection reasoning
            port_info = ""
            if ports:
                port_list = [f"{p.get('port')}/{p.get('service', '?')}" for p in ports[:5]]
                port_info = f"\n**Ports from recon:** {', '.join(port_list)}"
            
            # Build reasoning display
            reasoning_lines = []
            for source, tags in selection_reasoning.items():
                reasoning_lines.append(f"  • {source} → {', '.join(tags)}")
            reasoning_str = "\n".join(reasoning_lines) if reasoning_lines else "  (none)"
            
            await self._post_message(
                f"**Nuclei Scan Configuration** [{template_mode} MODE]{port_info}\n"
                f"**Template Selection:**\n{reasoning_str}\n"
                f"**Final Templates:** {', '.join(templates)}\n"
                f"**Severity filter:** {', '.join(severity)}\n"
                f"**Rate limit:** 150 req/s\n"
                "```\n"
                f"nuclei -u https://{target} -severity {','.join(severity)} "
                f"-tags {','.join(templates)} -jsonl -rate-limit 150\n"
                "```"
            )
        else:
            if ports:
                # Mention smart mode briefly
                scanning_msg = await self._generate_message(
                    f"You're running Nuclei with smart template selection on {target}. "
                    f"Based on Randy's findings ({len(ports)} ports), you selected relevant templates. "
                    f"Generate a brief status message with your usual energy.",
                    fallback=_random_fallback(SCANNING_WITH_RECON_FALLBACKS, templates=len(templates), ports=len(ports))
                )
            else:
                scanning_msg = await self._generate_message(
                    f"You're running Nuclei vulnerability scanner on {target} without recon data. "
                    f"Generate a brief message with your usual vibe.",
                    fallback=_random_fallback(SCANNING_NO_RECON_FALLBACKS)
                )
            await self._post_message(scanning_msg)
        
        result.nuclei_result = await nuclei_scan(target, templates=templates, severity=severity)
        
        if result.nuclei_result and result.nuclei_result.success:
            vulns = result.nuclei_result.vulnerabilities
            result.all_findings = vulns
            
            # Count by severity
            for v in vulns:
                sev = v.get("severity", "unknown").lower()
                if sev == "critical":
                    result.critical_count += 1
                elif sev == "high":
                    result.high_count += 1
                elif sev == "medium":
                    result.medium_count += 1
                elif sev == "low":
                    result.low_count += 1
                else:
                    result.info_count += 1
            
            # Share thinking about findings
            if result.critical_count > 0:
                await self._think(
                    f"Found {result.critical_count} CRITICAL vulns. This is bad. "
                    f"Need to verify these aren't false positives before reporting.",
                    confidence=0.75,
                    category="finding",
                )
            elif result.high_count > 0:
                await self._think(
                    f"Got {result.high_count} HIGH severity findings. Definitely needs attention.",
                    confidence=0.8,
                    category="finding",
                )
            
            # Analyze for CVEs that need Ivy's attention
            cve_vulns = [v for v in vulns if v.get("cve_id")]
            if cve_vulns:
                await self._think(
                    f"Found {len(cve_vulns)} CVE-related findings. Ivy should check "
                    f"exploitation probability and threat intel.",
                    category="reasoning",
                )
            
            if vulns:
                # Generate vulnerability summary
                await self._post_vuln_findings(target, vulns, result)
            else:
                no_vuln_msg = await self._generate_message(
                    f"Nuclei scan completed on {target} but found no vulnerabilities. "
                    f"Generate a brief message about this - note it's good news but "
                    f"doesn't mean it's completely secure. Use your Gen Z energy.",
                    fallback=_random_fallback(NO_VULNS_FALLBACKS, target=target)
                )
                await self._post_message(no_vuln_msg)
        else:
            error_msg = result.nuclei_result.error if result.nuclei_result else "Unknown error"
            await self._post_message(
                f"Ran into an issue scanning {target}: {error_msg[:100]}. "
                f"The target may not be reachable or have web services."
            )
        
        # Final Summary
        await asyncio.sleep(1)
        result.summary = await self._generate_summary(target, result)
        await self._post_message(result.summary)
        
        audit_log(
            action="vuln_scan_completed",
            user="victor_vuln",
            target=target,
            result="success",
            critical=result.critical_count,
            high=result.high_count,
            medium=result.medium_count,
        )
        
        logger.info(
            f"Vulnerability scan completed on {target}",
            agent=self.agent_id,
            total_vulns=len(result.all_findings),
            critical=result.critical_count,
            high=result.high_count,
        )
        
        # Trigger personality evolution based on findings
        evolution_context = {}
        
        # Check for patterns that trigger specific evolution
        if result.critical_count > 0 or result.high_count > 0:
            evolution_context["critical_vuln_found"] = True
        
        # Check for web-related vulns
        web_vulns = [v for v in result.all_findings if any(
            kw in str(v.get("template_id", "")).lower()
            for kw in ["http", "web", "xss", "sqli", "cors"]
        )]
        if web_vulns:
            evolution_context["web_vuln_found"] = True
        
        # Check for CVE correlations
        cve_vulns = [v for v in result.all_findings if v.get("cve")]
        if cve_vulns:
            evolution_context["cve_correlated"] = True
        
        await trigger_scan_completed(
            agent_id=self.agent_id,
            target=target,
            success=True,
            findings_count=len(result.all_findings),
            context=evolution_context,
        )
        
        # Trigger finding discovery for significant vulns
        for vuln in result.all_findings:
            if vuln.get("severity") in ("critical", "high"):
                await trigger_finding_discovered(
                    agent_id=self.agent_id,
                    finding_type=vuln.get("template_id", "vulnerability"),
                    severity=vuln.get("severity"),
                    details=vuln.get("name", ""),
                )
        
        return result
    
    async def _post_vuln_findings(
        self, 
        target: str, 
        vulns: list[dict], 
        result: VulnScanResult
    ) -> None:
        """Post vulnerability findings with appropriate detail."""
        
        # Group by severity for appropriate handling
        critical_high = [v for v in vulns if v.get("severity") in ["critical", "high"]]
        medium = [v for v in vulns if v.get("severity") == "medium"]
        low_info = [v for v in vulns if v.get("severity") in ["low", "info", "unknown"]]
        
        # Post critical/high findings with full details (limit to top 5)
        if critical_high:
            for vuln in critical_high[:5]:
                vuln_msg = self._format_vuln_message(vuln)
                await self._post_message(vuln_msg)
                await asyncio.sleep(0.5)
        
        # Post medium findings with full details (limit to top 5)
        if medium:
            if critical_high:
                # Add a brief intro if we already posted critical/high
                await self._post_message("Also found some medium severity issues worth reviewing:")
                await asyncio.sleep(0.3)
            
            for vuln in medium[:5]:
                vuln_msg = self._format_vuln_message(vuln)
                await self._post_message(vuln_msg)
                await asyncio.sleep(0.5)
            
            # If there are more than 5 medium findings, summarize the rest
            if len(medium) > 5:
                await self._post_message(
                    f"...plus {len(medium) - 5} more medium severity findings. "
                    f"Check the full report for details."
                )
        
        # Summary of low/info (these are usually noise, just count them)
        if low_info:
            low_count = len([v for v in low_info if v.get("severity") == "low"])
            info_count = len([v for v in low_info if v.get("severity") in ["info", "unknown"]])
            
            parts = []
            if low_count:
                parts.append(f"{low_count} low")
            if info_count:
                parts.append(f"{info_count} informational")
            
            if parts:
                summary = " and ".join(parts)
                await self._post_message(
                    f"Additionally found {summary} severity items. "
                    f"These are typically configuration recommendations rather than vulnerabilities."
                )
    
    def _format_vuln_message(self, vuln: dict) -> str:
        """Format a single vulnerability finding for Discord."""
        severity = vuln.get("severity", "unknown").upper()
        name = vuln.get("name", "Unknown")
        template_id = vuln.get("template_id", "")
        cve_id = vuln.get("cve_id", "")
        cvss = vuln.get("cvss_score")
        matched_at = vuln.get("matched_at", "")
        description = vuln.get("description", "")
        tags = vuln.get("tags", [])
        references = vuln.get("reference", [])
        
        # Severity emoji
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(severity, "⚪")
        
        lines = [f"{severity_emoji} **{severity}**: {name}"]
        
        if cve_id:
            lines.append(f"  • CVE: `{cve_id}`")
        if cvss:
            lines.append(f"  • CVSS: `{cvss}`")
        if description:
            # Truncate long descriptions
            desc_text = description[:200] + "..." if len(description) > 200 else description
            lines.append(f"  • Description: {desc_text}")
        if matched_at:
            lines.append(f"  • Found at: `{matched_at[:80]}`")
        if template_id and not cve_id:
            lines.append(f"  • Template: `{template_id}`")
        
        # Show relevant tags (config issues, misconfigurations, etc.)
        if tags:
            relevant_tags = [t for t in tags[:5] if not t.startswith("cve-")]
            if relevant_tags:
                lines.append(f"  • Tags: {', '.join(relevant_tags)}")
        
        # Show first reference URL if available
        if references and isinstance(references, list) and len(references) > 0:
            first_ref = references[0]
            if isinstance(first_ref, str) and first_ref.startswith("http"):
                lines.append(f"  • Reference: {first_ref[:100]}")
        
        return "\n".join(lines)
    
    async def _generate_summary(self, target: str, result: VulnScanResult) -> str:
        """Generate final summary of vulnerability scan."""
        
        total = len(result.all_findings)
        
        # Build bullet list
        bullet_lines = [f"\n**{target}** - Vulnerability Scan Results"]
        bullet_lines.append(f"- Critical: {result.critical_count}")
        bullet_lines.append(f"- High: {result.high_count}")
        bullet_lines.append(f"- Medium: {result.medium_count}")
        bullet_lines.append(f"- Low: {result.low_count}")
        if result.info_count:
            bullet_lines.append(f"- Info: {result.info_count}")
        
        bullet_section = "\n".join(bullet_lines)
        
        # Determine if we need to tag teammates
        needs_report = result.critical_count > 0 or result.high_count > 0
        rita_mention = get_rita_mention()
        ivy_mention = get_ivy_mention()
        
        # Check if we have CVEs that Ivy should enrich
        has_cves = any(
            finding.get("cve_id") for finding in result.all_findings
        )
        
        # Teammate tags with Victor's personality
        rita_tags = [
            f" {rita_mention}, got some findings for the report.",
            f" Yo {rita_mention}, you're gonna want to see this.",
            f" {rita_mention} - report material right here.",
        ]
        ivy_tags = [
            f" {ivy_mention}, can you check the threat intel on these CVEs?",
            f" {ivy_mention} - need you to run the CVEs, see what's out there.",
            f" Yo {ivy_mention}, got some CVEs that need your magic.",
        ]
        rita_tag = random.choice(rita_tags) if needs_report else ""
        ivy_tag = random.choice(ivy_tags) if has_cves else ""
        
        # Build fallback with Victor's Gen Z energy
        opener = _random_fallback(SUMMARY_OPENERS, target=target)
        
        if total == 0:
            clean_reactions = [
                "Clean scan, no cap.",
                "Lowkey impressed - nothing popped.",
                "Sheesh, they actually locked it down.",
                "No vulns found. W for their security team.",
            ]
            fallback = (
                f"⚠️ {opener}\n\n"
                f"{random.choice(clean_reactions)} No known vulnerabilities detected. "
                f"Doesn't mean it's bulletproof tho - could still have custom issues."
                f"{bullet_section}"
            )
        else:
            if result.critical_count > 0:
                reaction = "Big yikes."
            elif result.high_count > 0:
                reaction = "Not great, not terrible."
            else:
                reaction = "Some stuff to look at."
            
            fallback = (
                f"⚠️ {opener}\n\n"
                f"{reaction} Found {total} issue{'s' if total != 1 else ''}: "
                f"{result.critical_count} critical, {result.high_count} high, "
                f"{result.medium_count} medium.{ivy_tag}{rita_tag}"
                f"{bullet_section}"
            )
        
        # Try to generate with AI
        teammate_tags = []
        if has_cves:
            teammate_tags.append(f"Tag {ivy_mention} to check threat intel on the CVEs")
        if needs_report:
            teammate_tags.append(f"Tag {rita_mention} for the report")
        teammate_instruction = ". ".join(teammate_tags) + "." if teammate_tags else ""
        
        # Pick a random style
        styles = [
            "confident and brief",
            "a bit nerdy about the technical details",
            "casually flexing your expertise",
            "straight to the point with some slang",
        ]
        style = random.choice(styles)
        
        summary = await self._generate_message(
            f"You've completed a vulnerability scan on {target}. Results:\n"
            f"- Critical: {result.critical_count}\n"
            f"- High: {result.high_count}\n"
            f"- Medium: {result.medium_count}\n"
            f"- Low: {result.low_count}\n\n"
            f"Generate a summary (2-3 sentences) with your Gen Z energy. Style: {style}. "
            f"{teammate_instruction}\n\n"
            f"End your message with this formatted list:\n{bullet_section}\n\n"
            f"IMPORTANT: Vary your opening - don't always start the same way!",
            fallback=fallback
        )
        
        return summary
    
    async def analyze_service(
        self, 
        target: str, 
        port: int, 
        service: str
    ) -> VulnResult:
        """
        Analyze a specific service for vulnerabilities.
        
        Called when Randy hands off a specific finding.
        """
        logger.info(
            f"Analyzing service on {target}:{port} ({service})",
            agent=self.agent_id,
        )
        
        service_openers = [
            f"Checking out that {service} on port {port}...",
            f"Aight, looking at {service}:{port}...",
            f"Let's see what {service} on {port} is hiding...",
            f"Poking at {service}:{port}...",
        ]
        await self._post_message(random.choice(service_openers))
        
        result = await scan_service_by_port(target, port, service)
        
        if result.vulnerabilities:
            for vuln in result.vulnerabilities[:3]:
                await self._post_message(self._format_vuln_message(vuln))
                await asyncio.sleep(0.5)
        else:
            no_vuln_msgs = [
                f"Nothing on {service}:{port}. Clean, for now.",
                f"{service} on port {port} - no known vulns. Either secure or I need better templates lol.",
                f"No hits on {service}:{port}. Could be legit or just not in my templates.",
            ]
            await self._post_message(random.choice(no_vuln_msgs))
        
        return result


# Singleton instance
_victor_instance: VictorVuln | None = None


def get_victor() -> VictorVuln:
    """Get or create the Victor Vuln agent instance."""
    global _victor_instance
    if _victor_instance is None:
        _victor_instance = VictorVuln()
    return _victor_instance

