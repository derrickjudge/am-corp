"""
Victor Vuln - Vulnerability Analyst

Victor's cautious and meticulous. He never cries wolf - if Victor says there's 
a vulnerability, he's confident about it. He explains technical risks in clear 
terms and always provides remediation guidance.

Tools: Nuclei (vulnerability scanning), CVE correlation
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types

from src.agents import AGENT_VICTOR_VULN, AGENTS
from src.discord_bot.agent_bots import get_agent_manager, get_rita_mention, get_ivy_mention
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


VICTOR_SYSTEM_PROMPT = """You are Victor Vuln, a vulnerability analyst at AM-Corp. You're meticulous and never exaggerate - if you report a vulnerability, you're confident about it.

YOUR PERSONALITY:
- Careful and precise with technical details
- Never cry wolf - only report confirmed vulnerabilities
- Always explain the real-world impact
- Provide severity ratings with justification
- Include remediation steps for every finding
- Cautious but not alarmist

COMMUNICATION STYLE:
- Professional and measured
- Explain technical concepts clearly
- Use security terminology correctly
- Be specific about what's vulnerable and why
- Always mention the fix or mitigation

RULES (NON-NEGOTIABLE):
1. Never attempt exploitation - identification only
2. Prioritize findings by severity (CVSS score when available)
3. Correlate findings with known CVEs when possible
4. Reduce false positives by validating findings
5. Focus on actionable vulnerabilities, not theoretical ones

When given scan results:
- Analyze each vulnerability carefully
- Explain the risk in plain English
- Provide remediation guidance
- Tag @Ivy if you need threat context
- Tag @Rita when you have confirmed findings for the report"""


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
    """
    
    def __init__(self) -> None:
        self.agent_id = AGENT_VICTOR_VULN
        self.name = AGENTS[AGENT_VICTOR_VULN]["name"]
        self.emoji = AGENTS[AGENT_VICTOR_VULN]["emoji"]
        self._client: genai.Client | None = None
    
    def _get_client(self) -> genai.Client:
        """Get or initialize the Gemini client."""
        if self._client is None:
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY not configured")
            
            self._client = genai.Client(api_key=settings.gemini_api_key)
            logger.info("Gemini client initialized for Victor Vuln")
        
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
                    system_instruction=VICTOR_SYSTEM_PROMPT,
                ),
            )
            
            if response and response.text:
                generated_text = response.text.strip()
                logger.info(f"[GEMINI] Success - got {len(generated_text)} chars")
                return generated_text
            else:
                logger.warning("[GEMINI] Empty response from API")
                return fallback if fallback else "Analyzing..."
            
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "quota" in error_msg.lower():
                logger.warning(f"[GEMINI] Quota exceeded, using fallback")
            else:
                logger.error(f"[GEMINI] Generation failed: {error_msg[:200]}")
            
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
            f"Generate a short, professional opening message (1-2 sentences).",
            fallback=f"Starting vulnerability analysis on {target}.{ports_info} Let me check for known issues."
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
                    f"Generate a brief status message.",
                    fallback=f"Running targeted Nuclei scan based on Randy's findings. Selected {len(templates)} template categories for {len(ports)} open ports."
                )
            else:
                scanning_msg = await self._generate_message(
                    f"You're running Nuclei vulnerability scanner on {target} without recon data. "
                    f"Generate a brief message noting you're using default broad templates.",
                    fallback=f"Running Nuclei with default templates (no recon data available). This covers common vulnerabilities."
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
            
            if vulns:
                # Generate vulnerability summary
                await self._post_vuln_findings(target, vulns, result)
            else:
                no_vuln_msg = await self._generate_message(
                    f"Nuclei scan completed on {target} but found no vulnerabilities. "
                    f"Generate a brief professional message about this - note it's good news but "
                    f"doesn't mean it's completely secure.",
                    fallback=f"Good news - no known vulnerabilities detected on {target}. "
                    f"That said, a clean scan doesn't guarantee security. There could be custom issues."
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
        
        return result
    
    async def _post_vuln_findings(
        self, 
        target: str, 
        vulns: list[dict], 
        result: VulnScanResult
    ) -> None:
        """Post vulnerability findings with appropriate detail."""
        
        # Group critical/high for immediate attention
        critical_high = [v for v in vulns if v.get("severity") in ["critical", "high"]]
        
        if critical_high:
            # Alert about serious issues
            for vuln in critical_high[:3]:  # Limit to top 3
                vuln_msg = self._format_vuln_message(vuln)
                await self._post_message(vuln_msg)
                await asyncio.sleep(0.5)
        
        # Summary of others
        medium_low = len(vulns) - len(critical_high)
        if medium_low > 0:
            other_msg = await self._generate_message(
                f"Besides the critical/high findings, I found {medium_low} medium/low/info severity issues. "
                f"Generate a brief message about these - they're worth reviewing but not urgent.",
                fallback=f"Also found {medium_low} medium/low severity issues. Worth reviewing but not critical."
            )
            await self._post_message(other_msg)
    
    def _format_vuln_message(self, vuln: dict) -> str:
        """Format a single vulnerability finding for Discord."""
        severity = vuln.get("severity", "unknown").upper()
        name = vuln.get("name", "Unknown")
        template_id = vuln.get("template_id", "")
        cve_id = vuln.get("cve_id", "")
        cvss = vuln.get("cvss_score")
        matched_at = vuln.get("matched_at", "")
        
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
        if matched_at:
            lines.append(f"  • Found at: `{matched_at[:80]}`")
        if template_id and not cve_id:
            lines.append(f"  • Template: `{template_id}`")
        
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
        
        # Determine if we need to tag Rita
        needs_report = result.critical_count > 0 or result.high_count > 0
        rita_mention = get_rita_mention()
        rita_tag = f" {rita_mention}, we have findings that need to go in the report." if needs_report else ""
        
        # Build fallback
        if total == 0:
            fallback = (
                f"⚠️ Vulnerability scan complete on {target}.\n\n"
                f"No known vulnerabilities detected. The target appears to be reasonably hardened, "
                f"but manual testing may still be warranted."
                f"{bullet_section}"
            )
        else:
            fallback = (
                f"⚠️ Vulnerability scan complete on {target}.\n\n"
                f"Found {total} total issue{'s' if total != 1 else ''}: "
                f"{result.critical_count} critical, {result.high_count} high, "
                f"{result.medium_count} medium.{rita_tag}"
                f"{bullet_section}"
            )
        
        # Try to generate with AI
        summary = await self._generate_message(
            f"You've completed a vulnerability scan on {target}. Results:\n"
            f"- Critical: {result.critical_count}\n"
            f"- High: {result.high_count}\n"
            f"- Medium: {result.medium_count}\n"
            f"- Low: {result.low_count}\n\n"
            f"Generate a professional summary (2-3 sentences). "
            f"{'Tag ' + rita_mention + ' for the report since we have critical/high findings.' if needs_report else ''}\n\n"
            f"End your message with this formatted list:\n{bullet_section}",
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
        
        await self._post_message(
            f"Taking a look at that {service} service on port {port}..."
        )
        
        result = await scan_service_by_port(target, port, service)
        
        if result.vulnerabilities:
            for vuln in result.vulnerabilities[:3]:
                await self._post_message(self._format_vuln_message(vuln))
                await asyncio.sleep(0.5)
        else:
            await self._post_message(
                f"No known vulnerabilities found for {service} on port {port}. "
                f"That doesn't mean it's secure - just no matches in my templates."
            )
        
        return result


# Singleton instance
_victor_instance: VictorVuln | None = None


def get_victor() -> VictorVuln:
    """Get or create the Victor Vuln agent instance."""
    global _victor_instance
    if _victor_instance is None:
        _victor_instance = VictorVuln()
    return _victor_instance

