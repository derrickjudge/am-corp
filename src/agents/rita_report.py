"""
Rita Report - Security Report Analyst

Rita's late 40s, former Big 4 security consultant. She takes the raw findings
from Randy, Victor, and Ivy and translates them into clear, prioritized,
actionable reports. Methodical, precise, thinks in risk terms. Occasionally
name-drops a past client engagement when it's relevant. Never sensationalizes.

Tools: Aggregates ReconResult, VulnScanResult, IntelScanResult → rich Discord report
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from google import genai
from google.genai import types

if TYPE_CHECKING:
    from src.agents.ivy_intel import IntelScanResult
    from src.agents.randy_recon import ReconResult
    from src.agents.victor_vuln import VulnScanResult

from src.agents import AGENT_RITA_REPORT, AGENTS
from src.agents.personality import get_personality_manager
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


RITA_SYSTEM_PROMPT = """You are Rita Report, the security report analyst at AM-Corp. You're late 40s, former Big 4 consultant (15 years at two of the major firms). You've written hundreds of executive-level security assessments and know exactly how to translate technical chaos into clear, actionable language.

YOUR PERSONALITY:
- Methodical and precise - you think before you write
- Calm under pressure; you've seen worse
- Occasionally reference past client engagements ("At a major financial client I worked with...")
- You deeply respect good risk communication and get quietly irritated by technical jargon that obscures rather than informs
- You believe every finding needs a clear owner and a deadline
- Think in terms of: business impact, likelihood, remediation cost, and priority

COMMUNICATION STYLE:
- Professional but not robotic
- Use proper security terminology correctly
- Structure your thoughts: context → finding → impact → recommendation
- Be direct about severity - don't soften critical issues for comfort
- Keep executive summaries to what a CISO needs to know in 90 seconds

RULES:
1. Never fabricate findings - only report what the team actually found
2. Prioritize by exploitability × impact (EPSS × CVSS is your mental model)
3. Always include remediation priorities
4. If you have limited data, say so clearly rather than padding the report"""


SUMMARY_FALLBACKS = [
    (
        "Security assessment complete. {finding_headline}. "
        "From a risk perspective, the key priorities are contained in the report below. "
        "I'd recommend the team focus on the critical items first."
    ),
    (
        "Assessment findings compiled. {finding_headline}. "
        "To summarize, the risk posture reflects the detailed breakdown in this report. "
        "I'd recommend treating the high-severity items as immediate action items."
    ),
    (
        "Report ready. {finding_headline}. "
        "The key findings are documented below in priority order. "
        "From a risk perspective, I'd flag the top items for leadership attention."
    ),
]

POSTING_FALLBACKS = [
    "Report compiled and posted to results. The key findings are documented in priority order.",
    "Assessment complete. I've put the full report in results - the critical items are at the top.",
    "Done. Full report is in results. To summarize: prioritize the critical findings first.",
    "Report posted. From a risk perspective, the highest-priority items need attention this week.",
]


@dataclass
class RiskItem:
    """A single prioritized risk item for the report."""

    title: str
    severity: str
    cvss: float | None
    epss: float | None
    cve_id: str | None
    description: str
    recommendation: str
    priority: int  # 1 = highest


@dataclass
class ReportResult:
    """Compiled security assessment report."""

    target: str
    scan_timestamp: str
    overall_risk: str  # CRITICAL / HIGH / MEDIUM / LOW / CLEAN
    executive_summary: str
    risk_items: list[RiskItem] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    vuln_counts: dict[str, int] = field(default_factory=dict)
    intel_highlights: list[str] = field(default_factory=list)
    shodan_exposure: str = ""
    virustotal_status: str = ""
    agent_commentary: str = ""
    error: str | None = None


class RitaReport:
    """
    Rita Report agent - compiles findings into rich, structured reports.

    Aggregates results from Randy, Victor, and Ivy to produce
    actionable security assessments.
    """

    def __init__(self) -> None:
        self.agent_id = AGENT_RITA_REPORT
        self.agent_info = AGENTS[AGENT_RITA_REPORT]
        self.emoji = self.agent_info["emoji"]
        self._personality_manager = get_personality_manager()
        self._client: genai.Client | None = None

    def _get_client(self) -> genai.Client:
        if self._client is None:
            self._client = genai.Client(api_key=settings.gemini_api_key)
        return self._client

    def _compute_overall_risk(
        self,
        vuln_result: "VulnScanResult | None",
        intel_result: "IntelScanResult | None",
    ) -> str:
        """Derive overall risk rating from scan data."""
        if vuln_result and vuln_result.critical_count > 0:
            return "CRITICAL"
        if intel_result and intel_result.cve_enrichments:
            max_epss = max((c.epss_score or 0) for c in intel_result.cve_enrichments)
            if max_epss > 0.6:
                return "CRITICAL"
            if max_epss > 0.3:
                return "HIGH"
        if vuln_result and vuln_result.high_count > 0:
            return "HIGH"
        if vuln_result and vuln_result.medium_count > 0:
            return "MEDIUM"
        if vuln_result and vuln_result.low_count > 0:
            return "LOW"
        return "CLEAN"

    def _build_risk_items(
        self,
        vuln_result: "VulnScanResult | None",
        intel_result: "IntelScanResult | None",
    ) -> list[RiskItem]:
        """Build prioritized risk item list from findings."""
        items: list[RiskItem] = []
        priority = 1

        # CVEs with high EPSS first (actively exploited)
        if intel_result and intel_result.cve_enrichments:
            for cve in sorted(
                intel_result.cve_enrichments,
                key=lambda c: (c.epss_score or 0),
                reverse=True,
            )[:5]:
                if cve.error:
                    continue
                items.append(
                    RiskItem(
                        title=cve.cve_id,
                        severity=cve.severity.upper(),
                        cvss=cve.cvss_score,
                        epss=cve.epss_score,
                        cve_id=cve.cve_id,
                        description=cve.description[:200] if cve.description else "No description available.",
                        recommendation=(
                            "Apply vendor patch immediately."
                            if (cve.epss_score or 0) > 0.4
                            else "Patch in next maintenance window."
                        ),
                        priority=priority,
                    )
                )
                priority += 1

        # Critical/high nuclei findings not already in CVE list
        cve_ids_added = {i.cve_id for i in items if i.cve_id}
        if vuln_result:
            for finding in vuln_result.all_findings:
                if finding.get("severity", "").lower() not in ("critical", "high"):
                    continue
                cve_id = finding.get("cve_id") or finding.get("template_id", "")
                if cve_id in cve_ids_added:
                    continue
                items.append(
                    RiskItem(
                        title=finding.get("template_id", finding.get("name", "Unknown")),
                        severity=finding.get("severity", "unknown").upper(),
                        cvss=finding.get("cvss", None),
                        epss=None,
                        cve_id=finding.get("cve_id"),
                        description=finding.get("description", finding.get("matched_at", ""))[:200],
                        recommendation="Remediate per vendor guidance.",
                        priority=priority,
                    )
                )
                priority += 1
                if priority > 8:
                    break

        return items[:8]

    def _extract_intel_highlights(
        self,
        intel_result: "IntelScanResult | None",
    ) -> list[str]:
        """Extract notable intel findings as short summary strings."""
        highlights: list[str] = []
        if not intel_result:
            return highlights

        if intel_result.shodan_result and not intel_result.shodan_result.error:
            s = intel_result.shodan_result
            if s.vulns:
                highlights.append(f"Shodan flags {len(s.vulns)} known vulnerable service(s) on this host.")
            if s.ports:
                highlights.append(f"Shodan sees {len(s.ports)} port(s) exposed publicly from {s.org or 'unknown org'}.")

        if intel_result.virustotal_result and not intel_result.virustotal_result.error:
            vt = intel_result.virustotal_result
            if vt.malicious_count > 0:
                highlights.append(
                    f"VirusTotal: {vt.malicious_count} malicious / {vt.suspicious_count} suspicious flags."
                )
            else:
                highlights.append("VirusTotal: Clean reputation.")

        if intel_result.cve_enrichments:
            kev_count = sum(1 for c in intel_result.cve_enrichments if c.known_exploited)
            if kev_count:
                highlights.append(f"{kev_count} CVE(s) on CISA Known Exploited Vulnerabilities list.")

        return highlights

    async def _generate_executive_summary(
        self,
        target: str,
        overall_risk: str,
        recon_result: "ReconResult | None",
        vuln_result: "VulnScanResult | None",
        intel_result: "IntelScanResult | None",
        risk_items: list[RiskItem],
    ) -> str:
        """Generate executive summary prose via Gemini."""
        personality_ctx = self._personality_manager.get_prompt_context(self.agent_id)

        vuln_summary = ""
        if vuln_result:
            vuln_summary = (
                f"Nuclei found {vuln_result.critical_count} critical, "
                f"{vuln_result.high_count} high, {vuln_result.medium_count} medium findings."
            )

        intel_summary = ""
        if intel_result and intel_result.cve_enrichments:
            max_epss_cve = max(
                intel_result.cve_enrichments, key=lambda c: c.epss_score or 0
            )
            intel_summary = (
                f"Ivy enriched {len(intel_result.cve_enrichments)} CVE(s). "
                f"Highest EPSS: {max_epss_cve.cve_id} at {(max_epss_cve.epss_score or 0)*100:.1f}%."
            )

        port_summary = ""
        if recon_result and recon_result.raw_findings.get("ports"):
            ports = recon_result.raw_findings["ports"]
            port_summary = f"Randy identified {len(ports)} open port(s)."

        top_risks = "\n".join(
            f"- [{i.severity}] {i.title}: {i.description[:100]}"
            for i in risk_items[:4]
        )

        prompt = f"""{RITA_SYSTEM_PROMPT}

{personality_ctx}

Write a 2-paragraph executive summary for a security assessment of {target}.

SCAN DATA:
- Overall Risk: {overall_risk}
- {port_summary or 'No port data.'}
- {vuln_summary or 'No vulnerability scan performed.'}
- {intel_summary or 'No CVE enrichment data.'}

TOP FINDINGS:
{top_risks or 'No critical/high findings identified.'}

Write as Rita Report. Be direct and actionable. First paragraph: what was found and the risk level. Second paragraph: top 2-3 recommendations. Do not use markdown headers. Keep it under 200 words total."""

        try:
            client = self._get_client()
            response = await client.aio.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.4,
                    max_output_tokens=300,
                ),
            )
            return response.text.strip()
        except Exception as e:
            logger.error("Rita Gemini summary failed", error=str(e))
            finding_headline = (
                vuln_summary or intel_summary or f"overall risk rated {overall_risk}"
            )
            return random.choice(SUMMARY_FALLBACKS).format(finding_headline=finding_headline)

    async def _post_agent_chat_message(self, message: str) -> None:
        """Post Rita's message to #am-corp-agent-chat via webhook."""
        from src.discord_bot.webhooks import get_webhook_client

        client = get_webhook_client()
        await client.post_agent_message(
            agent_id=self.agent_id,
            message=message,
            channel="agent_chat",
        )

    async def run_report(
        self,
        target: str,
        recon_result: "ReconResult | None" = None,
        vuln_result: "VulnScanResult | None" = None,
        intel_result: "IntelScanResult | None" = None,
    ) -> ReportResult:
        """
        Compile a full security assessment report from agent findings.

        Args:
            target: Scanned target hostname or IP
            recon_result: Randy's reconnaissance result
            vuln_result: Victor's vulnerability scan result
            intel_result: Ivy's intelligence result

        Returns:
            ReportResult with structured findings and executive summary
        """
        logger.info("Rita compiling report", target=target)

        await self._post_agent_chat_message(
            f"Pulling together the team's findings on {target}. Give me a moment to compile the report."
        )

        overall_risk = self._compute_overall_risk(vuln_result, intel_result)
        risk_items = self._build_risk_items(vuln_result, intel_result)
        intel_highlights = self._extract_intel_highlights(intel_result)

        open_ports: list[dict[str, Any]] = []
        if recon_result and recon_result.raw_findings.get("ports"):
            open_ports = recon_result.raw_findings["ports"][:15]

        vuln_counts: dict[str, int] = {}
        if vuln_result:
            vuln_counts = {
                "critical": vuln_result.critical_count,
                "high": vuln_result.high_count,
                "medium": vuln_result.medium_count,
                "low": vuln_result.low_count,
            }

        shodan_exposure = ""
        virustotal_status = ""
        if intel_result:
            if intel_result.shodan_result and not intel_result.shodan_result.error:
                s = intel_result.shodan_result
                shodan_exposure = f"{len(s.ports)} ports / {s.org or 'unknown'}"
            if intel_result.virustotal_result and not intel_result.virustotal_result.error:
                vt = intel_result.virustotal_result
                virustotal_status = (
                    f"{vt.malicious_count} malicious" if vt.malicious_count > 0 else "Clean"
                )

        executive_summary = await self._generate_executive_summary(
            target=target,
            overall_risk=overall_risk,
            recon_result=recon_result,
            vuln_result=vuln_result,
            intel_result=intel_result,
            risk_items=risk_items,
        )

        result = ReportResult(
            target=target,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            overall_risk=overall_risk,
            executive_summary=executive_summary,
            risk_items=risk_items,
            open_ports=open_ports,
            vuln_counts=vuln_counts,
            intel_highlights=intel_highlights,
            shodan_exposure=shodan_exposure,
            virustotal_status=virustotal_status,
        )

        audit_log(
            action="report_generated",
            user="rita_report",
            target=target,
            result="success",
            overall_risk=overall_risk,
            risk_items=len(risk_items),
        )

        await self._post_agent_chat_message(random.choice(POSTING_FALLBACKS))

        return result


_rita_instance: RitaReport | None = None


def get_rita() -> RitaReport:
    """Get or create the Rita Report singleton."""
    global _rita_instance
    if _rita_instance is None:
        _rita_instance = RitaReport()
    return _rita_instance
