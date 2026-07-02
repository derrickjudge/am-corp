"""
Crew kickoff functions.

HOW A CREW RUN WORKS:
  1. We build an Agent (who does the work) and a Task (what to do).
  2. We wrap them in a Crew and call kickoff_async() so the Discord bot's
     event loop stays free during the scan.
  3. The agent reasons, calls tools, reasons again, until done or max_iter.
  4. Each tool writes structured data to the findings store and posts a
     structured per-phase update to #agent-chat as it runs.
  5. We read results from the findings store (ground truth), not the LLM prose.

GRACEFUL DEGRADATION (important):
  In agentic mode the LLM is the orchestrator — it decides which tool to call
  next. If the LLM is rate-limited (HTTP 429 / quota exhausted) or unreachable
  (e.g. a local Ollama outage), the agent cannot reason and the crew aborts.
  Unlike the old hand-rolled pipeline, that would leave the scan with no
  results. So when kickoff fails on such an error we finish the phase
  DETERMINISTICALLY: run whichever lookups/scans the agent did not reach by
  awaiting the same do_*() phase functions directly. The scan still completes
  with structured findings, just without LLM-chosen ordering.

CHANNEL CONTRACT (see CLAUDE.md):
  - #thoughts   gets each agent's data-driven reasoning (pushed from tools).
  - #agent-chat gets the opening line, structured per-phase findings, and a
    closing recap that hands findings off to the next agent (Randy -> Victor,
    Victor -> Ivy).

SCOPE SAFETY:
  The scope check happens in bot.py before these functions are called; tools
  also validate their target. Belt and suspenders.
"""

import asyncio
import random
import uuid
from typing import Any

from crewai import Crew, Process, Task

from src.agents import (
    AGENT_IVY_INTEL,
    AGENT_RANDY_RECON,
    AGENT_RITA_REPORT,
    AGENT_VICTOR_VULN,
)
from src.agents.evolution import trigger_scan_completed
from src.agents.ivy_intel import OPENING_FALLBACKS as IVY_OPENING_FALLBACKS
from src.agents.ivy_intel import PARANOID_CLOSERS as IVY_PARANOID_CLOSERS
from src.agents.ivy_intel import SUMMARY_OPENERS as IVY_SUMMARY_OPENERS
from src.agents.ivy_intel import IntelScanResult, get_ivy
from src.agents.randy_recon import (
    OPENING_FALLBACKS,
    SUMMARY_CLOSERS,
    SUMMARY_OPENERS,
    ReconResult,
)
from src.agents.rita_report import ReportResult
from src.agents.victor_vuln import OPENING_FALLBACKS as VICTOR_OPENING_FALLBACKS
from src.agents.victor_vuln import SUMMARY_OPENERS as VICTOR_SUMMARY_OPENERS
from src.agents.victor_vuln import VulnScanResult
from src.crew import agents as agent_factory
from src.crew import intel_tools, narration, report_tools, vuln_tools
from src.crew import tools as recon_tools
from src.crew.agents import (
    IVY_CHARACTER,
    RANDY_CHARACTER,
    RITA_CHARACTER,
    VICTOR_CHARACTER,
)
from src.crew.findings import (
    IntelFindings,
    ReconFindings,
    ReportFindings,
    VulnFindings,
    clear_intel_run,
    clear_report_run,
    clear_run,
    clear_vuln_run,
    init_intel_run,
    init_report_run,
    init_run,
    init_vuln_run,
)
from src.crew.narration import start_drainer, stop_drainer
from src.crew.personality_chat import generate_agent_message
from src.crew.tools import set_event_loop, set_job_id
from src.discord_bot.agent_bots import (
    get_agent_manager,
    get_ivy_mention,
    get_rita_mention,
    get_victor_mention,
)
from src.tools.intel_tools import get_intel_capabilities
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)

# Discord single-message hard limit is 2000 chars; stay under with headroom.
_MAX_CHAT_CHARS = 1900


def _should_degrade(exc: Exception) -> bool:
    """
    True if the crew LLM is unavailable — quota exhausted (Gemini) OR the model
    server can't be reached (e.g. a local Ollama outage). In those cases we
    finish recon deterministically instead of failing the scan. Genuine bugs
    (e.g. ValueError, a coding error) return False so they re-raise.
    """
    text = str(exc).lower()
    quota = (
        "429" in text
        or "resource_exhausted" in text
        or "quota" in text
        or "rate limit" in text
        or "ratelimit" in text
    )
    unavailable = (
        "connection refused" in text
        or "connection error" in text
        or "apiconnectionerror" in text
        or "failed to connect" in text
        or "max retries" in text
        or "timed out" in text
        or "timeout" in text
        or "service unavailable" in text
        or "ollama" in text
    )
    return quota or unavailable


async def _post_as(agent_id: str, message: str) -> None:
    """Post a message to #agent-chat as the given agent (bot, else webhook)."""
    if len(message) > _MAX_CHAT_CHARS:
        message = message[: _MAX_CHAT_CHARS - 1].rstrip() + "…"
    await get_agent_manager().send_as_agent(agent_id, message, channel="agent_chat")


async def _complete_phases_deterministically(findings: ReconFindings) -> None:
    """
    Run any recon phases the agent did not reach, with no LLM involved.

    Used when the CrewAI kickoff aborts on a quota error. Awaits the same
    do_*() phase functions the tools use, so findings and #agent-chat output
    are identical to the agentic path.
    """
    target = findings.target
    if "dns" not in findings.completed:
        await recon_tools.do_dns(target)
    if "whois" not in findings.completed:
        await recon_tools.do_whois(target)
    if "ports" not in findings.completed:
        await recon_tools.do_ports(target)


async def _complete_vuln_phases_deterministically(findings: VulnFindings) -> None:
    """
    Run the vuln scan if the agent did not reach it, with no LLM involved.

    Used when the CrewAI kickoff aborts on a quota/LLM-unavailable error.
    Awaits do_nuclei_scan() directly so findings and #agent-chat output are
    identical to the agentic path.
    """
    if "nuclei" not in findings.completed:
        await vuln_tools.do_nuclei_scan(findings.target, findings.ports)


async def _complete_intel_phases_deterministically(
    findings: IntelFindings, capabilities: dict[str, bool]
) -> None:
    """
    Run any intel sources the agent did not reach, with no LLM involved.

    Unlike Randy/Victor's always-run phases, each of Ivy's sources is
    independently optional (gated on an API key and/or available CVEs/IPs),
    so this checks each source's precondition before running it. Called both
    on LLM-unavailable degradation and as the clean-run safety net, since a
    successful agentic run might still have skipped an available source.
    """
    if findings.cves and "cve" not in findings.completed:
        await intel_tools.do_cve_enrichment(findings.cves)
    if capabilities["shodan"] and findings.ips and "shodan" not in findings.completed:
        await intel_tools.do_shodan_lookup(findings.ips[0])
    if capabilities["virustotal"] and "virustotal" not in findings.completed:
        await intel_tools.do_virustotal_lookup(findings.target)
    if capabilities["securitytrails"] and "securitytrails" not in findings.completed:
        await intel_tools.do_securitytrails_lookup(findings.target)


async def _complete_report_phases_deterministically(findings: ReportFindings) -> None:
    """
    Compile the report if the agent did not reach it, with no LLM involved.

    Used when the CrewAI kickoff aborts on a quota/LLM-unavailable error, or
    as the clean-run safety net. Awaits do_compile_report() directly so the
    findings store ends up populated identically to the agentic path.
    """
    if "report" not in findings.completed:
        await report_tools.do_compile_report(
            findings.target,
            findings.recon_result,
            findings.vuln_result,
            findings.intel_result,
        )


async def run_crew_recon(target: str, verbose: bool = False) -> ReconResult:
    """
    Run Randy Recon as a CrewAI agent against the given target.

    Drop-in replacement for the hand-rolled run_recon(): returns the same
    ReconResult so callers don't change. Degrades to a deterministic recon
    if Gemini quota is exhausted (see module docstring).

    Args:
        target:  Hostname or IP to scan (must already be scope-verified).
        verbose: If True, surface more detail to the thoughts channel.

    Returns:
        ReconResult populated from the findings store.
    """
    loop = asyncio.get_running_loop()
    job_id = str(uuid.uuid4())[:8]

    logger.info("CrewAI recon starting", target=target, job_id=job_id)

    set_event_loop(loop)
    set_job_id(job_id)
    findings = init_run(job_id, target)
    start_drainer(loop)

    degraded = False
    try:
        # --- Opening message in Randy's voice -> #agent-chat
        tools_list = "dig (DNS), whois, and nmap"
        opening = await generate_agent_message(
            agent_id=AGENT_RANDY_RECON,
            character=RANDY_CHARACTER,
            prompt=(
                f"You're starting reconnaissance on {target}. Write a short, "
                "friendly opening message (1-2 sentences) announcing you're "
                "starting the job and that you'll use "
                f"{tools_list}. Vary your greeting."
            ),
            fallback=random.choice(OPENING_FALLBACKS).format(
                target=target, tools=tools_list
            ),
        )
        await _post_as(AGENT_RANDY_RECON, opening)

        # --- Build the Agent and Task. The display is rendered from findings,
        #     so the task only needs to drive the tool calls — keep the
        #     expected_output tiny to minimise the final-answer token spend.
        randy = agent_factory.build_randy(target=target)
        task = Task(
            description=(
                f"Perform a complete reconnaissance assessment of '{target}'.\n"
                "Use your tools to: (1) run a DNS lookup, (2) run a WHOIS lookup, "
                "(3) run a port scan. Run all three."
            ),
            expected_output=(
                "A one-line confirmation that DNS, WHOIS, and the port scan were run."
            ),
            agent=randy,
        )
        crew = Crew(
            agents=[randy],
            tasks=[task],
            process=Process.sequential,
            verbose=verbose,
        )

        try:
            await crew.kickoff_async(inputs={"target": target})
        except Exception as e:
            if not _should_degrade(e):
                raise
            # LLM unavailable (quota exhausted or model server unreachable): the
            # agent can't orchestrate. Finish the recon deterministically so the
            # scan still produces structured findings.
            degraded = True
            logger.warning(
                "CrewAI kickoff could not reach the LLM; completing recon degraded",
                target=target,
                job_id=job_id,
                error=str(e)[:200],
            )
            await _post_as(
                AGENT_RANDY_RECON,
                "Well, my thinkin' cap's not cooperatin' right now (LLM's offline), so "
                "I'll run the rest of this by the book without the fancy reasoning.",
            )
            await _complete_phases_deterministically(findings)

        # Safety net: fill any phase the agent skipped even on a clean run.
        if not degraded and len(findings.completed) < 3:
            await _complete_phases_deterministically(findings)

        # Let queued per-phase messages and thoughts post before the recap.
        await narration.flush()

        # --- Closing recap -> #agent-chat (deterministic, structured)
        port_count = findings.open_port_count
        dns_count = sum(len(v) for v in findings.dns_records.values())
        whois_status = (
            "got the registration details"
            if findings.whois_info
            else "WHOIS came up empty"
        )
        port_status = (
            f"found {port_count} open port{'s' if port_count != 1 else ''}"
            if port_count
            else "didn't find any open ports on the common ones"
        )
        recap = (
            f"{random.choice(SUMMARY_OPENERS).format(target=target)}\n\n"
            f"Rounded up {dns_count} DNS record{'s' if dns_count != 1 else ''}, "
            f"{whois_status}, and {port_status}."
        )
        if port_count:
            recap += f" {get_victor_mention()}, some services here for you to dig into."
        recap += f"\n\n{random.choice(SUMMARY_CLOSERS)}"
        await _post_as(AGENT_RANDY_RECON, recap)

    except Exception as e:
        logger.error("CrewAI recon failed", target=target, job_id=job_id, error=str(e))
        audit_log(
            action="crew_recon_failed",
            user="randy_recon",
            target=target,
            result="error",
        )
        clear_run(job_id)
        raise
    finally:
        stop_drainer()

    raw_findings = {
        "ports": findings.ports,
        "dns_records": findings.dns_records,
        "whois_info": findings.whois_info,
    }
    port_count = findings.open_port_count

    audit_log(
        action="crew_recon_completed",
        user="randy_recon",
        target=target,
        result="degraded" if degraded else "success",
        port_count=port_count,
    )

    await trigger_scan_completed(
        agent_id=AGENT_RANDY_RECON,
        target=target,
        success=True,
        findings_count=port_count,
    )

    clear_run(job_id)

    return ReconResult(
        target=target,
        raw_findings=raw_findings,
        summary=f"Recon complete on {target}. {port_count} open port(s) found.",
    )


async def run_crew_vuln(
    target: str,
    ports: list[dict[str, Any]] | None = None,
    verbose: bool = False,
) -> VulnScanResult:
    """
    Run Victor Vuln as a CrewAI agent against the given target.

    Drop-in replacement for VictorVuln.run_vuln_scan(): returns the same
    VulnScanResult so callers don't change. Degrades to a deterministic scan
    if the crew LLM is unavailable (see module docstring).

    Args:
        target:  Hostname or IP to scan (must already be scope-verified).
        ports:   Open ports from Randy's recon, if any — drives smart template
                 selection. Empty/None falls back to broad default templates.
        verbose: If True, surface more detail to the thoughts channel.

    Returns:
        VulnScanResult populated from the findings store.
    """
    ports = ports or []
    loop = asyncio.get_running_loop()
    job_id = str(uuid.uuid4())[:8]

    logger.info("CrewAI vuln scan starting", target=target, job_id=job_id)

    vuln_tools.set_event_loop(loop)
    vuln_tools.set_job_id(job_id)
    findings = init_vuln_run(job_id, target, ports)
    start_drainer(loop)

    degraded = False
    try:
        # --- Opening message in Victor's voice -> #agent-chat
        ports_info = (
            f" I see {len(ports)} open ports from Randy's recon - I'll focus on those."
            if ports
            else ""
        )
        opening = await generate_agent_message(
            agent_id=AGENT_VICTOR_VULN,
            character=VICTOR_CHARACTER,
            prompt=(
                f"You're starting a vulnerability scan on {target}.{ports_info} "
                "Write a short, confident opening message (1-2 sentences) with "
                "your usual energy. Vary your greeting."
            ),
            fallback=random.choice(VICTOR_OPENING_FALLBACKS).format(
                target=target, ports_info=ports_info
            ),
        )
        await _post_as(AGENT_VICTOR_VULN, opening)

        # --- Build the Agent and Task. The display is rendered from findings,
        #     so the task only needs to drive the tool call — keep the
        #     expected_output tiny to minimise the final-answer token spend.
        victor = agent_factory.build_victor(target=target)
        task = Task(
            description=(
                f"Run a vulnerability scan of '{target}' using your Nuclei scanner "
                "tool. Call it exactly once."
            ),
            expected_output="A one-line confirmation that the vulnerability scan ran.",
            agent=victor,
        )
        crew = Crew(
            agents=[victor],
            tasks=[task],
            process=Process.sequential,
            verbose=verbose,
        )

        try:
            await crew.kickoff_async(inputs={"target": target})
        except Exception as e:
            if not _should_degrade(e):
                raise
            # LLM unavailable (quota exhausted or model server unreachable): the
            # agent can't orchestrate. Finish the scan deterministically so it
            # still produces structured findings.
            degraded = True
            logger.warning(
                "CrewAI kickoff could not reach the LLM; completing vuln scan degraded",
                target=target,
                job_id=job_id,
                error=str(e)[:200],
            )
            await _post_as(
                AGENT_VICTOR_VULN,
                "Ngl my brain's offline right now (LLM's down), running this the "
                "old-fashioned way.",
            )
            await _complete_vuln_phases_deterministically(findings)

        # Safety net: fill the phase if the agent skipped it even on a clean run.
        if not degraded and "nuclei" not in findings.completed:
            await _complete_vuln_phases_deterministically(findings)

        # Let queued per-phase messages and thoughts post before the recap.
        await narration.flush()

        # --- Closing recap -> #agent-chat (deterministic, structured)
        total = len(findings.findings)
        opener = random.choice(VICTOR_SUMMARY_OPENERS).format(target=target)
        if total == 0:
            recap = f"{opener}\n\nClean scan, no known vulnerabilities detected."
        else:
            recap = (
                f"{opener}\n\n"
                f"Found {total} issue{'s' if total != 1 else ''}: "
                f"{findings.critical_count} critical, {findings.high_count} high, "
                f"{findings.medium_count} medium."
            )
            if findings.cve_ids:
                recap += (
                    f" {get_ivy_mention()}, can you check threat intel on these CVEs?"
                )
            if findings.critical_count or findings.high_count:
                recap += f" {get_rita_mention()}, got some findings for the report."
        await _post_as(AGENT_VICTOR_VULN, recap)

    except Exception as e:
        logger.error(
            "CrewAI vuln scan failed", target=target, job_id=job_id, error=str(e)
        )
        audit_log(
            action="crew_vuln_failed",
            user="victor_vuln",
            target=target,
            result="error",
        )
        clear_vuln_run(job_id)
        raise
    finally:
        stop_drainer()

    audit_log(
        action="crew_vuln_completed",
        user="victor_vuln",
        target=target,
        result="degraded" if degraded else "success",
        critical=findings.critical_count,
        high=findings.high_count,
        medium=findings.medium_count,
    )

    await trigger_scan_completed(
        agent_id=AGENT_VICTOR_VULN,
        target=target,
        success=True,
        findings_count=len(findings.findings),
    )

    result = VulnScanResult(
        target=target,
        summary=(
            f"Vuln scan complete on {target}. {findings.critical_count} critical, "
            f"{findings.high_count} high, {findings.medium_count} medium finding(s)."
        ),
        critical_count=findings.critical_count,
        high_count=findings.high_count,
        medium_count=findings.medium_count,
        low_count=findings.low_count,
        info_count=findings.info_count,
        all_findings=findings.findings,
    )

    clear_vuln_run(job_id)

    return result


async def run_crew_intel(
    target: str,
    vuln_findings: list[dict[str, Any]] | None = None,
    verbose: bool = False,
) -> IntelScanResult:
    """
    Run Ivy Intel as a CrewAI agent against the given target.

    Drop-in replacement for IvyIntelAgent.run_intel(): returns the same
    IntelScanResult so callers don't change. Degrades to deterministic lookups
    if the crew LLM is unavailable (see module docstring).

    Args:
        target:        Hostname or IP to enrich (must already be scope-verified).
        vuln_findings: Victor's raw findings, used to extract CVE IDs and IPs
                       to enrich (same extraction logic as the hand-rolled path).
        verbose:       If True, surface more detail to the thoughts channel.

    Returns:
        IntelScanResult populated from the findings store.
    """
    cves: list[str] = []
    ips: list[str] = []
    if vuln_findings:
        ivy_agent = get_ivy()
        cves = ivy_agent._extract_cves_from_findings(vuln_findings)
        ips = ivy_agent._extract_ips_from_findings(vuln_findings)

    loop = asyncio.get_running_loop()
    job_id = str(uuid.uuid4())[:8]

    logger.info("CrewAI intel gathering starting", target=target, job_id=job_id)

    intel_tools.set_event_loop(loop)
    intel_tools.set_job_id(job_id)
    findings = init_intel_run(job_id, target, cves=cves, ips=ips)
    start_drainer(loop)

    capabilities = get_intel_capabilities()
    available_sources = ["CVE enrichment", "EPSS scores"]
    if capabilities["shodan"] and ips:
        available_sources.append("Shodan")
    if capabilities["virustotal"]:
        available_sources.append("VirusTotal")
    if capabilities["securitytrails"]:
        available_sources.append("SecurityTrails")

    degraded = False
    try:
        # --- Opening message in Ivy's voice -> #agent-chat
        opening = await generate_agent_message(
            agent_id=AGENT_IVY_INTEL,
            character=IVY_CHARACTER,
            prompt=(
                f"You're starting threat intelligence gathering on {target}. "
                f"Available sources: {', '.join(available_sources)}. Write a "
                "short opening message (1-2 sentences) with your British accent "
                "and slight paranoia. Vary your greeting."
            ),
            fallback=random.choice(IVY_OPENING_FALLBACKS).format(target=target),
        )
        await _post_as(AGENT_IVY_INTEL, opening)

        # --- Build the Agent and Task. The task description tells the LLM
        #     which sources are actually available, so it doesn't waste a
        #     tool call on one that will just report "not configured".
        ivy = agent_factory.build_ivy(target=target)
        task_lines = [f"Gather threat intelligence on '{target}'."]
        if cves:
            task_lines.append(f"Enrich the {len(cves)} known CVE(s) with the CVE tool.")
        if capabilities["shodan"] and ips:
            task_lines.append("Check Shodan for exposure history.")
        if capabilities["virustotal"]:
            task_lines.append("Check VirusTotal for reputation data.")
        if capabilities["securitytrails"]:
            task_lines.append("Check SecurityTrails for subdomain/attack-surface data.")
        task = Task(
            description="\n".join(task_lines),
            expected_output=(
                "A one-line confirmation of which intel sources were checked."
            ),
            agent=ivy,
        )
        crew = Crew(
            agents=[ivy],
            tasks=[task],
            process=Process.sequential,
            verbose=verbose,
        )

        try:
            await crew.kickoff_async(inputs={"target": target})
        except Exception as e:
            if not _should_degrade(e):
                raise
            # LLM unavailable (quota exhausted or model server unreachable): the
            # agent can't orchestrate. Finish the lookups deterministically so
            # the scan still produces structured findings.
            degraded = True
            logger.warning(
                "CrewAI kickoff could not reach the LLM; completing intel degraded",
                target=target,
                job_id=job_id,
                error=str(e)[:200],
            )
            await _post_as(
                AGENT_IVY_INTEL,
                "Right, my thinkin' cap's offline (LLM's down) — running the "
                "checks the old-fashioned way.",
            )

        # Safety net: fill any available source the agent skipped, whether
        # degraded or on a clean run (each source is independently optional).
        await _complete_intel_phases_deterministically(findings, capabilities)

        # Let queued per-phase messages and thoughts post before the recap.
        await narration.flush()

        # --- Closing recap -> #agent-chat (deterministic, structured)
        opener = random.choice(IVY_SUMMARY_OPENERS).format(target=target)
        closer = random.choice(IVY_PARANOID_CLOSERS)
        parts = []
        if findings.cve_enrichments:
            parts.append(
                f"{len(findings.cve_enrichments)} CVE(s) enriched, "
                f"{findings.high_risk_cve_count} high-risk"
            )
        if findings.shodan_result and not findings.shodan_result.error:
            parts.append(f"Shodan: {len(findings.shodan_result.ports)} exposed port(s)")
        if findings.virustotal_result and not findings.virustotal_result.error:
            vt = findings.virustotal_result
            parts.append(
                "VirusTotal: clean"
                if vt.malicious_count == 0
                else f"VirusTotal: {vt.malicious_count} malicious"
            )
        if findings.securitytrails_result and not findings.securitytrails_result.error:
            st_count = findings.securitytrails_result.subdomain_count
            parts.append(f"SecurityTrails: {st_count} subdomain(s)")
        context = "; ".join(parts) if parts else "Limited intel available"
        recap = (
            f"{opener}\n\n**Summary:** {context}\n\n"
            f"{get_rita_mention()}, got context for your report. {closer}"
        )
        await _post_as(AGENT_IVY_INTEL, recap)

    except Exception as e:
        logger.error(
            "CrewAI intel gathering failed", target=target, job_id=job_id, error=str(e)
        )
        audit_log(
            action="crew_intel_failed",
            user="ivy_intel",
            target=target,
            result="error",
        )
        clear_intel_run(job_id)
        raise
    finally:
        stop_drainer()

    findings_count = (
        len(findings.cve_enrichments)
        + (1 if findings.shodan_result else 0)
        + (1 if findings.virustotal_result else 0)
    )

    audit_log(
        action="crew_intel_completed",
        user="ivy_intel",
        target=target,
        result="degraded" if degraded else "success",
        cves_enriched=len(findings.cve_enrichments),
    )

    await trigger_scan_completed(
        agent_id=AGENT_IVY_INTEL,
        target=target,
        success=True,
        findings_count=findings_count,
    )

    result = IntelScanResult(
        target=target,
        cve_enrichments=findings.cve_enrichments,
        shodan_result=findings.shodan_result,
        virustotal_result=findings.virustotal_result,
        securitytrails_result=findings.securitytrails_result,
        summary=(
            f"Intel gathering complete on {target}. "
            f"{findings_count} finding(s) enriched."
        ),
        raw_findings={
            "cves_enriched": len(findings.cve_enrichments),
            "shodan_available": findings.shodan_result is not None
            and not findings.shodan_result.error,
            "virustotal_available": findings.virustotal_result is not None
            and not findings.virustotal_result.error,
            "securitytrails_available": findings.securitytrails_result is not None
            and not findings.securitytrails_result.error,
            "capabilities": capabilities,
        },
    )

    clear_intel_run(job_id)

    return result


async def run_crew_report(
    target: str,
    recon_result: ReconResult | None = None,
    vuln_result: VulnScanResult | None = None,
    intel_result: IntelScanResult | None = None,
    verbose: bool = False,
) -> ReportResult:
    """
    Run Rita Report as a CrewAI agent to compile the team's findings.

    Drop-in replacement for RitaReport.run_report(): returns the same
    ReportResult so callers don't change. Degrades to a deterministic compile
    if the crew LLM is unavailable (see module docstring).

    Rita has exactly one tool (see report_tools.py's module docstring), so
    this mirrors the other run_crew_*() functions structurally but has no
    per-source safety-net branching — just one phase to complete.

    Args:
        target:       Hostname or IP the report covers.
        recon_result: Randy's reconnaissance result, if available.
        vuln_result:  Victor's vulnerability scan result, if available.
        intel_result: Ivy's intelligence result, if available.
        verbose:      If True, surface more detail to the thoughts channel.

    Returns:
        ReportResult populated from the findings store.
    """
    loop = asyncio.get_running_loop()
    job_id = str(uuid.uuid4())[:8]

    logger.info("CrewAI report compilation starting", target=target, job_id=job_id)

    report_tools.set_event_loop(loop)
    report_tools.set_job_id(job_id)
    findings = init_report_run(job_id, target, recon_result, vuln_result, intel_result)
    start_drainer(loop)

    degraded = False
    try:
        # --- Opening message in Rita's voice -> #agent-chat
        opening = await generate_agent_message(
            agent_id=AGENT_RITA_REPORT,
            character=RITA_CHARACTER,
            prompt=(
                f"You're about to compile the team's findings on {target} into "
                "a report. Write a short opening message (1 sentence) letting "
                "the team know you're on it."
            ),
            fallback=(
                f"Pulling together the team's findings on {target}. "
                "Give me a moment to compile the report."
            ),
        )
        await _post_as(AGENT_RITA_REPORT, opening)

        # --- Build the Agent and Task. Rita has exactly one tool to call.
        rita = agent_factory.build_rita(target=target)
        task = Task(
            description=(
                f"Compile a security assessment report for '{target}' by "
                "calling your report tool once."
            ),
            expected_output="A one-line confirmation the report was compiled.",
            agent=rita,
        )
        crew = Crew(
            agents=[rita],
            tasks=[task],
            process=Process.sequential,
            verbose=verbose,
        )

        try:
            await crew.kickoff_async(inputs={"target": target})
        except Exception as e:
            if not _should_degrade(e):
                raise
            # LLM unavailable (quota exhausted or model server unreachable): the
            # agent can't orchestrate. Compile the report deterministically.
            degraded = True
            logger.warning(
                "CrewAI kickoff could not reach the LLM; compiling report degraded",
                target=target,
                job_id=job_id,
                error=str(e)[:200],
            )
            await _complete_report_phases_deterministically(findings)

        # Safety net: the agent should always call its one tool, but cover the
        # edge case where it doesn't.
        if not degraded and "report" not in findings.completed:
            await _complete_report_phases_deterministically(findings)

        await narration.flush()

    except Exception as e:
        logger.error(
            "CrewAI report compilation failed",
            target=target,
            job_id=job_id,
            error=str(e),
        )
        audit_log(
            action="crew_report_failed",
            user="rita_report",
            target=target,
            result="error",
        )
        clear_report_run(job_id)
        raise
    finally:
        stop_drainer()

    if findings.report is None:
        raise RuntimeError(f"Report compilation did not produce a result for {target}")
    report = findings.report

    audit_log(
        action="crew_report_completed",
        user="rita_report",
        target=target,
        result="degraded" if degraded else "success",
        overall_risk=report.overall_risk,
        risk_items=len(report.risk_items),
    )

    clear_report_run(job_id)

    return report
