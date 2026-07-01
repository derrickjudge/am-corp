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
  next. If Gemini is rate-limited (HTTP 429 / quota exhausted), the agent
  cannot reason and the crew aborts. Unlike the old hand-rolled pipeline, that
  would leave the scan with no results. So when kickoff fails on a quota error
  we finish the recon DETERMINISTICALLY: run whichever lookups the agent did
  not reach by awaiting the same do_*() phase functions directly. The recon
  still completes with structured findings, just without LLM-chosen ordering.

CHANNEL CONTRACT (see CLAUDE.md):
  - #thoughts   gets Randy's data-driven reasoning (pushed from the tools).
  - #agent-chat gets the opening line, structured per-phase findings, and a
    closing recap that hands open ports off to Victor.

SCOPE SAFETY:
  The scope check happens in bot.py before this function is called; tools also
  validate their target. Belt and suspenders.
"""

import asyncio
import random
import uuid

from crewai import Crew, Process, Task

from src.agents import AGENT_RANDY_RECON
from src.agents.evolution import trigger_scan_completed
from src.agents.randy_recon import (
    OPENING_FALLBACKS,
    SUMMARY_CLOSERS,
    SUMMARY_OPENERS,
    ReconResult,
)
from src.crew import agents as agent_factory
from src.crew import narration
from src.crew import tools as recon_tools
from src.crew.agents import RANDY_CHARACTER
from src.crew.findings import clear_run, init_run
from src.crew.narration import start_drainer, stop_drainer
from src.crew.personality_chat import generate_agent_message
from src.crew.tools import set_event_loop, set_job_id
from src.discord_bot.agent_bots import get_agent_manager, get_victor_mention
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)

# Discord single-message hard limit is 2000 chars; stay under with headroom.
_MAX_CHAT_CHARS = 1900


def _is_quota_error(exc: Exception) -> bool:
    """True if the exception is a Gemini rate-limit / quota-exhausted error."""
    text = str(exc).lower()
    return (
        "429" in text
        or "resource_exhausted" in text
        or "quota" in text
        or "rate limit" in text
        or "ratelimit" in text
    )


async def _post_as_randy(message: str) -> None:
    """Post a message to #agent-chat as Randy (agent bot if available, else webhook)."""
    if len(message) > _MAX_CHAT_CHARS:
        message = message[: _MAX_CHAT_CHARS - 1].rstrip() + "…"
    await get_agent_manager().send_as_agent(
        AGENT_RANDY_RECON, message, channel="agent_chat"
    )


async def _complete_phases_deterministically(findings) -> None:
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
        await _post_as_randy(opening)

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
            if not _is_quota_error(e):
                raise
            # Quota exhausted: the agent can't orchestrate. Finish the recon
            # deterministically so the scan still produces structured findings.
            degraded = True
            logger.warning(
                "CrewAI kickoff hit quota limit; completing recon deterministically",
                target=target,
                job_id=job_id,
            )
            await _post_as_randy(
                "Well, my thinkin' cap's tapped out for now (LLM quota's dry), so I'll "
                "run the rest of this by the book without the fancy reasoning."
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
        await _post_as_randy(recap)

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
