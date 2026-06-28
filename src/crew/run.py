"""
Crew kickoff functions.

HOW A CREW RUN WORKS:
  1. We build an Agent (who does the work) and a Task (what to do).
  2. We wrap them in a Crew and call kickoff_async().
  3. kickoff_async() runs the crew in a thread pool so the Discord
     bot's event loop stays free to handle other commands during the scan.
  4. The agent reasons, calls tools, reasons again, until it decides
     the task is done or hits max_iter.
  5. When done, we read structured results from the findings store
     (not from parsing the LLM's prose) and return them.

SCOPE SAFETY:
  The scope check happens in bot.py before this function is called.
  Tools also validate their target (inherited from the existing recon
  tools). Belt and suspenders.
"""

import asyncio
import uuid

from crewai import Crew, Process, Task

from src.agents.evolution import trigger_scan_completed
from src.agents.randy_recon import ReconResult
from src.crew import agents as agent_factory
from src.crew.findings import clear_run, get_findings, init_run
from src.crew.narration import setup_narration, start_drainer, stop_drainer
from src.crew.tools import set_event_loop, set_job_id
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


async def run_crew_recon(target: str, verbose: bool = False) -> ReconResult:
    """
    Run Randy Recon as a CrewAI agent against the given target.

    This is a drop-in replacement for the hand-rolled run_recon().
    It returns the same ReconResult dataclass so callers don't need
    to change — only the internal pipeline is different.

    Args:
        target:  Hostname or IP to scan (must already be scope-verified).
        verbose: If True, post more detailed narration to thoughts channel.

    Returns:
        ReconResult populated from the findings store.
    """
    loop = asyncio.get_running_loop()
    job_id = str(uuid.uuid4())[:8]  # short ID for log readability

    logger.info("CrewAI recon starting", target=target, job_id=job_id)

    # --- Setup: register loop + job_id so tools can bridge async calls
    #     and write to the findings store
    set_event_loop(loop)
    set_job_id(job_id)
    findings = init_run(job_id, target)

    # --- Narration: build callbacks and start the Discord drainer
    step_cb, task_cb = setup_narration(loop, agent_id="randy_recon")
    start_drainer(loop)

    try:
        # --- Build the Agent with personality and tools
        randy = agent_factory.build_randy(
            target=target,
            step_callback=step_cb,
            task_callback=task_cb,
        )

        # --- Define the Task
        # description: what the agent must accomplish (seen by the LLM)
        # expected_output: what a complete, correct result looks like
        #   (the LLM uses this to know when it's done)
        task = Task(
            description=(
                f"Perform a complete reconnaissance assessment of '{target}'.\n"
                "You must:\n"
                "1. Run a DNS lookup to gather all DNS records.\n"
                "2. Run a WHOIS lookup to identify the registrant and registration info.\n"
                "3. Run a port scan to identify all open ports and services.\n"
                "Report your findings clearly. Note any services that stand out as "
                "unusual or potentially risky."
            ),
            expected_output=(
                "A structured recon report containing: "
                "all DNS records found, WHOIS registrant info, "
                "a complete list of open ports with service names and versions, "
                "and a brief assessment of anything notable."
            ),
            agent=randy,
        )

        # --- Assemble the Crew and run it
        # Process.sequential is the right choice for a single-agent crew.
        # For multi-agent crews (Phase C) we keep sequential so each agent
        # can see the previous agent's output.
        crew = Crew(
            agents=[randy],
            tasks=[task],
            process=Process.sequential,
            verbose=verbose,
        )

        # kickoff_async() runs the crew without blocking the Discord event loop
        await crew.kickoff_async(inputs={"target": target})

    except Exception as e:
        logger.error("CrewAI recon failed", target=target, job_id=job_id, error=str(e))
        audit_log(action="crew_recon_failed", user="randy_recon", target=target, result="error")
        raise
    finally:
        stop_drainer()

    # --- Read structured results from the findings store
    # We trust the store over the LLM's prose output
    raw_findings = {
        "ports": findings.ports,
        "dns_records": findings.dns_records,
        "whois_info": findings.whois_info,
    }

    audit_log(
        action="crew_recon_completed",
        user="randy_recon",
        target=target,
        result="success",
        port_count=findings.open_port_count,
    )

    # Trigger personality evolution (same as hand-rolled path)
    await trigger_scan_completed(
        agent_id="randy_recon",
        target=target,
        success=True,
        findings_count=findings.open_port_count,
    )

    clear_run(job_id)

    # Return the same ReconResult the hand-rolled path returns
    # so bot.py doesn't need to change when USE_CREWAI is flipped on
    from src.tools.recon_tools import ToolResult
    return ReconResult(
        target=target,
        raw_findings=raw_findings,
        summary=f"CrewAI recon complete. {findings.open_port_count} open port(s) found.",
    )
