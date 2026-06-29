# CrewAI Agent Conversion — Pattern Reference

Canonical patterns distilled from the Randy Recon conversion. Copy these
shapes; adapt names/fields to the new agent. Randy's files are the live
reference — read them alongside this.

## Architecture in one paragraph

The CrewAI **LLM is the orchestrator** — it decides which tool to call. Tools
run **synchronously** in a CrewAI worker thread; our real tools and Discord are
**async**. Each phase is one `do_*()` async function that does the real work,
writes structured data to a **run-scoped findings store** (ground truth), and
posts a **deterministic, structured** message to #agent-chat. The `@tool`
wrapper calls `do_*()` through the sync→async bridge; the **degraded fallback**
awaits it directly. Display is rendered from findings, never from LLM prose, so
it stays tidy and survives a quota outage.

## The five hard-won rules

1. **Never let a 429 abort the scan.** Agentic mode dies if the LLM is
   unavailable. Catch quota errors and finish deterministically.
2. **Findings store is ground truth.** Downstream/handoffs/reports read it,
   not the LLM's text.
3. **One `do_*()`, two callers** (tool wrapper + fallback). No duplicated logic.
4. **Channel contract:** #thoughts = reasoning (`_think`), #agent-chat =
   personality + handoffs (`_chat`), #commands = embeds, #results = reports.
5. **Personality = backstory (fixed character + live YAML) + fallback pools**
   for short beats, so it degrades to deterministic voice at zero quota.

## Template: findings dataclass (`src/crew/findings.py`)

```python
@dataclass
class VulnFindings:
    target: str
    cve_ids: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    completed: set[str] = field(default_factory=set)  # phases attempted

    def set_findings(self, items: list[dict[str, Any]]) -> None:
        self.findings = items
        self.completed.add("nuclei")

# Reuse the same _store dict + init_run/get_findings/clear_run, or key by job_id
# with a separate store per agent. Keep init_run returning the typed object.
```

## Template: phase function + tool wrapper (`src/crew/tools.py` or `<agent>_tools.py`)

```python
async def do_nuclei(target: str, ports: list[dict]) -> str:
    """Run nuclei: write findings, post structured chat + thoughts, return LLM text."""
    _think("Selecting templates based on the open ports Randy found…", category="reasoning")
    templates = select_templates_for_ports(ports)          # reuse existing logic
    result = await nuclei_scan(target, templates=templates)
    if not result.success:
        _think(f"Nuclei scan failed: {result.error}", category="detail")
        _chat(f"Vuln scan on {target} hit a snag: {result.error}")
        return f"Vuln scan failed: {result.error}"
    items = result.parsed_data.get("findings", [])
    store = _store_findings()
    if store:
        store.set_findings(items)
    # deterministic structured #agent-chat message (bulleted), pool for voice
    _chat(_render_vuln_message(target, items))
    # analytical #thoughts for notable items
    for f in items:
        if f.get("severity") in ("critical", "high"):
            _think(f"{f['severity'].upper()}: {f.get('name')} ({f.get('cve_id','')})",
                   category="finding", confidence=0.85)
    return _summarize_for_llm(items)

@tool("Nuclei Scanner")
def nuclei_tool(target: str) -> str:
    """<LLM-facing docstring: when to use, what it returns>."""
    ports = _ports_from_findings()          # pull upstream ground truth
    return _run_async(do_nuclei(target, ports), timeout=600)
```

Keep `set_event_loop`, `set_job_id`, `_run_async`, `_think`, `_chat`,
`_store_findings` identical to Randy's. If you make a separate `<agent>_tools.py`,
either import these from a shared `crew/context.py` or duplicate the tiny set.

## Template: agent factory (`src/crew/agents.py`)

```python
VICTOR_CHARACTER = """You are Victor Vuln… <full personality, voice, rules —
as rich as the hand-rolled system prompt>"""

def build_victor(target: str) -> Agent:
    ctx = get_personality_manager().get_prompt_context(AGENT_VICTOR_VULN)
    return Agent(
        role="Vulnerability Assessment Specialist",
        goal=f"Identify and triage vulnerabilities on '{target}'.",
        backstory=f"{VICTOR_CHARACTER}\n\n{ctx}",
        tools=get_vuln_tools(),
        llm=get_llm(),
        max_rpm=10, max_iter=8, verbose=True,
    )
```

## Template: run function (`src/crew/run.py`)

Mirror `run_crew_recon` exactly. Skeleton:

```python
async def run_crew_vuln(target: str, ports: list[dict], verbose: bool = False) -> VulnScanResult:
    loop = asyncio.get_running_loop(); job_id = str(uuid.uuid4())[:8]
    set_event_loop(loop); set_job_id(job_id)
    findings = init_vuln_run(job_id, target, ports); start_drainer(loop)
    degraded = False
    try:
        await _post_as(AGENT_VICTOR_VULN, opening)        # pool fallback at zero quota
        crew = Crew(agents=[build_victor(target)], tasks=[task], process=Process.sequential)
        try:
            await crew.kickoff_async(inputs={"target": target})
        except Exception as e:
            if not _is_quota_error(e): raise
            degraded = True
            await _post_as(AGENT_VICTOR_VULN, "<quota note>")
            await _complete_vuln_phases_deterministically(findings)
        if not degraded and "<phases incomplete>":
            await _complete_vuln_phases_deterministically(findings)
        await narration.flush()
        await _post_as(AGENT_VICTOR_VULN, structured_recap)   # + Ivy handoff if findings
    except Exception as e:
        logger.error(...); audit_log(result="error"); clear_run(job_id); raise
    finally:
        stop_drainer()
    # build result from findings store; trigger evolution; clear_run; return
```

`_is_quota_error`, `_post_as_randy`/`_post_as`, `narration.flush`,
`_complete_phases_deterministically` already exist for Randy — generalize or copy.

## Template: bot.py wiring

```python
if settings.use_crewai:
    from src.crew.run import run_crew_vuln
    vuln_result = await run_crew_vuln(target, ports=ports, verbose=verbose)
else:
    vuln_result = await get_victor().run_vuln_scan(target, ports=ports, verbose=verbose)
```

Keep the existing handoff calls (`run_handoff(HandoffContext(...))`) at phase
boundaries; data still flows via Python return values / the findings store.

## Verification checklist

- [ ] `ast.parse` each changed file.
- [ ] Container rebuild + `from src.crew import run, tools, agents` import-check.
- [ ] Degraded path completes with structured findings (simulate by forcing a
      quota error or temporarily raising in kickoff).
- [ ] #thoughts vs #agent-chat content lands in the right channel.
- [ ] Handoff fires to the next agent with a real @mention.
- [ ] Rigor `demo`+: pytest/mypy/ruff pass; tests cover the findings dataclass,
      `do_*()` with tools mocked, quota detection, and message formatting.
- [ ] `CLAUDE.md` Phase Status + Agent Roster updated.
- [ ] No `Any`, explicit error handling, docstrings + type hints present.
```
