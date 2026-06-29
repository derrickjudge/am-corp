---
name: new-crew-agent
description: Interview the user and scaffold a new CrewAI agent for AM-Corp (e.g. converting Victor Vuln or Ivy Intel to the agentic pipeline, or adding a brand-new agent). Use when the user wants to add or convert an agent in src/crew/. Follows the canonical Randy Recon pattern: do_*() phase functions, findings store, deterministic structured display, graceful quota degradation, and the channel contract.
---

# New CrewAI Agent Builder

You are scaffolding a new CrewAI agent for AM-Corp. Randy Recon
(`src/crew/{tools,agents,run,findings,narration}.py`) is the reference
implementation — read it before generating anything. Honor every pattern in
`reference.md` in this skill directory; it encodes lessons learned the hard way.

## Step 1 — Ground yourself (do this first, no questions yet)

Read these so the scaffold matches reality:
- `src/crew/tools.py` — the `do_*()` + `@tool` wrapper pattern, the sync↔async
  bridge (`_run_async`), and `_think`/`_chat` helpers.
- `src/crew/run.py` — `run_crew_recon`: opening message, kickoff, the
  `_is_quota_error` guard, `_complete_phases_deterministically`, structured
  closing recap, evolution trigger.
- `src/crew/agents.py` — `build_randy`: character constant + live YAML backstory.
- `src/crew/findings.py` — the run-scoped ground-truth store with a `completed` set.
- `src/discord_bot/bot.py` — `start_scan`, where `settings.use_crewai` branches.
- `src/discord_bot/handoffs.py` — `run_handoff` / `HandoffContext`.
- The target agent's existing hand-rolled module (`src/agents/<agent>.py`) and
  its tools (`src/tools/<agent>_tools.py`) — reuse this logic, never rewrite it.
- The project's `CLAUDE.md` — note the declared **Rigor** level. It decides
  whether tests are required: `demo` and above require them; `poc` defers them
  (and you must say so). am-corp is currently `demo`.

Existing agent IDs: `randy_recon`, `victor_vuln`, `ivy_intel`, `rita_report`
(see `src/agents/__init__.py`). Existing tool functions:
- Vuln: `nuclei_scan`, `select_templates_for_ports`, `scan_service_by_port`
  (`src/tools/vuln_tools.py`)
- Intel: `lookup_cve`, `lookup_epss`, `lookup_multiple_cves`,
  `shodan_host_lookup`, `virustotal_lookup`, `securitytrails_lookup`
  (`src/tools/intel_tools.py`)

## Step 2 — Interview the user

Use the **AskUserQuestion** tool. Keep it to a few focused rounds — infer
sane defaults from the existing agent's personality YAML and hand-rolled
module instead of asking what you can already read. Cover:

1. **Which agent** — convert an existing one (Victor/Ivy) or create new?
   If converting, you already have its identity + personality YAML; skip those.
2. **Phases/tools** — which lookups/scans run, in what intended order, and
   which existing tool function backs each. (One `do_*()` per phase.)
3. **Inputs from upstream** — what does it consume from the findings store /
   handoff? (e.g. Victor needs Randy's open ports.)
4. **Structured outputs** — what fields belong in its `<Agent>Findings`
   dataclass (the ground truth downstream + the report read).
5. **Handoff target** — who it hands off to next (Victor→Ivy, etc.), or none.
6. **Command** — which `!command` / scan_type triggers it.

If creating a brand-new agent, also ask: name, emoji, role one-liner, voice
/ character traits, catchphrases.

## Step 3 — Scaffold (follow reference.md exactly)

Generate in this order, matching Randy's structure:

1. **Findings dataclass** in `src/crew/findings.py` — a new `<Agent>Findings`
   with a `completed: set[str]` and setter methods that record completion.
2. **`do_*()` phase functions + `@tool` wrappers** — either extend
   `src/crew/tools.py` or, if the file is getting large, create
   `src/crew/<agent>_tools.py` with its own `set_event_loop`/`set_job_id` or a
   shared context module. Each `do_*()`: run the real tool, write findings,
   `_chat()` a structured (bulleted, deterministic) update, `_think()`
   analytical notes, return concise text for the LLM.
3. **Agent factory** `build_<agent>(...)` in `src/crew/agents.py` — fixed
   `<AGENT>_CHARACTER` constant + live YAML via `get_prompt_context`, tools,
   `get_llm()`, `max_rpm`, `max_iter`. Keep the backstory as rich as the
   hand-rolled system prompt.
4. **Run function** `run_crew_<phase>(...)` in `src/crew/run.py` — mirror
   `run_crew_recon`: opening, kickoff inside `try`, `_is_quota_error` →
   deterministic completion, `narration.flush()`, structured recap +
   handoff, evolution trigger, `clear_run`. Keep `expected_output` to one line.
5. **Wire into `bot.py`** — branch the relevant `start_scan` phase on
   `settings.use_crewai`, exactly like the recon branch.
6. **Handoff** — if applicable, fire `run_handoff(HandoffContext(...))` at the
   boundary (full-scan path already does Randy→Victor; add Victor→Ivy etc.).
7. **Tests (Rigor `demo` and above)** — write pytest tests for the agent's
   pure logic: the `<Agent>Findings` dataclass, the `do_*()` phase functions
   with the underlying tool calls mocked, quota-error detection, and the
   structured-message formatting. Save as a discrete file under `tests/`. Mock
   all external dependencies. At `standard`/`production`, follow the TDD loop
   (tests first, shown red) per the global CLAUDE.md. At `poc`, state that tests
   are deferred.

## Step 4 — Verify (do not skip)

- `python3 -c "import ast; ast.parse(open(f).read())"` each changed file.
- Rebuild + import-check in the container:
  `podman-compose build && podman-compose up -d` then
  `podman exec am-corp-bot python -c "from src.crew import run, tools, agents"`.
- Confirm the **degraded path**: the new run function must complete and
  produce structured findings when the LLM raises a quota error.
- **Rigor `demo`+**: run `pytest`, `mypy`, and `ruff` and resolve failures.
- Update the Phase Status table and Agent Roster in `CLAUDE.md`.
- Do NOT commit unless the user asks.

## Hard rules (from reference.md)

- The LLM orchestrates; **never** let a quota/429 error abort the scan —
  always finish deterministically via the `do_*()` functions.
- Display is rendered from the **findings store**, never from the agent's prose.
- Tools are sync; bridge to async with `_run_async`. One `do_*()`, two callers.
- Respect the channel contract: #thoughts = reasoning, #agent-chat =
  personality + handoffs.
- Reuse existing `src/tools/*` logic and the personality/evolution systems.
- No `Any`, explicit error handling, type hints, docstrings (project CLAUDE.md).
- Generate tests to the project's declared Rigor (`demo`+ requires them);
  follow the TDD accountability rules in the global CLAUDE.md.
