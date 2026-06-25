# AM-Corp Codebase Review

**Date:** 2026-06-24
**Reviewer:** Claude (Opus 4.8)
**Scope:** Security, dead/inefficient code, dependency currency, and developer-workflow improvements.
**Method:** Static review of `src/`, `scripts/`, `config/`, `Dockerfile`, `docker-compose.yml`, `requirements.txt`, and ignore files. No code changes were made.

> **Assumption (please correct if wrong):** This is treated as a **private, single-user interview demo** — the bot runs locally and the Discord guild is controlled by you. Several findings below (especially authorization) change severity sharply if the guild is ever shared with other people. Each such finding is tagged accordingly.

---

## 0. Executive Summary — Priority Order

| # | Item | Severity | Effort |
|---|------|----------|--------|
| 1 | No shared Gemini rate limiter → structural quota exhaustion (root cause of the "On it…" fallback behavior) | **High** (functional) | Medium |
| 2 | `validate_target()` sanitizes the target then **discards** it; raw input flows to nmap/nuclei/dig/whois (argument-injection surface) | **Medium** | Low |
| 3 | CrewAI documented + intended but **never integrated** (a prior session hand-rolled around it) | **Medium** (architectural / learning-goal) | High |
| 4 | Secret-leakage risk: webhook URLs / API keys can reach logs via raw exception strings; no log redaction | **Medium** | Low |
| 5 | Unused/misplaced dependencies (`requests`, `python-json-logger`, `podman-compose`, dual HTTP stacks) | **Low** (bloat) | Low |
| 6 | No automated tests, no ruff/mypy/pyproject config — the project's own CLAUDE.md mandates all three | **Medium** (quality) | Medium |
| 7 | Any guild member can trigger/approve scans (no app-level RBAC) | **Low** now / **High** if shared | Medium |
| 8 | Two bare `except:` clauses; non-atomic state writes; supply-chain gaps in Dockerfile | **Low** | Low |

**Single highest-leverage change:** introduce one **LLM gateway** module (shared client + token-bucket rate limiter + centralized fallback). It fixes #1, de-duplicates seven call sites, and is where future CrewAI integration would plug in.

---

## 1. Security Findings

### 1.1 [Medium] Sanitized target is computed then thrown away — raw input reaches the CLI tools
`validators.validate_target()` builds `clean_target = sanitize_target(target)` and validates against it, but the returned `ValidationResult` does **not** carry the cleaned value. In `commands.handle_scan()` the original **raw** `target` is then passed to `bot.start_scan()` → `run_recon`/`run_vuln_scan` → `nmap`/`dig`/`whois`/`nuclei`.

- **Good news:** `run_command()` uses `asyncio.create_subprocess_exec(*cmd)` with an argv list and **no `shell=True`**, so classic shell-metacharacter RCE (`; rm -rf`, `$(…)`) is **not** possible.
- **Residual risk (argument injection):** there is no positive hostname/IP format check. A target like `--script=http-fetch` or one beginning with `-` is passed to `nmap` as **argv**, where it is parsed as a *flag*, not a host. `nmap` flags can write files (`-oN`), run NSE scripts (`--script`), etc. Blast radius is limited because the container runs as non-root `amcorp`, but this is still a real injection surface.

**Recommendations**
- Make `validate_target()` return the sanitized target (e.g., `ValidationResult.clean_target`) and use **that** everywhere downstream.
- Add a positive-format validator: accept only RFC-1123 hostnames or valid IPv4/IPv6 (reject anything starting with `-`, containing whitespace, or with shell/argv metacharacters) **before** the target reaches any tool.

### 1.2 [Medium] No Gemini rate limiting anywhere (also the cause of the fallback messages you saw)
There are **seven** independent `genai.Client(...)` + `generate_content` call sites (`preflight`, `randy_recon`, `victor_vuln`, `ivy_intel`, `casual_chat`, `handoffs`, `mention_router`) with **no shared semaphore, token bucket, or cooldown**. Casual chat fires every 5–10 minutes continuously; a full `!scan` adds ~4 handoff calls; each `@mention` adds one per agent. Nothing coordinates these against the 15 RPM / daily free-tier limits.

- This directly violates both CLAUDE.md files ("All APIs should be built with rate limits").
- It is the structural reason the live test fell back to `"On it. Will report back shortly."` — the daily quota was exhausted (`429 RESOURCE_EXHAUSTED`).
- **Disclosure:** the two features added this session (`handoffs.py`, `mention_router.py`) followed the existing per-call pattern and therefore **contribute to** this problem. They should migrate to the gateway proposed in §4.1.

**Recommendation:** one shared async LLM gateway with a token-bucket limiter (e.g., 15 requests / 60 s) and a single fallback path. See §4.1.

### 1.3 [Medium] Secret leakage into logs via raw exception strings; no redaction
- `webhooks.WebhookClient.post_message()` logs `error=str(e)` on `httpx.HTTPError`. httpx status errors stringify with the **full request URL** — and Discord webhook URLs embed a secret token. A failed webhook POST can therefore write the webhook secret to stdout/log file.
- `intel_tools.shodan_host_lookup()` passes the Shodan key as a query param (`params={"key": api_key}`); an `aiohttp.ClientError` string can include the URL+key, and the code stores `result.error = str(e)`.
- `logging.py` configures structlog with **no redaction processor**, so anything passed as a field is emitted verbatim (JSON in production).

**Recommendations**
- Add a structlog processor that scrubs known-secret patterns (Discord webhook URLs, `key=`, `apikey`, bearer tokens) from event dicts before rendering.
- When logging HTTP failures, log `e.__class__.__name__` + status code, not the raw URL-bearing string. Prefer the VirusTotal/SecurityTrails header style (`x-apikey` / `APIKEY` header) over Shodan's query-param key everywhere possible.

### 1.4 [Low now / High if shared] No application-level authorization (RBAC)
`bot.on_reaction_add()` approves an out-of-scope scan when **any** non-bot user reacts ✅. The original requester is stored in `pending["user"]` but **never compared** to the reactor, so any guild member who can see the confirmation can authorize scanning of arbitrary third-party domains (`.gov`/`.mil` excepted). Likewise, anyone with write access to `#am-corp-commands` can issue `!scan`.

- For a **private** demo, the practical control is Discord **channel permissions** — acceptable, low severity.
- For any **shared** guild this is a HIGH-severity abuse/legal risk (the bot becomes a scanning weapon-by-proxy).

**Recommendations**
- Enforce that the ✅ reactor equals `pending["user"]`, or restrict approval to a specific role/user ID.
- Add an allowlist of authorized Discord user IDs (env var) checked in `handle_scan()`.
- Document the "lock `#am-corp-commands` to trusted roles" requirement in SECURITY.md.

### 1.5 [Low] Two bare `except:` clauses (CLAUDE.md violation)
`src/feeds/security_news.py:278` and `:374` use bare `except:` that swallow everything (including `KeyboardInterrupt`/`SystemExit`) with no logging. Both CLAUDE.md files explicitly forbid this. Replace with specific exceptions (e.g., `except (ValueError, KeyError, AttributeError) as e:`) and log at warning.

### 1.6 [Low] Dockerfile supply-chain gaps
- Base image is the floating tag `python:3.12-slim` (not digest-pinned) → non-reproducible, silently shifting base.
- The Nuclei release zip is fetched over HTTPS with **no checksum/signature verification**; the templates fallback is `curl … | tar` with no integrity check.
- `deploy.resources.limits` in `docker-compose.yml` is a **Swarm-only** key and is **ignored by podman-compose** — the 2 CPU / 2 GB limits are *not actually enforced*. Use `mem_limit`/`cpus` (compose v2) or podman run flags.
- No container hardening (`cap_drop: [ALL]`, `security_opt: no-new-privileges`, `read_only` rootfs). The `-sT` connect scan does not need `NET_RAW`, so capabilities can be dropped.

**Recommendations:** pin base image by digest; verify the Nuclei zip SHA256; replace `deploy.resources` with enforced limits; add cap-drop + no-new-privileges.

### 1.7 [Info] What's already done well
- Secrets hygiene is solid: `.env` is git-ignored (only `.env.example`, all-blank, is tracked); no `.pem`/`.key`/tokens tracked; `data/` ignored; a real `.dockerignore` excludes `.env`/secrets/`.git`.
- `.gov`/`.mil` blocking, localhost block, private-IP confirmation, and audit logging are present and sensible.
- Subprocess calls use argv lists (no `shell=True`) — the most important injection class is already avoided.
- Container runs as a non-root user (UID 1000).

---

## 2. Inefficient / Unused Code

### 2.1 Unused or misplaced dependencies
Verified by grepping every import across `src/` and `scripts/`:

| Dependency | Status | Action |
|---|---|---|
| `crewai`, `crewai-tools` | **Never imported.** Documented as the orchestration layer (ADR-001) but not wired in. | **Keep — but actually integrate** (your learning goal). See §5. Until then it ships ~hundreds of unused transitive deps (langchain, litellm, chromadb…) into the image. |
| `requests` | **Never imported.** | Remove (project is fully async on httpx/aiohttp). |
| `python-json-logger` | **Never imported** (structlog renders JSON itself). | Remove. |
| `podman-compose` | Listed as an **app** dependency, but it's a **host** orchestration tool. | Remove from `requirements.txt` (it gets pointlessly installed *inside* the container). |
| `aiohttp` **and** `httpx` | Both present. `aiohttp` is used only in `intel_tools.py`; `httpx` is used in 6 files. | Standardize on **httpx**; port `intel_tools.py` and drop `aiohttp`. |

### 2.2 Duplicated code
- **`run_command()` is duplicated verbatim (~85 lines)** in `tools/recon_tools.py` and `tools/vuln_tools.py`. Extract to `src/utils/subprocess.py` and import in both.
- The async-shutdown cleanup block in `main.py` is copy-pasted across the two `if/else` branches.

### 2.3 Inefficient patterns
- **Per-call client creation:** `genai.Client(...)` is rebuilt on every call in `casual_chat`, `mention_router`, `handoffs`, and `ivy_intel` (randy/victor at least cache `self._client`). Use one shared client.
- **No connection pooling:** `intel_tools.py` opens a fresh `aiohttp.ClientSession()` per request. Reuse a session (or move to a shared httpx client).
- **Non-atomic state writes:** `personality.save()` does `open(path, "w")` + `yaml.dump`. A crash or concurrent write mid-dump corrupts the YAML — and CLAUDE.md itself warns that stale/corrupt personality state causes subtle bugs. Write to a temp file then `os.replace()` (atomic). Apply the same to `scope_cache` and `news_cache` JSON writes.
- **Unused import:** `main.py` imports `signal` but never uses it.

### 2.4 Known stubs (document, don't necessarily fix)
- `!report` and Rita's report generation are stubs ("not yet implemented") — consistent with Phase 3 status.
- `!scope add`/`remove` only print instructions; they don't persist. Either implement dynamic scope (write to `scope_cache`/a scopes file) or relabel the command as read-only to avoid confusion.

---

## 3. Component / Dependency Currency

**Nothing is running *old* — the opposite is the problem.** The floating `>=` pins resolved to the newest release of everything at build time (verified via `pip freeze` in the running container, 2026-06-24). The risk is *unpinned + bleeding-edge*, not stale.

### 3.1 Actual resolved versions vs. declared pins

| Package | Declared | **Actually installed** | Note |
|---|---|---|---|
| `crewai` / `crewai-tools` | `>=0.86.0` / `>=0.14.0` | **`1.14.7`** | **Silent 0.x → 1.x major-version jump** at build time. This is the textbook breaking-change risk of `>=`. |
| `discord.py` | `>=2.3.0` | `2.7.1` | Drifted several minors. |
| `google-genai` | `>=1.0.0` | `2.10.0` | **Major jump** 1.x → 2.x. |
| `pydantic` / `pydantic-settings` | `>=2.5` / `>=2.1` | `2.12.5` / `2.10.1` | Current. |
| `aiohttp` | `>=3.9.0` | `3.14.1` | (used only by `intel_tools.py`) |
| `python:3.12-slim` (base) | floating tag | — | Digest-pin for reproducibility. |

A `pip install` into this environment also surfaced **dependency conflicts** (`crewai` requires `tomli~=2.0.2` / `tomli-w~=1.1.0`, but `2.4.1` / `1.2.0` are installed) — i.e. CrewAI's own pins are already violated in the resolved tree. More evidence that the unpinned graph is internally inconsistent.

**The fix is to *pin*, not upgrade** — capture the working `pip freeze` as a lockfile so rebuilds stop leaping across majors. Adopt `uv` (already preferred in your global CLAUDE.md) → `pyproject.toml` + `uv.lock`, and digest-pin the base image.

### 3.2 Known CVEs (from `pip-audit`, run in-container 2026-06-24)

> These CVE IDs postdate the reviewer's training data; they are **reported from the `pip-audit` advisory database**, not asserted from prior knowledge. Re-run `python -m pip_audit` to refresh.

**6 known vulnerabilities across 2 packages:**

| Package | Version | Advisory | Fix | Action |
|---|---|---|---|---|
| `pip` | `25.0.1` | PYSEC-2026-196, CVE-2025-8869, CVE-2026-1703, CVE-2026-3219, CVE-2026-6357 | ≥ `26.1.2` | **Easy win:** add `RUN pip install --upgrade pip` early in the Dockerfile (or pin a patched pip). 5 CVEs cleared at once. |
| `chromadb` | `1.1.1` | CVE-2026-45829 | *(none listed)* | **`chromadb` is pulled in *solely* by CrewAI** and nothing in the running code uses it. Deferring/removing CrewAI (§2.1) eliminates this CVE entirely. If keeping CrewAI, track for a patched `chromadb` and pin `crewai` to a release that requires it. |

The headline: **the only runtime-dependency CVE you're carrying is being introduced by an unused framework.** That directly reinforces §2.1 — until CrewAI is actually integrated, its (currently dormant) sub-tree is pure liability, now with a concrete CVE attached.

---

## 4. Recommended Refactors

### 4.1 LLM Gateway (highest leverage — fixes §1.2 and collapses 7 call sites)
Create `src/utils/llm.py` exposing one async function used by **every** agent, casual-chat, handoff, and mention path:

```text
class LLMGateway:
    - one shared genai.Client
    - asyncio token-bucket limiter (e.g., 15 req / 60s, configurable via env)
    - generate(system_instruction, prompt, *, temperature, max_tokens, fallback) -> str
    - centralized 429/quota handling + single fallback path + structured logging
```

Every current `genai.Client(...)`/`generate_content` block becomes one `await gateway.generate(...)` call. This is also the natural seam for CrewAI later (the gateway becomes the LLM the Crew uses).

### 4.2 Shared subprocess util
Move `run_command()` into `src/utils/subprocess.py`; delete the two copies.

### 4.3 Validation hardening
Add `is_valid_hostname_or_ip()`; have `validate_target()` return `clean_target`; thread the sanitized value to all tools.

### 4.4 Atomic file writes
Add `src/utils/atomic_io.py` (`write_text_atomic`, `write_json_atomic`) and use it in `personality.save()`, `scope_cache._save_to_disk()`, and `news_cache`.

---

## 5. Adopting CrewAI (your stated learning goal)

You wanted CrewAI specifically to learn it; a prior session built a parallel hand-rolled system instead (plain `RandyRecon`/`VictorVuln`/`IvyIntelAgent` classes calling `google.genai` directly, with a fixed Python `start_scan` sequence). Nothing in the running code imports CrewAI today. Here's the concrete shape of an actual integration, so the migration is a learning exercise rather than a rewrite-from-scratch:

**1. Wrap your existing tools as CrewAI tools** — your `recon_tools`/`vuln_tools`/`intel_tools` functions are already clean async wrappers; expose them via `@tool` (or `BaseTool` subclasses) so an agent can call them.

```text
@tool("nmap_scan")
def nmap_tool(target: str) -> str:
    """Port-scan a host and return open ports."""  # wraps your existing nmap_scan()
```

**2. Define agents from your personality YAML** — map each `AgentPersonality` (role, traits, backstory) onto a `crewai.Agent(role=…, goal=…, backstory=…, tools=[…], llm=<gateway model>)`. Your YAML files become the source for `backstory`/`goal`, so the personality system you already built is *reused*, not discarded.

**3. Replace `start_scan()` with a Crew** — model Randy → Victor → Ivy as `Task`s in a `Crew(process=Process.sequential)`; CrewAI passes each task's output to the next, which is exactly the handoff you currently orchestrate by hand. Discord posting stays where it is (callbacks or task outputs → webhooks/agent bots).

**4. Point CrewAI's LLM at the §4.1 gateway** so rate limiting still applies (CrewAI uses LiteLLM under the hood; the daily-quota issue would otherwise bite harder, since agentic loops make *more* calls).

This lets you keep the parts that are genuinely yours (personality YAML + evolution, Discord layer, tool wrappers) while learning CrewAI's `Agent`/`Task`/`Crew`/tool abstractions on top.

**Guardrail for future sessions:** add an explicit instruction to `am-corp/CLAUDE.md` — *"Agent orchestration MUST use CrewAI (`Agent`/`Task`/`Crew`); do not hand-roll the pipeline. See ADR-001."* That single line would have prevented the divergence that frustrated you.

---

## 6. Testing & Tooling Gaps

- **`tests/` contains only `__init__.py` — zero pytest tests**, despite `pytest`/`pytest-asyncio`/`pytest-cov` in `requirements.txt` and CLAUDE.md mandating "MUST write unit tests for all new functions." The `scripts/test_*.py` files are **manual smoke scripts**, not collectable unit tests.
  - **Easy, high-value first tests (pure logic, no mocks needed):** `validators` (gov/mil blocking, sanitize, private-IP), `scope_cache` (TTL expiry), `mention_router.parse_agent_mentions`, `handoffs` fallback formatting, `vuln_tools.select_templates_for_ports`. Mock Gemini/Discord for the rest.
- **No `pyproject.toml`, no ruff/mypy config** — the project CLAUDE.md mandates Ruff + mypy as gates, but nothing enforces them. Add `pyproject.toml` with `[tool.ruff]`, `[tool.mypy]`, `[tool.pytest.ini_options]`.

---

## 7. Workflow / Efficiency Suggestions (skills, scripts, docs)

1. **`scripts/dev.sh`** — one command for `ruff format && ruff check && mypy src && pytest`. Wire into pre-commit hooks so the CLAUDE.md "Before Committing" checklist is actually enforced.
2. **Migrate to `uv` + `pyproject.toml`** (matches your global CLAUDE.md) and commit a lockfile for reproducible builds.
3. **Persist the channel/command map** — already captured in Claude memory this session (`#general` is the casual channel, full `!scan`/`!recon`/`!vuln`/`!intel` list, no `!full`). Consider mirroring it into `docs/` so it's visible to humans too.
4. **CLAUDE.md guardrail for CrewAI** (see §5) and for rate limiting ("all Gemini calls go through `src/utils/llm.py`").
5. **Log-redaction processor** (§1.3) as a small reusable structlog utility.
6. **Atomic-write utility** (§4.4) to protect evolving personality/cache state.

---

## 8. Open Questions for You

1. **Threat model** — confirm the Discord guild is private/single-user. If others are (or will be) present, §1.4 jumps to High and should be addressed before any shared demo.
2. **CrewAI timeline** — integrate now as a focused refactor (§5), or after the rate-limit gateway (§4.1) lands? (Doing the gateway first makes the CrewAI swap cleaner.)
3. **Dependency pinning** — okay to move to `uv` + `pyproject.toml` + lockfile, or keep `requirements.txt` (just with exact pins)?

*No code was changed as part of this review.*
