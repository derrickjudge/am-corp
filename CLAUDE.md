# AM-Corp – Project Context for Claude

## What This Project Is

A multi-agent cybersecurity platform where AI agents (Randy, Victor, Ivy, Rita) operate as teammates in a Discord server. Agents do reconnaissance, vulnerability scanning, and threat intelligence, then collaborate through natural language discussion. Everything runs as a single Podman container locally; Discord is the only UI.

**This is an interview demo project** — a portfolio-quality showcase of the work.

```
Rigor: demo         # rapid-experiment | poc | demo | standard | production
Hosting: local      # local | personal-infra | managed-cloud
```

`demo` rigor (see global CLAUDE.md) requires: tests for core logic, mypy + ruff
passing, and full type hints + docstrings. `src/crew/` (Randy and Victor's
CrewAI conversion) is at demo standard: tests, clean mypy/ruff. **Known gap:**
the rest of the codebase (hand-rolled agents, Discord bot, tools) still needs
the same pass. New code from here should meet demo rigor.

---

## Tech Stack

| Layer | Tech | Notes |
|-------|------|-------|
| Language | Python 3.12 | Strict typing — no `Any` |
| Agents | CrewAI ≥0.86.0 | Multi-agent orchestration |
| LLM | Google Gemini 2.5-flash-lite | Free tier ~20 requests/day (observed); paid tier or Ollama to scale — see `src/crew/llm.py` |
| Discord | discord.py ≥2.3.0 | Bot + webhooks |
| Container | **Podman** (NOT Docker) | macOS corporate security (Netskope) blocks Docker SSL |
| Compose | podman-compose | Use this — never `docker-compose` |
| Config | Pydantic Settings | Type-safe; loads `.env` automatically |
| Storage | File-based (YAML/JSON) | No database |
| Security Tools | nmap, nuclei v3.3.7, dig, whois | Installed inside the container image |

**Critical:** Always use `podman-compose`, never `docker-compose`. They are not interchangeable here.

---

## Project Structure

```
am-corp/
├── CLAUDE.md                      # This file
├── .env                           # Secrets (git-ignored — never commit)
├── .env.example                   # Template for .env
├── Dockerfile                     # python:3.12-slim, non-root user `amcorp` (UID 1000)
├── docker-compose.yml             # Single service: am-corp-bot
├── pyproject.toml                 # Python deps + tooling config (managed by uv)
├── uv.lock                        # Pinned lockfile — reproducible builds
├── config/
│   ├── personalities/             # Agent YAML state — persisted across restarts
│   │   ├── randy_recon.yaml
│   │   ├── victor_vuln.yaml
│   │   ├── ivy_intel.yaml
│   │   ├── rita_report.yaml
│   │   └── archive/               # Retired personality versions
│   └── scope.yaml                 # Approved target domains
├── src/
│   ├── main.py                    # Entry point
│   ├── preflight.py               # Startup validation (tools, config, connectivity)
│   ├── agents/
│   │   ├── randy_recon.py         # Recon agent — dig, whois, nmap
│   │   ├── victor_vuln.py         # Vuln agent — nuclei, CVE lookup
│   │   ├── ivy_intel.py           # Intel agent — Shodan, VirusTotal, EPSS
│   │   ├── personality.py         # Personality state loader (reads YAML)
│   │   └── evolution.py           # Personality evolution tracking
│   ├── discord_bot/
│   │   ├── bot.py                 # Main Discord client
│   │   ├── commands.py            # Command handlers (!scan, !intel, etc.)
│   │   ├── webhooks.py            # Webhook send utilities
│   │   ├── embeds.py              # Rich Discord embed builders
│   │   ├── thoughts.py            # Thoughts channel manager
│   │   ├── casual_chat.py         # General channel conversation engine
│   │   ├── agent_bots.py          # Per-agent Discord clients (multi-bot mode)
│   │   ├── conversation_memory.py # 30-day conversation history
│   │   ├── scope_cache.py         # Target approval cache
│   │   └── validators.py          # Input validation (targets, domains)
│   ├── tools/
│   │   ├── recon_tools.py         # CrewAI tools: DNS, whois, nmap
│   │   ├── vuln_tools.py          # CrewAI tools: nuclei, CVE APIs
│   │   └── intel_tools.py         # CrewAI tools: Shodan, VirusTotal, feeds
│   ├── feeds/
│   │   ├── security_news.py       # Security news aggregation
│   │   └── news_cache.py          # Feed cache management
│   └── utils/
│       ├── config.py              # Canonical source of all env vars and defaults
│       ├── logging.py             # Structured logging (structlog + rich)
│       └── debug.py               # Debug utilities
├── tests/                         # pytest suite
├── scripts/
│   ├── entrypoint.sh              # Container startup script
│   ├── restart.sh                 # Safe restart (cleans dangling processes)
│   └── test_*.py                  # Manual smoke/connectivity tests
└── docs/
    ├── ARCHITECTURE.md
    ├── AGENTS.md
    ├── SETUP.md
    ├── DEPLOYMENT.md
    ├── SECURITY.md
    ├── ENV_TEMPLATE.md
    └── adr/                       # 3 Architecture Decision Records
```

---

## Agent Roster

| Agent | Emoji | File | Role | Status | CrewAI |
|-------|-------|------|------|--------|--------|
| Randy Recon | 🔍 | `src/agents/randy_recon.py` | DNS, whois, nmap recon | ✅ Done | ✅ Converted (`src/crew/tools.py`, `run_crew_recon`) |
| Victor Vuln | ⚠️ | `src/agents/victor_vuln.py` | Nuclei scans, CVE lookup | ✅ Done | ✅ Converted (`src/crew/vuln_tools.py`, `run_crew_vuln`) |
| Ivy Intel | 🧠 | `src/agents/ivy_intel.py` | Shodan, VirusTotal, EPSS | ✅ Done | ⏳ Hand-rolled only |
| Rita Report | 📊 | `src/agents/rita_report.py` | Aggregation and reporting | 🔄 Partial | ⏳ Not started |

Rita has a personality YAML and base class but **report generation is not implemented** (Phase 3). Do not treat her as a working agent.

CrewAI conversion is gated behind `USE_CREWAI=true` (see Environment & Config
below); with it unset, all agents run their original hand-rolled path.

---

## Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| 1 – Infrastructure | ✅ Complete | Podman, Discord bot, personality system, preflight checks |
| 2 – Agents | ✅ Complete | Randy, Victor, Ivy, thoughts channel, casual chat, security news. Randy + Victor also have a CrewAI-agentic path (`src/crew/`). |
| 3 – Rita + Reporting | 🔄 In Progress | Rita skeleton exists; full report generation not built |
| 4 – n8n Workflows | 🔄 Scaffolded | Framework wired up but untested end-to-end |
| 5 – Sub-agents / SaaS | ⏳ Not Started | Out of scope for this demo |

---

## Environment & Config

- All secrets live in `.env` (git-ignored). See `.env.example` or `docs/ENV_TEMPLATE.md` for the full variable list.
- `src/utils/config.py` (Pydantic `BaseSettings`) is the **canonical reference** for every env var, its type, and its default. Read this file before assuming a variable exists.
- **Required to boot:** `DISCORD_BOT_TOKEN`, `DISCORD_GUILD_ID`, `GEMINI_API_KEY`, all channel IDs, all webhook URLs.
- **Optional (degrade gracefully):** `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, per-agent bot tokens.
- Multi-bot mode (each agent appears as its own Discord user) requires `DISCORD_BOT_TOKEN_RANDY`, `_VICTOR`, `_IVY`, `_RITA`.
- **Crew LLM routing:** the CrewAI crew path (Randy and Victor today) uses `crew_llm_model` — `LLM_MODEL` if set, else `gemini/<GEMINI_MODEL>`. To run the crew on a local Ollama model (no quota) set `LLM_MODEL=ollama/qwen2.5` (or `ollama/llama3.1` — must support tool calling) and `LLM_API_BASE=http://host.containers.internal:11434`; on the host run Ollama bound to `0.0.0.0` (loopback-only refuses the container). The rest of the app (casual chat, mentions, hand-rolled agents) stays on Gemini. See `src/crew/llm.py`.

---

## Critical Operational Rules

### 1. Always clean up before restarting
Dangling Python processes cause every Discord command to fire multiple times.
```bash
pkill -9 -f "python.*src" 2>/dev/null || true
podman-compose down
podman stop -a 2>/dev/null || true
```
The helper script `./scripts/restart.sh` does this automatically.

### 2. Gemini free-tier rate limits
- 15 requests/minute · 1,500 requests/day · 1M tokens/minute
- Production mode auto-reduces agent chattiness to conserve quota
- Never add features that fire multiple rapid Gemini calls without rate-limit awareness

### 3. Scope verification is non-negotiable
- `ENABLE_SCOPE_VERIFICATION=true` must stay enabled whenever touching real networks
- `.gov` and `.mil` domains are hardcoded-blocked — do not remove those checks
- New targets require human approval; approved targets cache to `data/scope_cache.json`

### 4. Personality files carry state between restarts
- `config/personalities/*.yaml` are modified at runtime as agents evolve
- If agent behavior seems wrong, inspect the YAML — stale state causes subtle bugs
- Move old files to `config/personalities/archive/` rather than deleting them

---

## Run Reference

```bash
# Build
podman-compose build

# Preflight validation (run before first start)
podman exec am-corp-bot python src/preflight.py --quick

# Start
podman-compose up -d

# Tail logs
podman-compose logs -f

# Stop
podman-compose down
```

### Smoke Tests
```bash
python scripts/test_gemini.py          # Verify Gemini API connectivity
python scripts/test_news_feeds.py      # Verify security news feeds
python scripts/test_casual_chat.py     # Verify casual chat engine
```

### Automated Tests
```bash
pytest                                 # All tests
pytest --cov=src --cov-report=html    # With coverage report
pytest tests/test_agents.py            # Specific module
```

---

## Architecture Decisions (ADRs in `docs/adr/`)

1. **CrewAI for orchestration** — chosen over raw LangChain for built-in multi-agent coordination and tool abstractions
2. **Natural language agent interaction** — agents communicate in prose so reasoning is transparent to humans watching Discord
3. **Agent transparency + smart scanning** — thoughts channel exposes raw reasoning; scanning is always explicit and scope-verified, never background or autonomous
