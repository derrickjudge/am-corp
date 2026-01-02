# Changelog

All notable changes to AM-Corp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial project structure and documentation
- **Docker containerization** (2026-01-01)
  - `Dockerfile` - Python 3.12 + security tools (dig, whois, nmap)
  - `docker-compose.yml` - Service definition with volumes and resource limits
  - `.dockerignore` - Optimized build context
  - Container runs as non-root user for security
  - gRPC SSL certificate fix for Gemini API
- **Randy Recon agent** (2026-01-01)
  - `src/agents/randy_recon.py` - Full reconnaissance agent implementation
  - `src/tools/recon_tools.py` - Tool wrappers for dig, whois, nmap
  - Gemini-powered conversational responses with Texas personality
  - Real-time progress updates to Discord
  - Structured final summary with bulleted findings
- **Scope approval caching** (2026-01-01)
  - `src/discord_bot/scope_cache.py` - Persistent scope approval storage
  - 12-hour approval cache with file-based persistence
  - Survives bot restarts
- **ADR-002: Natural Language Agent Interaction** (2026-01-01)
  - Documented future feature for @mention-based agent interaction
  - Intent parsing architecture
  - Phased implementation plan
- **ADR-003: Agent Transparency and Smart Scanning** (2026-01-02)
  - `!config` command design for agent configuration visibility
  - Verbose mode (`-v`) for troubleshooting
  - Debug channel (toggleable) for technical details
  - Smart template selection based on Randy's findings
- **`!config` command** (2026-01-02)
  - `!config` - Shows overview of all agents
  - `!config randy` - Randy's tools, nmap flags, timeout
  - `!config victor` - Nuclei templates, severity filter, rate limits
  - `!config ivy` - Planned capabilities (not yet implemented)
  - `!config rita` - Planned capabilities (not yet implemented)
  - Added to help menu
- **Verbose mode** (2026-01-02)
  - `-v` or `--verbose` flag for scan commands
  - Shows exact commands being executed
  - Displays template selection and configuration
  - Works with `!scan`, `!recon`, `!vuln` commands
- **Debug channel** (2026-01-02)
  - `!debug` command to toggle debug output
  - Posts technical details to dedicated debug channel
  - Includes: commands, exit codes, timing, errors
  - Configure with `DEBUG_CHANNEL_ENABLED` and `DISCORD_CHANNEL_DEBUG`
- **Smart template selection** (2026-01-02)
  - Victor automatically selects Nuclei templates based on Randy's findings
  - Service-to-template mapping for 30+ services
  - Port-based fallback when service name is unknown
  - Shows template selection reasoning in verbose mode
  - Falls back to default broad templates when no recon data
- **Victor Vuln agent** (2026-01-02)
  - `src/agents/victor_vuln.py` - Vulnerability analyst implementation
  - `src/tools/vuln_tools.py` - Nuclei wrapper with severity parsing
  - Nuclei v3.3.7 added to Docker container
  - `!vuln` command and full pipeline integration

### Changed
- **requirements.txt**: Switched from `google-generativeai` to `google-genai` (deprecated library)
- **nmap scan options**: Updated to `-sT -T4 --top-ports 500 -sV -n -Pn --open`
  - Scans top 500 ports instead of custom list
  - Added service version detection (`-sV`)
  - Added DNS resolution skip (`-n`) for speed
- **WHOIS lookup**: Now extracts base domain from subdomains (scanme.nmap.org → nmap.org)
- **.cursorrules**: Added system modifications rule (no installs without consent)
- Product Requirements Document (PRD)
- System architecture documentation
- Agent specifications (Recon, Vuln, Intel, Report)
- Security documentation and guidelines
- Development setup guide
- Deployment guide
- Python project structure (`src/`, `tests/`, `config/`, etc.)
- Configuration management with Pydantic Settings (`config.py`)
- Structured logging with structlog (`logging.py`)
- Application entry point (`main.py`)
- Requirements.txt with CrewAI and dependencies
- `.env.example` environment template
- `.gitignore` for Python/security projects
- **Multi-bot Discord architecture** (2025-12-31)
  - 5 separate Discord bots (AM Corp + Randy, Victor, Ivy, Rita)
  - Each agent appears as separate Discord user
  - `agent_bots.py` - Multi-bot manager with parallel startup
  - `webhooks.py` - Fallback webhook messaging
  - `validators.py` - Target security validation (.gov/.mil blocking)
  - `embeds.py` - Rich Discord embed formatting
  - `bot.py` - Main command handler bot
  - `commands.py` - `!help`, `!status`, `!ping`, `!scan`, `!scope` commands
  - `scripts/team_intro.py` - Agent introduction test script

### Changed
- **AGENTS.md**: Added agent names and conversational personalities
  - 🔍 Randy Recon - Reconnaissance Specialist
  - ⚠️ Victor Vuln - Vulnerability Analyst
  - 🧠 Ivy Intel - Threat Intelligence Analyst
  - 📊 Rita Report - Security Report Analyst
- **ARCHITECTURE.md**: Updated to reflect conversational interaction model
- **am-corp_PRD.md**: Revised vision for conversational AI team
- **phase-1-infrastructure.md**: Updated tasks for conversational bot approach
- **ENV_TEMPLATE.md**: Added separate webhook URLs for each channel
- **config.py**: Added agent bot token configuration

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- N/A

---

## [0.1.0] - YYYY-MM-DD

### Added
- 🎉 Initial release
- Core infrastructure setup
- Discord bot integration
- n8n workflow automation
- CrewAI orchestration layer
- Recon Agent with Nmap/Subfinder integration
- Basic command parsing

---

<!-- 
Template for new releases:

## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security fixes
-->

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | TBD | Initial release, core infrastructure |

---

## Release Notes Format

Each release should include:

1. **Summary**: Brief description of the release
2. **Breaking Changes**: Any changes that require user action
3. **New Features**: Detailed list of new capabilities
4. **Bug Fixes**: Issues resolved
5. **Known Issues**: Outstanding problems
6. **Upgrade Instructions**: How to update from previous version

