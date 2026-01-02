# ADR-003: Agent Transparency and Smart Template Selection

## Status
**Partially Implemented** - Phases B (`!config`), C (verbose mode), and D (debug channel) complete

## Date
2026-01-02

## Context

Users need visibility into what agents are actually doing during scans. Currently:
- Victor always runs the same Nuclei templates regardless of Randy's findings
- No easy way to see agent configurations
- No troubleshooting mode for debugging issues
- Agent behavior isn't fully documented

This creates uncertainty: "What templates did Victor run?", "Why did the scan take so long?", "Did it check for the right things?"

## Decision

Implement a multi-layered transparency system with smart template selection.

---

## Part 1: Transparency Features

### 1A. `!config` Command

Show agent configurations on demand.

```
!config              # All agents overview
!config randy        # Randy's detailed config
!config victor       # Victor's templates, severity, rate limits
```

**Example output:**
```
⚠️ Victor Vuln - Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Current Templates:
  • cves - Known CVE vulnerabilities
  • vulnerabilities - Generic vulnerability checks
  • misconfigurations - Security misconfigurations
  • exposures - Sensitive data exposure

Severity Filter: critical, high, medium
Rate Limit: 150 requests/second
Timeout: 10 minutes per scan

Smart Mode: ENABLED
  └── Templates adapt based on Randy's findings
```

### 1B. Verbose Mode (`-v` Flag)

Add troubleshooting output to scan commands.

```
!vuln scanme.nmap.org -v
!scan example.com --verbose
```

**Verbose output includes:**
- Exact command being executed
- Template selection reasoning
- Timing for each phase
- Raw tool output (summarized)

**Example:**
```
⚠️ Victor Vuln [VERBOSE MODE]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: scanme.nmap.org
Template Selection:
  • Randy found ports: 22/ssh, 80/http, 9929/nping-echo
  • Selected templates: cves, http, network, ssh
  • Skipped: database, cloud (no matching services)

Executing:
  nuclei -u https://scanme.nmap.org -severity critical,high,medium -tags cves,http,ssh -jsonl

Scan started at 19:45:02, timeout in 10 minutes...
```

### 1C. Debug Channel (Toggleable)

Route agent internals to dedicated channel.

**Environment variable:**
```env
DEBUG_CHANNEL_ENABLED=true
DISCORD_DEBUG_CHANNEL_ID=1234567890
```

**Behavior:**
- When enabled: Technical details → `#am-corp-debug`
- When disabled: No debug output
- Agent chat remains conversational

**Debug channel receives:**
- Raw tool commands and exit codes
- Template selection decisions
- Timing information
- Error stack traces (non-sensitive)

### 1D. Documentation

Update `docs/AGENTS.md` with:

1. **"What Does X Actually Do?"** section for each agent
2. Exact tools and their configurations
3. Decision logic (when does X happen?)
4. Default values and how to change them

---

## Part 2: Smart Template Selection

### Current Behavior (Static)

Victor always runs:
```
templates: cves, vulnerabilities, misconfigurations, exposures
severity: critical, high, medium
```

Regardless of what Randy found.

### Proposed Behavior (Smart)

Victor analyzes Randy's findings and selects relevant templates:

```
┌─────────────────────────────────────────────────────────────┐
│                    Randy's Findings                          │
│  ports: [{port: 80, service: http}, {port: 22, service: ssh}]│
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Template Selection Engine                       │
│                                                              │
│  1. Map services → template categories                       │
│  2. Always include: cves (baseline)                         │
│  3. Add service-specific: http, ssh, etc.                   │
│  4. Skip irrelevant: database (no DB ports found)           │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Selected Templates for This Scan                │
│  cves, http, ssl, network, ssh                              │
└─────────────────────────────────────────────────────────────┘
```

### Service-to-Template Mapping

| Service/Port | Template Tags | Notes |
|--------------|---------------|-------|
| http (80) | `http`, `cves`, `exposures` | Web application checks |
| https (443) | `http`, `ssl`, `cves`, `exposures` | + SSL/TLS checks |
| ssh (22) | `ssh`, `network`, `cves` | SSH-specific vulnerabilities |
| ftp (21) | `ftp`, `network`, `cves` | FTP misconfigs |
| mysql (3306) | `mysql`, `network`, `cves` | Database exposure |
| postgresql (5432) | `postgres`, `network`, `cves` | Database exposure |
| redis (6379) | `redis`, `network`, `cves` | Unauth access |
| elasticsearch (9200) | `elasticsearch`, `network`, `exposures` | Data exposure |
| mongodb (27017) | `mongodb`, `network`, `cves` | NoSQL exposure |
| smb (445) | `smb`, `network`, `cves` | Windows shares |
| rdp (3389) | `rdp`, `network`, `cves` | Remote desktop |

### Fallback Behavior

If Randy didn't run (e.g., `!vuln` command directly):
- Use default broad templates
- Log that no recon data was available

```
Victor: Running without Randy's recon data. Using default templates 
        which cover common vulnerabilities. For faster, targeted scans, 
        run !scan instead of !vuln directly.
```

---

## Implementation Phases

### Phase A: Documentation (No Code)
- Update AGENTS.md with detailed behavior specs
- Add "What does X actually do?" sections
- Document current default values

### Phase B: `!config` Command
- Add `!config` command to commands.py
- Create config display embeds
- Show agent-specific details

### Phase C: Verbose Mode
- Add `-v` / `--verbose` flag parsing
- Route verbose output to channel
- Show command and template reasoning

### Phase D: Debug Channel
- Add env vars for debug channel
- Create debug logging utility
- Toggle with environment variable

### Phase E: Smart Template Selection
- Create service-to-template mapping
- Modify victor_vuln.py to accept Randy's findings
- Select templates based on discovered services
- Log selection reasoning

---

## Required Changes

| File | Changes |
|------|---------|
| `docs/AGENTS.md` | Add detailed behavior sections |
| `src/discord_bot/commands.py` | Add `!config` command, verbose flag |
| `src/agents/victor_vuln.py` | Smart template selection |
| `src/tools/vuln_tools.py` | Service-to-template mapping |
| `src/utils/config.py` | Debug channel settings |
| `src/utils/debug.py` | NEW: Debug channel utility |
| `.env` | Add DEBUG_CHANNEL_ENABLED, DISCORD_DEBUG_CHANNEL_ID |

---

## Success Criteria

| Criteria | Measurement |
|----------|-------------|
| `!config` shows agent details | Accurate info displayed |
| Verbose mode shows internals | Command and reasoning visible |
| Debug channel toggleable | On/off via env var |
| Smart templates work | HTTP port → HTTP templates |
| Scans are faster | Fewer irrelevant templates = quicker |
| Documentation complete | All behaviors documented |

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Debug info leaks sensitive data | Filter out API keys, tokens |
| Smart selection misses vulnerabilities | Always include `cves` baseline |
| Verbose mode clutters chat | Output to thread or dedicated channel |
| Template mapping incomplete | Start with common services, expand |

---

## Related Documents
- [ADR-002: Natural Language Agent Interaction](002-natural-language-agent-interaction.md)
- [AGENTS.md](../AGENTS.md) - Agent specifications
- [Phase 2: Vuln + Intel Agents](../phases/phase-2-vuln-intel-agents.md)

