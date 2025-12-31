# AM-Corp System Architecture

## Overview

AM-Corp is a conversational multi-agent cybersecurity platform. Specialized AI agents collaborate through natural conversation in Discord, with a human operator providing oversight and direction. The system emphasizes transparency - all agent reasoning and collaboration is visible in Discord channels.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           DISCORD                                   │
│                  (Conversational Interface)                         │
│                                                                     │
│   #commands          #agent-chat         #results       #alerts     │
│   Human cmds    ←→   Agent collab   →    Reports    →   Errors     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       ORCHESTRATOR                                   │
│              (Command Routing & Agent Coordination)                  │
│                                                                     │
│   • Parse commands (!scan) and natural language                      │
│   • Route tasks to appropriate agents                                │
│   • Enforce scope verification                                       │
│   • Manage conversation flow and handoffs                            │
└─────────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ 🔍 RANDY      │  ───► │ ⚠️ VICTOR     │  ───► │ 🧠 IVY        │
│    RECON      │ ◄───  │    VULN       │ ◄───  │    INTEL      │
│               │       │               │       │               │
│ • Nmap        │       │ • Nuclei      │       │ • Shodan      │
│ • Subfinder   │       │ • CVE lookup  │       │ • VirusTotal  │
│ • httpx       │       │ • Version chk │       │ • Breach DB   │
└───────────────┘       └───────────────┘       └───────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                      ┌───────────────────┐
                      │   📊 RITA         │
                      │      REPORT       │
                      │                   │
                      │ • Aggregation     │
                      │ • Formatting      │
                      │ • Delivery        │
                      └───────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          n8n WORKFLOWS                               │
│                    (Automation & Tool Execution)                     │
│                                                                     │
│   • CLI tool execution (sandboxed)                                   │
│   • Scheduled scans                                                  │
│   • External API integrations                                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Team

AM-Corp is staffed by four AI agents who work as a team:

| Agent | Name | Role | Primary Tools |
|-------|------|------|---------------|
| 🔍 | **Randy Recon** | Reconnaissance Specialist | Nmap, Subfinder, httpx |
| ⚠️ | **Victor Vuln** | Vulnerability Analyst | Nuclei, CVE databases |
| 🧠 | **Ivy Intel** | Threat Intelligence Analyst | Shodan, VirusTotal |
| 📊 | **Rita Report** | Security Report Analyst | Templates, formatters |

See [AGENTS.md](./AGENTS.md) for detailed agent specifications and personalities.

---

## Discord Channel Structure

| Channel | Purpose | Who Posts |
|---------|---------|-----------|
| `#am-corp-commands` | Human commands (`!scan`, `!status`) | Humans only |
| `#am-corp-agent-chat` | Agent collaboration and status updates | All agents |
| `#am-corp-results` | Final deliverables and reports | Rita (primarily) |
| `#am-corp-alerts` | Errors, security warnings, scope issues | System + All agents |

### Interaction Model

**Commands Channel:** Humans issue structured commands or natural language requests. Only humans post here; agents respond in agent-chat.

**Agent Chat:** The "bullpen" where agents work together. All reasoning, status updates, and collaboration happens here visibly. Humans can interject to redirect work.

**Results:** Clean deliverables only. Reports, findings summaries, and final outputs.

**Alerts:** Critical notifications requiring human attention.

---

## Data Flow

### Command Flow

```
Human: !scan acme-corp.com
           │
           ▼
┌─────────────────────────┐
│    SCOPE VERIFICATION   │ ◄── CRITICAL SECURITY CHECK
│                         │
│  • Not .gov/.mil?       │
│  • In allowed scope?    │
│  • Human confirmed?     │
└───────────┬─────────────┘
            │ (if approved)
            ▼
┌─────────────────────────┐
│      ORCHESTRATOR       │
│                         │
│  Parse command          │
│  Create job context     │
│  Notify agents          │
└───────────┬─────────────┘
            │
            ▼
    Agents begin work in
    #am-corp-agent-chat
```

### Agent Collaboration Flow

```
🔍 Randy Recon
     │
     │ Finds assets, shares in #agent-chat
     │ Tags Victor for interesting findings
     ▼
⚠️ Victor Vuln
     │
     │ Scans for vulnerabilities
     │ Tags Ivy for threat context
     ▼
🧠 Ivy Intel
     │
     │ Provides context, adjusts priorities
     │ Tags Rita when findings are ready
     ▼
📊 Rita Report
     │
     │ Compiles everything
     │ Posts to #results
     ▼
    DONE
```

### Conversation Example

```
#am-corp-commands:
Human:            !scan acme-corp.com

#am-corp-agent-chat:
🔍 Randy Recon:   Starting recon on acme-corp.com. I'll update as I go.

🔍 Randy Recon:   Found 23 subdomains. Interesting: staging.acme-corp.com
                  has port 9200 open. @Victor worth checking.

⚠️ Victor Vuln:   Thanks Randy. Checking... That's an unauthenticated 
                  Elasticsearch instance. Severity: HIGH.

🧠 Ivy Intel:     @Victor FYI - that port has been exposed since 2023 
                  per Shodan. Recommend bumping to CRITICAL.

⚠️ Victor Vuln:   Agreed. @Rita, we have confirmed findings ready.

📊 Rita Report:   Drafting report now. Will post to #results shortly.

#am-corp-results:
📊 Rita Report:   [Report Embed]
                  Assessment Complete: acme-corp.com
                  1 CRITICAL, 2 HIGH severity findings
                  Full report attached.
```

---

## Component Details

### 1. Discord Interface Layer

**Technology:** discord.py

| Component | Responsibility |
|-----------|----------------|
| Bot Client | Connection management, event handling |
| Command Parser | Parse `!commands` from humans |
| Webhook Manager | Post agent messages to appropriate channels |
| Embed Builder | Format rich Discord embeds for findings |

### 2. Orchestrator

**Technology:** Python (CrewAI integration)

| Function | Description |
|----------|-------------|
| Command Router | Map commands to agent workflows |
| Scope Enforcer | Block unauthorized targets |
| Job Manager | Track active jobs and status |
| Handoff Coordinator | Manage agent-to-agent transitions |

### 3. Agent Layer

**Technology:** CrewAI + Gemini 1.5 Flash

Each agent runs as a CrewAI Agent with:
- Defined role, goal, and backstory (personality)
- Access to specific tools
- Discord webhook for posting updates
- Awareness of other agents for collaboration

### 4. n8n Automation Layer

**Technology:** n8n (Docker)

| Workflow | Purpose |
|----------|---------|
| Tool Executor | Run CLI tools (Nmap, Nuclei) in sandbox |
| API Integrator | Call external APIs (Shodan, VT) |
| Scheduler | Trigger periodic scans |

---

## API Contracts

### Command Input (Human → Orchestrator)

```json
{
  "command": "scan",
  "target": "example.com",
  "source": {
    "channel": "#am-corp-commands",
    "user": "human_operator",
    "timestamp": "2025-12-30T10:00:00Z"
  },
  "scope_verified": true
}
```

### Agent Message (Agent → Discord)

```json
{
  "agent": "randy_recon",
  "agent_name": "Randy Recon",
  "emoji": "🔍",
  "channel": "#am-corp-agent-chat",
  "message": "Found 23 subdomains. Interesting: staging.acme-corp.com",
  "mentions": ["victor_vuln"],
  "job_id": "uuid-v4",
  "timestamp": "2025-12-30T10:05:00Z"
}
```

### Finding Handoff (Agent → Agent)

```json
{
  "from_agent": "randy_recon",
  "to_agent": "victor_vuln",
  "job_id": "uuid-v4",
  "finding_type": "exposed_service",
  "data": {
    "host": "staging.acme-corp.com",
    "port": 9200,
    "service": "elasticsearch",
    "note": "Appears unauthenticated"
  }
}
```

---

## Infrastructure

### Docker Services

```yaml
services:
  n8n:
    port: 5678
    purpose: Workflow automation, tool execution
    
  orchestrator:
    port: 8000
    purpose: Agent coordination, command routing
    
  discord-bot:
    purpose: Discord connection (no external port)
```

### External Dependencies

| Service | Purpose | Required |
|---------|---------|----------|
| Discord API | Bot connection, webhooks | Yes |
| Gemini 1.5 Flash | Agent reasoning | Yes |
| Shodan API | Exposure data | Optional |
| VirusTotal API | Reputation data | Optional |

---

## Security Architecture

See [SECURITY.md](./SECURITY.md) for detailed security controls.

### Critical Controls

| Control | Implementation |
|---------|----------------|
| **Scope Verification** | All targets checked against blocklist and allowlist |
| **No .gov/.mil** | Hardcoded block on government/military domains |
| **Human Confirmation** | New targets require human approval |
| **Audit Logging** | All agent actions logged |
| **Visible Reasoning** | All agent work visible in Discord |

### Defense in Depth

```
┌─────────────────────────────────────────┐
│          INPUT VALIDATION               │
│  • Target format validation             │
│  • .gov/.mil blocklist (HARDCODED)      │
│  • Scope allowlist check                │
│  • Human confirmation for new targets   │
└─────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────┐
│          PROCESS CONTROLS               │
│  • Sandboxed tool execution             │
│  • Rate limiting on all operations      │
│  • Timeout enforcement                  │
│  • No exploitation capabilities         │
└─────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────┐
│          OUTPUT CONTROLS                │
│  • Sensitive data redaction             │
│  • Audit logging of all findings        │
│  • Human review before external share   │
└─────────────────────────────────────────┘
```

---

## Scalability Considerations

| Concern | Current Approach | Future Option |
|---------|------------------|---------------|
| Concurrent scans | Queue-based (1 at a time) | Worker pool |
| Large targets | Chunked processing | Distributed agents |
| Rate limits | Backoff + caching | Multiple API keys |
| Conversation history | In-memory | Database persistence |

---

## File Structure

```
am-corp/
├── src/
│   ├── main.py                 # Application entry point
│   ├── agents/                 # Agent definitions
│   │   ├── base.py            # Base agent class
│   │   ├── randy_recon.py     # Randy Recon agent
│   │   ├── victor_vuln.py     # Victor Vuln agent
│   │   ├── ivy_intel.py       # Ivy Intel agent
│   │   └── rita_report.py     # Rita Report agent
│   ├── discord_bot/           # Discord integration
│   │   ├── bot.py             # Bot client
│   │   ├── commands.py        # Command handlers
│   │   ├── webhooks.py        # Webhook utilities
│   │   └── embeds.py          # Embed formatters
│   ├── tools/                 # CrewAI tool wrappers
│   │   ├── nmap_tool.py
│   │   ├── nuclei_tool.py
│   │   └── ...
│   └── utils/                 # Shared utilities
│       ├── config.py          # Configuration
│       ├── logging.py         # Structured logging
│       └── validators.py      # Input validation
├── config/
│   └── agents.yaml            # Agent configuration
├── tests/
└── docs/
```

---

## Decision Records

See [/docs/adr/](./adr/) for Architecture Decision Records:

- [ADR-001: Use CrewAI for Orchestration](./adr/001-use-crewai-for-orchestration.md)
