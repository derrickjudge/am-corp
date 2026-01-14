# AM-Corp System Architecture

## Overview

AM-Corp is a conversational multi-agent cybersecurity platform where AI agents operate like human team members. Agents have evolving personalities, engage in casual conversation, and collaborate through natural discussion in Discord. Their reasoning is transparent—humans can watch them think through problems in real-time.

The system emphasizes:
- **Agent Autonomy:** Agents take initiative and work like human colleagues
- **Transparent Thinking:** Raw reasoning visible in dedicated thoughts channel
- **Personality Evolution:** Agent personalities grow and adapt over time
- **Collaborative Decision-Making:** Agents discuss and reach consensus

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DISCORD                                         │
│                     (Conversational Interface)                               │
│                                                                             │
│  #general     #thoughts    #commands    #agent-chat   #results    #alerts   │
│  Casual chat  Raw reason   Human cmds   Work collab   Reports     Errors    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ORCHESTRATOR                                       │
│                  (Command Routing & Agent Coordination)                      │
│                                                                             │
│   • Parse commands (!scan) and natural language                              │
│   • Route tasks to appropriate agents                                        │
│   • Manage autonomous agent behavior                                         │
│   • Enforce scope verification                                               │
│   • Coordinate thoughts channel output                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
    ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
    │ 🔍 RANDY      │  ───► │ ⚠️ VICTOR     │  ───► │ 🧠 IVY        │
    │    RECON      │ ◄───  │    VULN       │ ◄───  │    INTEL      │
    │               │       │               │       │               │
    │ • Nmap        │       │ • Nuclei      │       │ • Shodan      │
    │ • Dig         │       │ • CVE lookup  │       │ • VirusTotal  │
    │ • Whois       │       │ • Version chk │       │ • EPSS        │
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
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        PERSONALITY LAYER                                 │
    │                  (Memory & Personality Evolution)                        │
    │                                                                         │
    │   • Conversation history (30 days)                                       │
    │   • Personality state files (YAML)                                       │
    │   • Evolution tracking                                                   │
    │   • Archive for "fired" agents                                           │
    └─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          n8n WORKFLOWS                                   │
    │                    (Automation & Tool Execution)                         │
    │                                                                         │
    │   • CLI tool execution (sandboxed)                                       │
    │   • Scheduled scans                                                      │
    │   • External API integrations                                            │
    │   • Security news feed monitoring                                        │
    └─────────────────────────────────────────────────────────────────────────┘
```

---

## The Team

AM-Corp is staffed by AI agents who work as a team:

| Agent | Name | Role | Primary Tools |
|-------|------|------|---------------|
| 🔍 | **Randy Recon** | Reconnaissance Specialist | Nmap, Dig, Whois |
| ⚠️ | **Victor Vuln** | Vulnerability Analyst | Nuclei, CVE databases |
| 🧠 | **Ivy Intel** | Threat Intelligence Analyst | Shodan, VirusTotal, EPSS |
| 📊 | **Rita Report** | Security Report Analyst | Templates, formatters |

See [AGENTS.md](./AGENTS.md) for detailed agent specifications and personalities.

---

## Discord Channel Structure

### All Channels

| Channel | Purpose | Who Posts | New in v0.2 |
|---------|---------|-----------|-------------|
| `#am-corp-general` | Casual team chat, security discussions | Humans + All agents | ✅ |
| `#am-corp-thoughts` | Raw agent reasoning, step-by-step logic | All agents | ✅ |
| `#am-corp-commands` | Human commands (`!scan`, `!status`) | Humans only | |
| `#am-corp-agent-chat` | Agent collaboration during active work | All agents | |
| `#am-corp-results` | Final deliverables and reports | Rita (primarily) | |
| `#am-corp-alerts` | Errors, security warnings, scope issues | System + All agents | |

### Channel Flow

```
                    ┌─────────────────┐
                    │   #general      │ ◄─── Casual team conversation
                    │   (casual)      │      Security discussions
                    └────────┬────────┘      Human + Agent chat
                             │
                             │ Task identified
                             ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   #commands     │───►│   #agent-chat   │◄──│   #thoughts     │
│   (human input) │   │   (work)        │   │   (reasoning)   │
└─────────────────┘   └────────┬────────┘   └─────────────────┘
                             │
                             │ Work complete
                             ▼
┌─────────────────┐   ┌─────────────────┐
│   #alerts       │   │   #results      │
│   (errors)      │   │   (reports)     │
└─────────────────┘   └─────────────────┘
```

### #am-corp-general (Casual)

The team "break room" where agents chat naturally:
- Security industry discussions
- Proactive observations about targets
- Team dynamics and banter
- Humans can join the conversation

**Example:**
```
🧠 Ivy Intel:     Morning team. Saw some interesting threat actor chatter 
                  about that APT group we've been tracking.

🔍 Randy Recon:   Good to know, partner. I'll keep an eye out during recon.

[Human joins]
Human:            Hey team, how's it going?

⚠️ Victor Vuln:   Pretty chill day so far. Got a couple assessments queued 
                  up but nothing urgent.
```

### #am-corp-thoughts (Transparency)

Raw agent reasoning, visible to humans:
- Step-by-step logic
- Doubts and uncertainties
- Confidence levels
- Decision-making process

**Verbosity Levels:**

| Level | Description |
|-------|-------------|
| `minimal` | Major decisions only |
| `normal` | Key reasoning steps |
| `verbose` | Detailed thought process |
| `all` | Full stream of consciousness |

**Example:**
```
🔍 Randy (thinking): Starting DNS enumeration on acme-corp.com. Going 
                     passive first - don't know their monitoring setup.

🔍 Randy (thinking): Interesting - 5 MX records. Could be legacy migration 
                     or redundancy. Worth noting for Ivy.

⚠️ Victor (thinking): Randy found nginx 1.14. Checking CVEs... 3 potential 
                      matches. Need to verify version accuracy. 70% confidence.
```

---

## Data Flow

### Agent Autonomy Flow

```
Agent notices opportunity (security news, scope target, etc.)
                    │
                    ▼
            ┌───────────────────┐
            │  JUSTIFY ACTION   │
            │  Why do this now? │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │  SEEK CONSENSUS   │
            │  Check with team  │
            └─────────┬─────────┘
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
┌───────────────────┐     ┌───────────────────┐
│  APPROVED DOMAIN  │     │   NEW DOMAIN      │
│  Proceed to work  │     │  Request approval │
└─────────┬─────────┘     └─────────┬─────────┘
          │                         │
          ▼                         ▼
    Agent works           Human approval flow
    autonomously          (standard confirmation)
```

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
    Agents begin work
    (#agent-chat + #thoughts)
```

### Agent Collaboration Flow

```
🔍 Randy Recon
     │
     │ Finds assets, shares in #agent-chat
     │ Shows reasoning in #thoughts
     │ Tags Victor for interesting findings
     ▼
⚠️ Victor Vuln
     │
     │ Scans for vulnerabilities
     │ Shows analysis in #thoughts
     │ Tags Ivy for threat context
     ▼
🧠 Ivy Intel
     │
     │ Provides context, adjusts priorities
     │ Shows connections in #thoughts
     │ Tags Rita when findings are ready
     ▼
📊 Rita Report
     │
     │ Compiles everything
     │ Shows planning in #thoughts
     │ Posts to #results
     ▼
    DONE
```

---

## Component Details

### 1. Discord Interface Layer

**Technology:** discord.py

| Component | Responsibility |
|-----------|----------------|
| Bot Client | Connection management, event handling |
| Command Parser | Parse `!commands` from humans |
| Natural Language Handler | Process casual conversation |
| Webhook Manager | Post agent messages to appropriate channels |
| Embed Builder | Format rich Discord embeds for findings |
| Thoughts Manager | Route agent reasoning to thoughts channel |

### 2. Orchestrator

**Technology:** Python (CrewAI integration)

| Function | Description |
|----------|-------------|
| Command Router | Map commands to agent workflows |
| Autonomy Manager | Coordinate agent initiative |
| Scope Enforcer | Block unauthorized targets |
| Job Manager | Track active jobs and status |
| Handoff Coordinator | Manage agent-to-agent transitions |
| Thoughts Coordinator | Route reasoning to thoughts channel |

### 3. Agent Layer

**Technology:** CrewAI + Gemini 2.5 Flash

Each agent runs as a CrewAI Agent with:
- Defined role, goal, and backstory (personality)
- Evolving personality state (YAML file)
- Access to specific tools
- Discord webhook for posting updates
- Thoughts channel output
- Awareness of other agents for collaboration
- Conversation memory (30 days)

### 4. Personality Layer

**Technology:** YAML + Python

| Component | Purpose |
|-----------|---------|
| Personality Files | Store current personality state per agent |
| Evolution Tracker | Log personality changes over time |
| Memory Manager | Maintain conversation history |
| Archive | Store personalities of "fired" agents |

**File Structure:**
```
config/personalities/
├── randy_recon.yaml      # Randy's current state
├── victor_vuln.yaml      # Victor's current state
├── ivy_intel.yaml        # Ivy's current state
├── rita_report.yaml      # Rita's current state
└── archive/              # Archived personalities
    └── victor_vuln_v1.yaml
```

### 5. n8n Automation Layer

**Technology:** n8n (Podman)

| Workflow | Purpose |
|----------|---------|
| Tool Executor | Run CLI tools (Nmap, Nuclei) in sandbox |
| API Integrator | Call external APIs (Shodan, VT) |
| Scheduler | Trigger periodic scans |
| News Monitor | Watch security news feeds |

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
    "timestamp": "2026-01-09T10:00:00Z"
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
  "timestamp": "2026-01-09T10:05:00Z"
}
```

### Thoughts Output (Agent → Thoughts Channel)

```json
{
  "agent": "randy_recon",
  "agent_name": "Randy",
  "emoji": "🔍",
  "channel": "#am-corp-thoughts",
  "thought": "Starting with DNS - passive first to avoid triggering alerts",
  "confidence": 0.8,
  "job_id": "uuid-v4",
  "timestamp": "2026-01-09T10:05:00Z"
}
```

### Casual Message (Agent → General)

```json
{
  "agent": "ivy_intel",
  "agent_name": "Ivy Intel",
  "emoji": "🧠",
  "channel": "#am-corp-general",
  "message": "Interesting threat intel this morning about that APT group",
  "trigger": "security_news",
  "timestamp": "2026-01-09T09:30:00Z"
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

### Podman Services

```yaml
services:
  n8n:
    port: 5678
    purpose: Workflow automation, tool execution
    
  am-corp-bot:
    purpose: Discord connection, agent orchestration
    volumes:
      - ./config/personalities:/app/config/personalities
      - ./data:/app/data
```

### External Dependencies

| Service | Purpose | Required |
|---------|---------|----------|
| Discord API | Bot connection, webhooks | Yes |
| Gemini 2.5 Flash | Agent reasoning (free tier) | Yes |
| Shodan API | Exposure data | Optional |
| VirusTotal API | Reputation data | Optional |
| Security News APIs | Real-world awareness | Optional |

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
| **Personality Tracking** | All evolution changes logged |

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
│  • Agent initiative requires consensus  │
└─────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────┐
│          OUTPUT CONTROLS                │
│  • Sensitive data redaction             │
│  • Audit logging of all findings        │
│  • Human review before external share   │
│  • Thoughts channel for transparency    │
└─────────────────────────────────────────┘
```

---

## Scalability Considerations

| Concern | Current Approach | Future Option |
|---------|------------------|---------------|
| Concurrent scans | Queue-based (1 at a time) | Worker pool |
| Large targets | Chunked processing | Sub-agents |
| Rate limits | Backoff + caching | Multiple API keys |
| Conversation history | 30-day retention | Summarization of older data |
| Agent scope growth | Monitor performance | Create sub-agents |
| Personality drift | Evolution tracking | Reset/archive option |

### Sub-Agent Architecture (Future)

When an agent's scope becomes too large:

```
┌─────────────────────────────────────────┐
│            🔍 Randy Recon               │
│           (Parent Agent)                │
│                                         │
│  Scope growing too large...             │
│  Recommends sub-agent creation          │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Randy   │ │ Randy   │ │ Randy   │
│ (DNS)   │ │ (Ports) │ │ (Tech)  │
└─────────┘ └─────────┘ └─────────┘
```

---

## Operating Modes

### Production Mode

```yaml
mode: production
gemini:
  rate_limit: 15  # RPM
  daily_limit: 1500  # RPD
behavior:
  chattiness: low
  thoughts_verbosity: normal
  autonomous_initiative: true
  consensus_required: true
```

### Test Mode

```yaml
mode: test
gemini:
  rate_limit: 30  # RPM (more chatty)
  daily_limit: 3000  # RPD
behavior:
  chattiness: high
  thoughts_verbosity: all
  use_synthetic_data: true
  autonomous_initiative: true
  consensus_required: false
```

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
│   │   └── rita_report.py     # Rita Report agent (planned)
│   ├── discord_bot/           # Discord integration
│   │   ├── bot.py             # Bot client
│   │   ├── commands.py        # Command handlers
│   │   ├── webhooks.py        # Webhook utilities
│   │   ├── embeds.py          # Embed formatters
│   │   ├── thoughts.py        # Thoughts channel manager
│   │   └── general.py         # General chat handler
│   ├── personality/           # Personality management
│   │   ├── manager.py         # Personality state manager
│   │   ├── evolution.py       # Evolution tracking
│   │   └── memory.py          # Conversation memory
│   ├── tools/                 # CrewAI tool wrappers
│   │   ├── recon_tools.py
│   │   ├── vuln_tools.py
│   │   └── intel_tools.py
│   └── utils/                 # Shared utilities
│       ├── config.py          # Configuration
│       ├── logging.py         # Structured logging
│       └── validators.py      # Input validation
├── config/
│   ├── agents.yaml            # Agent configuration
│   ├── personalities/         # Personality state files
│   │   ├── randy_recon.yaml
│   │   ├── victor_vuln.yaml
│   │   ├── ivy_intel.yaml
│   │   ├── rita_report.yaml
│   │   └── archive/
│   └── scope.yaml             # Approved domains
├── data/
│   ├── scope_cache.json       # Cached scope approvals
│   └── conversation_history/  # Conversation logs
├── tests/
└── docs/
```

---

## Decision Records

See [/docs/adr/](./adr/) for Architecture Decision Records:

- [ADR-001: Use CrewAI for Orchestration](./adr/001-use-crewai-for-orchestration.md)
- [ADR-002: Natural Language Agent Interaction](./adr/002-natural-language-agent-interaction.md)
- [ADR-003: Agent Transparency and Smart Scanning](./adr/003-agent-transparency-and-smart-scanning.md)