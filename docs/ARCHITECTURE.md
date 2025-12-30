# AM-Corp System Architecture

## Overview

AM-Corp follows a modular, event-driven architecture where specialized AI agents communicate through a central orchestration layer, with Discord serving as the human interface.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           DISCORD                                   │
│                    (Human Interface Layer)                          │
│         Commands → Bot ← Webhooks ← Agent Messages                  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          n8n WORKFLOWS                              │
│                    (Automation & Routing)                           │
│    • Trigger handlers    • Tool integrations    • Scheduling        │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       CREWAI ORCHESTRATOR                           │
│                    (Agent Coordination)                             │
│         Task delegation → Agent execution → Result aggregation      │
└─────────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│  RECON AGENT  │       │  VULN AGENT   │       │ INTEL AGENT   │
│   • Nmap      │       │   • Nuclei    │       │   • OSINT     │
│   • Sublist3r │       │   • CVE DB    │       │   • Shodan    │
└───────────────┘       └───────────────┘       └───────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                        ┌───────────────┐
                        │ REPORT AGENT  │
                        │  • Aggregator │
                        │  • Formatter  │
                        └───────────────┘
```

---

## Component Details

### 1. Discord Interface Layer

**Purpose:** Human-in-the-loop command and monitoring interface

| Component | Technology | Responsibility |
|-----------|------------|----------------|
| Discord Bot | discord.py / discord.js | Receive commands, validate input |
| Webhooks | Discord Webhooks | Push agent status and results |
| Channels | Discord Channels | Separate channels per function |

**Channel Structure:**
```
#am-corp-commands     → User input / commands
#am-corp-agent-chat   → Agent reasoning / chatter
#am-corp-results      → Final outputs
#am-corp-alerts       → Errors / warnings
```

### 2. n8n Automation Layer

**Purpose:** Workflow automation, tool integration, and scheduling

| Workflow | Trigger | Actions |
|----------|---------|---------|
| Command Router | Discord webhook | Parse command → Route to appropriate agent |
| Scan Scheduler | Cron | Trigger scheduled reconnaissance |
| Tool Executor | HTTP request | Execute CLI tools (Nmap, Nuclei) |
| Result Formatter | Agent output | Format and post to Discord |

### 3. CrewAI Orchestration Layer

**Purpose:** Coordinate multi-agent workflows and manage task delegation

```python
# Example Crew Configuration
crew = Crew(
    agents=[recon_agent, vuln_agent, intel_agent, report_agent],
    tasks=[recon_task, vuln_task, intel_task, report_task],
    process=Process.sequential,  # or Process.hierarchical
    verbose=True
)
```

### 4. Specialist Agents

Each agent is isolated with specific tools and responsibilities:

| Agent | Primary Tools | Output Format |
|-------|---------------|---------------|
| Recon | Nmap, Sublist3r, httpx | JSON (hosts, ports, services) |
| Vuln | Nuclei, CVE lookup | JSON (vulnerabilities, severity) |
| Intel | OSINT tools, Shodan API | JSON (threat context, history) |
| Report | Template engine | Markdown / PDF |

---

## Data Flow

### Command Flow (Human → System)
```
1. User sends command in Discord (#am-corp-commands)
2. Discord Bot validates and forwards to n8n
3. n8n parses command and triggers appropriate workflow
4. CrewAI receives task and delegates to agents
5. Agents execute and post updates to Discord (#am-corp-agent-chat)
6. Final results posted to Discord (#am-corp-results)
```

### Agent Communication Flow
```
1. Recon Agent → Discovers targets → Passes to Vuln Agent
2. Vuln Agent → Scans for vulnerabilities → Passes to Intel Agent
3. Intel Agent → Enriches with context → Passes to Report Agent
4. Report Agent → Generates report → Posts to Discord
```

---

## API Contracts

### n8n → CrewAI
```json
{
  "command": "scan",
  "target": "example.com",
  "options": {
    "depth": "full",
    "agents": ["recon", "vuln"]
  },
  "callback_url": "https://discord.webhook.url",
  "request_id": "uuid-v4"
}
```

### Agent → Discord (via Webhook)
```json
{
  "agent": "recon",
  "status": "in_progress",
  "message": "Starting subdomain enumeration...",
  "request_id": "uuid-v4",
  "timestamp": "2025-12-30T10:00:00Z"
}
```

---

## Infrastructure

### Docker Services
```yaml
services:
  - n8n (port 5678)
  - crewai-orchestrator (port 8000)
  - discord-bot (no external port)
```

### External Dependencies
- Gemini 1.5 Flash API
- Discord API
- Optional: Shodan API, VirusTotal API

---

## Security Architecture

See [SECURITY.md](./SECURITY.md) for detailed security controls.

| Layer | Control |
|-------|---------|
| Input | Command validation, scope verification |
| Process | Sandboxed tool execution, rate limiting |
| Output | Sensitive data redaction, audit logging |

---

## Scalability Considerations

| Concern | Current Approach | Future Option |
|---------|------------------|---------------|
| Concurrent scans | Queue-based (1 at a time) | Worker pool |
| Large targets | Chunked processing | Distributed agents |
| Rate limits | Backoff + caching | Multiple API keys |

---

## Decision Records

See [/docs/adr/](./adr/) for Architecture Decision Records explaining key choices.

