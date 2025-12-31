# AM-Corp Product Requirements Document

## Project Overview

**Project Name:** AM-Corp  
**Version:** 0.1.0  
**Last Updated:** December 31, 2025  
**Status:** In Development (Phase 1)

---

## Vision

A cybersecurity company staffed almost entirely by AI agents. A single human operator manages a team of specialized AI agents who collaborate through natural conversation in Discord. The agents work together like human colleagues - discussing findings, asking questions, and delivering professional security assessments.

---

## Core Philosophy

| Principle | Description |
|-----------|-------------|
| **Conversational Collaboration** | Agents communicate naturally in Discord, visible to the human operator. They discuss, question, and collaborate like a real security team. |
| **Human as Manager** | The human provides direction and oversight, not micromanagement. Agents execute autonomously with the human available for decisions. |
| **Specialized Roles** | Each agent (Randy, Victor, Ivy, Rita) has a distinct personality and expertise to minimize hallucination and maximize accuracy. |
| **Transparent Reasoning** | All agent thinking and collaboration is visible in Discord for auditability and trust-building. |
| **Low Cost** | Self-hosted open-source tools and Gemini Flash (free tier) minimize operational costs. |

---

## The Team

AM-Corp is staffed by four AI agents:

| Agent | Name | Role | Personality |
|-------|------|------|-------------|
| 🔍 | **Randy Recon** | Reconnaissance Specialist | Methodical, thorough, reports findings in real-time |
| ⚠️ | **Victor Vuln** | Vulnerability Analyst | Cautious, detail-oriented, explains risks clearly |
| 🧠 | **Ivy Intel** | Threat Intelligence Analyst | Analytical, connects dots, provides context |
| 📊 | **Rita Report** | Security Report Analyst | Professional, concise, audience-aware |

---

## Target Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| **Orchestration** | CrewAI (Python) | Multi-agent framework for coordinating specialist agents |
| **Automation/Tools** | n8n (Docker) | Visual workflow automation + Linux CLI tools |
| **Security Tools** | Nmap, Nuclei | Open-source reconnaissance and vulnerability scanning |
| **Interface** | Discord (Bot + Webhooks) | Conversational interface for agent collaboration |
| **LLM** | Gemini 1.5 Flash | Cost-effective AI model for agent reasoning |

---

## Problem Statement

Traditional cybersecurity operations require:
- Large teams of specialized security professionals
- Expensive enterprise tooling
- Significant manual effort for routine tasks
- Constant context-switching between tools

**AM-Corp solves this by:**
- Replacing human task execution with AI agents who collaborate naturally
- Providing a single interface (Discord) where all work happens visibly
- Enabling one human to manage what traditionally requires a team
- Minimizing costs through open-source tooling and free-tier AI

---

## Target Users

| User Type | Description |
|-----------|-------------|
| **Primary** | Solo security operators / consultants |
| **Secondary** | Small security teams (2-5 people) |
| **Tertiary** | Bug bounty hunters |

---

## Interaction Model

### Discord Channels

| Channel | Purpose |
|---------|---------|
| `#am-corp-commands` | Human commands (`!scan`, `!status`) - humans only |
| `#am-corp-agent-chat` | Agent collaboration and status updates |
| `#am-corp-results` | Final deliverables and reports |
| `#am-corp-alerts` | Errors and security warnings |

### Command Shortcuts

Humans can issue structured commands for reliable control:

| Command | Description |
|---------|-------------|
| `!scan <target>` | Start full security assessment |
| `!recon <target>` | Reconnaissance only |
| `!status` | Current job status |
| `!abort` | Stop current job |
| `!scope add <domain>` | Authorize a target |
| `!help` | Show available commands |

### Natural Conversation

Agents can be directed through natural language:
- "Hey team, let's check out acme-corp.com"
- "@Victor focus on the API first"
- "Rita, make sure the executive summary highlights the Elasticsearch issue"

---

## Core Features (MVP)

### 🔍 Randy Recon - Reconnaissance
- Subdomain enumeration
- Port scanning (Nmap integration)
- Technology fingerprinting
- Real-time status updates to Discord

### ⚠️ Victor Vuln - Vulnerability Analysis
- Nuclei template scanning
- CVE correlation and lookup
- Risk scoring (CVSS)
- Remediation recommendations

### 🧠 Ivy Intel - Threat Intelligence
- OSINT gathering (Shodan, VirusTotal)
- Historical breach data lookup
- Exposure timeline analysis
- Risk priority adjustments based on context

### 📊 Rita Report - Reporting
- Aggregate findings from all agents
- Executive summary generation
- Technical detail documentation
- Prioritized remediation roadmap

---

## Example Workflow

```
#am-corp-commands:
Human:            !scan acme-corp.com

#am-corp-agent-chat:
🔍 Randy Recon:   On it! Starting recon on acme-corp.com. I'll update as I go.

🔍 Randy Recon:   Found 23 subdomains. Interesting one: staging.acme-corp.com
                  has port 9200 open. @Victor worth checking.

⚠️ Victor Vuln:   Thanks Randy. Checking that port... Confirmed - it's an
                  unauthenticated Elasticsearch instance. Severity: HIGH.

🧠 Ivy Intel:     @Victor context: that port has been exposed since 2023
                  per Shodan. Long exposure = higher risk. Recommend CRITICAL.

⚠️ Victor Vuln:   Agreed, bumping to CRITICAL. @Rita, findings ready for you.

📊 Rita Report:   Got it. Drafting report now.

#am-corp-results:
📊 Rita Report:   [Assessment Complete: acme-corp.com]
                  1 CRITICAL, 2 HIGH severity findings
                  Full report attached.
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Time to complete basic recon | < 10 minutes |
| Agent hallucination rate | < 5% |
| Monthly operational cost | < $50 |
| Human intervention required | < 20% of workflows |
| Agent conversation quality | Natural, professional |

---

## Constraints & Assumptions

### Constraints
- Must operate within Gemini Flash free tier limits
- Discord rate limits for webhooks/bot messages
- Self-hosted infrastructure (no cloud vendor lock-in)
- No scanning of .gov or .mil domains (hardcoded block)

### Assumptions
- Operators have basic security knowledge
- Target systems are authorized for testing
- Docker environment is available for deployment

---

## Out of Scope (v1.0)

- Automated exploitation
- Real-time attack simulation
- Multi-tenant SaaS deployment
- Mobile application interface
- Voice interaction
- Slack/Teams integration (Discord only for MVP)

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM hallucinations | High | Specialized agents + tool grounding + visible reasoning |
| Rate limiting | Medium | Queue system + caching + backoff |
| Tool failures | Medium | Graceful degradation + alerting |
| Unauthorized scanning | Critical | Scope verification + human confirmation + audit logging |
| Agent "off-character" | Medium | Clear personality prompts + conversation guidelines |

---

## Timeline & Phases

See individual phase documents in `/docs/phases/` for detailed breakdowns.

| Phase | Focus | Duration |
|-------|-------|----------|
| **Phase 1** | Core infrastructure + Discord bot + Randy Recon | 2 weeks |
| **Phase 2** | Victor Vuln + Ivy Intel agents | 2 weeks |
| **Phase 3** | Rita Report + Polish | 1 week |
| **Phase 4** | Testing + Documentation | 1 week |

---

## References

- [CrewAI Documentation](https://docs.crewai.com/)
- [n8n Documentation](https://docs.n8n.io/)
- [Discord Developer Portal](https://discord.com/developers/docs)
- [Gemini API](https://ai.google.dev/)
