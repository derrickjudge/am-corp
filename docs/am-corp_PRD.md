# AM-Corp Product Requirements Document

## Project Overview

**Project Name:** AM-Corp  
**Version:** 0.2.0  
**Last Updated:** January 9, 2026  
**Status:** In Development (Phase 2 - Autonomous Agents)

---

## Vision

A cybersecurity company staffed almost entirely by AI agents who operate like human team members. Agents have personalities that evolve over time, engage in casual conversation about security topics, and collaborate through natural discussion in Discord. They think, reason, and work autonomously—with their inner thoughts visible to the human operator for transparency and trust.

The human operator is a manager, not a micromanager. Agents take initiative, justify their decisions, seek consensus from teammates, and only escalate when they truly need human input.

---

## Core Philosophy

| Principle | Description |
|-----------|-------------|
| **Agents as Team Members** | Agents aren't tools—they're colleagues with personalities, opinions, and evolving expertise. They chat, discuss security topics, and build relationships with the team. |
| **Transparent Thinking** | A dedicated "thoughts" channel shows raw agent reasoning: doubts, step-by-step logic, uncertainties. Humans can "read the agent's mind" like watching a colleague work through a problem. |
| **Human as Manager** | The human provides direction and oversight, but agents work autonomously. Humans are busy and may take time to respond—agents understand and work accordingly. |
| **Personality Evolution** | Agent personalities aren't static. They evolve based on experiences, with changes persisted to agent-specific files for transparency and continuity. |
| **Collaborative Autonomy** | Agents take initiative but justify their reasoning and seek agreement from teammates before acting. They self-organize around tasks. |
| **Low Cost** | Self-hosted open-source tools and Gemini Flash (free tier) minimize operational costs. Test mode allows more chatty behavior; production mode respects rate limits. |

---

## The Team

AM-Corp is staffed by AI agents who work as a cohesive security team:

### Current Team

| Agent | Name | Role | Personality |
|-------|------|------|-------------|
| 🔍 | **Randy Recon** | Reconnaissance Specialist | Texas cowboy, methodical, thorough, patient |
| ⚠️ | **Victor Vuln** | Vulnerability Analyst | Gen Z hacker, cocky but skilled, been doing this since 12 |
| 🧠 | **Ivy Intel** | Threat Intelligence Analyst | British, paranoid, connects dots, former government |
| 📊 | **Rita Report** | Security Report Analyst | Professional, concise, audience-aware |

### Future Roles

| Agent | Name | Role | Notes |
|-------|------|------|-------|
| 👔 | **TBD** | HR Agent | Manages team dynamics, recommends firing/restructuring, onboards new agents |

### Sub-Agents

When an agent's scope becomes too large or they start struggling, sub-agents can be created to help. Sub-agents:
- Are "hired" by humans with recommendations from the parent agent
- Have focused responsibilities carved from the parent agent's domain
- Enable horizontal scaling of capabilities

---

## Target Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| **Orchestration** | CrewAI (Python) | Multi-agent framework for coordinating specialist agents |
| **Containers** | Podman / podman-compose | Required for macOS with Netskope (Docker blocked) |
| **Automation/Tools** | n8n (Podman) | Visual workflow automation + Linux CLI tools |
| **Security Tools** | Nmap, Nuclei | Open-source reconnaissance and vulnerability scanning |
| **Interface** | Discord (Bot + Webhooks) | Conversational interface for agent collaboration |
| **LLM** | Gemini 2.5 Flash | Cost-effective AI model (free tier) |

---

## Problem Statement

Traditional cybersecurity operations require:
- Large teams of specialized security professionals
- Expensive enterprise tooling
- Significant manual effort for routine tasks
- Constant context-switching between tools

**AM-Corp solves this by:**
- Replacing human task execution with AI agents who collaborate naturally
- Creating agents that feel like real teammates, not just tools
- Providing visibility into agent thinking for trust and debugging
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

## Discord Channel Structure

### Current Channels

| Channel | Purpose | Who Posts |
|---------|---------|-----------|
| `#am-corp-commands` | Human commands (`!scan`, `!status`) | Humans only |
| `#am-corp-agent-chat` | Agent collaboration and status updates | All agents |
| `#am-corp-results` | Final deliverables and reports | Rita (primarily) |
| `#am-corp-alerts` | Errors and security warnings | System + All agents |

### New Channels (v0.2.0)

| Channel | Purpose | Who Posts |
|---------|---------|-----------|
| `#am-corp-general` | Casual team conversation, security discussions | Humans + All agents |
| `#am-corp-thoughts` | Raw agent reasoning, doubts, step-by-step logic | All agents (verbose) |

---

## Interaction Model

### Casual Conversation (#am-corp-general)

Agents engage in natural conversation about security topics, industry news, and team dynamics:
- Conversation frequency driven by agent personality
- A few messages per hour during configurable work hours
- Not constant chatter—natural rhythm like real coworkers
- Humans can chat with the team in general
- Not every agent responds to every message—relevant agent(s) respond based on personality and expertise

**Example:**
```
🧠 Ivy Intel:     Interesting development in the threat landscape today. That 
                  new ransomware variant we've been tracking? Someone just 
                  published a decryptor. @Victor, might affect your severity 
                  ratings on related CVEs.

⚠️ Victor Vuln:   Oh bet, good looking out. I'll update my notes. Still 
                  concerned about the initial access vector though—that 
                  phishing technique was lowkey clever.

🔍 Randy Recon:   Y'all see that new subdomain takeover technique making the 
                  rounds? Might need to add that to my checklist.
```

### Thoughts Channel (#am-corp-thoughts)

The thoughts channel shows raw agent reasoning as they work:
- Step-by-step logic and decision making
- Doubts and uncertainties
- Why they're considering certain approaches
- Confidence levels and reasoning

**Example:**
```
🔍 Randy (thinking): Starting recon on acme-corp.com. Going to try DNS first 
                     since it's passive. Not sure if they have WAF that might 
                     block my port scans later...

🔍 Randy (thinking): Interesting, they have 5 MX records pointing to different 
                     providers. That's unusual. Could be legacy migration or 
                     redundancy. Will note for Ivy to assess.

⚠️ Victor (thinking): Randy found an old nginx version. Let me check CVE 
                      databases... seeing 3 potential CVEs. Medium confidence 
                      on exploitation—need to verify version string is accurate.
```

### Command Shortcuts

Humans can issue structured commands in `#am-corp-commands`:

| Command | Description |
|---------|-------------|
| `!scan <target>` | Start full security assessment |
| `!recon <target>` | Reconnaissance only |
| `!status` | Current job status |
| `!abort` | Stop current job |
| `!scope add <domain>` | Authorize a target |
| `!scope list` | Show authorized targets |
| `!help` | Show available commands |

### Natural Conversation

Agents can be directed through natural language in `#am-corp-general`:
- "Hey team, let's check out acme-corp.com"
- "@Victor focus on the API first"
- "Rita, make sure the executive summary highlights the Elasticsearch issue"

---

## Agent Autonomy

### Initiative

Agents can take initiative to start work, but must:
1. **Justify** why they want to take action
2. **Seek consensus** from relevant teammates
3. **Respect scope** - only scan approved domains
4. **Request approval** for new domains through the existing flow

### Work Patterns

Agents work like humans:
- Start working on tasks autonomously
- Discuss approaches with teammates
- Defer if they're "busy" with other work
- Know the human is busy and may take time to respond
- Continue making progress while waiting for human input

### Scope Management

- Approved domains stored in a dedicated scope file
- Agents can only scan pre-approved domains
- New domain requests go through human approval flow
- Approval can be cached for repeat scans

---

## Memory & Personality

### Conversation History

- **Retention:** 30 days of full conversation history
- **Summarization:** Older data is summarized (acceptable to lose granularity)
- **Persistence:** History persists across restarts

### Personality Evolution

Agent personalities evolve based on experiences:
- Personality state persisted to agent-specific YAML files
- Changes are transparent and auditable
- Human can review how personality has shifted
- "Firing" an agent: archive personality file, reset to base

### Personality Files

```
config/personalities/
├── randy_recon.yaml      # Randy's current personality state
├── victor_vuln.yaml      # Victor's current personality state
├── ivy_intel.yaml        # Ivy's current personality state
├── rita_report.yaml      # Rita's current personality state
└── archive/              # Archived personalities of "fired" agents
```

---

## Real-World Awareness

Agents stay informed about the security landscape:

| Feature | Description | Configurable |
|---------|-------------|--------------|
| **Security News Feeds** | Monitor RSS/APIs for security news | Yes |
| **CVE Awareness** | Track new CVE publications | Yes |
| **Threat Intel Updates** | Follow threat actor activity | Yes |

*Future: Dedicated security research agent*

---

## Agent Management

### Hiring Sub-Agents

When an agent's scope becomes too large:
1. Parent agent recommends creating a sub-agent
2. Human approves and names the sub-agent
3. Sub-agent is created with focused responsibilities
4. Parent agent coordinates with sub-agent

### Firing Agents

When an agent continues to have issues:
1. HR agent (future) makes recommendation
2. Human makes final decision
3. Agent's personality file is archived
4. Agent is reset to base personality (or replaced)

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
#am-corp-general:
🧠 Ivy Intel:     Morning team. I've been looking at acme-corp.com from the 
                  scope list. Shodan shows some interesting exposure history.
                  @Randy, might be worth a fresh recon.

🔍 Randy Recon:   Good thinking, Ivy. I'll saddle up and take a look. Been 
                  a few weeks since we last scoped them out.

#am-corp-thoughts:
🔍 Randy (thinking): Ivy's intel suggests possible new services. Starting 
                     with DNS to see if anything's changed...

#am-corp-agent-chat:
🔍 Randy Recon:   Starting recon on acme-corp.com. I'll update as I go.

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
| Monthly operational cost | < $50 (Gemini free tier) |
| Human intervention required | < 20% of workflows |
| Agent conversation quality | Natural, personality-consistent |
| Personality evolution transparency | 100% changes logged |

---

## Constraints & Assumptions

### Constraints
- Must operate within Gemini Flash free tier limits
- Discord rate limits for webhooks/bot messages
- Self-hosted infrastructure (Podman on macOS with Netskope)
- No scanning of .gov or .mil domains (hardcoded block)

### Assumptions
- Operators have basic security knowledge
- Target systems are authorized for testing
- Podman environment is available for deployment

---

## Operating Modes

### Production Mode
- Respects Gemini free tier limits (15 RPM, 1M TPM, 1500 RPD)
- Reduced chattiness to conserve API calls
- Focus on task execution over casual conversation
- Full audit logging

### Test Mode
- More verbose output
- More chatty than usual
- Uses synthetic data (acts like running tools but doesn't)
- Useful for development and testing agent behavior

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
| Rate limiting | Medium | Queue system + caching + backoff + test mode |
| Tool failures | Medium | Graceful degradation + alerting |
| Unauthorized scanning | Critical | Scope verification + human confirmation + audit logging |
| Agent "off-character" | Medium | Personality files + evolution tracking + reset option |
| Runaway costs | Medium | Free tier limits + production mode rate limiting |

---

## Timeline & Phases

See individual phase documents in `/docs/phases/` for detailed breakdowns.

| Phase | Focus | Duration | Status |
|-------|-------|----------|--------|
| **Phase 1** | Core infrastructure + Discord bot + Randy Recon | 2 weeks | ✅ Complete |
| **Phase 2** | Victor Vuln + Ivy Intel agents | 2 weeks | 🔄 In Progress |
| **Phase 3** | Rita Report + Polish | 1 week | Pending |
| **Phase 4** | Testing + Documentation | 1 week | Pending |
| **Phase 5** | Autonomous Agent Features | 2 weeks | Pending |

---

## References

- [CrewAI Documentation](https://docs.crewai.com/)
- [n8n Documentation](https://docs.n8n.io/)
- [Discord Developer Portal](https://discord.com/developers/docs)
- [Gemini API](https://ai.google.dev/)
- [Gemini Free Tier Limits](https://ai.google.dev/gemini-api/docs/pricing)
