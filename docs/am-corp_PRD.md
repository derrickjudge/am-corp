# AM-Corp Product Requirements Document

## Project Overview

**Project Name:** AM-Corp  
**Version:** 0.1.0  
**Last Updated:** December 30, 2025  
**Status:** Planning Phase

---

## Vision

A lean cybersecurity startup where a single human orchestrates a swarm of specialist AI agents to perform offensive security, reconnaissance, and threat intelligence.

---

## Core Philosophy

| Principle | Description |
|-----------|-------------|
| **Agent-First** | Humans manage workflows, not individual tasks. Agents handle execution autonomously. |
| **Specialization** | Individual agents (Recon, Vuln, Intel, Report) perform discrete roles to minimize hallucination and maximize accuracy. |
| **Transparency** | All agent reasoning and "chatter" occurs in Discord for human auditability and oversight. |
| **Low Cost** | Utilize self-hosted open-source tools and Gemini Flash (free tier) to minimize operational burn. |

---

## Target Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| **Orchestration** | CrewAI (Python) | Multi-agent framework for coordinating specialist agents |
| **Automation/Tools** | n8n (Docker) | Visual workflow automation + Linux CLI tools |
| **Security Tools** | Nmap, Nuclei | Open-source reconnaissance and vulnerability scanning |
| **Interface** | Discord (Webhooks + Bot) | Human-in-the-loop interface for commands and monitoring |
| **LLM** | Gemini 1.5 Flash | Cost-effective AI model for agent reasoning |

---

## Problem Statement

Traditional cybersecurity operations require:
- Large teams of specialized security professionals
- Expensive enterprise tooling
- Significant manual effort for routine tasks

**AM-Corp solves this by:**
- Replacing manual task execution with specialized AI agents
- Providing transparent, auditable agent workflows
- Minimizing costs through open-source tooling and free-tier AI

---

## Target Users

| User Type | Description |
|-----------|-------------|
| **Primary** | Solo security operators / consultants |
| **Secondary** | Small security teams (2-5 people) |
| **Tertiary** | Bug bounty hunters |

---

## Core Features (MVP)

### 1. Reconnaissance Agent
- Subdomain enumeration
- Port scanning (Nmap integration)
- Technology fingerprinting
- Output structured findings to Discord

### 2. Vulnerability Agent
- Nuclei template scanning
- CVE correlation
- Risk scoring
- Prioritized vulnerability list

### 3. Intelligence Agent
- OSINT gathering
- Threat actor correlation
- Historical breach data lookup
- Context enrichment

### 4. Reporting Agent
- Aggregate findings from other agents
- Generate structured reports
- Executive summary generation
- Technical detail appendices

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Time to complete basic recon | < 10 minutes |
| Agent hallucination rate | < 5% |
| Monthly operational cost | < $50 |
| Human intervention required | < 20% of workflows |

---

## Constraints & Assumptions

### Constraints
- Must operate within Gemini Flash free tier limits
- Discord rate limits for webhooks/bot messages
- Self-hosted infrastructure (no cloud vendor lock-in)

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

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM hallucinations | High | Specialized agents + human verification |
| Rate limiting | Medium | Queue system + caching |
| Tool failures | Medium | Graceful degradation + alerting |
| Unauthorized use | Critical | Scope verification + audit logging |

---

## Timeline & Phases

See individual phase documents in `/docs/phases/` for detailed breakdowns.

| Phase | Focus | Duration |
|-------|-------|----------|
| **Phase 1** | Core infrastructure + Recon agent | 2 weeks |
| **Phase 2** | Vuln + Intel agents | 2 weeks |
| **Phase 3** | Report agent + Polish | 1 week |
| **Phase 4** | Testing + Documentation | 1 week |

---

## References

- [CrewAI Documentation](https://docs.crewai.com/)
- [n8n Documentation](https://docs.n8n.io/)
- [Discord Developer Portal](https://discord.com/developers/docs)
- [Gemini API](https://ai.google.dev/)
