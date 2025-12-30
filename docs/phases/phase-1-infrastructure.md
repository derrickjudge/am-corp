# Phase 1: Core Infrastructure + Recon Agent

**Duration:** 2 weeks  
**Status:** Not Started  
**Priority:** Critical

---

## Objectives

1. Set up core infrastructure (Docker, n8n, Discord)
2. Implement basic Discord bot with command handling
3. Create Recon Agent with basic enumeration capabilities
4. Establish end-to-end workflow from Discord command to result

---

## Deliverables

| Deliverable | Description | Owner |
|-------------|-------------|-------|
| Docker Compose setup | n8n + orchestrator containers | - |
| Discord bot | Basic command parsing | - |
| Recon Agent | Subdomain + port scanning | - |
| n8n workflow | Command routing | - |
| Documentation | Setup guide updates | - |

---

## Tasks

### Week 1: Infrastructure

- [ ] **1.1** Initialize Python project structure
  - [ ] Create `src/` directory structure
  - [ ] Set up `requirements.txt` with CrewAI dependencies
  - [ ] Configure logging and error handling

- [ ] **1.2** Docker environment setup
  - [ ] Create `docker-compose.yml`
  - [ ] Configure n8n container
  - [ ] Set up networking between containers

- [ ] **1.3** Discord bot foundation
  - [ ] Create Discord application and bot
  - [ ] Implement basic bot with connection handling
  - [ ] Set up command prefix and parsing
  - [ ] Create Discord channels structure

- [ ] **1.4** n8n workflow setup
  - [ ] Configure n8n instance
  - [ ] Create webhook receiver workflow
  - [ ] Set up Discord webhook integration

### Week 2: Recon Agent

- [ ] **2.1** CrewAI setup
  - [ ] Install and configure CrewAI
  - [ ] Set up Gemini LLM integration
  - [ ] Create base agent configuration

- [ ] **2.2** Recon Agent implementation
  - [ ] Define agent role, goal, backstory
  - [ ] Create Nmap tool wrapper
  - [ ] Create Subfinder tool wrapper
  - [ ] Implement structured output

- [ ] **2.3** Integration
  - [ ] Connect Discord → n8n → CrewAI pipeline
  - [ ] Implement result formatting
  - [ ] Add Discord webhook for results

- [ ] **2.4** Testing & Documentation
  - [ ] Test against authorized targets
  - [ ] Document setup process
  - [ ] Create example commands

---

## Success Criteria

| Criteria | Measurement |
|----------|-------------|
| Discord bot responds | Bot acknowledges commands |
| Recon executes | Scan completes without errors |
| Results posted | Structured output in Discord |
| End-to-end time | < 5 minutes for basic scan |

---

## Risks

| Risk | Mitigation |
|------|------------|
| Discord API rate limits | Implement message queuing |
| Tool installation issues | Containerize all tools |
| Gemini quota exhaustion | Cache responses, monitor usage |

---

## Dependencies

- Discord Developer account
- Google AI Studio account (Gemini API)
- Docker installed on development machine
- Authorized test target

---

## Notes

- Start with minimal viable implementation
- Focus on reliability over features
- Document all setup steps as you go

