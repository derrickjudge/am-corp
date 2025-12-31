# Phase 1: Core Infrastructure + Randy Recon

**Duration:** 2 weeks  
**Status:** In Progress  
**Priority:** Critical

---

## Objectives

1. Set up core infrastructure (Python project, Docker, n8n)
2. Implement conversational Discord bot with command handling
3. Create Randy Recon agent with basic enumeration capabilities
4. Establish end-to-end workflow from Discord command to agent conversation to results

---

## Deliverables

| Deliverable | Description | Status |
|-------------|-------------|--------|
| Python project structure | src/, config, logging, main entry | ✅ Complete |
| Docker Compose setup | n8n + orchestrator containers | Not Started |
| Discord bot | Conversational bot with command parsing | In Progress |
| Randy Recon agent | First agent with recon tools | Not Started |
| Agent conversation | Visible agent updates in Discord | Not Started |
| Documentation | Setup guide updates | Ongoing |

---

## Tasks

### Week 1: Infrastructure

- [x] **1.1** Initialize Python project structure ✅
  - [x] Create `src/` directory structure
  - [x] Set up `requirements.txt` with CrewAI dependencies
  - [x] Configure logging and error handling (structlog)
  - [x] Create `.env.example` and `.gitignore`
  - [x] Implement `config.py` (Pydantic settings)
  - [x] Implement `logging.py` (structlog)
  - [x] Create `main.py` entry point

- [ ] **1.2** Docker environment setup
  - [ ] Create `docker-compose.yml`
  - [ ] Configure n8n container
  - [ ] Set up networking between containers
  - [ ] Add security tools container (nmap, nuclei)

- [ ] **1.3** Discord bot foundation
  - [x] Create Discord application and bot
  - [x] Create Discord channels structure
  - [x] Create webhooks for each channel
  - [ ] Implement `validators.py` (security validation)
  - [ ] Implement `webhooks.py` (agent message posting)
  - [ ] Implement `embeds.py` (rich embed formatters)
  - [ ] Implement `bot.py` (main bot with connection handling)
  - [ ] Implement `commands.py` (command handlers)
  - [ ] Test bot connection and basic responses

- [ ] **1.4** n8n workflow setup
  - [ ] Configure n8n instance
  - [ ] Create webhook receiver workflow
  - [ ] Set up tool execution workflows

### Week 2: Randy Recon Agent

- [ ] **2.1** CrewAI setup
  - [ ] Verify CrewAI installation
  - [ ] Set up Gemini LLM integration
  - [ ] Create base agent class with Discord integration
  - [ ] Implement agent-to-Discord message posting

- [ ] **2.2** Randy Recon implementation
  - [ ] Create `randy_recon.py` with personality
  - [ ] Define role, goal, backstory per AGENTS.md
  - [ ] Create Nmap tool wrapper
  - [ ] Create Subfinder tool wrapper
  - [ ] Implement conversational status updates
  - [ ] Implement structured JSON output

- [ ] **2.3** Integration
  - [ ] Connect `!scan` command → Randy Recon
  - [ ] Implement scope verification flow
  - [ ] Randy posts updates to #am-corp-agent-chat
  - [ ] Results posted to #am-corp-results
  - [ ] Errors posted to #am-corp-alerts

- [ ] **2.4** Testing & Documentation
  - [ ] Test against authorized targets only
  - [ ] Verify .gov/.mil blocking works
  - [ ] Test conversation flow end-to-end
  - [ ] Document setup process
  - [ ] Create example commands

---

## Discord Bot Components

| File | Purpose | Priority |
|------|---------|----------|
| `validators.py` | Input validation, scope checking, .gov/.mil blocking | 1 |
| `webhooks.py` | Post agent messages to Discord channels | 2 |
| `embeds.py` | Rich embed formatters for findings | 3 |
| `bot.py` | Main bot class with connection handling | 4 |
| `commands.py` | Command handlers (!scan, !status, etc.) | 5 |

---

## Agent Conversation Flow

When `!scan acme-corp.com` is issued:

```
#am-corp-commands:
Human:           !scan acme-corp.com

Bot:             ⚠️ Target not in pre-approved scope.
                 React ✅ to confirm authorization, ❌ to cancel.

[Human reacts ✅]

#am-corp-agent-chat:
🔍 Randy Recon:  Got it! Starting reconnaissance on acme-corp.com.
                 I'll update as I find things.

🔍 Randy Recon:  Running subdomain enumeration... Found 15 so far.

🔍 Randy Recon:  Subdomain enumeration complete. 23 total.
                 Moving to port scanning.

🔍 Randy Recon:  Interesting finding: staging.acme-corp.com has 
                 port 9200 open. Looks like Elasticsearch.

🔍 Randy Recon:  Recon complete! Summary: 23 subdomains, 4 IPs,
                 42 open ports. Findings ready for the team.

#am-corp-results:
🔍 Randy Recon:  [Embed: Recon Complete for acme-corp.com]
                 • 23 subdomains discovered
                 • 4 unique IP addresses  
                 • 42 open ports
                 • Notable: Elasticsearch on staging (port 9200)
```

---

## Success Criteria

| Criteria | Measurement |
|----------|-------------|
| Discord bot connects | Bot shows online, responds to commands |
| Scope verification works | .gov/.mil blocked, unknown targets require confirmation |
| Randy Recon executes | Scan completes without errors |
| Conversational updates | Randy posts updates as he works |
| Results formatted | Clean embed in #am-corp-results |
| End-to-end time | < 5 minutes for basic scan |

---

## Risks

| Risk | Mitigation |
|------|------------|
| Discord API rate limits | Implement message queuing, batch updates |
| Tool installation issues | Containerize all security tools |
| Gemini quota exhaustion | Cache responses, monitor usage |
| Randy "breaking character" | Clear personality prompt, conversation examples |

---

## Dependencies

- [x] Discord Developer account (complete)
- [x] Discord server with channels (complete)
- [x] Discord webhooks configured (complete)
- [ ] Google AI Studio account (Gemini API)
- [ ] Docker installed on development machine
- [ ] Authorized test target for scanning

---

## Notes

- **Conversational First:** Randy should feel like a team member, not a tool
- **Security First:** Scope verification before any scanning
- **Visible Work:** All agent updates go to Discord, not just final results
- Start with minimal viable implementation
- Focus on reliability over features
- Document all setup steps as you go
