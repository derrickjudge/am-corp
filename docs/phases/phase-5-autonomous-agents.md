# Phase 5: Autonomous Agent Features

**Duration:** 2 weeks  
**Status:** Planned  
**Dependencies:** Phase 1-4 complete

---

## Overview

Phase 5 transforms agents from command-driven tools into autonomous team members. Agents will have evolving personalities, engage in casual conversation, show their reasoning transparently, and take initiative while respecting team consensus.

---

## Goals

1. **Agents as Team Members** - Agents chat, discuss, and collaborate naturally
2. **Transparent Thinking** - Raw reasoning visible in dedicated thoughts channel
3. **Personality Evolution** - Agent personalities grow and adapt over time
4. **Autonomous Initiative** - Agents take action when appropriate, with justification
5. **Memory Persistence** - Conversation history and personality survive restarts

---

## Deliverables

### Week 1: Thoughts Channel & Personality

#### 5.1 Thoughts Channel Implementation
- [ ] Create `#am-corp-thoughts` channel integration
- [ ] Add thoughts output method to base agent class
- [ ] Implement verbosity levels (minimal, normal, verbose, all)
- [ ] Format thoughts with "(thinking)" prefix
- [ ] Add confidence levels to thought output
- [ ] Test thoughts visibility during active scans

#### 5.2 Personality System
- [ ] Design personality YAML schema
- [ ] Create personality file for each agent
- [ ] Implement personality loading on startup
- [ ] Add personality persistence across restarts
- [ ] Create base personality templates
- [ ] Implement personality reset functionality

#### 5.3 Personality Evolution
- [ ] Define evolution triggers (experiences, interactions)
- [ ] Implement trait modification logic
- [ ] Add evolution logging for transparency
- [ ] Create personality diff tracking
- [ ] Build archive system for "fired" agents

### Week 2: Autonomy & Casual Chat

#### 5.4 General Channel & Casual Chat
- [ ] Create `#am-corp-general` channel integration
- [ ] Implement personality-driven chat frequency
- [ ] Add configurable work hours per agent
- [ ] Build message relevance filtering (not everyone responds)
- [ ] Integrate security news feeds (optional)
- [ ] Test natural conversation flow

#### 5.5 Agent Initiative
- [ ] Implement initiative proposal system
- [ ] Add justification requirement for autonomous actions
- [ ] Build teammate consensus mechanism
- [ ] Ensure scope verification for all initiatives
- [ ] Add human approval flow for new domains
- [ ] Test autonomous workflow triggers

#### 5.6 Conversation Memory
- [ ] Implement 30-day conversation history retention
- [ ] Build conversation summarization for older data
- [ ] Add memory persistence across restarts
- [ ] Implement memory access in agent prompts
- [ ] Test context awareness from past conversations

---

## Technical Specifications

### Personality YAML Schema

```yaml
agent: randy_recon
version: 1
created: 2026-01-09T00:00:00Z
last_updated: 2026-01-09T10:00:00Z

base_traits:
  methodical: 0.9      # 0-1 scale
  patience: 0.85
  humor: 0.6
  technical_detail: 0.8
  
evolved_traits: {}     # Populated through experience

communication:
  personality_expression: 0.5   # How much personality shows
  formality: 0.3                # 0=casual, 1=formal
  
relationships:
  works_well_with: []
  defers_to: []
  
recent_learnings: []

evolution_log:
  - date: 2026-01-09T10:00:00Z
    trait: api_security_interest
    old_value: 0.0
    new_value: 0.3
    trigger: "Found multiple API vulnerabilities in recent scans"
```

### Thoughts Channel Output

```python
class ThoughtOutput:
    agent: str
    thought: str
    confidence: float  # 0-1
    timestamp: datetime
    job_id: Optional[str]
    
# Example output
# 🔍 Randy (thinking): Starting DNS enumeration. Going passive first - 
#                      don't know their monitoring setup. Confidence: 0.8
```

### Chat Frequency Configuration

```yaml
chat_behavior:
  randy_recon:
    frequency: moderate      # low, moderate, active
    work_hours: "09:00-18:00"
    timezone: "America/Chicago"
    topics:
      - reconnaissance_techniques
      - infrastructure_security
      - team_collaboration
      
  victor_vuln:
    frequency: active
    work_hours: "10:00-22:00"
    timezone: "America/Los_Angeles"
    topics:
      - vulnerabilities
      - exploits
      - hacking_culture
```

### Initiative Proposal

```python
class InitiativeProposal:
    agent: str
    action: str
    target: str
    justification: str
    requires_scope_approval: bool
    teammate_consensus_required: list[str]
    
# Flow:
# 1. Agent proposes action
# 2. Posts justification to #agent-chat
# 3. Relevant teammates agree/disagree
# 4. If approved domain: proceed
# 5. If new domain: human approval flow
```

---

## Testing Plan

### Unit Tests
- [ ] Personality loading and saving
- [ ] Evolution trait modification
- [ ] Thoughts formatting and output
- [ ] Chat frequency timing
- [ ] Initiative proposal validation

### Integration Tests
- [ ] Full thoughts channel flow during scan
- [ ] Personality persistence across restart
- [ ] Casual conversation between agents
- [ ] Initiative → consensus → action flow
- [ ] Memory context in agent responses

### Manual Testing
- [ ] Watch thoughts channel during real scan
- [ ] Verify personality feels natural
- [ ] Test casual conversation quality
- [ ] Validate initiative justifications make sense
- [ ] Confirm memory improves context awareness

---

## Configuration

### Environment Variables

```bash
# Thoughts Channel
THOUGHTS_CHANNEL_ID=<discord_channel_id>
THOUGHTS_VERBOSITY=normal  # minimal, normal, verbose, all

# General Channel
GENERAL_CHANNEL_ID=<discord_channel_id>
ENABLE_CASUAL_CHAT=true

# Personality
PERSONALITY_DIR=/app/config/personalities
ENABLE_PERSONALITY_EVOLUTION=true

# Memory
CONVERSATION_HISTORY_DAYS=30
MEMORY_SUMMARIZATION_ENABLED=true
```

### agents.yaml Updates

```yaml
global:
  thoughts_channel_enabled: true
  thoughts_verbosity: normal
  general_channel_enabled: true
  enable_autonomous_initiative: true
  require_consensus: true
  
agents:
  randy_recon:
    personality_file: randy_recon.yaml
    chat_behavior:
      frequency: moderate
      work_hours: "09:00-18:00"
      timezone: "America/Chicago"
```

---

## Rate Limiting Considerations

### Gemini Free Tier Limits
- 15 requests per minute (RPM)
- 1,000,000 tokens per minute (TPM)
- 1,500 requests per day (RPD)

### Impact on Features

| Feature | API Calls | Strategy |
|---------|-----------|----------|
| Thoughts | Low | Only during active work |
| Casual Chat | Medium | Few per hour, configurable |
| Initiative | Low | Only when proposing action |
| Memory | Low | Cached locally |

### Production Mode Adjustments
- Reduce chat frequency
- Batch thoughts output
- Cache memory aggressively
- Prioritize work over conversation

### Test Mode Adjustments
- Increase chat frequency for testing
- Full thoughts verbosity
- No rate limiting concerns
- Use synthetic data to avoid tool calls

---

## Success Criteria

| Metric | Target |
|--------|--------|
| Thoughts channel useful for debugging | Yes |
| Personality feels consistent and natural | Subjective review |
| Casual conversation is relevant, not spam | <5 messages/hour average |
| Initiative proposals are well-justified | 80%+ make sense |
| Memory improves context awareness | Noticeable improvement |
| Stays within Gemini free tier | <1500 RPD |

---

## Dependencies

- Phase 1-4 complete
- Discord channels created
- Gemini API configured
- Podman environment running

---

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Personality drift | Medium | Evolution logging, reset option |
| Excessive chattiness | Medium | Configurable limits, production mode |
| Rate limit exceeded | High | Careful budgeting, test mode |
| Memory bloat | Medium | 30-day retention, summarization |
| Consensus deadlock | Low | Timeout, human escalation |

---

## Future Considerations (Out of Scope)

- HR Agent for team management
- Sub-agent creation and coordination
- Multi-team support
- Voice interaction
- Real-time security research agent

