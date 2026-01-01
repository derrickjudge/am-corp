# ADR-002: Natural Language Agent Interaction via @Mentions

## Status
**Proposed** - Pending Implementation

## Date
2026-01-01

## Context

Currently, users interact with AM-Corp agents through explicit commands (e.g., `!recon target.com`) processed by the main `AM Corp` bot. While functional, this feels mechanical and doesn't align with our vision of agents as AI coworkers.

Users should be able to talk to agents naturally:
```
@Randy Recon can you see what you can find about example.com
@Victor Vuln check those open ports Randy found
@Ivy Intel what do you know about this IP?
```

## Decision

Implement natural language interaction where agents can be @mentioned and respond to conversational requests.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Discord Message                          │
│          "@Randy Recon check out example.com for me"            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Randy's on_message Handler                    │
│  1. Check if bot is mentioned                                   │
│  2. Ignore if not mentioned or if from another bot              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Intent Classification                        │
│  Use Gemini to parse the request:                               │
│  - action: "recon" | "scan" | "lookup" | "question" | "chat"    │
│  - target: "example.com" (extracted domain/IP)                  │
│  - context: any additional parameters                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Scope Validation                            │
│  - Check if target is in approved scope cache                   │
│  - If not approved: request confirmation via reaction           │
│  - Block .gov/.mil domains absolutely                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Execute & Respond                           │
│  - Run appropriate tools (dig, whois, nmap)                     │
│  - Post conversational updates                                  │
│  - Tag other agents if relevant (@Victor for open ports)        │
└─────────────────────────────────────────────────────────────────┘
```

### Intent Classification Schema

```python
class AgentIntent:
    action: str          # recon, scan, lookup, question, chat, unknown
    target: str | None   # Domain, IP, or None for general questions
    tools: list[str]     # Specific tools requested (optional)
    context: str         # Original message for context
    confidence: float    # 0.0 - 1.0 confidence in classification
```

### Example Interactions

| User Message | Parsed Intent |
|--------------|---------------|
| "@Randy Recon check out example.com" | `action=recon, target=example.com` |
| "@Randy what ports are open on 10.0.0.1?" | `action=scan, target=10.0.0.1, tools=[nmap]` |
| "@Randy Recon who owns this domain: test.org" | `action=lookup, target=test.org, tools=[whois]` |
| "@Randy what did you find on the last scan?" | `action=question, target=None` |
| "@Randy Recon hey partner, how's it going?" | `action=chat, target=None` |

### Scope Approval Flow

```
User: @Randy Recon scan mtpcollective.com

Randy: Howdy! I'd be happy to scout out mtpcollective.com. 
       🔒 This target isn't in my approved list yet.
       React with ✅ to authorize or ❌ to cancel.

[User reacts ✅]

Randy: Much obliged! Adding mtpcollective.com to the approved list.
       Saddlin' up now - I'll use dig, whois, and nmap for this job...
```

### Required Changes

1. **Agent Bot Intents** (`src/discord_bot/agent_bots.py`)
   - Enable `message_content` intent for agent bots
   - Add `on_message` handler with mention detection

2. **Intent Parser** (`src/agents/intent_parser.py`) - NEW
   - Gemini-powered natural language understanding
   - Extract action, target, and context
   - Return structured `AgentIntent` object

3. **Agent Base Class** (`src/agents/base.py`) - NEW
   - Common mention handling logic
   - Scope validation integration
   - Reaction-based approval flow

4. **Randy Recon** (`src/agents/randy_recon.py`)
   - Integrate with intent parser
   - Handle various action types
   - Conversational responses for non-recon requests

5. **Scope Cache** (`src/discord_bot/scope_cache.py`)
   - Add reaction-based approval method
   - Track who approved and when

### Security Considerations

- **Rate Limiting**: Prevent spam by limiting requests per user per minute
- **Scope Validation**: All targets must be approved before scanning
- **Audit Trail**: Log all natural language requests and parsed intents
- **Blocked Domains**: .gov/.mil blocking applies regardless of phrasing
- **Bot Ignore**: Agents must ignore messages from other bots

### Interaction Boundaries

| Agent | Responds To |
|-------|-------------|
| Randy Recon | Recon requests, DNS questions, domain lookups |
| Victor Vuln | Vulnerability questions, CVE lookups, exploit info |
| Ivy Intel | Threat intel, IOC lookups, actor information |
| Rita Report | Report requests, summary questions |

Agents should:
- Acknowledge requests outside their domain
- Suggest the appropriate teammate
- Example: "That's more Victor's territory - hey @Victor Vuln, can you take a look?"

## Consequences

### Positive
- More natural, conversational interaction
- Agents feel like real teammates
- Flexible request phrasing
- Better user experience

### Negative
- Increased complexity in message handling
- Gemini API costs for intent parsing
- Potential for misunderstood requests
- Need to handle edge cases gracefully

### Risks
- Intent misclassification leading to wrong actions
- Users attempting prompt injection via messages
- Rate limit issues with high message volume

## Implementation Priority

**Phase 1**: Randy Recon only (validate the pattern)
- Mention detection
- Basic intent parsing (recon/scan/chat)
- Reaction-based approval

**Phase 2**: Extend to other agents
- Victor, Ivy, Rita mention handling
- Cross-agent handoffs
- Shared intent parser

**Phase 3**: Advanced features
- Multi-turn conversations
- Context awareness (remember previous scans)
- Proactive suggestions

## Related Documents
- [AGENTS.md](../AGENTS.md) - Agent personalities and capabilities
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
- [ADR-001](001-use-crewai-for-orchestration.md) - CrewAI orchestration

