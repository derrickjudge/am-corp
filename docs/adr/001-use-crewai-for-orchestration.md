# ADR 001: Use CrewAI for Multi-Agent Orchestration

## Status

**Accepted**

## Date

2025-12-30

---

## Context

AM-Corp requires a framework to orchestrate multiple specialized AI agents that work together to perform security assessments. We need:

- Multi-agent coordination with task delegation
- Tool integration for security utilities (Nmap, Nuclei)
- LLM abstraction to use cost-effective models (Gemini Flash)
- Structured output handling
- Human-in-the-loop capabilities

### Options Considered

1. **CrewAI** - Python framework for multi-agent orchestration
2. **AutoGen** - Microsoft's multi-agent framework
3. **LangGraph** - LangChain's graph-based agent framework
4. **Custom Implementation** - Build from scratch with LangChain

---

## Decision

We will use **CrewAI** as the multi-agent orchestration framework.

---

## Rationale

### Why CrewAI

| Factor | CrewAI | AutoGen | LangGraph | Custom |
|--------|--------|---------|-----------|--------|
| Learning curve | Low | Medium | High | High |
| Role-based agents | Native | Possible | Possible | Manual |
| Tool integration | Built-in | Built-in | Built-in | Manual |
| Gemini support | Yes | Yes | Yes | Manual |
| Active development | Yes | Yes | Yes | N/A |
| Documentation | Good | Good | Medium | N/A |

### Key Advantages

1. **Role-based agent definition**: Agents have roles, goals, and backstories that shape behavior
2. **Task delegation**: Built-in sequential and hierarchical process flows
3. **Tool abstraction**: Easy integration of custom tools
4. **LLM flexibility**: Supports multiple LLM providers including Gemini
5. **Active community**: Regular updates and community support

### Trade-offs

- Less flexibility than custom implementation
- Abstraction layer adds some overhead
- Framework lock-in risk

---

## Consequences

### Positive

- Faster development with pre-built patterns
- Consistent agent behavior across the system
- Built-in patterns for common multi-agent scenarios
- Easier onboarding for new developers

### Negative

- Framework updates may require code changes
- Some advanced patterns may be harder to implement
- Dependency on external project maintenance

### Mitigations

- Abstract agent definitions to allow framework migration if needed
- Pin CrewAI version in requirements
- Monitor framework health and community activity

---

## Implementation Notes

```python
# Example CrewAI implementation pattern
from crewai import Agent, Crew, Task, Process

recon_agent = Agent(
    role="Reconnaissance Specialist",
    goal="Comprehensively map target attack surface",
    backstory="Expert in passive and active reconnaissance",
    tools=[nmap_tool, subfinder_tool],
    llm=gemini_flash
)

crew = Crew(
    agents=[recon_agent, vuln_agent, intel_agent, report_agent],
    tasks=[recon_task, vuln_task, intel_task, report_task],
    process=Process.sequential,
    verbose=True
)
```

---

## References

- [CrewAI Documentation](https://docs.crewai.com/)
- [CrewAI GitHub](https://github.com/joaomdmoura/crewAI)
- [Gemini with CrewAI](https://docs.crewai.com/how-to/llm-connections/)

