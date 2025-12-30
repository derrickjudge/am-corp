# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for AM-Corp.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision along with its context and consequences.

## ADR Template

When creating a new ADR, use this template:

```markdown
# ADR NNN: Title

## Status

[Proposed | Accepted | Deprecated | Superseded by ADR-XXX]

## Date

YYYY-MM-DD

---

## Context

What is the issue that we're seeing that is motivating this decision or change?

---

## Decision

What is the change that we're proposing and/or doing?

---

## Rationale

Why did we make this decision? What alternatives were considered?

---

## Consequences

What becomes easier or more difficult to do because of this change?

---

## References

Links to related documents, discussions, or resources.
```

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](./001-use-crewai-for-orchestration.md) | Use CrewAI for Multi-Agent Orchestration | Accepted | 2025-12-30 |

## Naming Convention

ADRs are numbered sequentially: `NNN-short-title.md`

Examples:
- `001-use-crewai-for-orchestration.md`
- `002-discord-as-primary-interface.md`
- `003-gemini-flash-for-llm.md`

