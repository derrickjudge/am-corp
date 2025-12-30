# AM-Corp Agent Specifications

## Overview

AM-Corp uses specialized AI agents, each designed for a specific security function. This document details agent configurations, capabilities, and interaction patterns.

---

## Agent Architecture

```
                    ┌─────────────────────┐
                    │   CREW MANAGER      │
                    │  (Orchestrator)     │
                    └──────────┬──────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
       ▼                       ▼                       ▼
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   RECON     │────────▶│    VULN     │────────▶│   INTEL     │
│   AGENT     │         │    AGENT    │         │   AGENT     │
└─────────────┘         └─────────────┘         └─────────────┘
                               │                       │
                               └───────────┬───────────┘
                                           ▼
                                    ┌─────────────┐
                                    │   REPORT    │
                                    │   AGENT     │
                                    └─────────────┘
```

---

## Agent Definitions

### 1. Recon Agent

**Purpose:** Discover and enumerate target attack surface

| Attribute | Value |
|-----------|-------|
| **Role** | Reconnaissance Specialist |
| **Goal** | Comprehensively map the target's digital footprint |
| **Backstory** | Expert in passive and active reconnaissance techniques |

#### Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| `nmap` | Port/service discovery | `nmap -sV -sC target.com` |
| `subfinder` | Subdomain enumeration | `subfinder -d target.com` |
| `httpx` | HTTP probing | `httpx -l hosts.txt` |
| `whois` | Domain information | `whois target.com` |

#### System Prompt

```
You are a reconnaissance specialist AI agent. Your mission is to thoroughly 
enumerate the target's attack surface while staying within authorized scope.

RULES:
1. Only scan targets that have been explicitly authorized
2. Start with passive techniques before active scanning
3. Document all findings with evidence
4. Flag any scope concerns immediately
5. Never attempt exploitation

OUTPUT FORMAT:
Provide structured JSON with discovered assets:
- Subdomains
- IP addresses
- Open ports and services
- Technologies detected
```

#### Output Schema

```json
{
  "target": "example.com",
  "timestamp": "2025-12-30T10:00:00Z",
  "subdomains": [
    {"name": "www.example.com", "ip": "192.168.1.1", "status": "active"}
  ],
  "ports": [
    {"host": "192.168.1.1", "port": 443, "service": "https", "version": "nginx/1.18"}
  ],
  "technologies": ["nginx", "cloudflare", "react"],
  "notes": []
}
```

---

### 2. Vulnerability Agent

**Purpose:** Identify security vulnerabilities in discovered assets

| Attribute | Value |
|-----------|-------|
| **Role** | Vulnerability Analyst |
| **Goal** | Identify and prioritize security weaknesses |
| **Backstory** | Expert in vulnerability assessment and CVE analysis |

#### Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| `nuclei` | Template-based scanning | `nuclei -u target.com -t cves/` |
| `cve_lookup` | CVE database query | Custom tool |
| `version_check` | Version vulnerability check | Custom tool |

#### System Prompt

```
You are a vulnerability analysis AI agent. Your mission is to identify 
security weaknesses in the assets discovered by the Recon Agent.

RULES:
1. Never attempt exploitation - identification only
2. Prioritize findings by severity (CVSS score)
3. Correlate findings with known CVEs when possible
4. Reduce false positives by validating findings
5. Focus on actionable vulnerabilities

OUTPUT FORMAT:
Provide structured findings with:
- Vulnerability name and type
- Affected asset
- Severity (Critical/High/Medium/Low/Info)
- CVE reference if applicable
- Remediation guidance
```

#### Output Schema

```json
{
  "target": "example.com",
  "timestamp": "2025-12-30T10:30:00Z",
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "name": "Outdated nginx version",
      "type": "version",
      "asset": "192.168.1.1:443",
      "severity": "medium",
      "cvss": 5.3,
      "cve": "CVE-2021-XXXXX",
      "description": "nginx 1.18 has known vulnerabilities",
      "remediation": "Upgrade to nginx 1.24 or later",
      "confidence": "high"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 5,
    "info": 10
  }
}
```

---

### 3. Intelligence Agent

**Purpose:** Provide threat context and OSINT enrichment

| Attribute | Value |
|-----------|-------|
| **Role** | Threat Intelligence Analyst |
| **Goal** | Contextualize findings with threat intelligence |
| **Backstory** | Expert in OSINT and threat actor analysis |

#### Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| `shodan_lookup` | Shodan query | Custom tool |
| `virustotal_check` | VT reputation check | Custom tool |
| `breach_check` | Breach database query | Custom tool |
| `whois_history` | Historical WHOIS | Custom tool |

#### System Prompt

```
You are a threat intelligence AI agent. Your mission is to provide context 
and enrichment for findings from other agents.

RULES:
1. Focus on actionable intelligence
2. Correlate findings with known threat actors when possible
3. Identify patterns and trends
4. Assess likelihood of exploitation
5. Provide historical context

OUTPUT FORMAT:
Provide intelligence enrichment with:
- Threat actor associations
- Historical breach data
- Reputation scores
- Recommended priority adjustments
```

#### Output Schema

```json
{
  "target": "example.com",
  "timestamp": "2025-12-30T11:00:00Z",
  "intelligence": {
    "threat_actors": [],
    "historical_breaches": [
      {
        "date": "2023-01-15",
        "type": "credential_leak",
        "records": 50000
      }
    ],
    "reputation": {
      "virustotal": "clean",
      "shodan_exposure": "medium"
    },
    "exposed_services": [
      {"port": 22, "first_seen": "2020-01-01"}
    ]
  },
  "risk_adjustment": {
    "vuln-001": {
      "original_severity": "medium",
      "adjusted_severity": "high",
      "reason": "Previously exploited in similar breaches"
    }
  }
}
```

---

### 4. Report Agent

**Purpose:** Aggregate findings and generate comprehensive reports

| Attribute | Value |
|-----------|-------|
| **Role** | Security Report Analyst |
| **Goal** | Create actionable, professional security reports |
| **Backstory** | Expert in security communication and reporting |

#### Tools

| Tool | Purpose |
|------|---------|
| `template_renderer` | Markdown/PDF generation |
| `chart_generator` | Visualization creation |
| `summary_writer` | Executive summary generation |

#### System Prompt

```
You are a security reporting AI agent. Your mission is to compile findings 
from all agents into clear, actionable reports.

RULES:
1. Tailor language to audience (executive vs technical)
2. Prioritize findings by business impact
3. Provide clear remediation steps
4. Include evidence and references
5. Never exaggerate or sensationalize

REPORT SECTIONS:
1. Executive Summary (non-technical)
2. Scope and Methodology
3. Key Findings (prioritized)
4. Detailed Findings
5. Remediation Roadmap
6. Appendices (raw data)
```

#### Output Schema

```json
{
  "target": "example.com",
  "timestamp": "2025-12-30T12:00:00Z",
  "report": {
    "format": "markdown",
    "sections": {
      "executive_summary": "...",
      "scope": "...",
      "key_findings": "...",
      "detailed_findings": "...",
      "remediation": "...",
      "appendices": "..."
    }
  },
  "artifacts": [
    {"name": "report.md", "type": "markdown"},
    {"name": "findings.json", "type": "json"}
  ]
}
```

---

## Agent Communication

### Message Format (Discord)

```
🔍 [RECON] Starting subdomain enumeration for example.com...
✅ [RECON] Found 15 subdomains
⚠️ [VULN] Detected potential vulnerability: CVE-2021-XXXXX
🧠 [INTEL] Historical breach detected - adjusting risk score
📊 [REPORT] Generating final report...
```

### Inter-Agent Data Passing

Agents pass data through CrewAI's task context:

```python
@task
def recon_task(self) -> Task:
    return Task(
        description="Enumerate target attack surface",
        agent=self.recon_agent,
        expected_output="JSON with discovered assets",
        output_file="recon_output.json"
    )

@task
def vuln_task(self) -> Task:
    return Task(
        description="Scan discovered assets for vulnerabilities",
        agent=self.vuln_agent,
        context=[self.recon_task],  # Receives recon output
        expected_output="JSON with vulnerabilities"
    )
```

---

## Hallucination Mitigation

| Strategy | Implementation |
|----------|----------------|
| **Specialization** | Each agent has narrow, focused responsibilities |
| **Tool Grounding** | Agents must use tools for facts, not generate them |
| **Output Validation** | JSON schemas enforce structured output |
| **Human Verification** | Critical findings require human confirmation |
| **Confidence Scores** | Agents report confidence levels |

### Confidence Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **High** | Tool-verified, multiple sources | Auto-accept |
| **Medium** | Single source, consistent with context | Review recommended |
| **Low** | Inference-based, limited evidence | Manual verification required |

---

## Error Handling

### Agent Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Tool timeout | Execution timeout | Retry with backoff |
| Invalid output | Schema validation | Re-run with clarification |
| API rate limit | Error code | Queue and wait |
| Scope violation | Pre-execution check | Block and alert |

### Graceful Degradation

If an agent fails, the workflow continues with available data:

```python
try:
    intel_result = intel_agent.execute()
except AgentError:
    intel_result = {"status": "unavailable", "reason": "agent_failure"}
    notify_discord("⚠️ Intel Agent unavailable, proceeding without enrichment")
```

---

## Configuration

### Agent Config File (`config/agents.yaml`)

```yaml
agents:
  recon:
    enabled: true
    max_execution_time: 300
    tools:
      - nmap
      - subfinder
      - httpx
    rate_limits:
      requests_per_minute: 60
      
  vuln:
    enabled: true
    max_execution_time: 600
    tools:
      - nuclei
    nuclei_templates:
      - cves
      - vulnerabilities
      - misconfigurations
      
  intel:
    enabled: true
    max_execution_time: 180
    tools:
      - shodan_lookup
      - virustotal_check
    # Disabled if no API keys
    optional: true
    
  report:
    enabled: true
    max_execution_time: 120
    output_formats:
      - markdown
      - json
```

---

## Extending Agents

### Adding New Tools

```python
from crewai_tools import BaseTool

class CustomTool(BaseTool):
    name: str = "custom_tool"
    description: str = "Description for the agent"
    
    def _run(self, argument: str) -> str:
        # Tool implementation
        return result
```

### Creating New Agents

```python
from crewai import Agent

new_agent = Agent(
    role="New Specialist",
    goal="Specific goal for this agent",
    backstory="Background that shapes agent behavior",
    tools=[tool1, tool2],
    llm=gemini_llm,
    verbose=True
)
```

