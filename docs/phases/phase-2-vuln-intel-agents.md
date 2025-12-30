# Phase 2: Vulnerability + Intelligence Agents

**Duration:** 2 weeks  
**Status:** Not Started  
**Priority:** High  
**Dependencies:** Phase 1 Complete

---

## Objectives

1. Implement Vulnerability Agent with Nuclei integration
2. Implement Intelligence Agent with OSINT capabilities
3. Create inter-agent data passing workflow
4. Enhance Discord reporting for multi-agent output

---

## Deliverables

| Deliverable | Description | Owner |
|-------------|-------------|-------|
| Vuln Agent | Nuclei-based vulnerability scanning | - |
| Intel Agent | OSINT gathering and enrichment | - |
| Agent pipeline | Recon → Vuln → Intel flow | - |
| Enhanced Discord | Multi-agent status updates | - |

---

## Tasks

### Week 1: Vulnerability Agent

- [ ] **1.1** Nuclei integration
  - [ ] Install Nuclei in container
  - [ ] Configure template categories (CVEs, misconfigs)
  - [ ] Create Nuclei tool wrapper

- [ ] **1.2** Vuln Agent implementation
  - [ ] Define agent role, goal, backstory
  - [ ] Implement vulnerability parsing
  - [ ] Create severity classification
  - [ ] Add CVE correlation logic

- [ ] **1.3** Pipeline integration
  - [ ] Connect Recon output → Vuln input
  - [ ] Implement asset handoff
  - [ ] Add progress reporting to Discord

### Week 2: Intelligence Agent

- [ ] **2.1** OSINT tools setup
  - [ ] Integrate Shodan API (optional)
  - [ ] Integrate VirusTotal API (optional)
  - [ ] Create fallback for missing APIs

- [ ] **2.2** Intel Agent implementation
  - [ ] Define agent role, goal, backstory
  - [ ] Implement threat context enrichment
  - [ ] Add historical data lookup
  - [ ] Create risk adjustment logic

- [ ] **2.3** Full pipeline testing
  - [ ] Test Recon → Vuln → Intel flow
  - [ ] Validate output formats
  - [ ] Test with/without optional APIs

- [ ] **2.4** Discord enhancements
  - [ ] Add agent status emojis
  - [ ] Implement progress tracking
  - [ ] Create summary messages

---

## Success Criteria

| Criteria | Measurement |
|----------|-------------|
| Vuln Agent finds issues | Nuclei returns results |
| Intel enriches data | Context added to findings |
| Pipeline flows | All agents complete in sequence |
| Severity correct | CVSS scores match CVE data |

---

## Technical Specifications

### Vuln Agent Tools

```python
tools = [
    NucleiTool(templates=["cves", "vulnerabilities", "misconfigurations"]),
    CVELookupTool(database="nvd"),
    VersionCheckTool()
]
```

### Intel Agent Tools

```python
tools = [
    ShodanTool(api_key=os.getenv("SHODAN_API_KEY")),  # Optional
    VirusTotalTool(api_key=os.getenv("VIRUSTOTAL_API_KEY")),  # Optional
    BreachCheckTool(),
    WHOISHistoryTool()
]
```

---

## Risks

| Risk | Mitigation |
|------|------------|
| Nuclei false positives | Confidence scoring, validation |
| API rate limits | Caching, request queuing |
| Missing API keys | Graceful degradation |
| Long scan times | Timeout handling, chunking |

---

## Notes

- Intel Agent should be optional (enhance when APIs available)
- Focus on accuracy over speed for Vuln Agent
- Consider caching for repeated targets

