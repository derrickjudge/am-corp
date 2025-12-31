"""
AM-Corp Agent Definitions

The AM-Corp security team consists of specialized AI agents who collaborate
through natural conversation in Discord.

Agents:
    🔍 Randy Recon  - Reconnaissance Specialist
       Methodical, thorough, reports findings in real-time.
       Tools: Nmap, Subfinder, httpx, whois
       
    ⚠️ Victor Vuln  - Vulnerability Analyst  
       Cautious, detail-oriented, explains risks clearly.
       Tools: Nuclei, CVE lookup, version checking
       
    🧠 Ivy Intel    - Threat Intelligence Analyst
       Analytical, connects dots, provides context.
       Tools: Shodan, VirusTotal, breach databases
       
    📊 Rita Report  - Security Report Analyst
       Professional, concise, audience-aware.
       Tools: Template rendering, report formatting

Module Structure:
    base.py         - Base agent class with Discord integration
    randy_recon.py  - Randy Recon agent implementation
    victor_vuln.py  - Victor Vuln agent implementation
    ivy_intel.py    - Ivy Intel agent implementation
    rita_report.py  - Rita Report agent implementation
"""

# Agent identifiers
AGENT_RANDY_RECON = "randy_recon"
AGENT_VICTOR_VULN = "victor_vuln"
AGENT_IVY_INTEL = "ivy_intel"
AGENT_RITA_REPORT = "rita_report"

# Agent display info
AGENTS = {
    AGENT_RANDY_RECON: {
        "name": "Randy Recon",
        "emoji": "🔍",
        "role": "Reconnaissance Specialist",
    },
    AGENT_VICTOR_VULN: {
        "name": "Victor Vuln",
        "emoji": "⚠️",
        "role": "Vulnerability Analyst",
    },
    AGENT_IVY_INTEL: {
        "name": "Ivy Intel",
        "emoji": "🧠",
        "role": "Threat Intelligence Analyst",
    },
    AGENT_RITA_REPORT: {
        "name": "Rita Report",
        "emoji": "📊",
        "role": "Security Report Analyst",
    },
}
