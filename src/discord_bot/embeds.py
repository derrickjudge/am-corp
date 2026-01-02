"""
AM-Corp Discord Embed Builders

Rich embed formatters for Discord messages. Creates beautiful, consistent
embeds for scan results, findings, and reports.
"""

from datetime import datetime, timezone
from typing import Any

import discord

from src.agents import AGENTS


# Color scheme
class Colors:
    """Discord embed colors."""
    
    SUCCESS = 0x2ECC71  # Green
    WARNING = 0xF1C40F  # Yellow
    ERROR = 0xE74C3C   # Red
    INFO = 0x3498DB    # Blue
    RECON = 0x9B59B6   # Purple (Randy)
    VULN = 0xE67E22    # Orange (Victor)
    INTEL = 0x1ABC9C   # Teal (Ivy)
    REPORT = 0x34495E  # Dark gray (Rita)


def create_help_embed() -> discord.Embed:
    """Create the help command embed."""
    embed = discord.Embed(
        title="🤖 AM-Corp Commands",
        description="Available commands for the AM-Corp security team.",
        color=Colors.INFO,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="🔍 Reconnaissance",
        value=(
            "`!scan <target> [-v]` - Full security assessment\n"
            "`!recon <target> [-v]` - Reconnaissance only"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="⚠️ Analysis",
        value=(
            "`!vuln <target> [-v]` - Vulnerability scan\n"
            "`!intel <target>` - Threat intelligence lookup\n\n"
            "*Use `-v` for verbose output with commands and timing*"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="📊 Management",
        value=(
            "`!status` - Current job status\n"
            "`!abort` - Stop current job\n"
            "`!report` - Generate report\n"
            "`!config [agent]` - Show agent configuration\n"
            "`!debug [on/off]` - Toggle debug output"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="🎯 Scope",
        value=(
            "`!scope add <domain>` - Authorize a target\n"
            "`!scope list` - Show authorized targets\n"
            "`!scope remove <domain>` - Remove authorization"
        ),
        inline=False,
    )
    
    embed.set_footer(text="AM-Corp Security Team")
    
    return embed


def create_scan_started_embed(target: str, scan_type: str = "full") -> discord.Embed:
    """Create embed for scan started notification."""
    embed = discord.Embed(
        title="🔍 Scan Initiated",
        description=f"Starting {scan_type} security assessment on `{target}`",
        color=Colors.RECON,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Target",
        value=f"`{target}`",
        inline=True,
    )
    
    embed.add_field(
        name="Scan Type",
        value=scan_type.title(),
        inline=True,
    )
    
    embed.add_field(
        name="Status",
        value="🟡 In Progress",
        inline=True,
    )
    
    embed.set_footer(text="Watch #am-corp-agent-chat for live updates")
    
    return embed


def create_scan_complete_embed(
    target: str,
    duration: str,
    subdomains: int = 0,
    ports: int = 0,
    vulns: int = 0,
) -> discord.Embed:
    """Create embed for scan completion."""
    embed = discord.Embed(
        title="✅ Scan Complete",
        description=f"Security assessment finished for `{target}`",
        color=Colors.SUCCESS,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Target",
        value=f"`{target}`",
        inline=True,
    )
    
    embed.add_field(
        name="Duration",
        value=duration,
        inline=True,
    )
    
    embed.add_field(
        name="Findings",
        value=(
            f"🌐 {subdomains} subdomains\n"
            f"🔌 {ports} open ports\n"
            f"⚠️ {vulns} vulnerabilities"
        ),
        inline=False,
    )
    
    embed.set_footer(text="See #am-corp-results for detailed report")
    
    return embed


def create_vulnerability_embed(
    vuln_name: str,
    asset: str,
    severity: str,
    cvss: float | None = None,
    cve: str | None = None,
    description: str | None = None,
    remediation: str | None = None,
) -> discord.Embed:
    """Create embed for a vulnerability finding."""
    # Color based on severity
    severity_colors = {
        "critical": 0x9B0000,  # Dark red
        "high": Colors.ERROR,
        "medium": Colors.WARNING,
        "low": Colors.INFO,
        "info": 0x95A5A6,  # Gray
    }
    color = severity_colors.get(severity.lower(), Colors.WARNING)
    
    embed = discord.Embed(
        title=f"⚠️ {vuln_name}",
        description=description or "Vulnerability detected.",
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Affected Asset",
        value=f"`{asset}`",
        inline=True,
    )
    
    embed.add_field(
        name="Severity",
        value=severity.upper(),
        inline=True,
    )
    
    if cvss is not None:
        embed.add_field(
            name="CVSS Score",
            value=str(cvss),
            inline=True,
        )
    
    if cve:
        embed.add_field(
            name="CVE Reference",
            value=f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})",
            inline=True,
        )
    
    if remediation:
        embed.add_field(
            name="Remediation",
            value=remediation,
            inline=False,
        )
    
    embed.set_footer(text="Found by Victor Vuln")
    
    return embed


def create_error_embed(
    title: str,
    message: str,
    details: str | None = None,
) -> discord.Embed:
    """Create embed for error messages."""
    embed = discord.Embed(
        title=f"❌ {title}",
        description=message,
        color=Colors.ERROR,
        timestamp=datetime.now(timezone.utc),
    )
    
    if details:
        embed.add_field(
            name="Details",
            value=f"```{details}```",
            inline=False,
        )
    
    embed.set_footer(text="AM-Corp System")
    
    return embed


def create_scope_confirmation_embed(target: str) -> discord.Embed:
    """Create embed for scope confirmation request."""
    embed = discord.Embed(
        title="⚠️ Authorization Required",
        description=(
            f"Target `{target}` is not in pre-approved scope.\n\n"
            "**Please confirm you have authorization to scan this target.**"
        ),
        color=Colors.WARNING,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="To Proceed",
        value="React with ✅",
        inline=True,
    )
    
    embed.add_field(
        name="To Cancel",
        value="React with ❌",
        inline=True,
    )
    
    embed.set_footer(text="This confirmation expires in 60 seconds")
    
    return embed


def create_blocked_embed(target: str, reason: str) -> discord.Embed:
    """Create embed for blocked target."""
    embed = discord.Embed(
        title="🚫 Target Blocked",
        description=f"Cannot scan `{target}`",
        color=Colors.ERROR,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Reason",
        value=reason,
        inline=False,
    )
    
    embed.add_field(
        name="Policy",
        value="AM-Corp strictly prohibits scanning government (.gov) and military (.mil) domains.",
        inline=False,
    )
    
    embed.set_footer(text="This action has been logged")
    
    return embed


def create_status_embed(
    active_job: dict[str, Any] | None = None,
) -> discord.Embed:
    """Create embed for status command."""
    if active_job:
        embed = discord.Embed(
            title="📊 Current Status",
            description="A job is currently running.",
            color=Colors.INFO,
            timestamp=datetime.now(timezone.utc),
        )
        
        embed.add_field(
            name="Target",
            value=f"`{active_job.get('target', 'Unknown')}`",
            inline=True,
        )
        
        embed.add_field(
            name="Phase",
            value=active_job.get("phase", "Unknown"),
            inline=True,
        )
        
        embed.add_field(
            name="Started",
            value=active_job.get("started", "Unknown"),
            inline=True,
        )
    else:
        embed = discord.Embed(
            title="📊 Current Status",
            description="No active jobs. Ready for commands.",
            color=Colors.SUCCESS,
            timestamp=datetime.now(timezone.utc),
        )
        
        embed.add_field(
            name="Team Status",
            value=(
                "🔍 Randy Recon - Ready\n"
                "⚠️ Victor Vuln - Ready\n"
                "🧠 Ivy Intel - Ready\n"
                "📊 Rita Report - Ready"
            ),
            inline=False,
        )
    
    embed.set_footer(text="AM-Corp Security Team")
    
    return embed


def create_config_overview_embed() -> discord.Embed:
    """Create embed showing all agents configuration overview."""
    embed = discord.Embed(
        title="🤖 AM-Corp Agent Configuration",
        description="Overview of all agents and their current settings.",
        color=Colors.INFO,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="🔍 Randy Recon",
        value=(
            "**Tools:** dig, whois, nmap\n"
            "**Scan Type:** TCP connect (-sT)\n"
            "**Ports:** Top 500\n"
            "`!config randy` for details"
        ),
        inline=True,
    )
    
    embed.add_field(
        name="⚠️ Victor Vuln",
        value=(
            "**Tool:** Nuclei\n"
            "**Templates:** 4 categories\n"
            "**Severity:** critical, high, medium\n"
            "`!config victor` for details"
        ),
        inline=True,
    )
    
    embed.add_field(
        name="🧠 Ivy Intel",
        value=(
            "**Status:** Not yet implemented\n"
            "**Planned:** OSINT, threat intel\n"
            "`!config ivy` for details"
        ),
        inline=True,
    )
    
    embed.add_field(
        name="📊 Rita Report",
        value=(
            "**Status:** Not yet implemented\n"
            "**Planned:** Report generation\n"
            "`!config rita` for details"
        ),
        inline=True,
    )
    
    embed.set_footer(text="Use !config <agent> for detailed configuration")
    
    return embed


def create_randy_config_embed() -> discord.Embed:
    """Create detailed config embed for Randy Recon."""
    embed = discord.Embed(
        title="🔍 Randy Recon - Configuration",
        description="Reconnaissance specialist settings and tools.",
        color=Colors.RECON,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="DNS Lookup (dig)",
        value=(
            "```\n"
            "dig +short <target> A\n"
            "dig +short <target> AAAA\n"
            "dig +short <target> MX\n"
            "dig +short <target> NS\n"
            "dig +short <target> TXT\n"
            "dig +short <target> CNAME\n"
            "```"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="WHOIS Lookup",
        value=(
            "```\n"
            "whois <base_domain>\n"
            "```\n"
            "Extracts: registrar, creation date, expiry, name servers"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Port Scan (nmap)",
        value=(
            "```\n"
            "nmap -sT -T4 --top-ports 500 -sV -n -Pn --open\n"
            "```"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Nmap Flags",
        value=(
            "• `-sT` TCP connect scan (no root)\n"
            "• `-T4` Aggressive timing\n"
            "• `--top-ports 500` Most common ports\n"
            "• `-sV` Service version detection\n"
            "• `-n` Skip DNS resolution\n"
            "• `-Pn` Skip host discovery\n"
            "• `--open` Only show open ports"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Timeout",
        value="5 minutes (300 seconds)",
        inline=True,
    )
    
    embed.add_field(
        name="Restrictions",
        value="❌ .gov/.mil domains blocked",
        inline=True,
    )
    
    embed.set_footer(text="Randy Recon")
    
    return embed


def create_victor_config_embed() -> discord.Embed:
    """Create detailed config embed for Victor Vuln."""
    embed = discord.Embed(
        title="⚠️ Victor Vuln - Configuration",
        description="Vulnerability analyst settings and templates.",
        color=Colors.VULN,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Scanner",
        value="**Nuclei** v3.3.7 by ProjectDiscovery",
        inline=False,
    )
    
    embed.add_field(
        name="Current Templates",
        value=(
            "• `cves` - Known CVE vulnerabilities\n"
            "• `vulnerabilities` - Generic security issues\n"
            "• `misconfigurations` - Security misconfigs\n"
            "• `exposures` - Sensitive data exposure"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Severity Filter",
        value="`critical`, `high`, `medium`\n(low/info excluded)",
        inline=True,
    )
    
    embed.add_field(
        name="Rate Limit",
        value="150 requests/second",
        inline=True,
    )
    
    embed.add_field(
        name="Timeout",
        value="10 minutes per scan",
        inline=True,
    )
    
    embed.add_field(
        name="Command",
        value=(
            "```\n"
            "nuclei -u <target> -severity critical,high,medium\n"
            "       -tags cves,vulnerabilities,misconfigurations,exposures\n"
            "       -jsonl -silent -rate-limit 150\n"
            "```"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Smart Mode",
        value=(
            "✅ **Enabled** - Templates adapt based on Randy's findings\n"
            "• With recon data: Selects templates matching discovered services\n"
            "• Without recon: Uses default broad templates"
        ),
        inline=False,
    )
    
    embed.set_footer(text="Victor Vuln")
    
    return embed


def create_ivy_config_embed() -> discord.Embed:
    """Create detailed config embed for Ivy Intel."""
    embed = discord.Embed(
        title="🧠 Ivy Intel - Configuration",
        description="Threat intelligence analyst settings.",
        color=Colors.INTEL,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Status",
        value="⏳ **Not Yet Implemented**",
        inline=False,
    )
    
    embed.add_field(
        name="Planned Tools",
        value=(
            "• `shodan_lookup` - Internet exposure data\n"
            "• `virustotal_check` - Reputation and malware\n"
            "• `breach_check` - Historical breaches\n"
            "• `whois_history` - Domain ownership history"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Planned Capabilities",
        value=(
            "• OSINT gathering\n"
            "• Threat actor correlation\n"
            "• Breach history analysis\n"
            "• Reputation scoring"
        ),
        inline=False,
    )
    
    embed.set_footer(text="Ivy Intel")
    
    return embed


def create_rita_config_embed() -> discord.Embed:
    """Create detailed config embed for Rita Report."""
    embed = discord.Embed(
        title="📊 Rita Report - Configuration",
        description="Security report analyst settings.",
        color=Colors.REPORT,
        timestamp=datetime.now(timezone.utc),
    )
    
    embed.add_field(
        name="Status",
        value="⏳ **Not Yet Implemented**",
        inline=False,
    )
    
    embed.add_field(
        name="Planned Tools",
        value=(
            "• `template_renderer` - Markdown/PDF generation\n"
            "• `chart_generator` - Visualization creation\n"
            "• `summary_writer` - Executive summary generation"
        ),
        inline=False,
    )
    
    embed.add_field(
        name="Planned Report Structure",
        value=(
            "1. Executive Summary\n"
            "2. Scope and Methodology\n"
            "3. Key Findings (prioritized)\n"
            "4. Technical Details\n"
            "5. Remediation Roadmap\n"
            "6. Appendices"
        ),
        inline=False,
    )
    
    embed.set_footer(text="Rita Report")
    
    return embed


def create_agent_embed(
    agent_id: str,
    title: str,
    description: str,
    fields: list[tuple[str, str, bool]] | None = None,
) -> discord.Embed:
    """
    Create an embed styled for a specific agent.
    
    Args:
        agent_id: Agent identifier
        title: Embed title
        description: Embed description
        fields: List of (name, value, inline) tuples
    """
    agent = AGENTS.get(agent_id, {})
    
    agent_colors = {
        "randy_recon": Colors.RECON,
        "victor_vuln": Colors.VULN,
        "ivy_intel": Colors.INTEL,
        "rita_report": Colors.REPORT,
    }
    
    color = agent_colors.get(agent_id, Colors.INFO)
    emoji = agent.get("emoji", "🤖")
    name = agent.get("name", "Agent")
    
    embed = discord.Embed(
        title=f"{emoji} {title}",
        description=description,
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    
    if fields:
        for field_name, field_value, inline in fields:
            embed.add_field(name=field_name, value=field_value, inline=inline)
    
    embed.set_footer(text=name)
    
    return embed

