"""
Run-scoped findings collector.

WHY THIS EXISTS:
  CrewAI tools return text strings to the LLM. That text lives in the
  model's context window but is not accessible as structured data in
  Python. This module gives tools a place to write parsed results so
  the rest of the pipeline (handoffs, embeds, next-agent context) can
  read real data instead of trying to parse the LLM's prose.

USAGE:
  - At crew kickoff: call init_run(job_id) to create a fresh slot.
  - Inside a tool:   call get_findings(job_id).set_ports([...]) etc.
  - After the crew:  call get_findings(job_id) to read results.
  - On cleanup:      call clear_run(job_id).

Each !scan gets a unique job_id so concurrent scans (future) don't
collide. For now there's only ever one active scan at a time.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.tools.intel_tools import (
    CVEDetails,
    SecurityTrailsResult,
    ShodanResult,
    VirusTotalResult,
    assess_exploitation_risk,
)

if TYPE_CHECKING:
    from src.agents.ivy_intel import IntelScanResult
    from src.agents.randy_recon import ReconResult
    from src.agents.rita_report import ReportResult
    from src.agents.victor_vuln import VulnScanResult


@dataclass
class ReconFindings:
    """Structured output from Randy's recon crew."""

    target: str
    ports: list[dict[str, Any]] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    whois_info: dict[str, str] = field(default_factory=dict)
    raw_output: str = ""
    # Which lookups have been attempted, so a degraded (no-LLM) fallback
    # only runs the phases the agent did not reach. Tracks attempts, not
    # successes — a phase that ran but found nothing is still "done".
    completed: set[str] = field(default_factory=set)

    def set_ports(self, ports: list[dict[str, Any]]) -> None:
        """Called by port_scan_tool after an nmap run."""
        self.ports = ports
        self.completed.add("ports")

    def set_dns(self, records: dict[str, list[str]]) -> None:
        """Called by dns_lookup_tool after a dig run."""
        self.dns_records = records
        self.completed.add("dns")

    def set_whois(self, info: dict[str, str]) -> None:
        """Called by whois_lookup_tool after a whois run."""
        self.whois_info = info
        self.completed.add("whois")

    @property
    def open_port_count(self) -> int:
        return len(self.ports)

    @property
    def has_web_ports(self) -> bool:
        web_ports = {80, 443, 8080, 8443, 8000, 8888}
        return any(int(p.get("port", 0)) in web_ports for p in self.ports)


# In-memory store keyed by job_id
_store: dict[str, ReconFindings] = {}


def init_run(job_id: str, target: str) -> ReconFindings:
    """Create a fresh findings slot for a new scan job."""
    findings = ReconFindings(target=target)
    _store[job_id] = findings
    return findings


def get_findings(job_id: str) -> ReconFindings | None:
    """Retrieve findings for an active run. Returns None if not found."""
    return _store.get(job_id)


def clear_run(job_id: str) -> None:
    """Remove findings after the job is complete."""
    _store.pop(job_id, None)


@dataclass
class VulnFindings:
    """Structured output from Victor's vulnerability scan crew."""

    target: str
    # Open ports from Randy's recon, fed in at init_vuln_run(). Read by the
    # nuclei tool wrapper to drive smart template selection.
    ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    templates_used: list[str] = field(default_factory=list)
    # Which phases have been attempted, so a degraded (no-LLM) fallback only
    # runs the phases the agent did not reach.
    completed: set[str] = field(default_factory=set)

    def set_findings(
        self, findings: list[dict[str, Any]], templates: list[str]
    ) -> None:
        """Called by nuclei_scan_tool after a scan run."""
        self.findings = findings
        self.templates_used = templates
        self.completed.add("nuclei")

    def _count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.get("severity") == severity)

    @property
    def critical_count(self) -> int:
        return self._count("critical")

    @property
    def high_count(self) -> int:
        return self._count("high")

    @property
    def medium_count(self) -> int:
        return self._count("medium")

    @property
    def low_count(self) -> int:
        return self._count("low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") in ("info", "unknown"))

    @property
    def cve_ids(self) -> list[str]:
        return [f["cve_id"] for f in self.findings if f.get("cve_id")]


# In-memory store keyed by job_id, separate from the recon store above since
# the two dataclasses are shaped differently and a full scan runs both in the
# same process with distinct job_ids.
_vuln_store: dict[str, VulnFindings] = {}


def init_vuln_run(
    job_id: str, target: str, ports: list[dict[str, Any]] | None = None
) -> VulnFindings:
    """Create a fresh vuln findings slot for a new scan job."""
    findings = VulnFindings(target=target, ports=ports or [])
    _vuln_store[job_id] = findings
    return findings


def get_vuln_findings(job_id: str) -> VulnFindings | None:
    """Retrieve vuln findings for an active run. Returns None if not found."""
    return _vuln_store.get(job_id)


def clear_vuln_run(job_id: str) -> None:
    """Remove vuln findings after the job is complete."""
    _vuln_store.pop(job_id, None)


@dataclass
class IntelFindings:
    """Structured output from Ivy's threat intelligence crew."""

    target: str
    # Inputs extracted from Victor's handoff, fed in at init_intel_run(). Read
    # by the tool wrappers to know what to enrich/look up.
    cves: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cve_enrichments: list[CVEDetails] = field(default_factory=list)
    shodan_result: ShodanResult | None = None
    virustotal_result: VirusTotalResult | None = None
    securitytrails_result: SecurityTrailsResult | None = None
    # Which sources have been attempted, so a degraded (no-LLM) fallback only
    # runs the sources the agent did not reach.
    completed: set[str] = field(default_factory=set)

    def set_cve_enrichments(self, items: list[CVEDetails]) -> None:
        """Called by cve_enrichment_tool after an NVD/EPSS lookup."""
        self.cve_enrichments = items
        self.completed.add("cve")

    def set_shodan_result(self, result: ShodanResult) -> None:
        """Called by shodan_lookup_tool after a Shodan lookup."""
        self.shodan_result = result
        self.completed.add("shodan")

    def set_virustotal_result(self, result: VirusTotalResult) -> None:
        """Called by virustotal_lookup_tool after a VirusTotal lookup."""
        self.virustotal_result = result
        self.completed.add("virustotal")

    def set_securitytrails_result(self, result: SecurityTrailsResult) -> None:
        """Called by securitytrails_lookup_tool after a SecurityTrails lookup."""
        self.securitytrails_result = result
        self.completed.add("securitytrails")

    @property
    def high_risk_cve_count(self) -> int:
        return sum(
            1
            for c in self.cve_enrichments
            if not c.error and assess_exploitation_risk(c) in ("CRITICAL", "HIGH")
        )


# In-memory store keyed by job_id, separate from the recon/vuln stores above.
_intel_store: dict[str, IntelFindings] = {}


def init_intel_run(
    job_id: str,
    target: str,
    cves: list[str] | None = None,
    ips: list[str] | None = None,
) -> IntelFindings:
    """Create a fresh intel findings slot for a new scan job."""
    findings = IntelFindings(target=target, cves=cves or [], ips=ips or [])
    _intel_store[job_id] = findings
    return findings


def get_intel_findings(job_id: str) -> IntelFindings | None:
    """Retrieve intel findings for an active run. Returns None if not found."""
    return _intel_store.get(job_id)


def clear_intel_run(job_id: str) -> None:
    """Remove intel findings after the job is complete."""
    _intel_store.pop(job_id, None)


@dataclass
class ReportFindings:
    """Structured output from Rita's report-compilation crew."""

    target: str
    # Inputs from the other three agents, fed in at init_report_run(). Read by
    # the tool wrapper since the LLM has no way to pass these complex objects.
    recon_result: "ReconResult | None" = None
    vuln_result: "VulnScanResult | None" = None
    intel_result: "IntelScanResult | None" = None
    report: "ReportResult | None" = None
    # Rita has exactly one phase ("report"), tracked for consistency with the
    # other findings stores and the degraded-fallback safety net.
    completed: set[str] = field(default_factory=set)

    def set_report(self, report: "ReportResult") -> None:
        """Called by compile_report_tool once the report is compiled."""
        self.report = report
        self.completed.add("report")


# In-memory store keyed by job_id, separate from the other stores above.
_report_store: dict[str, ReportFindings] = {}


def init_report_run(
    job_id: str,
    target: str,
    recon_result: "ReconResult | None" = None,
    vuln_result: "VulnScanResult | None" = None,
    intel_result: "IntelScanResult | None" = None,
) -> ReportFindings:
    """Create a fresh report findings slot for a new scan job."""
    findings = ReportFindings(
        target=target,
        recon_result=recon_result,
        vuln_result=vuln_result,
        intel_result=intel_result,
    )
    _report_store[job_id] = findings
    return findings


def get_report_findings(job_id: str) -> ReportFindings | None:
    """Retrieve report findings for an active run. Returns None if not found."""
    return _report_store.get(job_id)


def clear_report_run(job_id: str) -> None:
    """Remove report findings after the job is complete."""
    _report_store.pop(job_id, None)
