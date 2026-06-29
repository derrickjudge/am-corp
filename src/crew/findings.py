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
from typing import Any


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
