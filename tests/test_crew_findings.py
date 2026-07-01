"""Tests for the run-scoped recon findings store (src/crew/findings.py)."""

from src.crew import findings as f


def test_init_get_clear_lifecycle() -> None:
    """init_run stores an object, get_findings retrieves it, clear_run removes it."""
    # Arrange / Act
    obj = f.init_run("job-1", "example.com")

    # Assert
    assert f.get_findings("job-1") is obj
    assert obj.target == "example.com"

    f.clear_run("job-1")
    assert f.get_findings("job-1") is None


def test_setters_populate_and_track_completed() -> None:
    """Each setter stores data and records the phase as completed."""
    # Arrange
    obj = f.init_run("job-2", "example.com")

    # Act
    obj.set_dns({"A": ["1.2.3.4"]})
    obj.set_whois({"registrar": "Dynadot"})
    obj.set_ports([{"port": 80}, {"port": 443}])

    # Assert
    assert obj.dns_records == {"A": ["1.2.3.4"]}
    assert obj.whois_info == {"registrar": "Dynadot"}
    assert obj.open_port_count == 2
    assert obj.completed == {"dns", "whois", "ports"}

    f.clear_run("job-2")


def test_completed_tracks_empty_port_scan() -> None:
    """A port scan that finds nothing is still marked completed (attempted)."""
    # Arrange
    obj = f.init_run("job-3", "example.com")

    # Act
    obj.set_ports([])

    # Assert
    assert obj.open_port_count == 0
    assert "ports" in obj.completed

    f.clear_run("job-3")


def test_has_web_ports() -> None:
    """has_web_ports is True only when a known web port is open."""
    # Arrange
    obj = f.init_run("job-4", "example.com")

    # Act / Assert
    obj.set_ports([{"port": 22}])
    assert obj.has_web_ports is False

    obj.set_ports([{"port": 22}, {"port": 443}])
    assert obj.has_web_ports is True

    f.clear_run("job-4")


def test_clear_run_is_idempotent() -> None:
    """Clearing a job id that was never registered does not raise."""
    # Act / Assert — should be a no-op, not a KeyError
    f.clear_run("never-existed")
