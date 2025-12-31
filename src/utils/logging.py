"""
AM-Corp Logging Configuration

Structured logging setup using structlog for consistent,
machine-readable log output with rich console formatting.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.typing import EventDict, Processor

from .config import settings


def add_app_context(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add application context to all log entries."""
    event_dict["app"] = "am-corp"
    event_dict["environment"] = settings.environment
    return event_dict


def setup_logging(
    log_level: str | None = None,
    log_file: str | None = None,
    json_logs: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Override log level (defaults to settings.log_level)
        log_file: Override log file path (defaults to settings.log_file)
        json_logs: If True, output JSON logs (useful for production)
    """
    level = log_level or settings.log_level
    file_path = log_file or settings.log_file

    # Ensure log directory exists
    log_dir = Path(file_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    # Shared processors for all outputs
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        add_app_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_logs or settings.is_production:
        # JSON output for production/machine parsing
        processors: list[Processor] = [
            *shared_processors,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Rich console output for development
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also configure standard library logging for third-party libraries
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=getattr(logging, level.upper()),
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(file_path),
        ],
    )

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("discord").setLevel(logging.WARNING)


def get_logger(name: str | None = None, **initial_context: Any) -> structlog.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)
        **initial_context: Initial context to bind to all log entries

    Returns:
        Configured structlog BoundLogger

    Example:
        logger = get_logger(__name__, agent="recon")
        logger.info("Starting scan", target="example.com")
    """
    logger = structlog.get_logger(name)

    if initial_context:
        logger = logger.bind(**initial_context)

    return logger


# Convenience function for audit logging
def audit_log(
    action: str,
    target: str | None = None,
    user: str | None = None,
    result: str | None = None,
    **extra: Any,
) -> None:
    """
    Log an audit entry for security-relevant actions.

    All agent actions should be logged via this function.

    Args:
        action: The action being performed (e.g., "scan_started", "vuln_found")
        target: The target of the action
        user: The user/agent that initiated the action
        result: The result of the action
        **extra: Additional context
    """
    logger = get_logger("audit")
    logger.info(
        action,
        audit=True,
        target=target,
        user=user,
        result=result,
        **extra,
    )

