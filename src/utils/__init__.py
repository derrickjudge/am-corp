"""
AM-Corp Utilities

Shared utilities for configuration, logging, and common operations.
"""

from .config import settings
from .logging import get_logger, setup_logging

__all__ = ["settings", "get_logger", "setup_logging"]

