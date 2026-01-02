"""
AM-Corp Debug Channel Utility

Provides functions to post technical debug information to a dedicated
Discord channel when debug mode is enabled.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Global reference to debug channel (set by agent bots)
_debug_channel = None


def set_debug_channel(channel) -> None:
    """Set the debug channel reference (called during bot startup)."""
    global _debug_channel
    _debug_channel = channel
    if channel:
        logger.info(f"Debug channel set: #{channel.name}")


def is_debug_enabled() -> bool:
    """Check if debug channel output is enabled."""
    return settings.debug_channel_enabled and _debug_channel is not None


async def post_debug(
    message: str,
    category: str = "INFO",
    agent: str | None = None,
    data: dict[str, Any] | None = None,
) -> bool:
    """
    Post a debug message to the debug channel.
    
    Args:
        message: Debug message to post
        category: Category (INFO, CMD, RESULT, ERROR, TIMING)
        agent: Agent ID posting the debug message
        data: Optional structured data to include
    
    Returns:
        True if posted successfully, False otherwise
    """
    if not is_debug_enabled():
        return False
    
    try:
        # Format timestamp
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        
        # Category emoji
        category_emoji = {
            "INFO": "ℹ️",
            "CMD": "⚙️",
            "RESULT": "📤",
            "ERROR": "❌",
            "TIMING": "⏱️",
        }.get(category.upper(), "🔹")
        
        # Agent prefix
        agent_prefix = f"[{agent}] " if agent else ""
        
        # Build message
        formatted = f"`{timestamp}` {category_emoji} {agent_prefix}{message}"
        
        # Add data block if provided
        if data:
            import json
            data_str = json.dumps(data, indent=2, default=str)
            # Truncate if too long
            if len(data_str) > 500:
                data_str = data_str[:497] + "..."
            formatted += f"\n```json\n{data_str}\n```"
        
        await _debug_channel.send(formatted)
        return True
        
    except Exception as e:
        logger.error(f"Failed to post debug message: {e}")
        return False


async def debug_command(
    command: str,
    agent: str | None = None,
) -> bool:
    """Log a command being executed."""
    return await post_debug(
        f"Executing: `{command}`",
        category="CMD",
        agent=agent,
    )


async def debug_result(
    command: str,
    exit_code: int,
    duration: float,
    agent: str | None = None,
    output_preview: str | None = None,
) -> bool:
    """Log command result."""
    status = "✅" if exit_code == 0 else "❌"
    message = f"{status} `{command}` → exit {exit_code} ({duration:.2f}s)"
    
    if output_preview:
        # Truncate preview
        preview = output_preview[:100].replace("\n", " ")
        if len(output_preview) > 100:
            preview += "..."
        message += f"\n> {preview}"
    
    return await post_debug(message, category="RESULT", agent=agent)


async def debug_timing(
    phase: str,
    duration: float,
    agent: str | None = None,
) -> bool:
    """Log timing information."""
    return await post_debug(
        f"Phase `{phase}` completed in {duration:.2f}s",
        category="TIMING",
        agent=agent,
    )


async def debug_error(
    error: str,
    agent: str | None = None,
    exception: Exception | None = None,
) -> bool:
    """Log an error."""
    message = error
    if exception:
        message += f"\n```\n{type(exception).__name__}: {str(exception)[:200]}\n```"
    
    return await post_debug(message, category="ERROR", agent=agent)


async def debug_info(
    message: str,
    agent: str | None = None,
    data: dict[str, Any] | None = None,
) -> bool:
    """Log informational debug message."""
    return await post_debug(message, category="INFO", agent=agent, data=data)

