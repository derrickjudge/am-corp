"""
AM-Corp Discord Webhook Utilities

Post messages to Discord channels via webhooks. This allows agents to
communicate in Discord without needing the bot to be online.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from src.agents import AGENTS
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


class WebhookClient:
    """Client for posting messages to Discord webhooks."""

    def __init__(self) -> None:
        self.webhooks = {
            "agent_chat": settings.discord_webhook_agent_chat,
            "results": settings.discord_webhook_results,
            "alerts": settings.discord_webhook_alerts,
        }

    async def post_message(
        self,
        channel: str,
        content: str,
        username: str | None = None,
        avatar_url: str | None = None,
    ) -> bool:
        """
        Post a message to a Discord channel via webhook.

        Args:
            channel: Channel name ("agent_chat", "results", "alerts")
            content: Message content
            username: Override webhook username
            avatar_url: Override webhook avatar

        Returns:
            True if successful, False otherwise
        """
        webhook_url = self.webhooks.get(channel)
        if not webhook_url:
            logger.error(f"No webhook configured for channel: {channel}")
            return False

        payload: dict[str, Any] = {"content": content}
        if username:
            payload["username"] = username
        if avatar_url:
            payload["avatar_url"] = avatar_url

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
                logger.debug(f"Posted to {channel}", content_preview=content[:50])
                return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to post to {channel}", error=str(e))
            return False

    async def post_agent_message(
        self,
        agent_id: str,
        message: str,
        channel: str = "agent_chat",
    ) -> bool:
        """
        Post a message as a specific agent.

        Args:
            agent_id: Agent identifier (e.g., "randy_recon")
            message: Message content (without emoji prefix)
            channel: Target channel (default: agent_chat)

        Returns:
            True if successful, False otherwise
        """
        agent = AGENTS.get(agent_id)
        if not agent:
            logger.error(f"Unknown agent: {agent_id}")
            return False

        # Format message with agent emoji and name
        formatted_message = f"{agent['emoji']} **{agent['name']}:** {message}"

        # Audit log the agent message
        audit_log(
            action="agent_message",
            user=agent_id,
            result="posting",
            channel=channel,
            message_preview=message[:100],
        )

        return await self.post_message(
            channel=channel,
            content=formatted_message,
            username=agent["name"],
        )

    async def post_alert(
        self,
        message: str,
        severity: str = "warning",
    ) -> bool:
        """
        Post an alert to the alerts channel.

        Args:
            message: Alert message
            severity: Alert severity (info, warning, error, critical)

        Returns:
            True if successful, False otherwise
        """
        emoji_map = {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "❌",
            "critical": "🚨",
        }
        emoji = emoji_map.get(severity, "⚠️")
        formatted_message = f"{emoji} **ALERT [{severity.upper()}]:** {message}"

        audit_log(
            action="system_alert",
            user="system",
            result=severity,
            message_preview=message[:100],
        )

        return await self.post_message(
            channel="alerts",
            content=formatted_message,
            username="AM-Corp System",
        )


# Convenience functions for direct use
_client: WebhookClient | None = None


def get_webhook_client() -> WebhookClient:
    """Get or create the webhook client singleton."""
    global _client
    if _client is None:
        _client = WebhookClient()
    return _client


async def post_as_randy(message: str, channel: str = "agent_chat") -> bool:
    """Post a message as Randy Recon."""
    return await get_webhook_client().post_agent_message("randy_recon", message, channel)


async def post_as_victor(message: str, channel: str = "agent_chat") -> bool:
    """Post a message as Victor Vuln."""
    return await get_webhook_client().post_agent_message("victor_vuln", message, channel)


async def post_as_ivy(message: str, channel: str = "agent_chat") -> bool:
    """Post a message as Ivy Intel."""
    return await get_webhook_client().post_agent_message("ivy_intel", message, channel)


async def post_as_rita(message: str, channel: str = "agent_chat") -> bool:
    """Post a message as Rita Report."""
    return await get_webhook_client().post_agent_message("rita_report", message, channel)


async def post_alert(message: str, severity: str = "warning") -> bool:
    """Post a system alert."""
    return await get_webhook_client().post_alert(message, severity)

