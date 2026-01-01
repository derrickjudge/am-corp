"""
AM-Corp Agent Bot Manager

Manages multiple Discord bot connections for each agent persona.
Each agent (Randy, Victor, Ivy, Rita) has their own bot that appears
as a separate user in Discord.
"""

import asyncio
from dataclasses import dataclass
from typing import Callable

import discord

from src.agents import AGENTS, AGENT_RANDY_RECON, AGENT_VICTOR_VULN, AGENT_IVY_INTEL, AGENT_RITA_REPORT
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


@dataclass
class AgentBotConfig:
    """Configuration for an agent bot."""
    
    agent_id: str
    name: str
    emoji: str
    token: str
    activity: str = "Ready to help"


class AgentBot(discord.Client):
    """A Discord bot for a specific agent persona."""

    def __init__(self, config: AgentBotConfig) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        
        super().__init__(intents=intents)
        
        self.config = config
        self.agent_chat_channel: discord.TextChannel | None = None
        self.results_channel: discord.TextChannel | None = None
        self.alerts_channel: discord.TextChannel | None = None
        self._ready = asyncio.Event()

    async def on_ready(self) -> None:
        """Called when the bot is connected and ready."""
        logger.info(
            f"{self.config.name} connected to Discord",
            user=str(self.user),
            agent=self.config.agent_id,
        )

        # Set presence/activity
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=self.config.activity,
            )
        )

        # Get channel references
        guild_id = int(settings.discord_guild_id) if settings.discord_guild_id else None
        if guild_id:
            guild = self.get_guild(guild_id)
            if guild:
                if settings.discord_channel_agent_chat:
                    self.agent_chat_channel = guild.get_channel(
                        int(settings.discord_channel_agent_chat)
                    )
                if settings.discord_channel_results:
                    self.results_channel = guild.get_channel(
                        int(settings.discord_channel_results)
                    )
                if settings.discord_channel_alerts:
                    self.alerts_channel = guild.get_channel(
                        int(settings.discord_channel_alerts)
                    )

        self._ready.set()

    async def wait_until_ready(self) -> None:
        """Wait until the bot is ready."""
        await self._ready.wait()

    async def send_message(
        self,
        message: str,
        channel: str = "agent_chat",
    ) -> bool:
        """
        Send a message as this agent.
        
        Args:
            message: Message content (without emoji prefix)
            channel: Target channel ("agent_chat", "results", "alerts")
            
        Returns:
            True if successful
        """
        await self.wait_until_ready()

        # Get target channel
        target_channel = None
        if channel == "agent_chat":
            target_channel = self.agent_chat_channel
        elif channel == "results":
            target_channel = self.results_channel
        elif channel == "alerts":
            target_channel = self.alerts_channel

        if not target_channel:
            logger.error(f"Channel not found: {channel}", agent=self.config.agent_id)
            return False

        # Format message with emoji
        formatted_message = f"{self.config.emoji} {message}"

        try:
            await target_channel.send(formatted_message)
            logger.debug(
                f"Message sent",
                agent=self.config.agent_id,
                channel=channel,
                preview=message[:50],
            )
            return True
        except discord.DiscordException as e:
            logger.error(
                f"Failed to send message",
                agent=self.config.agent_id,
                error=str(e),
            )
            return False

    async def send_embed(
        self,
        embed: discord.Embed,
        channel: str = "agent_chat",
    ) -> bool:
        """Send an embed as this agent."""
        await self.wait_until_ready()

        target_channel = None
        if channel == "agent_chat":
            target_channel = self.agent_chat_channel
        elif channel == "results":
            target_channel = self.results_channel
        elif channel == "alerts":
            target_channel = self.alerts_channel

        if not target_channel:
            return False

        try:
            await target_channel.send(embed=embed)
            return True
        except discord.DiscordException as e:
            logger.error(f"Failed to send embed", agent=self.config.agent_id, error=str(e))
            return False


class AgentBotManager:
    """Manages all agent bots."""

    def __init__(self) -> None:
        self.bots: dict[str, AgentBot] = {}
        self._tasks: list[asyncio.Task] = []

    def _create_agent_configs(self) -> list[AgentBotConfig]:
        """Create configurations for all agent bots."""
        configs = []

        # Randy Recon
        if settings.discord_bot_token_randy:
            configs.append(AgentBotConfig(
                agent_id=AGENT_RANDY_RECON,
                name="Randy Recon",
                emoji="🔍",
                token=settings.discord_bot_token_randy,
                activity="for targets to scan",
            ))

        # Victor Vuln
        if settings.discord_bot_token_victor:
            configs.append(AgentBotConfig(
                agent_id=AGENT_VICTOR_VULN,
                name="Victor Vuln",
                emoji="⚠️",
                token=settings.discord_bot_token_victor,
                activity="for vulnerabilities",
            ))

        # Ivy Intel
        if settings.discord_bot_token_ivy:
            configs.append(AgentBotConfig(
                agent_id=AGENT_IVY_INTEL,
                name="Ivy Intel",
                emoji="🧠",
                token=settings.discord_bot_token_ivy,
                activity="threat intelligence",
            ))

        # Rita Report
        if settings.discord_bot_token_rita:
            configs.append(AgentBotConfig(
                agent_id=AGENT_RITA_REPORT,
                name="Rita Report",
                emoji="📊",
                token=settings.discord_bot_token_rita,
                activity="findings to report",
            ))

        return configs

    async def start_all(self) -> None:
        """Start all agent bots."""
        configs = self._create_agent_configs()

        if not configs:
            logger.warning("No agent bot tokens configured")
            return

        logger.info(f"Starting {len(configs)} agent bots...")

        for config in configs:
            bot = AgentBot(config)
            self.bots[config.agent_id] = bot

            # Start bot in background task
            task = asyncio.create_task(
                bot.start(config.token),
                name=f"agent_bot_{config.agent_id}",
            )
            self._tasks.append(task)

        # Wait for all bots to be ready
        await asyncio.gather(
            *[bot.wait_until_ready() for bot in self.bots.values()],
            return_exceptions=True,
        )

        logger.info(
            "All agent bots ready",
            agents=list(self.bots.keys()),
        )

        audit_log(
            action="agent_bots_started",
            user="system",
            result="success",
            agents=list(self.bots.keys()),
        )

    async def stop_all(self) -> None:
        """Stop all agent bots."""
        logger.info("Stopping agent bots...")

        for bot in self.bots.values():
            await bot.close()

        for task in self._tasks:
            task.cancel()

        self.bots.clear()
        self._tasks.clear()

    def get_bot(self, agent_id: str) -> AgentBot | None:
        """Get a specific agent bot."""
        return self.bots.get(agent_id)

    async def send_as_agent(
        self,
        agent_id: str,
        message: str,
        channel: str = "agent_chat",
    ) -> bool:
        """
        Send a message as a specific agent.
        
        Falls back to webhook if bot not available.
        """
        bot = self.get_bot(agent_id)
        if bot:
            return await bot.send_message(message, channel)
        else:
            # Fall back to webhook
            from .webhooks import get_webhook_client
            client = get_webhook_client()
            return await client.post_agent_message(agent_id, message, channel)


# Singleton manager instance
_manager: AgentBotManager | None = None


def get_agent_manager() -> AgentBotManager:
    """Get the agent bot manager singleton."""
    global _manager
    if _manager is None:
        _manager = AgentBotManager()
    return _manager


# Convenience functions
async def send_as_randy(message: str, channel: str = "agent_chat") -> bool:
    """Send a message as Randy Recon."""
    return await get_agent_manager().send_as_agent(AGENT_RANDY_RECON, message, channel)


async def send_as_victor(message: str, channel: str = "agent_chat") -> bool:
    """Send a message as Victor Vuln."""
    return await get_agent_manager().send_as_agent(AGENT_VICTOR_VULN, message, channel)


async def send_as_ivy(message: str, channel: str = "agent_chat") -> bool:
    """Send a message as Ivy Intel."""
    return await get_agent_manager().send_as_agent(AGENT_IVY_INTEL, message, channel)


async def send_as_rita(message: str, channel: str = "agent_chat") -> bool:
    """Send a message as Rita Report."""
    return await get_agent_manager().send_as_agent(AGENT_RITA_REPORT, message, channel)

