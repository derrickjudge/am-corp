"""
AM-Corp Discord Bot

Main bot class that connects to Discord, listens for commands,
and coordinates agent responses.
"""

import asyncio
from datetime import datetime, timezone

import discord
from discord.ext import commands

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

from .embeds import (
    Colors,
    create_blocked_embed,
    create_error_embed,
    create_help_embed,
    create_scope_confirmation_embed,
    create_status_embed,
)
from .validators import validate_command, validate_target
from .webhooks import post_alert
from .agent_bots import send_as_randy

logger = get_logger(__name__)


class AMCorpBot(commands.Bot):
    """AM-Corp Discord Bot."""

    def __init__(self) -> None:
        # Set up intents
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.reactions = True

        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None,  # We'll use our own
        )

        self.commands_channel_id = int(settings.discord_channel_commands) if settings.discord_channel_commands else None
        self.active_job: dict | None = None
        self.pending_confirmations: dict[int, dict] = {}  # message_id -> job info

    async def setup_hook(self) -> None:
        """Called when the bot is starting up."""
        logger.info("Bot setup starting...")

    async def on_ready(self) -> None:
        """Called when the bot is connected and ready."""
        logger.info(
            "Bot connected to Discord",
            user=str(self.user),
            guilds=len(self.guilds),
        )

        audit_log(
            action="bot_connected",
            user="system",
            result="success",
            bot_user=str(self.user),
        )

        # Post startup message to alerts
        await post_alert(
            f"AM-Corp Bot online. Connected as {self.user}.",
            severity="info",
        )

        # Set presence
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="for !help",
            )
        )

    async def on_message(self, message: discord.Message) -> None:
        """Handle incoming messages."""
        # Ignore messages from bots (including ourselves)
        if message.author.bot:
            return

        # Only process commands in the commands channel
        if self.commands_channel_id and message.channel.id != self.commands_channel_id:
            # Ignore messages in other channels
            return

        # Check if it's a command
        if not message.content.startswith("!"):
            return

        # Log the command
        logger.info(
            "Command received",
            command=message.content,
            user=str(message.author),
            channel=str(message.channel),
        )

        audit_log(
            action="command_received",
            user=str(message.author),
            result="processing",
            command=message.content[:100],
        )

        # Process commands
        await self.process_commands(message)

    async def on_reaction_add(
        self, reaction: discord.Reaction, user: discord.User
    ) -> None:
        """Handle reaction additions for confirmations."""
        # Ignore bot reactions
        if user.bot:
            return

        message_id = reaction.message.id

        # Check if this is a pending confirmation
        if message_id not in self.pending_confirmations:
            return

        pending = self.pending_confirmations[message_id]

        if str(reaction.emoji) == "✅":
            # Approved
            logger.info(
                "Scan approved via reaction",
                user=str(user),
                target=pending.get("target"),
            )

            audit_log(
                action="scan_approved",
                user=str(user),
                target=pending.get("target"),
                result="approved",
            )

            # Remove from pending
            del self.pending_confirmations[message_id]

            # Start the scan
            await self.start_scan(
                pending["target"],
                pending["scan_type"],
                reaction.message.channel,
            )

        elif str(reaction.emoji) == "❌":
            # Cancelled
            logger.info(
                "Scan cancelled via reaction",
                user=str(user),
                target=pending.get("target"),
            )

            del self.pending_confirmations[message_id]

            await reaction.message.reply("❌ Scan cancelled.")

    async def start_scan(
        self,
        target: str,
        scan_type: str,
        channel: discord.TextChannel,
    ) -> None:
        """
        Start a scan on the given target.

        For now, this just has Randy announce the scan.
        In the future, this will trigger the full CrewAI pipeline.
        """
        self.active_job = {
            "target": target,
            "scan_type": scan_type,
            "phase": "recon",
            "started": datetime.now(timezone.utc).isoformat(),
        }

        # Have Randy announce the scan
        await post_as_randy(
            f"Got it! Starting {scan_type} scan on `{target}`. "
            "I'll report my findings as I go."
        )

        # TODO: Actually run the CrewAI agents here
        # For now, just simulate with a message
        await asyncio.sleep(2)

        await post_as_randy(
            f"Beginning subdomain enumeration on `{target}`... "
            "This is a simulation for now - full agent integration coming soon!"
        )

    async def on_command_error(
        self, ctx: commands.Context, error: commands.CommandError
    ) -> None:
        """Handle command errors."""
        if isinstance(error, commands.CommandNotFound):
            await ctx.send(
                embed=create_error_embed(
                    "Unknown Command",
                    f"Command not found. Use `!help` for available commands.",
                )
            )
        elif isinstance(error, commands.MissingRequiredArgument):
            await ctx.send(
                embed=create_error_embed(
                    "Missing Argument",
                    f"Missing required argument: `{error.param.name}`",
                )
            )
        else:
            logger.error("Command error", error=str(error))
            await ctx.send(
                embed=create_error_embed(
                    "Error",
                    "An error occurred while processing your command.",
                    details=str(error)[:500],
                )
            )


def create_bot() -> AMCorpBot:
    """Create and configure the AM-Corp bot."""
    return AMCorpBot()


async def run_bot() -> None:
    """Run the Discord bot."""
    if not settings.discord_bot_token:
        logger.error("DISCORD_BOT_TOKEN not set")
        return

    bot = create_bot()

    # Import and add commands
    from .commands import setup_commands
    await setup_commands(bot)

    logger.info("Starting bot...")

    try:
        await bot.start(settings.discord_bot_token)
    except discord.LoginFailure:
        logger.error("Invalid bot token")
    except Exception as e:
        logger.error("Bot error", error=str(e))
    finally:
        if not bot.is_closed():
            await bot.close()

