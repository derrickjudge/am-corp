"""
AM-Corp Discord Command Handlers

Defines all bot commands (!scan, !help, !status, etc.)
"""

import discord
from discord.ext import commands

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

from .embeds import (
    create_blocked_embed,
    create_error_embed,
    create_help_embed,
    create_scan_started_embed,
    create_scope_confirmation_embed,
    create_status_embed,
)
from .validators import validate_target
from .webhooks import post_alert
from .agent_bots import send_as_randy

logger = get_logger(__name__)


async def setup_commands(bot: commands.Bot) -> None:
    """Set up all bot commands."""

    @bot.command(name="help")
    async def help_command(ctx: commands.Context) -> None:
        """Show available commands."""
        await ctx.send(embed=create_help_embed())

    @bot.command(name="status")
    async def status_command(ctx: commands.Context) -> None:
        """Show current job status."""
        await ctx.send(embed=create_status_embed(bot.active_job))

    @bot.command(name="scan")
    async def scan_command(ctx: commands.Context, target: str) -> None:
        """Start a full security assessment."""
        await handle_scan(ctx, target, "full", bot)

    @bot.command(name="recon")
    async def recon_command(ctx: commands.Context, target: str) -> None:
        """Start reconnaissance only."""
        await handle_scan(ctx, target, "recon", bot)

    @bot.command(name="vuln")
    async def vuln_command(ctx: commands.Context, target: str) -> None:
        """Start vulnerability scan only."""
        await handle_scan(ctx, target, "vuln", bot)

    @bot.command(name="intel")
    async def intel_command(ctx: commands.Context, target: str) -> None:
        """Start threat intelligence lookup only."""
        await handle_scan(ctx, target, "intel", bot)

    @bot.command(name="abort")
    async def abort_command(ctx: commands.Context) -> None:
        """Abort the current job."""
        if not bot.active_job:
            await ctx.send(
                embed=create_error_embed(
                    "No Active Job",
                    "There is no active job to abort.",
                )
            )
            return

        target = bot.active_job.get("target", "Unknown")
        bot.active_job = None

        audit_log(
            action="scan_aborted",
            user=str(ctx.author),
            target=target,
            result="aborted",
        )

        await ctx.send(f"🛑 Job aborted for `{target}`.")
        await post_alert(f"Scan aborted by {ctx.author}: {target}", severity="warning")

    @bot.command(name="scope")
    async def scope_command(
        ctx: commands.Context,
        action: str | None = None,
        domain: str | None = None,
    ) -> None:
        """Manage target scope."""
        if action is None:
            # Show help
            await ctx.send(
                embed=create_error_embed(
                    "Scope Command",
                    "Usage:\n"
                    "`!scope list` - Show allowed targets\n"
                    "`!scope add <domain>` - Add to allowed targets\n"
                    "`!scope remove <domain>` - Remove from allowed targets",
                )
            )
            return

        action = action.lower()

        if action == "list":
            allowed = settings.allowed_targets_list
            if allowed:
                targets_list = "\n".join(f"• `{t}`" for t in allowed)
                embed = discord.Embed(
                    title="🎯 Allowed Targets",
                    description=targets_list,
                    color=0x2ECC71,
                )
            else:
                embed = discord.Embed(
                    title="🎯 Allowed Targets",
                    description="No pre-approved targets. All scans require manual confirmation.",
                    color=0xF1C40F,
                )
            await ctx.send(embed=embed)

        elif action == "add":
            if not domain:
                await ctx.send(
                    embed=create_error_embed(
                        "Missing Domain",
                        "Usage: `!scope add <domain>`",
                    )
                )
                return

            # Note: This would need to persist to a database in production
            # For now, just acknowledge
            await ctx.send(
                f"⚠️ To add `{domain}` to allowed targets, please update "
                f"`ALLOWED_TARGETS` in your `.env` file and restart the bot.\n\n"
                f"Future versions will support dynamic scope management."
            )

        elif action == "remove":
            if not domain:
                await ctx.send(
                    embed=create_error_embed(
                        "Missing Domain",
                        "Usage: `!scope remove <domain>`",
                    )
                )
                return

            await ctx.send(
                f"⚠️ To remove `{domain}` from allowed targets, please update "
                f"`ALLOWED_TARGETS` in your `.env` file and restart the bot."
            )

        else:
            await ctx.send(
                embed=create_error_embed(
                    "Unknown Action",
                    f"Unknown scope action: `{action}`\n"
                    "Use `list`, `add`, or `remove`.",
                )
            )

    @bot.command(name="report")
    async def report_command(ctx: commands.Context) -> None:
        """Generate a report from current findings."""
        if not bot.active_job:
            await ctx.send(
                embed=create_error_embed(
                    "No Findings",
                    "No active job or findings to report on. Run a scan first.",
                )
            )
            return

        await ctx.send("📊 Report generation is not yet implemented. Coming soon!")

    @bot.command(name="ping")
    async def ping_command(ctx: commands.Context) -> None:
        """Check bot latency."""
        latency = round(bot.latency * 1000)
        await ctx.send(f"🏓 Pong! Latency: {latency}ms")

    logger.info("Commands registered")


async def handle_scan(
    ctx: commands.Context,
    target: str,
    scan_type: str,
    bot: commands.Bot,
) -> None:
    """
    Handle scan commands with validation and confirmation flow.
    """
    # Check if already running a job
    if bot.active_job:
        await ctx.send(
            embed=create_error_embed(
                "Job In Progress",
                f"A scan is already running on `{bot.active_job.get('target')}`. "
                "Use `!abort` to cancel it first.",
            )
        )
        return

    # Validate the target
    result = validate_target(target)

    if not result.is_valid:
        # Target is blocked
        if result.blocked_reason == "government_military":
            await ctx.send(embed=create_blocked_embed(target, result.message))
        else:
            await ctx.send(
                embed=create_error_embed("Invalid Target", result.message)
            )
        return

    if result.requires_confirmation:
        # Send confirmation request
        embed = create_scope_confirmation_embed(target)
        message = await ctx.send(embed=embed)

        # Add reactions
        await message.add_reaction("✅")
        await message.add_reaction("❌")

        # Store pending confirmation
        bot.pending_confirmations[message.id] = {
            "target": target,
            "scan_type": scan_type,
            "user": str(ctx.author),
        }

        logger.info(
            "Awaiting scan confirmation",
            target=target,
            user=str(ctx.author),
        )
        return

    # Target is approved, start scan
    await ctx.send(embed=create_scan_started_embed(target, scan_type))
    await bot.start_scan(target, scan_type, ctx.channel)

