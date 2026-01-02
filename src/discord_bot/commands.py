"""
AM-Corp Discord Command Handlers

Defines all bot commands (!scan, !help, !status, etc.)
"""

import discord
from discord.ext import commands

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

from .agent_bots import send_as_randy
from .embeds import (
    create_blocked_embed,
    create_config_overview_embed,
    create_error_embed,
    create_help_embed,
    create_ivy_config_embed,
    create_randy_config_embed,
    create_rita_config_embed,
    create_scan_started_embed,
    create_scope_confirmation_embed,
    create_status_embed,
    create_victor_config_embed,
)
from .scope_cache import get_scope_cache
from .validators import validate_target
from .webhooks import post_alert

logger = get_logger(__name__)


def _parse_verbose_flag(args: tuple[str, ...]) -> bool:
    """Check if -v or --verbose flag is present in args."""
    return "-v" in args or "--verbose" in args


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
    async def scan_command(ctx: commands.Context, target: str, *args: str) -> None:
        """Start a full security assessment. Use -v for verbose mode."""
        verbose = _parse_verbose_flag(args)
        await handle_scan(ctx, target, "full", bot, verbose=verbose)

    @bot.command(name="recon")
    async def recon_command(ctx: commands.Context, target: str, *args: str) -> None:
        """Start reconnaissance only. Use -v for verbose mode."""
        verbose = _parse_verbose_flag(args)
        await handle_scan(ctx, target, "recon", bot, verbose=verbose)

    @bot.command(name="vuln")
    async def vuln_command(ctx: commands.Context, target: str, *args: str) -> None:
        """Start vulnerability scan only. Use -v for verbose mode."""
        verbose = _parse_verbose_flag(args)
        await handle_scan(ctx, target, "vuln", bot, verbose=verbose)

    @bot.command(name="intel")
    async def intel_command(ctx: commands.Context, target: str, *args: str) -> None:
        """Start threat intelligence lookup only. Use -v for verbose mode."""
        verbose = _parse_verbose_flag(args)
        await handle_scan(ctx, target, "intel", bot, verbose=verbose)

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

    @bot.command(name="debug")
    async def debug_command(ctx: commands.Context, action: str | None = None) -> None:
        """Toggle debug channel output."""
        from src.utils.debug import is_debug_enabled, set_debug_channel
        from src.utils.config import settings
        
        if action is None:
            # Show current status
            status = "✅ **Enabled**" if is_debug_enabled() else "❌ **Disabled**"
            channel_info = ""
            if settings.discord_channel_debug:
                channel_info = f"\nDebug channel: <#{settings.discord_channel_debug}>"
            
            embed = discord.Embed(
                title="🐛 Debug Mode Status",
                description=f"Status: {status}{channel_info}",
                color=0x9B59B6,
            )
            embed.add_field(
                name="Usage",
                value=(
                    "`!debug on` - Enable debug output\n"
                    "`!debug off` - Disable debug output\n"
                    "`!debug` - Show current status"
                ),
                inline=False,
            )
            embed.add_field(
                name="Note",
                value="Debug channel must be configured in `.env` with `DEBUG_CHANNEL_ENABLED=true` and `DISCORD_CHANNEL_DEBUG=<channel_id>`",
                inline=False,
            )
            await ctx.send(embed=embed)
            return
        
        action_lower = action.lower()
        
        if action_lower in ("on", "enable", "true", "1"):
            if not settings.discord_channel_debug:
                await ctx.send(
                    embed=create_error_embed(
                        "Debug Channel Not Configured",
                        "Set `DISCORD_CHANNEL_DEBUG` in your `.env` file to enable debug output."
                    )
                )
                return
            
            # Enable debug channel
            settings.debug_channel_enabled = True
            
            # Try to set up the channel
            guild = ctx.guild
            if guild:
                debug_channel = guild.get_channel(int(settings.discord_channel_debug))
                if debug_channel:
                    set_debug_channel(debug_channel)
                    await ctx.send("✅ Debug mode **enabled**. Technical details will be posted to the debug channel.")
                else:
                    await ctx.send(
                        embed=create_error_embed(
                            "Debug Channel Not Found",
                            f"Could not find channel with ID `{settings.discord_channel_debug}`"
                        )
                    )
        
        elif action_lower in ("off", "disable", "false", "0"):
            settings.debug_channel_enabled = False
            set_debug_channel(None)
            await ctx.send("❌ Debug mode **disabled**.")
        
        else:
            await ctx.send(
                embed=create_error_embed(
                    "Unknown Action",
                    f"Unknown action: `{action}`\n\nUse `on` or `off`."
                )
            )

    @bot.command(name="config")
    async def config_command(ctx: commands.Context, agent: str | None = None) -> None:
        """Show agent configuration details."""
        if agent is None:
            # Show overview of all agents
            await ctx.send(embed=create_config_overview_embed())
            return
        
        # Normalize agent name
        agent_lower = agent.lower().strip()
        
        # Map common names to canonical names
        agent_map = {
            "randy": "randy",
            "randy_recon": "randy",
            "recon": "randy",
            "victor": "victor",
            "victor_vuln": "victor",
            "vuln": "victor",
            "ivy": "ivy",
            "ivy_intel": "ivy",
            "intel": "ivy",
            "rita": "rita",
            "rita_report": "rita",
            "report": "rita",
        }
        
        canonical = agent_map.get(agent_lower)
        
        if canonical == "randy":
            await ctx.send(embed=create_randy_config_embed())
        elif canonical == "victor":
            await ctx.send(embed=create_victor_config_embed())
        elif canonical == "ivy":
            await ctx.send(embed=create_ivy_config_embed())
        elif canonical == "rita":
            await ctx.send(embed=create_rita_config_embed())
        else:
            await ctx.send(
                embed=create_error_embed(
                    "Unknown Agent",
                    f"Unknown agent: `{agent}`\n\n"
                    "Available agents:\n"
                    "• `randy` (or `recon`)\n"
                    "• `victor` (or `vuln`)\n"
                    "• `ivy` (or `intel`)\n"
                    "• `rita` (or `report`)"
                )
            )

    logger.info("Commands registered")


async def handle_scan(
    ctx: commands.Context,
    target: str,
    scan_type: str,
    bot: commands.Bot,
    verbose: bool = False,
) -> None:
    """
    Handle scan commands with validation and confirmation flow.
    
    Scope approvals are cached for 12 hours to avoid repeated confirmations.
    
    Args:
        ctx: Discord command context
        target: Target to scan
        scan_type: Type of scan (recon, vuln, full, intel)
        bot: Bot instance
        verbose: If True, agents output additional technical details
    """
    # Debug: Track invocations
    logger.info(
        "handle_scan called",
        target=target,
        scan_type=scan_type,
        message_id=ctx.message.id,
        bot_user=str(bot.user),
    )
    
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

    # Check scope cache for recent approval (12hr window)
    scope_cache = get_scope_cache()
    
    if result.requires_confirmation and not scope_cache.is_approved(target):
        # Need confirmation - send request
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
            "verbose": verbose,
        }

        logger.info(
            "Awaiting scan confirmation",
            target=target,
            user=str(ctx.author),
        )
        return
    
    # Log if using cached approval
    if result.requires_confirmation and scope_cache.is_approved(target):
        remaining = scope_cache.time_remaining(target)
        hours_left = remaining.total_seconds() / 3600 if remaining else 0
        logger.info(
            f"Using cached scope approval for {target}",
            hours_remaining=f"{hours_left:.1f}",
        )

    # Target is approved (either pre-approved, or cached), start scan
    await ctx.send(embed=create_scan_started_embed(target, scan_type))
    await bot.start_scan(target, scan_type, ctx.channel, verbose=verbose)

