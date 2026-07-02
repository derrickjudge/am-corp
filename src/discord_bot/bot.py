"""
AM-Corp Discord Bot

Main bot class that connects to Discord, listens for commands,
and coordinates agent responses.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

import discord
from discord.ext import commands

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

from .embeds import (
    Colors,
    create_blocked_embed,
    create_error_embed,
    create_help_embed,
    create_report_findings_embed,
    create_report_header_embed,
    create_report_intel_embed,
    create_report_priorities_embed,
    create_report_summary_embed,
    create_scope_confirmation_embed,
    create_status_embed,
)
from .validators import validate_command, validate_target
from .agent_bots import send_as_randy, get_agent_manager
from .scope_cache import get_scope_cache
from .webhooks import post_alert, get_webhook_client
from .casual_chat import handle_human_message
from .mention_router import route_mentions
from .handoffs import HandoffContext, run_handoff
from src.agents import AGENT_RANDY_RECON, AGENT_VICTOR_VULN, AGENT_IVY_INTEL

logger = get_logger(__name__)


async def _post_report_to_results(report: "Any") -> None:
    """Post Rita's report as a series of embeds to the results webhook."""
    from src.agents.rita_report import ReportResult

    if not isinstance(report, ReportResult):
        return

    client = get_webhook_client()
    webhook_url = client.webhooks.get("results")
    if not webhook_url:
        logger.error("No results webhook configured — cannot post report")
        return

    embeds_to_post = [
        create_report_header_embed(report.target, report.overall_risk, report.scan_timestamp),
        create_report_summary_embed(report.executive_summary),
        create_report_findings_embed(report.vuln_counts, report.open_ports),
    ]

    if report.risk_items:
        embeds_to_post.append(create_report_priorities_embed(report.risk_items))

    if report.intel_highlights or report.shodan_exposure or report.virustotal_status:
        embeds_to_post.append(
            create_report_intel_embed(
                report.intel_highlights, report.shodan_exposure, report.virustotal_status
            )
        )

    # Discord allows max 10 embeds per message; split if needed
    import httpx
    chunk_size = 10
    for i in range(0, len(embeds_to_post), chunk_size):
        chunk = embeds_to_post[i : i + chunk_size]
        payload = {"embeds": [e.to_dict() for e in chunk]}
        try:
            async with httpx.AsyncClient() as http:
                resp = await http.post(webhook_url, json=payload)
                resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.error("Failed to post report to results", error=str(e))


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
        self.last_scan_results: dict | None = None  # persists after active_job clears
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
        # Ignore messages from bots (including ourselves) — loop prevention
        if message.author.bot:
            return

        channel_id = str(message.channel.id)

        # Check for @mentions of specific agents (any watched channel)
        mention_handled = await route_mentions(
            message_content=message.content,
            author_display=str(message.author.display_name),
            author_id=str(message.author.id),
            channel_id=channel_id,
            active_job=self.active_job,
            agent_manager=get_agent_manager(),
        )
        if mention_handled:
            return

        # Check for messages in #general channel (human interaction with agents)
        general_channel_id = settings.discord_channel_general
        if general_channel_id and channel_id == general_channel_id:
            # Human message in general chat - trigger agent response
            logger.debug(
                "Human message in general",
                author=str(message.author),
                content=message.content[:50],
            )
            # Fire and forget - don't block on response
            asyncio.create_task(
                handle_human_message(
                    message=message.content,
                    author=str(message.author.display_name),
                    author_id=str(message.author.id),
                )
            )
            return

        # Only process commands in the commands channel
        if self.commands_channel_id and message.channel.id != self.commands_channel_id:
            # Ignore messages in other channels
            return

        # Check if it's a command
        if not message.content.startswith("!"):
            return

        # Dedupe check - prevent processing the same message twice
        if hasattr(self, '_processed_messages'):
            if message.id in self._processed_messages:
                logger.warning(f"Duplicate message detected: {message.id}")
                return
            self._processed_messages.add(message.id)
            # Keep set small - only track last 100 messages
            if len(self._processed_messages) > 100:
                self._processed_messages = set(list(self._processed_messages)[-50:])
        else:
            self._processed_messages = {message.id}

        # Log the command
        logger.info(
            "Command received",
            command=message.content,
            user=str(message.author),
            channel=str(message.channel),
            message_id=message.id,
            bot_user=str(self.user),
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
            # Approved - add to scope cache (12hr TTL)
            target = pending.get("target")
            scope_cache = get_scope_cache()
            scope_cache.add_approval(
                target=target,
                approved_by=str(user),
                scan_type=pending.get("scan_type", "any"),
            )
            
            logger.info(
                "Scan approved via reaction",
                user=str(user),
                target=target,
            )

            audit_log(
                action="scan_approved",
                user=str(user),
                target=target,
                result="approved",
            )

            # Remove from pending
            del self.pending_confirmations[message_id]

            # Start the scan
            await self.start_scan(
                target,
                pending["scan_type"],
                reaction.message.channel,
                verbose=pending.get("verbose", False),
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
        verbose: bool = False,
    ) -> None:
        """
        Start a scan on the given target.

        Routes to appropriate agent(s) based on scan_type:
        - recon: Randy only
        - vuln: Randy → Victor (future)
        - intel: Ivy only (future)
        - full: Randy → Victor → Ivy → Rita (future)
        
        Args:
            target: Target to scan
            scan_type: Type of scan
            channel: Discord channel to post updates
            verbose: If True, agents output additional technical details
        """
        self.active_job = {
            "target": target,
            "scan_type": scan_type,
            "phase": "starting",
            "started": datetime.now(timezone.utc).isoformat(),
            "findings": {},
            "verbose": verbose,
        }

        try:
            recon_result = None
            vuln_result = None
            intel_result = None

            if scan_type in ("recon", "full"):
                # Run Randy's reconnaissance
                self.active_job["phase"] = "recon"

                if settings.use_crewai:
                    from src.crew.run import run_crew_recon
                    recon_result = await run_crew_recon(target, verbose=verbose)
                else:
                    from src.agents.randy_recon import run_recon
                    recon_result = await run_recon(target, verbose=verbose)

                # Store findings
                self.active_job["findings"]["recon"] = recon_result.raw_findings

                if scan_type == "full":
                    # Handoff conversation: Randy → Victor
                    ports = recon_result.raw_findings.get("ports", [])
                    await run_handoff(HandoffContext(
                        from_agent=AGENT_RANDY_RECON,
                        to_agent=AGENT_VICTOR_VULN,
                        target=target,
                        summary={"port_count": len(ports), "ports": ports[:5]},
                    ))

                    # Chain to Victor for vulnerability scanning
                    self.active_job["phase"] = "vuln"

                    if settings.use_crewai:
                        from src.crew.run import run_crew_vuln
                        vuln_result = await run_crew_vuln(
                            target, ports=ports, verbose=verbose
                        )
                    else:
                        from src.agents.victor_vuln import get_victor
                        victor = get_victor()
                        vuln_result = await victor.run_vuln_scan(
                            target, ports=ports, verbose=verbose
                        )

                    self.active_job["findings"]["vuln"] = {
                        "critical": vuln_result.critical_count,
                        "high": vuln_result.high_count,
                        "medium": vuln_result.medium_count,
                        "low": vuln_result.low_count,
                        "total": len(vuln_result.all_findings),
                    }

                    # Chain to Ivy for threat intelligence enrichment
                    if vuln_result.all_findings:
                        # Handoff conversation: Victor → Ivy
                        await run_handoff(HandoffContext(
                            from_agent=AGENT_VICTOR_VULN,
                            to_agent=AGENT_IVY_INTEL,
                            target=target,
                            summary={
                                "critical": vuln_result.critical_count,
                                "high": vuln_result.high_count,
                                "cve_count": len([
                                    f for f in vuln_result.all_findings if f.get("cve_id")
                                ]),
                            },
                        ))

                        self.active_job["phase"] = "intel"

                        from src.agents.ivy_intel import get_ivy
                        ivy = get_ivy()

                        # Pass Victor's findings to Ivy for enrichment
                        intel_result = await ivy.run_intel(
                            target=target,
                            vuln_findings=vuln_result.all_findings,
                            verbose=verbose,
                        )

                        self.active_job["findings"]["intel"] = {
                            "cves_enriched": len(intel_result.cve_enrichments),
                            "shodan_available": intel_result.shodan_result is not None,
                            "virustotal_available": intel_result.virustotal_result is not None,
                        }

                    # Rita compiles the final report and posts to #results
                    self.active_job["phase"] = "report"
                    from src.agents.rita_report import get_rita
                    rita = get_rita()
                    report_result = await rita.run_report(
                        target=target,
                        recon_result=recon_result,
                        vuln_result=vuln_result,
                        intel_result=intel_result,
                    )
                    await _post_report_to_results(report_result)

            elif scan_type == "vuln":
                # Run Victor's vulnerability scan directly
                self.active_job["phase"] = "vuln"

                if settings.use_crewai:
                    from src.crew.run import run_crew_vuln
                    vuln_result = await run_crew_vuln(target, verbose=verbose)
                else:
                    from src.agents.victor_vuln import get_victor
                    victor = get_victor()
                    vuln_result = await victor.run_vuln_scan(target, verbose=verbose)

                self.active_job["findings"]["vuln"] = {
                    "critical": vuln_result.critical_count,
                    "high": vuln_result.high_count,
                    "medium": vuln_result.medium_count,
                    "low": vuln_result.low_count,
                    "total": len(vuln_result.all_findings),
                }

            elif scan_type == "intel":
                # Run Ivy's intelligence gathering directly
                self.active_job["phase"] = "intel"

                from src.agents.ivy_intel import get_ivy
                ivy = get_ivy()
                intel_result = await ivy.run_intel(target=target, verbose=verbose)

            # Persist results for !report even after job clears
            self.last_scan_results = {
                "target": target,
                "scan_type": scan_type,
                "recon": recon_result,
                "vuln": vuln_result,
                "intel": intel_result,
            }

            # Compute completion stats before clearing the job
            from src.discord_bot.embeds import create_scan_complete_embed
            started = datetime.fromisoformat(self.active_job["started"])
            elapsed = datetime.now(timezone.utc) - started
            mins, secs = divmod(int(elapsed.total_seconds()), 60)
            duration = f"{mins}m {secs}s" if mins else f"{secs}s"
            ports = len(recon_result.raw_findings.get("ports", [])) if recon_result else 0
            vulns = self.active_job["findings"].get("vuln", {}).get("total", 0)
            subdomains = len(recon_result.raw_findings.get("dns_records", {})) if recon_result else 0

            # Job completed successfully — clear active job BEFORE sending Discord
            # messages so new commands aren't blocked if the send fails
            self.active_job = None

            try:
                await channel.send(
                    embed=create_scan_complete_embed(
                        target=target,
                        duration=duration,
                        subdomains=subdomains,
                        ports=ports,
                        vulns=vulns,
                    )
                )
            except Exception as embed_err:
                logger.error("Failed to send completion embed", error=str(embed_err))
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", target=target, scan_type=scan_type)
            await post_alert(
                f"Scan failed on {target}: {str(e)[:200]}",
                severity="error",
            )
            self.active_job = None
            raise

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

