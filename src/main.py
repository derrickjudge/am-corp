"""
AM-Corp Main Entry Point

Multi-agent cybersecurity automation platform.
"""

import asyncio
import signal
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger, setup_logging


def validate_environment() -> bool:
    """Validate required environment variables are set."""
    logger = get_logger(__name__)

    # Check for required settings in production
    if settings.is_production:
        missing = settings.validate_required_for_production()
        if missing:
            logger.error(
                "Missing required environment variables",
                missing=missing,
            )
            return False

    # Always warn about missing Discord token
    if not settings.discord_bot_token:
        logger.warning(
            "DISCORD_BOT_TOKEN not set - command bot disabled"
        )

    # Check agent tokens
    agent_tokens = {
        "Randy": settings.discord_bot_token_randy,
        "Victor": settings.discord_bot_token_victor,
        "Ivy": settings.discord_bot_token_ivy,
        "Rita": settings.discord_bot_token_rita,
    }
    
    configured_agents = [name for name, token in agent_tokens.items() if token]
    if configured_agents:
        logger.info(f"Agent bots configured: {', '.join(configured_agents)}")
    else:
        logger.warning("No agent bot tokens configured - using webhooks only")

    # Always warn about missing Gemini key
    if not settings.gemini_api_key:
        logger.warning(
            "GEMINI_API_KEY not set - AI agent functionality disabled"
        )

    return True


def print_banner() -> None:
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ███╗   ███╗       ██████╗ ██████╗ ██████╗ ██████╗  ║
    ║    ██╔══██╗████╗ ████║      ██╔════╝██╔═══██╗██╔══██╗██╔══██╗ ║
    ║    ███████║██╔████╔██║█████╗██║     ██║   ██║██████╔╝██████╔╝ ║
    ║    ██╔══██║██║╚██╔╝██║╚════╝██║     ██║   ██║██╔══██╗██╔═══╝  ║
    ║    ██║  ██║██║ ╚═╝ ██║      ╚██████╗╚██████╔╝██║  ██║██║      ║
    ║    ╚═╝  ╚═╝╚═╝     ╚═╝       ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝      ║
    ║                                                               ║
    ║         Multi-Agent Cybersecurity Automation Platform         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


async def main() -> None:
    """Main application entry point."""
    # Initialize logging
    setup_logging()
    logger = get_logger(__name__)

    # Print banner
    print_banner()

    # Log startup
    logger.info(
        "AM-Corp starting",
        version="0.1.0",
        environment=settings.environment,
        log_level=settings.log_level,
    )

    # Audit log startup
    audit_log(
        action="application_started",
        user="system",
        result="success",
        environment=settings.environment,
    )

    # Validate environment
    if not validate_environment():
        logger.error("Environment validation failed - exiting")
        sys.exit(1)

    logger.info("Environment validation passed")

    # Import bot components
    from src.discord_bot.agent_bots import get_agent_manager
    from src.discord_bot.bot import create_bot
    from src.discord_bot.casual_chat import get_casual_chat_manager, start_casual_chat
    from src.discord_bot.commands import setup_commands

    # Start agent bots first
    agent_manager = get_agent_manager()
    await agent_manager.start_all()

    # Start casual chat background task if enabled
    casual_chat_task = None
    casual_manager = get_casual_chat_manager()
    if casual_manager.enabled and settings.discord_webhook_general:
        logger.info("Starting casual chat background task...")
        casual_chat_task = await start_casual_chat()
    else:
        logger.info(
            "Casual chat disabled or not configured",
            enabled=casual_manager.enabled,
            webhook_configured=bool(settings.discord_webhook_general),
        )

    # Create and start main command bot
    main_bot = None
    if settings.discord_bot_token:
        logger.info("Starting main command bot...")
        main_bot = create_bot()
        await setup_commands(main_bot)

        # Run the main bot (this blocks until bot is closed)
        try:
            await main_bot.start(settings.discord_bot_token)
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            # Clean up
            if casual_chat_task:
                casual_chat_task.cancel()
                try:
                    await casual_chat_task
                except asyncio.CancelledError:
                    pass
            if agent_manager:
                await agent_manager.stop_all()
            if main_bot and not main_bot.is_closed():
                await main_bot.close()
    else:
        logger.warning("Main bot not started (no token)")
        # Keep running for agent bots
        try:
            await asyncio.Event().wait()  # Wait forever
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            if casual_chat_task:
                casual_chat_task.cancel()
                try:
                    await casual_chat_task
                except asyncio.CancelledError:
                    pass
            if agent_manager:
                await agent_manager.stop_all()

    audit_log(action="application_stopped", user="system", result="success")


def run() -> None:
    """Run the application."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    run()
