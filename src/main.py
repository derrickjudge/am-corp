"""
AM-Corp Main Entry Point

Multi-agent cybersecurity automation platform.
"""

import asyncio
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
            "DISCORD_BOT_TOKEN not set - bot functionality disabled"
        )

    # Always warn about missing Gemini key
    if not settings.gemini_api_key:
        logger.warning(
            "GEMINI_API_KEY not set - agent functionality disabled"
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

    # TODO: Initialize components
    # - Discord bot
    # - CrewAI agents
    # - n8n integration

    logger.info(
        "AM-Corp initialized successfully",
        discord_configured=bool(settings.discord_bot_token),
        gemini_configured=bool(settings.gemini_api_key),
        scope_verification=settings.enable_scope_verification,
    )

    # Keep running (placeholder for actual bot/server loop)
    logger.info("Ready for commands. Press Ctrl+C to exit.")

    try:
        # In the future, this will run the Discord bot and other services
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
        audit_log(action="application_stopped", user="system", result="success")


def run() -> None:
    """Run the application."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    run()

