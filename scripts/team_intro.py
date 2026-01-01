"""Quick script to have the team introduce themselves."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.discord_bot.agent_bots import (
    get_agent_manager,
    send_as_randy,
    send_as_victor,
    send_as_ivy,
    send_as_rita,
)
from src.utils.logging import setup_logging


async def team_intro() -> None:
    """Have each agent introduce themselves."""
    setup_logging()
    
    manager = get_agent_manager()
    await manager.start_all()
    
    # Small delay to ensure all bots are ready
    await asyncio.sleep(2)
    
    # Team introductions
    await send_as_randy(
        "Hey team! Randy Recon reporting for duty. I'll handle all recon ops - "
        "subdomain enum, port scanning, OSINT gathering. Just point me at a target!"
    )
    
    await asyncio.sleep(1.5)
    
    await send_as_victor(
        "Victor here. Once Randy maps the attack surface, I'll analyze it for vulnerabilities. "
        "CVEs, misconfigs, exposed services - nothing escapes my attention."
    )
    
    await asyncio.sleep(1.5)
    
    await send_as_ivy(
        "Ivy Intel at your service. I correlate everything with threat intelligence - "
        "known attacker TTPs, industry trends, and emerging threats. Context is everything."
    )
    
    await asyncio.sleep(1.5)
    
    await send_as_rita(
        "And I'm Rita! I'll compile everyone's findings into professional reports. "
        "Executive summaries, technical details, remediation guidance - I've got it covered. "
        "Ready when you are, boss! 📋"
    )
    
    await asyncio.sleep(2)
    
    # Clean shutdown
    await manager.stop_all()


if __name__ == "__main__":
    asyncio.run(team_intro())

