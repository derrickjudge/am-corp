#!/usr/bin/env python3
"""
Test script to have Randy Recon post a message to Discord.

Run with: python scripts/test_randy.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.discord_bot.webhooks import (
    post_as_randy,
    post_as_victor,
    post_as_ivy,
    post_as_rita,
    post_alert,
)


async def test_randy():
    """Have Randy introduce himself."""
    print("🔍 Sending message as Randy Recon...")
    
    success = await post_as_randy(
        "Hey team! Randy Recon here. Systems are online and I'm ready to "
        "start reconnaissance whenever you need me. Just give the word!"
    )
    
    if success:
        print("✅ Randy's message sent successfully!")
    else:
        print("❌ Failed to send Randy's message. Check webhook configuration.")
    
    return success


async def test_all_agents():
    """Have all agents introduce themselves."""
    print("\n🚀 Testing all agents...\n")
    
    # Randy
    print("🔍 Randy Recon...")
    await post_as_randy(
        "Randy Recon reporting in! I'm your reconnaissance specialist. "
        "I'll find every subdomain, open port, and service running on your targets."
    )
    await asyncio.sleep(1)  # Small delay between messages
    
    # Victor
    print("⚠️ Victor Vuln...")
    await post_as_victor(
        "Victor Vuln here. I analyze the vulnerabilities in whatever Randy finds. "
        "If there's a CVE or misconfiguration, I'll catch it."
    )
    await asyncio.sleep(1)
    
    # Ivy
    print("🧠 Ivy Intel...")
    await post_as_ivy(
        "Ivy Intel, threat intelligence. I provide the context - breach history, "
        "threat actors, exposure timelines. The story behind the data."
    )
    await asyncio.sleep(1)
    
    # Rita
    print("📊 Rita Report...")
    await post_as_rita(
        "Rita Report here. I take everything the team finds and turn it into "
        "clear, actionable reports. Executive summaries and technical details."
    )
    await asyncio.sleep(1)
    
    # System alert test
    print("🚨 System alert...")
    await post_alert(
        "AM-Corp agent team initialized successfully. All systems operational.",
        severity="info"
    )
    
    print("\n✅ All agents tested!")


async def main():
    """Main entry point."""
    print("=" * 60)
    print("AM-Corp Agent Test")
    print("=" * 60)
    
    # Check for command line args
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        await test_all_agents()
    else:
        await test_randy()
        print("\nTip: Run with --all to test all agents")


if __name__ == "__main__":
    asyncio.run(main())

