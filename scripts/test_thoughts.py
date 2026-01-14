#!/usr/bin/env python3
"""
Test script for the Thoughts Channel implementation.

Run from project root:
    source venv/bin/activate
    python scripts/test_thoughts.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.discord_bot.thoughts import (
    get_thoughts_manager,
    post_thought,
    post_decision,
    post_finding,
    post_uncertainty,
    ThoughtLevel,
)
from src.utils.config import settings


async def test_thoughts_channel():
    """Test the thoughts channel with sample thoughts from each agent."""
    
    print("=" * 60)
    print("AM-Corp Thoughts Channel Test")
    print("=" * 60)
    
    # Check configuration
    manager = get_thoughts_manager()
    
    print(f"\n📋 Configuration:")
    print(f"   Enabled: {manager.enabled}")
    print(f"   Verbosity: {manager.verbosity.value}")
    print(f"   Webhook configured: {'✅ Yes' if manager.webhook_url else '❌ No'}")
    
    if not manager.webhook_url:
        print("\n❌ ERROR: DISCORD_WEBHOOK_THOUGHTS not configured in .env")
        print("   Add: DISCORD_WEBHOOK_THOUGHTS=<your_webhook_url>")
        return False
    
    print(f"\n🧪 Testing thoughts at '{manager.verbosity.value}' verbosity level...")
    print("-" * 60)
    
    # Test 1: Decision (should always show at minimal+)
    print("\n1️⃣ Testing DECISION (category: decision)...")
    result = await post_decision(
        agent_id="randy_recon",
        decision="Starting recon on test-target.com",
        reasoning="Going passive first with DNS before active scanning",
        confidence=0.9,
    )
    print(f"   Posted: {'✅' if result else '❌ (filtered by verbosity)'}")
    
    await asyncio.sleep(1)
    
    # Test 2: Finding (should show at minimal+)
    print("\n2️⃣ Testing FINDING (category: finding)...")
    result = await post_finding(
        agent_id="victor_vuln",
        finding="Found 2 CRITICAL vulnerabilities",
        significance="These need immediate attention - actively exploited in the wild",
        confidence=0.85,
    )
    print(f"   Posted: {'✅' if result else '❌ (filtered by verbosity)'}")
    
    await asyncio.sleep(1)
    
    # Test 3: Reasoning (should show at normal+)
    print("\n3️⃣ Testing REASONING (category: reasoning)...")
    result = await post_thought(
        agent_id="ivy_intel",
        thought="Cross-referencing CVE data with EPSS scores. The CVSS is one thing, "
                "but real-world exploitation probability tells the real story.",
        confidence=0.8,
        category="reasoning",
    )
    print(f"   Posted: {'✅' if result else '❌ (filtered by verbosity)'}")
    
    await asyncio.sleep(1)
    
    # Test 4: Uncertainty (should show at verbose+)
    print("\n4️⃣ Testing UNCERTAINTY (category: uncertainty)...")
    result = await post_uncertainty(
        agent_id="randy_recon",
        uncertainty="SPF record is missing from DNS but might be intentional",
        consideration="Will note it but not flag as definite issue",
    )
    print(f"   Posted: {'✅' if result else '❌ (filtered by verbosity)'}")
    
    await asyncio.sleep(1)
    
    # Test 5: Detail (should show at verbose+)
    print("\n5️⃣ Testing DETAIL (category: detail)...")
    result = await post_thought(
        agent_id="victor_vuln",
        thought="Got version info: nginx 1.14.0 - checking CVE databases for matches",
        category="detail",
    )
    print(f"   Posted: {'✅' if result else '❌ (filtered by verbosity)'}")
    
    print("\n" + "=" * 60)
    print("✅ Test complete! Check #am-corp-thoughts in Discord.")
    print("=" * 60)
    
    # Show what should have been posted based on verbosity
    print(f"\n📊 Expected posts at '{manager.verbosity.value}' verbosity:")
    categories = {
        "decision": ThoughtLevel.MINIMAL,
        "finding": ThoughtLevel.MINIMAL,
        "reasoning": ThoughtLevel.NORMAL,
        "uncertainty": ThoughtLevel.VERBOSE,
        "detail": ThoughtLevel.VERBOSE,
    }
    
    for cat, min_level in categories.items():
        should_post = manager.should_post(cat)
        status = "✅ Posted" if should_post else "⏭️ Skipped"
        print(f"   {cat}: {status}")
    
    return True


if __name__ == "__main__":
    print("\n🚀 Starting thoughts channel test...\n")
    
    try:
        success = asyncio.run(test_thoughts_channel())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
