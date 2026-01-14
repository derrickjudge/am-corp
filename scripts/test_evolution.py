#!/usr/bin/env python3
"""
Test script for the Personality Evolution System.

Run from project root:
    source venv/bin/activate
    python scripts/test_evolution.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.evolution import (
    get_evolution_engine,
    trigger_scan_completed,
    trigger_finding_discovered,
    trigger_pattern_observed,
    get_personality_diff,
    TriggerType,
)
from src.agents.personality import get_personality_manager


async def test_evolution_system():
    """Test the personality evolution system."""
    
    print("=" * 60)
    print("AM-Corp Personality Evolution Test")
    print("=" * 60)
    
    pm = get_personality_manager()
    
    # Get baseline for Randy
    randy_before = pm.load("randy_recon")
    print(f"\n📊 Randy BEFORE evolution:")
    print(f"   Version: {randy_before.version}")
    print(f"   Evolved traits: {randy_before.evolved_traits}")
    print(f"   Learnings: {len(randy_before.recent_learnings)}")
    
    # Test 1: Scan completion trigger
    print("\n1️⃣ Testing scan completion trigger...")
    changes = await trigger_scan_completed(
        agent_id="randy_recon",
        target="test.example.com",
        success=True,
        findings_count=15,
        context={
            "dns_complexity": True,
            "large_attack_surface": True,
        },
    )
    print(f"   Changes made: {len(changes)}")
    for trait, old, new in changes:
        print(f"   • {trait}: {old:.3f} → {new:.3f}")
    
    # Test 2: Finding discovery trigger for Victor
    print("\n2️⃣ Testing finding discovery trigger...")
    changes = await trigger_finding_discovered(
        agent_id="victor_vuln",
        finding_type="http-vuln-cve2021-1234",
        severity="critical",
        details="Remote code execution in web server",
    )
    print(f"   Changes made: {len(changes)}")
    for trait, old, new in changes:
        print(f"   • {trait}: {old:.3f} → {new:.3f}")
    
    # Test 3: Pattern observation for Ivy
    print("\n3️⃣ Testing pattern observation trigger...")
    changes = await trigger_pattern_observed(
        agent_id="ivy_intel",
        pattern="Multiple exposed Elasticsearch instances with default credentials",
        significance="high",
    )
    print(f"   Changes made: {len(changes)}")
    for trait, old, new in changes:
        print(f"   • {trait}: {old:.3f} → {new:.3f}")
    
    # Test 4: Multiple triggers (should hit daily limits)
    print("\n4️⃣ Testing daily limits (10 rapid triggers)...")
    for i in range(10):
        await trigger_scan_completed(
            agent_id="randy_recon",
            target=f"target{i}.example.com",
            success=True,
            findings_count=5,
        )
    print("   ✅ Daily limits should prevent excessive evolution")
    
    # Get Randy after all triggers
    pm._cache.clear()  # Clear cache to reload from disk
    randy_after = pm.load("randy_recon")
    print(f"\n📊 Randy AFTER evolution:")
    print(f"   Version: {randy_after.version}")
    print(f"   Evolved traits: {randy_after.evolved_traits}")
    print(f"   Learnings: {randy_after.recent_learnings[-3:] if randy_after.recent_learnings else 'None'}")
    
    # Test 5: Personality diff
    print("\n5️⃣ Testing personality diff...")
    diff = get_personality_diff("randy_recon")
    print(f"   Current version: {diff['current_version']}")
    print(f"   Total changes: {diff['changes_count']}")
    print(f"   Evolved traits: {list(diff['evolved_traits'].keys())}")
    if diff['recent_changes']:
        print("   Recent changes:")
        for change in diff['recent_changes'][-3:]:
            print(f"     • {change['trait']}: {change['old']:.3f} → {change['new']:.3f} ({change['trigger']})")
    
    # Test 6: Verify evolution log persistence
    print("\n6️⃣ Verifying evolution log persistence...")
    if randy_after.evolution_log:
        print(f"   Evolution log has {len(randy_after.evolution_log)} entries")
        latest = randy_after.evolution_log[-1]
        print(f"   Latest: {latest.trait} changed to {latest.new_value:.3f}")
        print(f"   Trigger: {latest.trigger}")
    
    print("\n" + "=" * 60)
    print("✅ Evolution system test complete!")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    print("\n🧬 Starting evolution system test...\n")
    
    try:
        success = asyncio.run(test_evolution_system())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
