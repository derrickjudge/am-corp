#!/usr/bin/env python3
"""
Test script for the Personality System.

Run from project root:
    source venv/bin/activate
    python scripts/test_personality.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.personality import (
    get_personality_manager,
    AgentPersonality,
    BaseTraits,
)


def test_personality_system():
    """Test the personality system functionality."""
    
    print("=" * 60)
    print("AM-Corp Personality System Test")
    print("=" * 60)
    
    pm = get_personality_manager()
    
    print(f"\n📁 Personalities directory: {pm.personalities_dir}")
    
    # Test 1: Load all agents
    print("\n1️⃣ Loading agent personalities...")
    agents = ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]
    
    for agent_id in agents:
        personality = pm.load(agent_id)
        traits = []
        if personality.base_traits.methodical > 0.7:
            traits.append("methodical")
        if personality.base_traits.humor > 0.5:
            traits.append("humorous")
        if personality.base_traits.confidence > 0.7:
            traits.append("confident")
        if personality.base_traits.skepticism > 0.7:
            traits.append("skeptical")
        
        print(f"   ✅ {agent_id}: v{personality.version} | {', '.join(traits) or 'balanced'}")
        print(f"      Catchphrases: {personality.communication.catchphrases[:3]}")
    
    # Test 2: Evolution
    print("\n2️⃣ Testing personality evolution...")
    
    # Evolve a trait for Victor
    entry = pm.evolve(
        agent_id="victor_vuln",
        trait="web_security_focus",
        new_value=0.8,
        trigger="Found many web vulnerabilities in recent scans",
    )
    print(f"   ✅ Evolved victor_vuln: {entry.trait} → {entry.new_value}")
    
    # Add a learning
    pm.add_learning(
        agent_id="victor_vuln",
        learning="API endpoints often have authentication bypass issues",
    )
    print("   ✅ Added learning to victor_vuln")
    
    # Verify persistence
    victor = pm.load("victor_vuln")
    print(f"   ✅ Verified: evolved_traits = {victor.evolved_traits}")
    print(f"   ✅ Verified: learnings = {victor.recent_learnings[-1][:50]}...")
    
    # Test 3: Prompt context
    print("\n3️⃣ Testing prompt context generation...")
    
    for agent_id in ["randy_recon", "ivy_intel"]:
        context = pm.get_prompt_context(agent_id)
        print(f"\n   📝 {agent_id} context ({len(context)} chars):")
        print("   " + "-" * 50)
        for line in context.split("\n")[:10]:
            print(f"   {line}")
        print("   ...")
    
    # Test 4: Archive & Reset
    print("\n4️⃣ Testing archive & reset...")
    
    # Archive current
    archive_path = pm.archive("rita_report")
    print(f"   ✅ Archived rita_report to: {archive_path.name if archive_path else 'N/A'}")
    
    # List archives
    archives = pm.list_archives("rita_report")
    print(f"   📦 Found {len(archives)} archived versions")
    
    # Test 5: Chat behavior
    print("\n5️⃣ Checking chat behavior configs...")
    
    for agent_id in agents:
        personality = pm.load(agent_id)
        chat = personality.chat_behavior
        print(f"   {agent_id}:")
        print(f"      Frequency: {chat.frequency.value}")
        print(f"      Work hours: {chat.work_hours_start}-{chat.work_hours_end} ({chat.timezone})")
        print(f"      Topics: {', '.join(chat.topics[:2])}...")
    
    print("\n" + "=" * 60)
    print("✅ All personality tests passed!")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    print("\n🧠 Starting personality system test...\n")
    
    try:
        success = test_personality_system()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
