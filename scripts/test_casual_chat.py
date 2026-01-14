#!/usr/bin/env python3
"""
Test script for the Casual Chat system.

This script tests:
1. Work hours detection
2. Chat frequency calculations
3. Message generation
4. Response probability
"""

import asyncio
import sys
from datetime import datetime, time, timezone
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.personality import ChatBehavior, get_personality_manager
from src.discord_bot.casual_chat import CasualChatManager, FREQUENCY_INTERVALS


def test_work_hours():
    """Test work hours detection."""
    print("\n🕐 Testing Work Hours Detection")
    print("-" * 40)
    
    pm = get_personality_manager()
    manager = CasualChatManager()
    
    for agent_id in ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]:
        personality = pm.load(agent_id)
        chat_behavior = personality.chat_behavior
        within = manager.is_within_work_hours(personality)
        
        print(f"  {agent_id}:")
        print(f"    Work hours: {chat_behavior.work_hours_start} - {chat_behavior.work_hours_end}")
        print(f"    Timezone: {chat_behavior.timezone}")
        print(f"    Currently within work hours: {'✅ Yes' if within else '❌ No'}")
    
    print("\n✅ Work hours test complete")
    return True


def test_chat_frequency():
    """Test chat frequency intervals."""
    print("\n📊 Testing Chat Frequency Intervals")
    print("-" * 40)
    
    for freq, (min_mins, max_mins) in FREQUENCY_INTERVALS.items():
        print(f"  {freq.value}: {min_mins}-{max_mins} minutes between messages")
    
    pm = get_personality_manager()
    manager = CasualChatManager()
    
    print("\n  Agent chat delays:")
    for agent_id in ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]:
        personality = pm.load(agent_id)
        delay = manager.get_next_chat_delay(personality)
        print(f"    {agent_id}: {delay/60:.1f} minutes (frequency: {personality.chat_behavior.frequency.value})")
    
    print("\n✅ Frequency test complete")
    return True


def test_should_respond():
    """Test response probability."""
    print("\n🎲 Testing Response Probability")
    print("-" * 40)
    
    pm = get_personality_manager()
    manager = CasualChatManager()
    
    # Run multiple trials for each agent
    trials = 10
    print(f"  Running {trials} trials per agent...")
    
    for agent_id in ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]:
        personality = pm.load(agent_id)
        
        # Test with matching topic
        matching_topic = personality.chat_behavior.topics[0] if personality.chat_behavior.topics else "security"
        
        responses_no_topic = sum(1 for _ in range(trials) if manager.should_respond(personality))
        responses_with_topic = sum(1 for _ in range(trials) if manager.should_respond(personality, matching_topic))
        
        print(f"\n  {agent_id}:")
        print(f"    Topics: {', '.join(personality.chat_behavior.topics[:3])}...")
        print(f"    Responded (no topic): {responses_no_topic}/{trials}")
        print(f"    Responded (topic: {matching_topic}): {responses_with_topic}/{trials}")
    
    print("\n✅ Response probability test complete")
    return True


async def test_message_generation():
    """Test message generation with personality."""
    print("\n💬 Testing Message Generation")
    print("-" * 40)
    
    pm = get_personality_manager()
    manager = CasualChatManager()
    
    for agent_id in ["randy_recon", "victor_vuln"]:
        personality = pm.load(agent_id)
        
        print(f"\n  Generating message for {agent_id}...")
        message = await manager.generate_chat_message(personality)
        print(f"    Message: {message[:100]}{'...' if len(message) > 100 else ''}")
    
    print("\n✅ Message generation test complete")
    return True


async def test_topic_selection():
    """Test topic selection based on personality."""
    print("\n🎯 Testing Topic Selection")
    print("-" * 40)
    
    pm = get_personality_manager()
    manager = CasualChatManager()
    
    for agent_id in ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]:
        personality = pm.load(agent_id)
        
        # Get a few topic selections
        topics = set()
        for _ in range(5):
            topic, message = manager.select_topic(personality)
            topics.add(topic)
        
        print(f"\n  {agent_id}:")
        print(f"    Agent interests: {', '.join(personality.chat_behavior.topics[:3])}")
        print(f"    Topics selected: {', '.join(topics)}")
    
    print("\n✅ Topic selection test complete")
    return True


async def main():
    """Run all casual chat tests."""
    print("=" * 60)
    print("AM-Corp Casual Chat Test Suite")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    # Synchronous tests
    tests = [
        test_work_hours,
        test_chat_frequency,
        test_should_respond,
    ]
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed with error: {e}")
            failed += 1
    
    # Async tests
    async_tests = [
        test_topic_selection,
        test_message_generation,
    ]
    
    for test in async_tests:
        try:
            if await test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed with error: {e}")
            failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
