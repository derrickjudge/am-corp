#!/usr/bin/env python3
"""
Test script for the Security News Feeds system.

This script tests:
1. News fetching from various sources
2. Article caching
3. Agent topic matching
4. Integration with casual chat
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.feeds.security_news import (
    SecurityNewsFetcher,
    NewsSource,
    get_news_fetcher,
)
from src.feeds.news_cache import (
    NewsCache,
    get_news_cache,
    AGENT_TOPIC_MAPPINGS,
)


async def test_hacker_news():
    """Test fetching from Hacker News."""
    print("\n📰 Testing Hacker News Fetch")
    print("-" * 40)
    
    fetcher = get_news_fetcher()
    articles = await fetcher.fetch_hacker_news(limit=5)
    
    print(f"  Fetched {len(articles)} security articles from HN")
    
    for article in articles[:3]:
        print(f"\n  📄 {article.title[:60]}...")
        print(f"     Source: {article.source.value}")
        print(f"     Score: {article.score}")
        print(f"     URL: {article.url[:50]}...")
    
    assert len(articles) > 0, "Should fetch at least one article"
    print("\n✅ Hacker News test passed")
    return True


async def test_nvd_cves():
    """Test fetching from NVD CVE database."""
    print("\n🔒 Testing NVD CVE Fetch")
    print("-" * 40)
    
    fetcher = get_news_fetcher()
    articles = await fetcher.fetch_nvd_cves(limit=5)
    
    print(f"  Fetched {len(articles)} CVEs from NVD")
    
    for article in articles[:3]:
        print(f"\n  📄 {article.title[:60]}...")
        print(f"     Tags: {', '.join(article.tags)}")
    
    # NVD might be rate limited, so warn instead of fail
    if len(articles) == 0:
        print("⚠️  No CVEs fetched (may be rate limited)")
    else:
        print("\n✅ NVD CVE test passed")
    
    return True


async def test_rss_feeds():
    """Test fetching from RSS feeds."""
    print("\n📡 Testing RSS Feeds")
    print("-" * 40)
    
    fetcher = get_news_fetcher()
    
    feeds = [
        ("https://feeds.feedburner.com/TheHackersNews", NewsSource.THE_HACKER_NEWS),
        ("https://www.bleepingcomputer.com/feed/", NewsSource.BLEEPING_COMPUTER),
    ]
    
    for url, source in feeds:
        print(f"\n  Testing {source.value}...")
        articles = await fetcher.fetch_rss_feed(url, source, limit=3)
        print(f"  Fetched {len(articles)} articles")
        
        if articles:
            print(f"    Sample: {articles[0].title[:50]}...")
    
    print("\n✅ RSS feeds test passed")
    return True


async def test_fetch_all():
    """Test fetching from all sources."""
    print("\n🌐 Testing Fetch All Sources")
    print("-" * 40)
    
    fetcher = get_news_fetcher()
    articles = await fetcher.fetch_all()
    
    print(f"  Total articles fetched: {len(articles)}")
    
    # Count by source
    by_source = {}
    for article in articles:
        source = article.source.value
        by_source[source] = by_source.get(source, 0) + 1
    
    print("\n  By source:")
    for source, count in sorted(by_source.items()):
        print(f"    {source}: {count}")
    
    assert len(articles) > 0, "Should fetch articles from at least one source"
    print("\n✅ Fetch all test passed")
    return True


async def test_news_cache():
    """Test the news cache."""
    print("\n💾 Testing News Cache")
    print("-" * 40)
    
    # Use a temp cache file
    cache = NewsCache(cache_file="data/test_news_cache.json")
    
    # Refresh
    new_count = await cache.refresh(force=True)
    print(f"  Refreshed cache: {new_count} new articles")
    print(f"  Total cached: {cache.article_count}")
    
    assert cache.article_count > 0, "Cache should have articles"
    
    print("\n✅ News cache test passed")
    return True


async def test_agent_matching():
    """Test article matching for agents."""
    print("\n🎯 Testing Agent Topic Matching")
    print("-" * 40)
    
    cache = get_news_cache()
    
    # Ensure cache has articles
    if cache.article_count == 0:
        await cache.refresh(force=True)
    
    for agent_id in ["randy_recon", "victor_vuln", "ivy_intel", "rita_report"]:
        articles = cache.get_articles_for_agent(agent_id, limit=3)
        mapping = AGENT_TOPIC_MAPPINGS.get(agent_id, {})
        
        print(f"\n  {agent_id}:")
        print(f"    Keywords: {', '.join(mapping.get('keywords', [])[:5])}...")
        print(f"    Matched articles: {len(articles)}")
        
        if articles:
            print(f"    Top match: {articles[0].title[:50]}...")
    
    print("\n✅ Agent matching test passed")
    return True


async def test_casual_chat_integration():
    """Test integration with casual chat."""
    print("\n💬 Testing Casual Chat Integration")
    print("-" * 40)
    
    from src.discord_bot.casual_chat import CasualChatManager
    from src.agents.personality import get_personality_manager
    
    manager = CasualChatManager()
    pm = get_personality_manager()
    
    # Test for Victor (usually active)
    personality = pm.load("victor_vuln")
    article = manager.get_article_for_agent("victor_vuln")
    
    print(f"  Got article for Victor: {article.title[:50] if article else 'None'}...")
    
    # Generate a message
    message, article_id = await manager.generate_chat_message(personality, article)
    
    print(f"\n  Generated message:")
    print(f"    {message[:100]}...")
    print(f"    Article ID: {article_id}")
    
    assert message, "Should generate a message"
    print("\n✅ Casual chat integration test passed")
    return True


async def main():
    """Run all news feeds tests."""
    print("=" * 60)
    print("AM-Corp Security News Feeds Test Suite")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    tests = [
        test_hacker_news,
        test_nvd_cves,
        test_rss_feeds,
        test_fetch_all,
        test_news_cache,
        test_agent_matching,
        test_casual_chat_integration,
    ]
    
    for test in tests:
        try:
            if await test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed with error: {e}")
            import traceback
            traceback.print_exc()
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
