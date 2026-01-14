"""
AM-Corp News Cache

Caches security news articles for efficient access by casual chat.
Articles are stored for 24-48 hours and matched to agent topics.
"""

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from src.feeds.security_news import (
    NewsArticle,
    NewsSource,
    SecurityNewsFetcher,
    get_news_fetcher,
)
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# CACHE CONFIGURATION
# =============================================================================


DEFAULT_CACHE_HOURS = 24
DEFAULT_FETCH_INTERVAL_MINUTES = 60
CACHE_FILE = "data/news_cache.json"


# =============================================================================
# AGENT TOPIC MAPPINGS
# =============================================================================


# Map agent topics to news sources and keywords
AGENT_TOPIC_MAPPINGS = {
    "randy_recon": {
        "preferred_sources": [NewsSource.HACKER_NEWS, NewsSource.BLEEPING_COMPUTER],
        "keywords": [
            "reconnaissance", "infrastructure", "dns", "network", "scan",
            "subdomain", "cloud", "aws", "azure", "misconfiguration",
            "exposed", "s3", "bucket", "certificate", "ssl", "tls",
        ],
    },
    "victor_vuln": {
        "preferred_sources": [NewsSource.NVD_CVE, NewsSource.THE_HACKER_NEWS],
        "keywords": [
            "vulnerability", "cve", "exploit", "zero-day", "0day", "rce",
            "patch", "critical", "high", "buffer", "overflow", "injection",
            "xss", "csrf", "ssrf", "lfi", "rfi", "deserialization",
        ],
    },
    "ivy_intel": {
        "preferred_sources": [NewsSource.KREBS, NewsSource.THE_HACKER_NEWS],
        "keywords": [
            "apt", "threat", "ransomware", "breach", "attack", "campaign",
            "nation-state", "espionage", "malware", "botnet", "phishing",
            "social engineering", "supply chain", "attribution",
        ],
    },
    "rita_report": {
        "preferred_sources": [NewsSource.HACKER_NEWS, NewsSource.BLEEPING_COMPUTER],
        "keywords": [
            "report", "disclosure", "compliance", "regulation", "gdpr",
            "audit", "framework", "nist", "iso", "risk", "governance",
        ],
    },
}


# =============================================================================
# CACHE CLASS
# =============================================================================


@dataclass
class CachedArticle:
    """An article with cache metadata."""
    
    article: NewsArticle
    cached_at: datetime
    used_count: int = 0
    
    def is_expired(self, max_hours: int = DEFAULT_CACHE_HOURS) -> bool:
        """Check if article is expired."""
        age = datetime.now(timezone.utc) - self.cached_at
        return age > timedelta(hours=max_hours)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "article": self.article.to_dict(),
            "cached_at": self.cached_at.isoformat(),
            "used_count": self.used_count,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "CachedArticle":
        """Create from dictionary."""
        return cls(
            article=NewsArticle.from_dict(data["article"]),
            cached_at=datetime.fromisoformat(data["cached_at"]),
            used_count=data.get("used_count", 0),
        )


class NewsCache:
    """
    Manages cached security news articles.
    
    Features:
    - Persistent storage in JSON file
    - Automatic expiration (24-48 hours)
    - Agent topic matching
    - Background refresh
    """
    
    def __init__(
        self,
        cache_file: str = CACHE_FILE,
        cache_hours: int = DEFAULT_CACHE_HOURS,
    ) -> None:
        self.cache_file = Path(cache_file)
        self.cache_hours = cache_hours
        self._articles: dict[str, CachedArticle] = {}
        self._last_fetch: Optional[datetime] = None
        self._fetcher = get_news_fetcher()
        
        # Ensure data directory exists
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing cache
        self._load_cache()
        
        logger.info(
            "NewsCache initialized",
            cache_file=str(self.cache_file),
            articles_loaded=len(self._articles),
        )
    
    def _load_cache(self) -> None:
        """Load cache from disk."""
        if not self.cache_file.exists():
            return
        
        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            
            self._last_fetch = (
                datetime.fromisoformat(data["last_fetch"])
                if data.get("last_fetch")
                else None
            )
            
            for article_data in data.get("articles", []):
                cached = CachedArticle.from_dict(article_data)
                if not cached.is_expired(self.cache_hours * 2):  # Keep for 2x
                    self._articles[cached.article.id] = cached
            
            logger.debug(f"Loaded {len(self._articles)} articles from cache")
            
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            data = {
                "last_fetch": self._last_fetch.isoformat() if self._last_fetch else None,
                "articles": [c.to_dict() for c in self._articles.values()],
            }
            
            with open(self.cache_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved {len(self._articles)} articles to cache")
            
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    async def refresh(self, force: bool = False) -> int:
        """
        Refresh the cache from news sources.
        
        Args:
            force: Force refresh even if not due
        
        Returns:
            Number of new articles fetched
        """
        # Check if refresh is needed
        if not force and self._last_fetch:
            since_fetch = datetime.now(timezone.utc) - self._last_fetch
            if since_fetch < timedelta(minutes=DEFAULT_FETCH_INTERVAL_MINUTES):
                logger.debug("Cache refresh not due yet")
                return 0
        
        logger.info("Refreshing news cache...")
        
        # Fetch from all sources
        articles = await self._fetcher.fetch_all()
        
        # Add to cache
        new_count = 0
        for article in articles:
            if article.id not in self._articles:
                self._articles[article.id] = CachedArticle(
                    article=article,
                    cached_at=datetime.now(timezone.utc),
                )
                new_count += 1
        
        # Prune expired articles
        self._prune_expired()
        
        self._last_fetch = datetime.now(timezone.utc)
        self._save_cache()
        
        logger.info(f"Cache refreshed: {new_count} new articles, {len(self._articles)} total")
        
        return new_count
    
    def _prune_expired(self) -> None:
        """Remove expired articles from cache."""
        expired = [
            article_id
            for article_id, cached in self._articles.items()
            if cached.is_expired(self.cache_hours)
        ]
        
        for article_id in expired:
            del self._articles[article_id]
        
        if expired:
            logger.debug(f"Pruned {len(expired)} expired articles")
    
    def get_articles_for_agent(
        self,
        agent_id: str,
        limit: int = 5,
        exclude_used: bool = True,
    ) -> list[NewsArticle]:
        """
        Get articles relevant to a specific agent.
        
        Args:
            agent_id: Agent identifier
            limit: Maximum articles to return
            exclude_used: Exclude articles already used in chat
        
        Returns:
            List of relevant articles
        """
        mapping = AGENT_TOPIC_MAPPINGS.get(agent_id, {})
        preferred_sources = mapping.get("preferred_sources", [])
        keywords = mapping.get("keywords", [])
        
        # Score and filter articles
        scored_articles = []
        
        for cached in self._articles.values():
            if cached.is_expired(self.cache_hours):
                continue
            
            if exclude_used and cached.used_count > 0:
                continue
            
            article = cached.article
            score = 0
            
            # Boost for preferred sources
            if article.source in preferred_sources:
                score += 10
            
            # Boost for keyword matches
            text = f"{article.title} {article.summary or ''}".lower()
            for keyword in keywords:
                if keyword in text:
                    score += 5
            
            # Boost for recency
            # Ensure timezone-aware comparison
            pub_time = article.published
            if pub_time.tzinfo is None:
                pub_time = pub_time.replace(tzinfo=timezone.utc)
            age_hours = (
                datetime.now(timezone.utc) - pub_time
            ).total_seconds() / 3600
            if age_hours < 6:
                score += 5
            elif age_hours < 24:
                score += 2
            
            # Boost for high-scoring HN articles
            if article.score and article.score > 100:
                score += 3
            
            if score > 0:
                scored_articles.append((score, cached))
        
        # Sort by score and return top N
        scored_articles.sort(key=lambda x: x[0], reverse=True)
        
        return [cached.article for score, cached in scored_articles[:limit]]
    
    def mark_used(self, article_id: str) -> None:
        """Mark an article as used in chat."""
        if article_id in self._articles:
            self._articles[article_id].used_count += 1
            self._save_cache()
    
    def get_random_article(self, agent_id: Optional[str] = None) -> Optional[NewsArticle]:
        """
        Get a random article, optionally filtered for agent relevance.
        
        Args:
            agent_id: Optional agent to filter for
        
        Returns:
            A random relevant article, or None if cache is empty
        """
        import random
        
        if agent_id:
            articles = self.get_articles_for_agent(agent_id, limit=10, exclude_used=False)
        else:
            articles = [
                cached.article
                for cached in self._articles.values()
                if not cached.is_expired(self.cache_hours)
            ]
        
        if not articles:
            return None
        
        return random.choice(articles)
    
    @property
    def article_count(self) -> int:
        """Get number of cached articles."""
        return len(self._articles)
    
    @property
    def needs_refresh(self) -> bool:
        """Check if cache needs refresh."""
        if not self._last_fetch:
            return True
        
        since_fetch = datetime.now(timezone.utc) - self._last_fetch
        return since_fetch > timedelta(minutes=DEFAULT_FETCH_INTERVAL_MINUTES)


# =============================================================================
# BACKGROUND REFRESH TASK
# =============================================================================


async def news_cache_refresh_loop(cache: NewsCache) -> None:
    """
    Background task to periodically refresh the news cache.
    
    Runs every hour by default.
    """
    logger.info("Starting news cache refresh loop")
    
    # Initial refresh
    await cache.refresh(force=True)
    
    while True:
        try:
            await asyncio.sleep(DEFAULT_FETCH_INTERVAL_MINUTES * 60)
            await cache.refresh()
            
        except asyncio.CancelledError:
            logger.info("News cache refresh loop cancelled")
            break
        except Exception as e:
            logger.error(f"Error in news cache refresh loop: {e}")
            await asyncio.sleep(300)  # Wait 5 min on error


# =============================================================================
# SINGLETON
# =============================================================================


_cache: Optional[NewsCache] = None


def get_news_cache() -> NewsCache:
    """Get or create the news cache singleton."""
    global _cache
    if _cache is None:
        _cache = NewsCache()
    return _cache


async def start_news_cache_refresh() -> asyncio.Task:
    """Start the background cache refresh task."""
    cache = get_news_cache()
    task = asyncio.create_task(news_cache_refresh_loop(cache))
    return task
