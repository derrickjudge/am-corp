"""
AM-Corp Security News Fetcher

Fetches security news from various RSS feeds and APIs.
Provides real content for agent casual conversation.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum

import httpx

from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# DATA MODELS
# =============================================================================


class NewsSource(str, Enum):
    """Supported news sources."""
    HACKER_NEWS = "hacker_news"
    NVD_CVE = "nvd_cve"
    CISA = "cisa"
    THE_HACKER_NEWS = "the_hacker_news"
    BLEEPING_COMPUTER = "bleeping_computer"
    KREBS = "krebs_on_security"


@dataclass
class NewsArticle:
    """A single news article."""
    
    id: str
    title: str
    url: str
    source: NewsSource
    published: datetime
    summary: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    score: Optional[int] = None  # For Hacker News
    
    def matches_topics(self, topics: list[str]) -> bool:
        """Check if article matches any of the given topics."""
        search_text = f"{self.title} {self.summary or ''} {' '.join(self.tags)}".lower()
        
        for topic in topics:
            # Convert topic to search terms
            search_terms = topic.lower().replace("_", " ").split()
            if all(term in search_text for term in search_terms):
                return True
        
        return False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "source": self.source.value,
            "published": self.published.isoformat(),
            "summary": self.summary,
            "tags": self.tags,
            "score": self.score,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "NewsArticle":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            url=data["url"],
            source=NewsSource(data["source"]),
            published=datetime.fromisoformat(data["published"]),
            summary=data.get("summary"),
            tags=data.get("tags", []),
            score=data.get("score"),
        )


# =============================================================================
# NEWS SOURCE CONFIGURATIONS
# =============================================================================


# Keywords to filter Hacker News for security content
SECURITY_KEYWORDS = [
    "security", "vulnerability", "cve", "exploit", "hack", "breach",
    "ransomware", "malware", "phishing", "zero-day", "0day", "apt",
    "cyber", "infosec", "pentest", "ctf", "bug bounty", "encryption",
    "authentication", "oauth", "jwt", "xss", "sql injection", "rce",
    "buffer overflow", "privilege escalation", "lateral movement",
]


# =============================================================================
# FETCHER CLASS
# =============================================================================


class SecurityNewsFetcher:
    """
    Fetches security news from multiple sources.
    
    Sources:
    - Hacker News API (filtered for security)
    - NVD CVE Feed (JSON)
    - CISA Alerts (RSS via JSON proxy)
    - The Hacker News (RSS)
    - Bleeping Computer (RSS)
    - Krebs on Security (RSS)
    """
    
    def __init__(self) -> None:
        self.timeout = 30.0
        self._client: Optional[httpx.AsyncClient] = None
        
        logger.info("SecurityNewsFetcher initialized")
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    # =========================================================================
    # HACKER NEWS
    # =========================================================================
    
    async def fetch_hacker_news(self, limit: int = 30) -> list[NewsArticle]:
        """
        Fetch top stories from Hacker News and filter for security content.
        
        Uses the official HN API (no auth required).
        """
        articles = []
        
        try:
            client = await self._get_client()
            
            # Get top story IDs
            response = await client.get(
                "https://hacker-news.firebaseio.com/v0/topstories.json"
            )
            response.raise_for_status()
            story_ids = response.json()[:100]  # Get top 100 to filter
            
            # Fetch story details (in parallel, limited)
            tasks = []
            for story_id in story_ids[:50]:  # Limit to 50 requests
                tasks.append(self._fetch_hn_story(client, story_id))
            
            stories = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter for security content
            for story in stories:
                if isinstance(story, Exception):
                    continue
                if story and self._is_security_related(story):
                    articles.append(story)
                    if len(articles) >= limit:
                        break
            
            logger.info(
                f"Fetched {len(articles)} security articles from Hacker News"
            )
            
        except Exception as e:
            logger.error(f"Failed to fetch Hacker News: {e}")
        
        return articles
    
    async def _fetch_hn_story(
        self, client: httpx.AsyncClient, story_id: int
    ) -> Optional[NewsArticle]:
        """Fetch a single HN story."""
        try:
            response = await client.get(
                f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"
            )
            response.raise_for_status()
            data = response.json()
            
            if not data or data.get("type") != "story":
                return None
            
            return NewsArticle(
                id=f"hn_{story_id}",
                title=data.get("title", ""),
                url=data.get("url", f"https://news.ycombinator.com/item?id={story_id}"),
                source=NewsSource.HACKER_NEWS,
                published=datetime.fromtimestamp(
                    data.get("time", 0), tz=timezone.utc
                ),
                summary=None,
                tags=["hacker_news"],
                score=data.get("score", 0),
            )
        except Exception:
            return None
    
    def _is_security_related(self, article: NewsArticle) -> bool:
        """Check if an article is security-related."""
        text = article.title.lower()
        return any(keyword in text for keyword in SECURITY_KEYWORDS)
    
    # =========================================================================
    # NVD CVE FEED
    # =========================================================================
    
    async def fetch_nvd_cves(self, limit: int = 20) -> list[NewsArticle]:
        """
        Fetch recent CVEs from NVD.
        
        Uses the NVD API 2.0 (no auth required, rate limited).
        """
        articles = []
        
        try:
            client = await self._get_client()
            
            # Get CVEs from last 7 days
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "resultsPerPage": limit,
                    "startIndex": 0,
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                
                # Get description
                descriptions = cve.get("descriptions", [])
                summary = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    None,
                )
                
                # Get severity
                metrics = cve.get("metrics", {})
                cvss = None
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
                
                tags = ["cve", "vulnerability"]
                if cvss:
                    if cvss >= 9.0:
                        tags.append("critical")
                    elif cvss >= 7.0:
                        tags.append("high")
                
                # Parse published date
                pub_date = cve.get("published", "")
                try:
                    published = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                except:
                    published = datetime.now(timezone.utc)
                
                articles.append(NewsArticle(
                    id=f"nvd_{cve_id}",
                    title=f"{cve_id}: {summary[:100] if summary else 'No description'}...",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    source=NewsSource.NVD_CVE,
                    published=published,
                    summary=summary,
                    tags=tags,
                    score=int(cvss * 10) if cvss else None,
                ))
            
            logger.info(f"Fetched {len(articles)} CVEs from NVD")
            
        except Exception as e:
            logger.error(f"Failed to fetch NVD CVEs: {e}")
        
        return articles
    
    # =========================================================================
    # RSS FEEDS (Generic)
    # =========================================================================
    
    async def fetch_rss_feed(
        self,
        url: str,
        source: NewsSource,
        limit: int = 20,
    ) -> list[NewsArticle]:
        """
        Fetch articles from an RSS feed.
        
        Uses a simple XML parser (no feedparser dependency).
        """
        articles = []
        
        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()
            
            # Simple RSS parsing
            content = response.text
            articles = self._parse_rss(content, source, limit)
            
            logger.info(f"Fetched {len(articles)} articles from {source.value}")
            
        except Exception as e:
            logger.error(f"Failed to fetch RSS from {source.value}: {e}")
        
        return articles
    
    def _parse_rss(
        self, content: str, source: NewsSource, limit: int
    ) -> list[NewsArticle]:
        """Parse RSS XML content."""
        articles = []
        
        # Simple regex-based RSS parsing (avoids xml.etree security issues)
        item_pattern = re.compile(r"<item>(.*?)</item>", re.DOTALL)
        title_pattern = re.compile(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", re.DOTALL)
        link_pattern = re.compile(r"<link>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</link>", re.DOTALL)
        desc_pattern = re.compile(r"<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>", re.DOTALL)
        date_pattern = re.compile(r"<pubDate>(.*?)</pubDate>", re.DOTALL)
        guid_pattern = re.compile(r"<guid[^>]*>(.*?)</guid>", re.DOTALL)
        
        items = item_pattern.findall(content)
        
        for i, item in enumerate(items[:limit]):
            title_match = title_pattern.search(item)
            link_match = link_pattern.search(item)
            desc_match = desc_pattern.search(item)
            date_match = date_pattern.search(item)
            guid_match = guid_pattern.search(item)
            
            if not title_match:
                continue
            
            title = self._clean_html(title_match.group(1).strip())
            url = link_match.group(1).strip() if link_match else ""
            summary = self._clean_html(desc_match.group(1).strip()) if desc_match else None
            guid = guid_match.group(1).strip() if guid_match else f"{source.value}_{i}"
            
            # Parse date
            published = datetime.now(timezone.utc)
            if date_match:
                try:
                    from email.utils import parsedate_to_datetime
                    parsed = parsedate_to_datetime(date_match.group(1).strip())
                    # Ensure timezone aware
                    if parsed.tzinfo is None:
                        published = parsed.replace(tzinfo=timezone.utc)
                    else:
                        published = parsed
                except:
                    pass
            
            articles.append(NewsArticle(
                id=f"{source.value}_{hash(guid) % 10000000}",
                title=title[:200],
                url=url,
                source=source,
                published=published,
                summary=summary[:500] if summary else None,
                tags=[source.value.replace("_", " ")],
            ))
        
        return articles
    
    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        clean = re.sub(r"<[^>]+>", "", text)
        clean = clean.replace("&nbsp;", " ")
        clean = clean.replace("&amp;", "&")
        clean = clean.replace("&lt;", "<")
        clean = clean.replace("&gt;", ">")
        clean = clean.replace("&quot;", '"')
        return clean.strip()
    
    # =========================================================================
    # FETCH ALL SOURCES
    # =========================================================================
    
    async def fetch_all(self) -> list[NewsArticle]:
        """
        Fetch from all configured news sources.
        
        Returns combined list of articles, deduplicated and sorted.
        """
        all_articles = []
        
        # Fetch from all sources in parallel
        tasks = [
            self.fetch_hacker_news(limit=15),
            self.fetch_nvd_cves(limit=10),
            self.fetch_rss_feed(
                "https://feeds.feedburner.com/TheHackersNews",
                NewsSource.THE_HACKER_NEWS,
                limit=10,
            ),
            self.fetch_rss_feed(
                "https://www.bleepingcomputer.com/feed/",
                NewsSource.BLEEPING_COMPUTER,
                limit=10,
            ),
            self.fetch_rss_feed(
                "https://krebsonsecurity.com/feed/",
                NewsSource.KREBS,
                limit=5,
            ),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Feed fetch error: {result}")
                continue
            all_articles.extend(result)
        
        # Sort by published date (newest first)
        # Ensure all datetimes are timezone-aware for comparison
        def get_published_utc(article: NewsArticle) -> datetime:
            if article.published.tzinfo is None:
                return article.published.replace(tzinfo=timezone.utc)
            return article.published
        
        all_articles.sort(key=get_published_utc, reverse=True)
        
        logger.info(f"Total articles fetched: {len(all_articles)}")
        
        return all_articles


# =============================================================================
# SINGLETON
# =============================================================================


_fetcher: Optional[SecurityNewsFetcher] = None


def get_news_fetcher() -> SecurityNewsFetcher:
    """Get or create the news fetcher singleton."""
    global _fetcher
    if _fetcher is None:
        _fetcher = SecurityNewsFetcher()
    return _fetcher
