"""
AM-Corp Casual Chat System (General Channel Integration)

Manages casual conversation in #am-corp-general.
Agents chat based on their personality traits, topics of interest,
work hours, and chat frequency settings.

Casual chat is driven by REAL security news, not generic prompts.
Agents comment on actual articles, CVEs, and security events.
"""

import asyncio
import random
from datetime import datetime, time, timezone
from typing import Optional

import httpx

try:
    import zoneinfo
except ImportError:
    from backports import zoneinfo  # type: ignore

from src.agents import AGENTS
from src.agents.personality import (
    AgentPersonality,
    ChatBehavior,
    get_personality_manager,
)
from src.feeds.news_cache import NewsCache, get_news_cache
from src.feeds.security_news import NewsArticle
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# CHAT FREQUENCY INTERVALS (in minutes)
# =============================================================================

FREQUENCY_INTERVALS = {
    ChatBehavior.Frequency.LOW: (60, 120),       # 1-2 hours between messages
    ChatBehavior.Frequency.MODERATE: (30, 60),   # 30-60 minutes
    ChatBehavior.Frequency.ACTIVE: (15, 30),     # 15-30 minutes
}


# =============================================================================
# FALLBACK TOPICS (Only used if news cache is empty)
# =============================================================================

FALLBACK_PROMPTS = [
    "Security news has been quiet today. Anyone working on anything interesting?",
    "Haven't seen many new CVEs drop lately. Is it just me?",
    "The threat landscape seems calmer than usual. Suspicious.",
]


class CasualChatManager:
    """
    Manages casual chat in the general channel.
    
    Features:
    - News-driven conversations (real security content)
    - Personality-driven chat frequency
    - Work hours awareness
    - Message relevance filtering
    - NO emoji prefix (emoji is for work only)
    """

    def __init__(self) -> None:
        self.enabled = settings.casual_chat_enabled
        self.webhook_url = settings.discord_webhook_general
        self.pm = get_personality_manager()
        self.news_cache: Optional[NewsCache] = None
        
        # Track last chat times for each agent
        self._last_chat_times: dict[str, datetime] = {}
        
        # Track ongoing conversations
        self._active_article: Optional[NewsArticle] = None
        
        logger.info(
            "CasualChatManager initialized",
            enabled=self.enabled,
            webhook_configured=bool(self.webhook_url),
        )
    
    def _get_news_cache(self) -> NewsCache:
        """Get or initialize the news cache."""
        if self.news_cache is None:
            self.news_cache = get_news_cache()
        return self.news_cache

    def is_within_work_hours(self, personality: AgentPersonality) -> bool:
        """Check if the current time is within the agent's work hours."""
        chat_behavior = personality.chat_behavior
        
        try:
            tz = zoneinfo.ZoneInfo(chat_behavior.timezone)
        except Exception:
            tz = timezone.utc
        
        now = datetime.now(tz)
        current_time = now.time()
        
        # Parse work hours
        try:
            start_parts = chat_behavior.work_hours_start.split(":")
            end_parts = chat_behavior.work_hours_end.split(":")
            work_start = time(int(start_parts[0]), int(start_parts[1]))
            work_end = time(int(end_parts[0]), int(end_parts[1]))
        except (ValueError, IndexError):
            # Default work hours if parsing fails
            work_start = time(9, 0)
            work_end = time(18, 0)
        
        return work_start <= current_time <= work_end

    def get_next_chat_delay(self, personality: AgentPersonality) -> float:
        """Get the delay in seconds before the next chat based on frequency."""
        frequency = personality.chat_behavior.frequency
        min_mins, max_mins = FREQUENCY_INTERVALS.get(
            frequency, FREQUENCY_INTERVALS[ChatBehavior.Frequency.MODERATE]
        )
        
        delay_minutes = random.uniform(min_mins, max_mins)
        return delay_minutes * 60  # Convert to seconds

    def should_respond(
        self, personality: AgentPersonality, topic: Optional[str] = None
    ) -> bool:
        """
        Determine if an agent should respond to a message.
        
        Considers:
        - Work hours
        - Topic relevance
        - Initiative trait
        - Random chance based on frequency
        """
        # Check work hours
        if not self.is_within_work_hours(personality):
            return False
        
        # Topic relevance - if topic matches agent's interests, higher chance
        topic_match = False
        if topic:
            topic_lower = topic.lower()
            for agent_topic in personality.chat_behavior.topics:
                if agent_topic.lower() in topic_lower or topic_lower in agent_topic.lower():
                    topic_match = True
                    break
        
        # Base probability based on frequency
        frequency = personality.chat_behavior.frequency
        base_prob = {
            ChatBehavior.Frequency.LOW: 0.3,
            ChatBehavior.Frequency.MODERATE: 0.5,
            ChatBehavior.Frequency.ACTIVE: 0.7,
        }.get(frequency, 0.5)
        
        # Adjust for initiative trait
        initiative = personality.get_trait("initiative")
        prob = base_prob * (0.5 + initiative)
        
        # Boost if topic matches
        if topic_match:
            prob *= 1.5
        
        # Cap at reasonable max
        prob = min(prob, 0.9)
        
        return random.random() < prob

    def get_article_for_agent(self, agent_id: str) -> Optional[NewsArticle]:
        """
        Get a relevant news article for the agent to discuss.
        
        Returns:
            A news article relevant to the agent's interests, or None
        """
        cache = self._get_news_cache()
        articles = cache.get_articles_for_agent(agent_id, limit=5, exclude_used=True)
        
        if articles:
            return random.choice(articles)
        
        # If no unused articles, allow reuse
        articles = cache.get_articles_for_agent(agent_id, limit=5, exclude_used=False)
        if articles:
            return random.choice(articles)
        
        return None

    async def generate_chat_message(
        self,
        personality: AgentPersonality,
        article: Optional[NewsArticle] = None,
    ) -> tuple[str, Optional[str]]:
        """
        Generate a chat message about a news article using the agent's personality.
        
        Args:
            personality: Agent personality
            article: Optional article to discuss (fetches one if not provided)
        
        Returns:
            Tuple of (message, article_id) - article_id is None if no article used
        """
        from google import genai
        from google.genai import types
        
        # Get article if not provided
        if article is None:
            article = self.get_article_for_agent(personality.agent_id)
        
        # Build personality context
        personality_context = self.pm.get_prompt_context(personality.agent_id)
        
        if article:
            # Generate commentary on the article
            # Clean article title - truncate if too long
            clean_title = article.title[:100] if len(article.title) > 100 else article.title
            
            prompt = f"""You are {personality.agent_id}, a security professional sharing an interesting article with teammates.

{personality_context}

You found this security news article and want to share it with your team:

ARTICLE: {clean_title}
SOURCE: {article.source.value}

Write a message sharing this article. The article link will be added automatically after your message.

FORMAT EXAMPLES:
- "Was just reading about [topic]. [Your take on it]. [Why it matters]."
- "Interesting article on [topic]. [Your reaction]. Worth a read."
- "Came across this piece on [topic]. [Brief analysis or opinion]."

RULES:
- Write 2-3 COMPLETE sentences that provide context
- Reference that you're sharing an article (e.g. "was reading", "came across", "interesting piece on")
- Include your opinion, reaction, or why it matters
- Be conversational - like sharing a link with a colleague
- DO NOT use hashtags or emojis
- DO NOT start with greetings like "Hey", "Yo", "Alright"
- Keep slang minimal and natural
"""
        else:
            # Fallback: generate a generic message
            fallback = random.choice(FALLBACK_PROMPTS)
            prompt = f"""You are {personality.agent_id}, a security professional chatting casually with teammates.

{personality_context}

Generate a brief casual message. Starting point: {fallback}

CRITICAL RULES:
- Write 1-2 COMPLETE sentences (must end with proper punctuation)
- Be conversational and natural
- DO NOT use hashtags or emojis
- DO NOT start with greetings like "Hey", "Yo", "Alright"
"""
        
        try:
            client = genai.Client(api_key=settings.gemini_api_key)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.8,
                    max_output_tokens=300,
                ),
            )
            
            if response and response.text:
                message = response.text.strip()
                
                # Clean up any accidental emoji at the start
                while message and message[0] in "🔍⚠️🧠📊⚡🔥💀":
                    message = message[1:].strip()
                
                # Validate message is complete (ends with punctuation)
                if message and message[-1] not in ".!?":
                    # Try to find the last complete sentence
                    for punct in ".!?":
                        idx = message.rfind(punct)
                        if idx > 20:  # At least 20 chars for a sentence
                            message = message[:idx + 1]
                            break
                
                # Ensure message isn't too short or empty
                if len(message) < 20:
                    logger.warning(
                        "Generated message too short, using fallback",
                        agent=personality.agent_id,
                        message=message,
                    )
                else:
                    # Append article URL if we have one
                    if article and article.url:
                        message = f"{message}\n{article.url}"
                    
                    logger.info(
                        "Generated casual chat message",
                        agent=personality.agent_id,
                        message_length=len(message),
                        has_article_link=bool(article),
                    )
                    return message, article.id if article else None
                
        except Exception as e:
            logger.error(
                "Failed to generate chat message",
                agent=personality.agent_id,
                error=str(e),
            )
        
        # Fallback - generate a simple but complete message with article link
        if article:
            fallback_msg = f"Came across this article on {article.title[:50]}. Worth checking out."
            if article.url:
                fallback_msg = f"{fallback_msg}\n{article.url}"
            return fallback_msg, article.id
        return random.choice(FALLBACK_PROMPTS), None

    async def post_chat_message(
        self,
        agent_id: str,
        message: str,
        article_id: Optional[str] = None,
    ) -> bool:
        """
        Post a casual chat message to the general channel.
        
        NOTE: No emoji prefix for casual chat - emoji is for work only.
        """
        if not self.webhook_url:
            logger.warning("No general webhook configured, cannot post chat")
            return False
        
        agent = AGENTS.get(agent_id)
        if not agent:
            logger.error(f"Unknown agent: {agent_id}")
            return False
        
        # NO emoji prefix for casual chat - just the message
        # Emoji prefixes are reserved for work-related messages
        formatted_message = message
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json={
                        "content": formatted_message,
                        "username": agent["name"],
                    },
                )
                response.raise_for_status()
                
                self._last_chat_times[agent_id] = datetime.now(timezone.utc)
                
                # Mark article as used
                if article_id:
                    cache = self._get_news_cache()
                    cache.mark_used(article_id)
                
                logger.info(
                    "Posted casual chat",
                    agent=agent_id,
                    article_id=article_id,
                    message_length=len(message),
                    message=message[:100] if len(message) > 100 else message,
                )
                return True
                
        except httpx.HTTPError as e:
            logger.error(
                "Failed to post casual chat",
                agent=agent_id,
                error=str(e),
            )
            return False

    async def trigger_casual_chat(
        self,
        agent_id: Optional[str] = None,
        force: bool = False,
    ) -> bool:
        """
        Trigger a casual chat message from one or more agents.
        
        Args:
            agent_id: Specific agent to trigger (None = select based on personality)
            force: Bypass work hours and frequency checks
        
        Returns:
            True if a message was posted
        """
        if not self.enabled and not force:
            logger.debug("Casual chat disabled")
            return False
        
        if not self.webhook_url:
            logger.debug("No general webhook configured")
            return False
        
        # Ensure news cache is refreshed
        cache = self._get_news_cache()
        if cache.needs_refresh:
            await cache.refresh()
        
        # Determine which agent(s) should chat
        candidates = [agent_id] if agent_id else list(AGENTS.keys())
        
        for aid in candidates:
            personality = self.pm.load(aid)
            
            if not force:
                if not self.is_within_work_hours(personality):
                    continue
                if not self.should_respond(personality):
                    continue
            
            # Generate and post message based on news
            message, article_id = await self.generate_chat_message(personality)
            success = await self.post_chat_message(aid, message, article_id)
            
            if success:
                return True
        
        return False


# =============================================================================
# BACKGROUND CHAT TASK
# =============================================================================


async def casual_chat_loop(manager: CasualChatManager) -> None:
    """
    Background task that triggers casual chat at intervals.
    
    This runs continuously and selects agents to chat based on
    their personality-driven schedules. Chat content is driven
    by real security news from the news cache.
    """
    logger.info("Starting casual chat background loop")
    
    # Initial news cache refresh
    try:
        cache = manager._get_news_cache()
        await cache.refresh(force=True)
        logger.info(f"Initial news cache loaded: {cache.article_count} articles")
    except Exception as e:
        logger.error(f"Failed initial news cache refresh: {e}")
    
    while True:
        try:
            if not manager.enabled:
                await asyncio.sleep(60)
                continue
            
            # Refresh news cache periodically
            cache = manager._get_news_cache()
            if cache.needs_refresh:
                await cache.refresh()
            
            # Pick a random agent to potentially chat
            agent_ids = list(AGENTS.keys())
            random.shuffle(agent_ids)
            
            for agent_id in agent_ids:
                personality = manager.pm.load(agent_id)
                
                # Check if within work hours
                if not manager.is_within_work_hours(personality):
                    continue
                
                # Check if enough time has passed since last chat
                last_chat = manager._last_chat_times.get(agent_id)
                if last_chat:
                    elapsed = (datetime.now(timezone.utc) - last_chat).total_seconds()
                    min_delay = manager.get_next_chat_delay(personality) / 2
                    if elapsed < min_delay:
                        continue
                
                # Random chance based on frequency
                if manager.should_respond(personality):
                    await manager.trigger_casual_chat(agent_id=agent_id)
                    break  # Only one agent chats per interval
            
            # Wait before next check (5-10 minutes)
            delay = random.uniform(300, 600)
            await asyncio.sleep(delay)
            
        except asyncio.CancelledError:
            logger.info("Casual chat loop cancelled")
            break
        except Exception as e:
            logger.error(f"Error in casual chat loop: {e}")
            await asyncio.sleep(60)


# =============================================================================
# SINGLETON AND CONVENIENCE FUNCTIONS
# =============================================================================

_manager: Optional[CasualChatManager] = None


def get_casual_chat_manager() -> CasualChatManager:
    """Get or create the casual chat manager singleton."""
    global _manager
    if _manager is None:
        _manager = CasualChatManager()
    return _manager


async def start_casual_chat() -> asyncio.Task:
    """Start the casual chat background task."""
    manager = get_casual_chat_manager()
    task = asyncio.create_task(casual_chat_loop(manager))
    return task


async def post_casual_message(agent_id: str, message: str) -> bool:
    """Post a casual message from a specific agent."""
    manager = get_casual_chat_manager()
    return await manager.post_chat_message(agent_id, message)
