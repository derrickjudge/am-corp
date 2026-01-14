"""
AM-Corp Casual Chat System (General Channel Integration)

Manages natural conversation in #am-corp-general.
Features:
- Multiple conversation types (security, news, personal, banter)
- 24-hour conversation memory for context
- Human message responses
- Personality-driven chat frequency and style
"""

import asyncio
import random
from datetime import datetime, time, timezone
from enum import Enum
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
from src.discord_bot.conversation_memory import (
    ConversationMemory,
    get_conversation_memory,
)
from src.feeds.news_cache import NewsCache, get_news_cache
from src.feeds.security_news import NewsArticle
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# CONVERSATION TYPES
# =============================================================================


class ConversationType(str, Enum):
    """Types of casual conversation."""
    SECURITY_DISCUSSION = "security_discussion"  # 50% - opinions on security topics
    NEWS_REACTION = "news_reaction"              # 25% - react to articles
    PERSONAL_HOBBY = "personal_hobby"            # 15% - non-work interests
    TEAM_BANTER = "team_banter"                  # 5% - jokes, responses to teammates
    HUMAN_RESPONSE = "human_response"            # Variable - reply to human message


# Weights for random selection (must sum to 100)
CONVERSATION_WEIGHTS = {
    ConversationType.SECURITY_DISCUSSION: 50,
    ConversationType.NEWS_REACTION: 25,
    ConversationType.PERSONAL_HOBBY: 15,
    ConversationType.TEAM_BANTER: 10,
}

# Probability of including a link in news reactions
LINK_PROBABILITY = 0.30


# =============================================================================
# CHAT FREQUENCY INTERVALS (in minutes)
# =============================================================================


FREQUENCY_INTERVALS = {
    ChatBehavior.Frequency.LOW: (60, 120),       # 1-2 hours
    ChatBehavior.Frequency.MODERATE: (30, 60),   # 30-60 minutes
    ChatBehavior.Frequency.ACTIVE: (15, 30),     # 15-30 minutes
}


# =============================================================================
# SECURITY DISCUSSION TOPICS
# =============================================================================


SECURITY_TOPICS = [
    "browser zero-days and exploit markets",
    "supply chain attacks and dependencies",
    "cloud misconfiguration trends",
    "ransomware group tactics",
    "API security and authentication bypasses",
    "patch management challenges",
    "nation-state attribution difficulties",
    "bug bounty program evolution",
    "AI in security tooling",
    "container and Kubernetes security",
    "zero trust architecture adoption",
    "phishing technique evolution",
]


# =============================================================================
# CASUAL CHAT MANAGER
# =============================================================================


class CasualChatManager:
    """
    Manages casual chat in the general channel.
    
    Features:
    - Multiple conversation types with weighted selection
    - Context-aware responses using 24hr memory
    - Human message detection and response
    - Personality-driven chat frequency
    - NO emoji prefix (emoji is for work only)
    """

    def __init__(self) -> None:
        self.enabled = settings.casual_chat_enabled
        self.webhook_url = settings.discord_webhook_general
        self.pm = get_personality_manager()
        self.memory = get_conversation_memory()
        self.news_cache: Optional[NewsCache] = None
        
        # Track last chat times for each agent
        self._last_chat_times: dict[str, datetime] = {}
        
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

    # =========================================================================
    # WORK HOURS & FREQUENCY
    # =========================================================================

    def is_within_work_hours(self, personality: AgentPersonality) -> bool:
        """Check if the current time is within the agent's work hours."""
        chat_behavior = personality.chat_behavior
        
        try:
            tz = zoneinfo.ZoneInfo(chat_behavior.timezone)
        except Exception:
            tz = timezone.utc
        
        now = datetime.now(tz)
        current_time = now.time()
        
        try:
            start_parts = chat_behavior.work_hours_start.split(":")
            end_parts = chat_behavior.work_hours_end.split(":")
            work_start = time(int(start_parts[0]), int(start_parts[1]))
            work_end = time(int(end_parts[0]), int(end_parts[1]))
        except (ValueError, IndexError):
            work_start = time(9, 0)
            work_end = time(18, 0)
        
        return work_start <= current_time <= work_end

    def get_next_chat_delay(self, personality: AgentPersonality) -> float:
        """Get delay in seconds before next chat based on frequency."""
        frequency = personality.chat_behavior.frequency
        min_mins, max_mins = FREQUENCY_INTERVALS.get(
            frequency, FREQUENCY_INTERVALS[ChatBehavior.Frequency.MODERATE]
        )
        return random.uniform(min_mins, max_mins) * 60

    def should_chat(self, personality: AgentPersonality) -> bool:
        """Determine if agent should initiate chat now."""
        if not self.is_within_work_hours(personality):
            # Very limited off-hours activity
            if random.random() > 0.05:  # 5% chance outside work hours
                return False
        
        frequency = personality.chat_behavior.frequency
        base_prob = {
            ChatBehavior.Frequency.LOW: 0.3,
            ChatBehavior.Frequency.MODERATE: 0.5,
            ChatBehavior.Frequency.ACTIVE: 0.7,
        }.get(frequency, 0.5)
        
        initiative = personality.get_trait("initiative")
        prob = base_prob * (0.5 + initiative)
        
        return random.random() < min(prob, 0.9)

    # =========================================================================
    # CONVERSATION TYPE SELECTION
    # =========================================================================

    def select_conversation_type(self) -> ConversationType:
        """Select a conversation type based on weights."""
        total = sum(CONVERSATION_WEIGHTS.values())
        r = random.randint(1, total)
        
        cumulative = 0
        for conv_type, weight in CONVERSATION_WEIGHTS.items():
            cumulative += weight
            if r <= cumulative:
                return conv_type
        
        return ConversationType.SECURITY_DISCUSSION

    # =========================================================================
    # MESSAGE GENERATION
    # =========================================================================

    async def generate_message(
        self,
        agent_id: str,
        conv_type: ConversationType,
        context: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """
        Generate a message based on conversation type.
        
        Returns:
            Tuple of (message, article_id or None)
        """
        personality = self.pm.load(agent_id)
        personality_context = self.pm.get_prompt_context(agent_id)
        
        # Get conversation context
        conv_context = self.memory.get_context_for_prompt(limit=5, hours=2.0)
        
        if conv_type == ConversationType.SECURITY_DISCUSSION:
            return await self._generate_security_discussion(
                personality, personality_context, conv_context
            )
        elif conv_type == ConversationType.NEWS_REACTION:
            return await self._generate_news_reaction(
                personality, personality_context, conv_context
            )
        elif conv_type == ConversationType.PERSONAL_HOBBY:
            return await self._generate_personal_hobby(
                personality, personality_context, conv_context
            )
        elif conv_type == ConversationType.TEAM_BANTER:
            return await self._generate_team_banter(
                personality, personality_context, conv_context
            )
        elif conv_type == ConversationType.HUMAN_RESPONSE:
            return await self._generate_human_response(
                personality, personality_context, context or ""
            )
        
        return "...", None

    async def _generate_security_discussion(
        self,
        personality: AgentPersonality,
        personality_context: str,
        conv_context: str,
    ) -> tuple[str, None]:
        """Generate a security topic discussion."""
        from google import genai
        from google.genai import types
        
        topic = random.choice(SECURITY_TOPICS)
        
        prompt = f"""You are {personality.agent_id}, a security professional chatting with teammates.

{personality_context}

{conv_context}

Share your thoughts on this security topic: {topic}

RULES:
- Write 2-4 COMPLETE sentences with your opinion/analysis
- Be conversational - like talking to colleagues
- Include WHY you think this way or what you've observed
- Reference your experience or something you've noticed
- DO NOT use emojis or hashtags
- DO NOT start with greetings
- Keep slang minimal

EXAMPLES:
- "Been thinking about how [topic] has evolved. [Opinion]. [Reasoning]."
- "Something I've noticed lately with [topic] - [observation]. [Analysis]."
"""
        
        result = await self._call_llm(prompt, personality.agent_id)
        if result[0] is None:
            # Fallback for failed generation
            return f"Been thinking about {topic} lately. The landscape keeps evolving.", None
        return result

    async def _generate_news_reaction(
        self,
        personality: AgentPersonality,
        personality_context: str,
        conv_context: str,
    ) -> tuple[str, Optional[str]]:
        """Generate a reaction to a news article."""
        from google import genai
        from google.genai import types
        
        cache = self._get_news_cache()
        article = cache.get_random_article(personality.agent_id)
        
        if not article:
            # Fall back to security discussion
            return await self._generate_security_discussion(
                personality, personality_context, conv_context
            )
        
        include_link = random.random() < LINK_PROBABILITY
        clean_title = article.title[:100] if len(article.title) > 100 else article.title
        
        prompt = f"""You are {personality.agent_id}, a security professional who just read an article.

{personality_context}

{conv_context}

You read this article and want to share your thoughts:
ARTICLE: {clean_title}
SOURCE: {article.source.value}

RULES:
- Write 2-3 COMPLETE sentences with your reaction/opinion
- Reference what you read naturally (e.g., "saw that...", "was reading about...")
- Include YOUR TAKE - why it matters, what you think, implications
- Be conversational - sharing with colleagues
- DO NOT use emojis or hashtags
- DO NOT start with greetings
- DO NOT just summarize - give your opinion

EXAMPLES:
- "Saw that [topic] thing. [Your reaction]. [Why it matters]."
- "Was reading about [topic] - [your take]. Pretty [assessment]."
"""
        
        message, _ = await self._call_llm(prompt, personality.agent_id)
        
        # Handle failed generation
        if message is None:
            message = f"Saw an interesting piece about {clean_title[:50]}. Worth reading."
        
        # Append link if selected
        if include_link and article.url:
            message = f"{message}\n{article.url}"
        
        return message, article.id

    async def _generate_personal_hobby(
        self,
        personality: AgentPersonality,
        personality_context: str,
        conv_context: str,
    ) -> tuple[str, None]:
        """Generate a message about personal interests."""
        from google import genai
        from google.genai import types
        
        hobbies = personality.personal_interests.hobbies
        if not hobbies:
            # Fall back to security discussion
            return await self._generate_security_discussion(
                personality, personality_context, conv_context
            )
        
        hobby = random.choice(hobbies)
        
        prompt = f"""You are {personality.agent_id}, chatting casually with work colleagues about non-work stuff.

{personality_context}

{conv_context}

Share something about your hobby/interest: {hobby}

RULES:
- Write 2-3 COMPLETE sentences about this hobby
- Be genuine - share something specific (a recent experience, project, discovery)
- Keep it casual - like water cooler chat
- It's OK if it has nothing to do with security
- DO NOT use emojis or hashtags
- DO NOT start with greetings

EXAMPLES:
- "Finally [did something with hobby] last night. [Detail]. [Reaction]."
- "Been [hobby activity] lately. [Observation or progress]."
"""
        
        result = await self._call_llm(prompt, personality.agent_id)
        if result[0] is None:
            return f"Been getting into {hobby} lately. Nice change of pace from work.", None
        return result

    async def _generate_team_banter(
        self,
        personality: AgentPersonality,
        personality_context: str,
        conv_context: str,
    ) -> tuple[str, None]:
        """Generate light team banter or response to recent conversation."""
        from google import genai
        from google.genai import types
        
        prompt = f"""You are {personality.agent_id}, having casual banter with your team.

{personality_context}

{conv_context}

Based on the recent conversation (or just general team vibes), add a light comment.
This could be:
- A follow-up to something someone said
- A friendly observation about the team
- A relevant joke or light comment

RULES:
- Write 1-2 COMPLETE sentences
- Keep it light and friendly
- Be natural - like real team chat
- DO NOT use emojis or hashtags
- DO NOT start with greetings

EXAMPLES:
- "[Reaction to what someone said]. [Your addition]."
- "Speaking of [topic], [related thought]."
"""
        
        result = await self._call_llm(prompt, personality.agent_id)
        if result[0] is None:
            return "Quiet day around here. Everyone must be heads down on something.", None
        return result

    async def _generate_human_response(
        self,
        personality: AgentPersonality,
        personality_context: str,
        human_message: str,
    ) -> tuple[str, None]:
        """Generate a response to a human message."""
        from google import genai
        from google.genai import types
        
        conv_context = self.memory.get_context_for_prompt(limit=10, hours=1.0)
        
        prompt = f"""You are {personality.agent_id}, responding to a human colleague in team chat.

{personality_context}

{conv_context}

A human team member just said:
"{human_message}"

Respond naturally based on your expertise and personality.

RULES:
- Write 2-4 COMPLETE sentences
- Be helpful and conversational
- Share your expertise if relevant
- Be genuine - it's OK to say you don't know something
- DO NOT use emojis or hashtags
- DO NOT start with "Hey" or greetings
- Keep slang minimal

EXAMPLES:
- "[Direct response]. [Your perspective or experience]. [Optional follow-up]."
- "Good question. [Your take]. [Additional context]."
"""
        
        result = await self._call_llm(prompt, personality.agent_id)
        if result[0] is None:
            return "Good point. Something to think about.", None
        return result

    async def _call_llm(
        self,
        prompt: str,
        agent_id: str,
    ) -> tuple[str, None]:
        """Call the LLM and clean up the response."""
        from google import genai
        from google.genai import types
        
        # Intro phrases to strip (case-insensitive)
        INTRO_PHRASES = [
            "right then,", "right then ", "hey,", "hey ", "yo,", "yo ",
            "alright,", "alright ", "well,", "well ", "so,", "so ",
            "howdy,", "howdy ", "listen,", "listen ", "ok,", "ok ",
            "okay,", "okay ", "sure,", "sure ", "hey team,", "hey team ",
        ]
        
        try:
            client = genai.Client(api_key=settings.gemini_api_key)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.85,
                    max_output_tokens=400,  # Increased for complete sentences
                ),
            )
            
            if response and response.text:
                message = response.text.strip()
                
                # Clean up emoji at start
                while message and message[0] in "🔍⚠️🧠📊⚡🔥💀😀👍":
                    message = message[1:].strip()
                
                # Remove intro phrases
                message_lower = message.lower()
                for phrase in INTRO_PHRASES:
                    if message_lower.startswith(phrase):
                        message = message[len(phrase):].strip()
                        # Capitalize first letter
                        if message:
                            message = message[0].upper() + message[1:]
                        break
                
                # Find the last complete sentence
                if message and message[-1] not in ".!?":
                    # Search for last sentence-ending punctuation
                    last_period = message.rfind(".")
                    last_exclaim = message.rfind("!")
                    last_question = message.rfind("?")
                    last_punct = max(last_period, last_exclaim, last_question)
                    
                    if last_punct > 30:  # Need at least 30 chars for a good sentence
                        message = message[:last_punct + 1]
                    else:
                        # Message has no complete sentence - reject it
                        logger.warning(
                            f"Incomplete message from {agent_id}: {message[:50]}..."
                        )
                        return None, None  # Signal to use fallback
                
                # Validate message quality
                if len(message) >= 40:  # Minimum length for quality message
                    return message, None
                else:
                    logger.warning(f"Message too short from {agent_id}: {message}")
                    
        except Exception as e:
            logger.error(f"LLM call failed for {agent_id}: {e}")
        
        return None, None  # Return None to trigger fallback

    # =========================================================================
    # POSTING MESSAGES
    # =========================================================================

    async def post_message(
        self,
        agent_id: str,
        message: str,
        article_id: Optional[str] = None,
    ) -> bool:
        """Post a message to the general channel."""
        if not self.webhook_url:
            logger.warning("No general webhook configured")
            return False
        
        agent = AGENTS.get(agent_id)
        if not agent:
            logger.error(f"Unknown agent: {agent_id}")
            return False
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json={
                        "content": message,
                        "username": agent["name"],
                    },
                )
                response.raise_for_status()
                
                self._last_chat_times[agent_id] = datetime.now(timezone.utc)
                
                # Mark article as used
                if article_id:
                    cache = self._get_news_cache()
                    cache.mark_used(article_id)
                
                # Add to conversation memory
                self.memory.add_message(
                    author=agent["name"],
                    author_id=agent_id,
                    content=message[:500],
                    is_agent=True,
                    is_human=False,
                )
                
                logger.info(
                    "Posted casual chat",
                    agent=agent_id,
                    message_length=len(message),
                )
                return True
                
        except httpx.HTTPError as e:
            logger.error(f"Failed to post chat: {e}")
            return False

    # =========================================================================
    # TRIGGER METHODS
    # =========================================================================

    async def trigger_chat(self, agent_id: Optional[str] = None) -> bool:
        """Trigger a casual chat message."""
        if not self.enabled:
            return False
        
        # Ensure news cache is fresh
        cache = self._get_news_cache()
        if cache.needs_refresh:
            await cache.refresh()
        
        # Select agent if not specified
        if agent_id is None:
            candidates = list(AGENTS.keys())
            random.shuffle(candidates)
            for aid in candidates:
                personality = self.pm.load(aid)
                if self.should_chat(personality):
                    agent_id = aid
                    break
        
        if agent_id is None:
            return False
        
        # Select conversation type and generate message
        conv_type = self.select_conversation_type()
        message, article_id = await self.generate_message(agent_id, conv_type)
        
        return await self.post_message(agent_id, message, article_id)

    async def respond_to_human(
        self,
        human_message: str,
        human_author: str,
        human_author_id: str,
    ) -> bool:
        """Respond to a human message in general chat."""
        if not self.enabled:
            return False
        
        # Add human message to memory
        self.memory.add_message(
            author=human_author,
            author_id=human_author_id,
            content=human_message[:500],
            is_agent=False,
            is_human=True,
        )
        
        # Select which agent should respond
        # Prefer agents within work hours with relevant expertise
        best_agent = None
        best_score = 0
        
        for agent_id in AGENTS.keys():
            personality = self.pm.load(agent_id)
            
            score = 0
            
            # Work hours bonus
            if self.is_within_work_hours(personality):
                score += 5
            else:
                score += 1  # Can still respond outside work hours
            
            # Topic relevance
            msg_lower = human_message.lower()
            for topic in personality.chat_behavior.topics:
                if topic.lower() in msg_lower:
                    score += 3
            
            # Initiative trait
            score += personality.get_trait("initiative") * 2
            
            # Random factor
            score += random.random() * 2
            
            if score > best_score:
                best_score = score
                best_agent = agent_id
        
        if best_agent:
            # Small delay to feel natural
            await asyncio.sleep(random.uniform(2, 8))
            
            message, _ = await self.generate_message(
                best_agent,
                ConversationType.HUMAN_RESPONSE,
                context=human_message,
            )
            return await self.post_message(best_agent, message)
        
        return False


# =============================================================================
# BACKGROUND LOOP
# =============================================================================


async def casual_chat_loop(manager: CasualChatManager) -> None:
    """Background task for periodic casual chat."""
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
            
            # Try to trigger a chat
            await manager.trigger_chat()
            
            # Wait before next attempt (5-10 minutes)
            delay = random.uniform(300, 600)
            await asyncio.sleep(delay)
            
        except asyncio.CancelledError:
            logger.info("Casual chat loop cancelled")
            break
        except Exception as e:
            logger.error(f"Error in casual chat loop: {e}")
            await asyncio.sleep(60)


# =============================================================================
# SINGLETON AND CONVENIENCE
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
    return asyncio.create_task(casual_chat_loop(manager))


async def handle_human_message(
    message: str,
    author: str,
    author_id: str,
) -> bool:
    """Handle a human message in general chat."""
    manager = get_casual_chat_manager()
    return await manager.respond_to_human(message, author, author_id)
