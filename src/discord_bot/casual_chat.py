"""
AM-Corp Casual Chat System (General Channel Integration)

Manages casual conversation in #am-corp-general.
Agents chat based on their personality traits, topics of interest,
work hours, and chat frequency settings.
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
# CASUAL CHAT TOPICS (Security-focused conversation starters)
# =============================================================================

TOPIC_PROMPTS = {
    "reconnaissance_techniques": [
        "What's your favorite passive recon technique?",
        "I've been thinking about DNS enumeration patterns...",
        "Anyone else notice interesting subdomain naming conventions lately?",
        "Port scanning best practices - what's your approach?",
    ],
    "infrastructure_security": [
        "Cloud misconfigurations are getting wild these days.",
        "Load balancer fingerprinting is underrated.",
        "What's your take on certificate transparency logs?",
    ],
    "dns_security": [
        "DNS rebinding attacks are still a thing in 2026.",
        "DNSSEC adoption is still surprisingly low.",
        "Zone transfers shouldn't still be open, yet here we are.",
    ],
    "network_mapping": [
        "Network topology discovery is an art form.",
        "Finding the edge of a network is always interesting.",
    ],
    "vulnerabilities": [
        "The CVE flood this week is wild.",
        "Critical vulns keep getting more creative.",
        "Patch management is harder than it should be.",
    ],
    "exploits": [
        "Proof of concepts are getting faster to release.",
        "Exploit chains are the new normal.",
    ],
    "hacking_culture": [
        "The security community has been active lately.",
        "Conferences this year have great talks lined up.",
    ],
    "threat_intelligence": [
        "APT attribution is getting complicated.",
        "Threat feeds need better correlation.",
    ],
    "correlation": [
        "Connecting the dots between intel sources is key.",
        "Pattern recognition in threat data is fascinating.",
    ],
    "security_research": [
        "The research community keeps finding new attack surfaces.",
        "Responsible disclosure timelines are a constant debate.",
    ],
    "reporting": [
        "Report clarity is just as important as findings.",
        "Executive summaries are an art form.",
    ],
    "documentation": [
        "Good documentation saves so much time later.",
        "Templates are useful but context matters.",
    ],
}


class CasualChatManager:
    """
    Manages casual chat in the general channel.
    
    Features:
    - Personality-driven chat frequency
    - Work hours awareness
    - Topic-based conversations
    - Message relevance filtering
    """

    def __init__(self) -> None:
        self.enabled = settings.casual_chat_enabled
        self.webhook_url = settings.discord_webhook_general
        self.pm = get_personality_manager()
        
        # Track last chat times for each agent
        self._last_chat_times: dict[str, datetime] = {}
        
        # Track ongoing conversations
        self._active_topic: Optional[str] = None
        self._conversation_starter: Optional[str] = None
        
        logger.info(
            "CasualChatManager initialized",
            enabled=self.enabled,
            webhook_configured=bool(self.webhook_url),
        )

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

    def select_topic(self, personality: AgentPersonality) -> tuple[str, str]:
        """
        Select a topic and message for the agent to discuss.
        
        Returns:
            Tuple of (topic_key, message)
        """
        # Prefer agent's topics of interest
        agent_topics = personality.chat_behavior.topics
        available_topics = [t for t in agent_topics if t in TOPIC_PROMPTS]
        
        if not available_topics:
            # Fall back to any topic
            available_topics = list(TOPIC_PROMPTS.keys())
        
        topic = random.choice(available_topics)
        messages = TOPIC_PROMPTS.get(topic, ["..."])
        message = random.choice(messages)
        
        return topic, message

    async def generate_chat_message(
        self,
        personality: AgentPersonality,
        context: Optional[str] = None,
    ) -> str:
        """
        Generate a chat message using the agent's personality.
        
        Uses Gemini to create a natural, personality-driven response.
        """
        from google import genai
        from google.genai import types
        
        topic, base_message = self.select_topic(personality)
        
        # Build personality context
        personality_context = self.pm.get_prompt_context(personality.agent_id)
        
        prompt = f"""You are {personality.agent_id}, a security professional chatting casually with teammates.

{personality_context}

Generate a casual message about this topic: {topic}
Starting point (rephrase naturally): {base_message}

Rules:
- Keep it short (1-2 sentences)
- Be conversational and natural
- Show your personality through word choice
- Reference your interests or recent experiences if relevant
- DO NOT use hashtags
- DO NOT be overly formal
"""
        
        if context:
            prompt += f"\nContext from ongoing conversation: {context}"
        
        try:
            client = genai.Client(api_key=settings.gemini_api_key)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.9,
                    max_output_tokens=150,
                ),
            )
            
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            logger.error(
                "Failed to generate chat message",
                agent=personality.agent_id,
                error=str(e),
            )
        
        return base_message

    async def post_chat_message(
        self,
        agent_id: str,
        message: str,
    ) -> bool:
        """Post a casual chat message to the general channel."""
        if not self.webhook_url:
            logger.warning("No general webhook configured, cannot post chat")
            return False
        
        agent = AGENTS.get(agent_id)
        if not agent:
            logger.error(f"Unknown agent: {agent_id}")
            return False
        
        # Format message with agent emoji
        formatted_message = f"{agent['emoji']} {message}"
        
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
                
                logger.debug(
                    "Posted casual chat",
                    agent=agent_id,
                    preview=message[:50],
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
        
        # Determine which agent(s) should chat
        candidates = [agent_id] if agent_id else list(AGENTS.keys())
        
        for aid in candidates:
            personality = self.pm.load(aid)
            
            if not force:
                if not self.is_within_work_hours(personality):
                    continue
                if not self.should_respond(personality):
                    continue
            
            # Generate and post message
            message = await self.generate_chat_message(personality)
            success = await self.post_chat_message(aid, message)
            
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
    their personality-driven schedules.
    """
    logger.info("Starting casual chat background loop")
    
    while True:
        try:
            if not manager.enabled:
                await asyncio.sleep(60)
                continue
            
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
