"""
AM-Corp Thoughts Channel Manager

Handles posting agent reasoning/thoughts to the #am-corp-thoughts channel.
This provides transparency into how agents are thinking through problems.

Verbosity Levels:
    - minimal: Major decisions only
    - normal: Key reasoning steps (default)
    - verbose: Everything including uncertainties
    - all: Full stream of consciousness
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import httpx

from src.agents import AGENTS
from src.utils.config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


class ThoughtLevel(Enum):
    """Verbosity levels for thoughts - determines which thoughts are posted."""
    
    MINIMAL = "minimal"     # Major decisions only
    NORMAL = "normal"       # Key reasoning steps
    VERBOSE = "verbose"     # Everything including uncertainties
    ALL = "all"             # Full stream of consciousness
    
    @classmethod
    def from_string(cls, value: str) -> "ThoughtLevel":
        """Convert string to ThoughtLevel."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.NORMAL


# Define which thought categories are shown at each level
LEVEL_PRIORITY = {
    ThoughtLevel.MINIMAL: 1,
    ThoughtLevel.NORMAL: 2,
    ThoughtLevel.VERBOSE: 3,
    ThoughtLevel.ALL: 4,
}

# Thought categories and their minimum verbosity level
THOUGHT_CATEGORIES = {
    "decision": ThoughtLevel.MINIMAL,      # Major decisions
    "finding": ThoughtLevel.MINIMAL,       # Important findings
    "reasoning": ThoughtLevel.NORMAL,      # Step-by-step logic
    "status": ThoughtLevel.NORMAL,         # Status updates
    "uncertainty": ThoughtLevel.VERBOSE,   # Doubts and uncertainties
    "detail": ThoughtLevel.VERBOSE,        # Technical details
    "stream": ThoughtLevel.ALL,            # Stream of consciousness
}


@dataclass
class Thought:
    """A single thought from an agent."""
    
    agent_id: str
    thought: str
    confidence: Optional[float] = None  # 0.0 to 1.0
    category: str = "reasoning"         # See THOUGHT_CATEGORIES
    job_id: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class ThoughtsManager:
    """
    Manager for posting agent thoughts to the thoughts channel.
    
    Thoughts provide transparency into agent reasoning during operations.
    The verbosity level controls how much detail is shown.
    """
    
    def __init__(self) -> None:
        self.enabled = settings.thoughts_channel_enabled
        self.verbosity = ThoughtLevel.from_string(settings.thoughts_verbosity)
        self.webhook_url = settings.discord_webhook_thoughts
        
        if not self.webhook_url and self.enabled:
            logger.warning(
                "Thoughts channel enabled but no webhook URL configured. "
                "Set DISCORD_WEBHOOK_THOUGHTS in .env"
            )
    
    def should_post(self, category: str) -> bool:
        """Check if a thought of this category should be posted at current verbosity."""
        if not self.enabled:
            return False
        
        if not self.webhook_url:
            return False
        
        # Get the minimum level required for this category
        min_level = THOUGHT_CATEGORIES.get(category, ThoughtLevel.NORMAL)
        
        # Compare priorities
        current_priority = LEVEL_PRIORITY.get(self.verbosity, 2)
        required_priority = LEVEL_PRIORITY.get(min_level, 2)
        
        return current_priority >= required_priority
    
    def format_thought(self, thought: Thought) -> str:
        """
        Format a thought for Discord display.
        
        Example output:
            🔍 Randy (thinking): Starting DNS enumeration. Going passive first.
                                Confidence: 0.8
        """
        agent = AGENTS.get(thought.agent_id)
        if not agent:
            logger.error(f"Unknown agent: {thought.agent_id}")
            return f"**(thinking):** {thought.thought}"
        
        emoji = agent["emoji"]
        # Use first name only for thoughts
        first_name = agent["name"].split()[0]
        
        # Build the message
        lines = [f"{emoji} **{first_name}** *(thinking):* {thought.thought}"]
        
        # Add confidence if provided
        if thought.confidence is not None:
            confidence_pct = int(thought.confidence * 100)
            lines.append(f"    *Confidence: {confidence_pct}%*")
        
        return "\n".join(lines)
    
    async def post_thought(
        self,
        agent_id: str,
        thought: str,
        confidence: Optional[float] = None,
        category: str = "reasoning",
        job_id: Optional[str] = None,
    ) -> bool:
        """
        Post a thought to the thoughts channel.
        
        Args:
            agent_id: Agent identifier (e.g., "randy_recon")
            thought: The thought text
            confidence: Optional confidence level (0.0 to 1.0)
            category: Thought category (determines verbosity filtering)
            job_id: Optional job ID for tracking
        
        Returns:
            True if posted successfully, False otherwise
        """
        if not self.should_post(category):
            logger.debug(
                f"Thought filtered out",
                agent=agent_id,
                category=category,
                verbosity=self.verbosity.value,
            )
            return False
        
        thought_obj = Thought(
            agent_id=agent_id,
            thought=thought,
            confidence=confidence,
            category=category,
            job_id=job_id,
        )
        
        formatted = self.format_thought(thought_obj)
        
        try:
            async with httpx.AsyncClient() as client:
                agent = AGENTS.get(agent_id, {})
                response = await client.post(
                    self.webhook_url,
                    json={
                        "content": formatted,
                        "username": f"{agent.get('name', 'Agent')} (thinking)",
                    },
                )
                response.raise_for_status()
                
                logger.debug(
                    "Posted thought",
                    agent=agent_id,
                    category=category,
                    preview=thought[:50],
                )
                return True
                
        except httpx.HTTPError as e:
            logger.error(
                "Failed to post thought",
                agent=agent_id,
                error=str(e),
            )
            return False
    
    async def post_decision(
        self,
        agent_id: str,
        decision: str,
        reasoning: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> bool:
        """
        Post a major decision (always shown at minimal+ verbosity).
        
        Args:
            agent_id: Agent identifier
            decision: The decision being made
            reasoning: Optional reasoning behind the decision
            confidence: Optional confidence level
        """
        full_thought = decision
        if reasoning:
            full_thought = f"{decision} — {reasoning}"
        
        return await self.post_thought(
            agent_id=agent_id,
            thought=full_thought,
            confidence=confidence,
            category="decision",
        )
    
    async def post_finding(
        self,
        agent_id: str,
        finding: str,
        significance: str = "",
        confidence: Optional[float] = None,
    ) -> bool:
        """
        Post an important finding (always shown at minimal+ verbosity).
        
        Args:
            agent_id: Agent identifier
            finding: The finding
            significance: Why this finding matters
            confidence: Optional confidence level
        """
        full_thought = finding
        if significance:
            full_thought = f"{finding} — {significance}"
        
        return await self.post_thought(
            agent_id=agent_id,
            thought=full_thought,
            confidence=confidence,
            category="finding",
        )
    
    async def post_uncertainty(
        self,
        agent_id: str,
        uncertainty: str,
        consideration: Optional[str] = None,
    ) -> bool:
        """
        Post a doubt or uncertainty (shown at verbose+ verbosity).
        
        Args:
            agent_id: Agent identifier
            uncertainty: What the agent is uncertain about
            consideration: What they're considering doing about it
        """
        full_thought = uncertainty
        if consideration:
            full_thought = f"{uncertainty} Considering: {consideration}"
        
        return await self.post_thought(
            agent_id=agent_id,
            thought=full_thought,
            category="uncertainty",
        )


# Singleton instance
_thoughts_manager: Optional[ThoughtsManager] = None


def get_thoughts_manager() -> ThoughtsManager:
    """Get or create the thoughts manager singleton."""
    global _thoughts_manager
    if _thoughts_manager is None:
        _thoughts_manager = ThoughtsManager()
    return _thoughts_manager


# Convenience functions for agents to use directly
async def post_thought(
    agent_id: str,
    thought: str,
    confidence: Optional[float] = None,
    category: str = "reasoning",
) -> bool:
    """Post a thought from an agent."""
    manager = get_thoughts_manager()
    return await manager.post_thought(
        agent_id=agent_id,
        thought=thought,
        confidence=confidence,
        category=category,
    )


async def post_decision(
    agent_id: str,
    decision: str,
    reasoning: Optional[str] = None,
    confidence: Optional[float] = None,
) -> bool:
    """Post a major decision from an agent."""
    manager = get_thoughts_manager()
    return await manager.post_decision(
        agent_id=agent_id,
        decision=decision,
        reasoning=reasoning,
        confidence=confidence,
    )


async def post_finding(
    agent_id: str,
    finding: str,
    significance: str = "",
    confidence: Optional[float] = None,
) -> bool:
    """Post an important finding from an agent."""
    manager = get_thoughts_manager()
    return await manager.post_finding(
        agent_id=agent_id,
        finding=finding,
        significance=significance,
        confidence=confidence,
    )


async def post_uncertainty(
    agent_id: str,
    uncertainty: str,
    consideration: Optional[str] = None,
) -> bool:
    """Post a doubt or uncertainty from an agent."""
    manager = get_thoughts_manager()
    return await manager.post_uncertainty(
        agent_id=agent_id,
        uncertainty=uncertainty,
        consideration=consideration,
    )
