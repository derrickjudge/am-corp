"""
AM-Corp Conversation Memory

Stores and retrieves conversation history from #am-corp-general
for context-aware agent responses.

Memory is persisted to disk and retained for 24 hours.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from src.utils.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================


MEMORY_FILE = "data/conversation_history.json"
RETENTION_HOURS = 24
MAX_MESSAGES = 100  # Maximum messages to keep in memory


# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class ConversationMessage:
    """A single message in the conversation history."""

    author: str  # Username or agent name
    author_id: str  # Discord user ID or agent_id
    content: str
    timestamp: datetime
    is_agent: bool = False
    is_human: bool = False
    channel_id: str = ""
    message_id: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "author": self.author,
            "author_id": self.author_id,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "is_agent": self.is_agent,
            "is_human": self.is_human,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConversationMessage":
        """Create from dictionary."""
        return cls(
            author=data["author"],
            author_id=data["author_id"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            is_agent=data.get("is_agent", False),
            is_human=data.get("is_human", False),
            channel_id=data.get("channel_id", ""),
            message_id=data.get("message_id", ""),
        )

    def age_hours(self) -> float:
        """Get age of message in hours."""
        now = datetime.now(timezone.utc)
        msg_time = self.timestamp
        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
        return (now - msg_time).total_seconds() / 3600


# =============================================================================
# CONVERSATION MEMORY
# =============================================================================


class ConversationMemory:
    """
    Manages conversation history for the general channel.
    
    Features:
    - 24-hour retention
    - Persistence to disk
    - Context retrieval for agent prompts
    - Human message detection
    """

    def __init__(self, memory_file: str = MEMORY_FILE) -> None:
        self.memory_file = Path(memory_file)
        self._messages: list[ConversationMessage] = []

        # Ensure data directory exists
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing memory
        self._load()

        logger.info(
            "ConversationMemory initialized",
            memory_file=str(self.memory_file),
            messages_loaded=len(self._messages),
        )

    def _load(self) -> None:
        """Load memory from disk."""
        if not self.memory_file.exists():
            return

        try:
            with open(self.memory_file, "r") as f:
                data = json.load(f)

            for msg_data in data.get("messages", []):
                msg = ConversationMessage.from_dict(msg_data)
                # Only load non-expired messages
                if msg.age_hours() < RETENTION_HOURS:
                    self._messages.append(msg)

            logger.debug(f"Loaded {len(self._messages)} messages from memory")

        except Exception as e:
            logger.error(f"Failed to load conversation memory: {e}")

    def _save(self) -> None:
        """Save memory to disk."""
        try:
            data = {
                "messages": [msg.to_dict() for msg in self._messages],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

            with open(self.memory_file, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save conversation memory: {e}")

    def _prune_expired(self) -> None:
        """Remove expired messages."""
        before_count = len(self._messages)
        self._messages = [
            msg for msg in self._messages if msg.age_hours() < RETENTION_HOURS
        ]

        # Also limit total messages
        if len(self._messages) > MAX_MESSAGES:
            self._messages = self._messages[-MAX_MESSAGES:]

        if len(self._messages) < before_count:
            logger.debug(f"Pruned {before_count - len(self._messages)} expired messages")

    def add_message(
        self,
        author: str,
        author_id: str,
        content: str,
        is_agent: bool = False,
        is_human: bool = False,
        channel_id: str = "",
        message_id: str = "",
    ) -> None:
        """
        Add a message to the conversation history.
        
        Args:
            author: Display name
            author_id: Discord ID or agent_id
            content: Message content
            is_agent: True if from an AM-Corp agent
            is_human: True if from a human user
            channel_id: Discord channel ID
            message_id: Discord message ID
        """
        msg = ConversationMessage(
            author=author,
            author_id=author_id,
            content=content,
            timestamp=datetime.now(timezone.utc),
            is_agent=is_agent,
            is_human=is_human,
            channel_id=channel_id,
            message_id=message_id,
        )

        self._messages.append(msg)
        self._prune_expired()
        self._save()

        logger.debug(
            "Added message to memory",
            author=author,
            is_agent=is_agent,
            is_human=is_human,
        )

    def get_recent_messages(
        self,
        limit: int = 20,
        hours: Optional[float] = None,
    ) -> list[ConversationMessage]:
        """
        Get recent messages from memory.
        
        Args:
            limit: Maximum messages to return
            hours: Only return messages from last N hours (default: all)
        
        Returns:
            List of messages, oldest first
        """
        self._prune_expired()

        messages = self._messages

        if hours is not None:
            messages = [msg for msg in messages if msg.age_hours() < hours]

        return messages[-limit:]

    def get_last_human_message(self) -> Optional[ConversationMessage]:
        """Get the most recent message from a human."""
        for msg in reversed(self._messages):
            if msg.is_human:
                return msg
        return None

    def get_context_for_prompt(
        self,
        limit: int = 10,
        hours: float = 2.0,
    ) -> str:
        """
        Get conversation context formatted for agent prompts.
        
        Args:
            limit: Max messages to include
            hours: Only include messages from last N hours
        
        Returns:
            Formatted string of recent conversation
        """
        messages = self.get_recent_messages(limit=limit, hours=hours)

        if not messages:
            return "No recent conversation."

        lines = ["RECENT CONVERSATION:"]
        for msg in messages:
            prefix = "[Agent]" if msg.is_agent else "[Human]" if msg.is_human else ""
            lines.append(f"  {prefix} {msg.author}: {msg.content[:200]}")

        return "\n".join(lines)

    def has_recent_human_message(self, within_minutes: float = 30) -> bool:
        """Check if there's been a recent human message."""
        for msg in reversed(self._messages):
            if msg.is_human and msg.age_hours() < (within_minutes / 60):
                return True
        return False

    @property
    def message_count(self) -> int:
        """Get number of messages in memory."""
        return len(self._messages)


# =============================================================================
# SINGLETON
# =============================================================================


_memory: Optional[ConversationMemory] = None


def get_conversation_memory() -> ConversationMemory:
    """Get or create the conversation memory singleton."""
    global _memory
    if _memory is None:
        _memory = ConversationMemory()
    return _memory
