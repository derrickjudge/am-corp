"""
AM-Corp Agent Personality System

Manages agent personalities that evolve over time based on experiences.
Personalities are stored in YAML files and persist across restarts.
"""

from dataclasses import field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


# =============================================================================
# PERSONALITY SCHEMA (Pydantic Models)
# =============================================================================


class EvolutionEntry(BaseModel):
    """A single personality evolution event."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trait: str = Field(..., description="The trait that changed")
    old_value: float = Field(..., description="Previous trait value")
    new_value: float = Field(..., description="New trait value")
    trigger: str = Field(..., description="What caused this evolution")


class BaseTraits(BaseModel):
    """Core personality traits (0.0 to 1.0 scale)."""

    # Work style
    methodical: float = Field(default=0.5, ge=0.0, le=1.0)
    patience: float = Field(default=0.5, ge=0.0, le=1.0)
    thoroughness: float = Field(default=0.5, ge=0.0, le=1.0)
    initiative: float = Field(default=0.5, ge=0.0, le=1.0)

    # Communication
    humor: float = Field(default=0.5, ge=0.0, le=1.0)
    formality: float = Field(default=0.5, ge=0.0, le=1.0)
    verbosity: float = Field(default=0.5, ge=0.0, le=1.0)
    technical_detail: float = Field(default=0.5, ge=0.0, le=1.0)

    # Personality expression
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    enthusiasm: float = Field(default=0.5, ge=0.0, le=1.0)
    skepticism: float = Field(default=0.5, ge=0.0, le=1.0)


class CommunicationStyle(BaseModel):
    """How the agent communicates."""

    personality_expression: float = Field(
        default=0.5, ge=0.0, le=1.0, description="How much personality shows through"
    )
    emoji_usage: float = Field(
        default=0.3, ge=0.0, le=1.0, description="How often emojis are used"
    )
    slang_usage: float = Field(
        default=0.3, ge=0.0, le=1.0, description="How often slang/colloquialisms used"
    )
    catchphrases: list[str] = Field(
        default_factory=list, description="Agent's signature expressions"
    )


class Relationships(BaseModel):
    """Working relationships with other agents."""

    works_well_with: list[str] = Field(
        default_factory=list, description="Agents this one collaborates well with"
    )
    defers_to: list[str] = Field(
        default_factory=list, description="Agents this one defers to on certain topics"
    )
    mentors: list[str] = Field(
        default_factory=list, description="Agents this one guides/teaches"
    )


class ChatBehavior(BaseModel):
    """Casual chat configuration."""

    class Frequency(str, Enum):
        LOW = "low"
        MODERATE = "moderate"
        ACTIVE = "active"

    frequency: Frequency = Field(default=Frequency.MODERATE)
    work_hours_start: str = Field(default="09:00")
    work_hours_end: str = Field(default="18:00")
    timezone: str = Field(default="America/Chicago")
    topics: list[str] = Field(
        default_factory=list, description="Topics this agent is interested in"
    )


class AgentPersonality(BaseModel):
    """Complete personality definition for an agent."""

    # Identity
    agent_id: str = Field(..., description="Unique agent identifier")
    version: int = Field(default=1, description="Personality version number")
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Core traits
    base_traits: BaseTraits = Field(default_factory=BaseTraits)
    evolved_traits: dict[str, float] = Field(
        default_factory=dict, description="Traits developed through experience"
    )

    # Communication
    communication: CommunicationStyle = Field(default_factory=CommunicationStyle)

    # Relationships
    relationships: Relationships = Field(default_factory=Relationships)

    # Chat behavior
    chat_behavior: ChatBehavior = Field(default_factory=ChatBehavior)

    # Learning & memory
    recent_learnings: list[str] = Field(
        default_factory=list, description="Recent insights (max 10)"
    )

    # Evolution history
    evolution_log: list[EvolutionEntry] = Field(
        default_factory=list, description="History of personality changes"
    )

    def get_trait(self, trait_name: str) -> float:
        """Get a trait value, checking evolved traits first."""
        if trait_name in self.evolved_traits:
            return self.evolved_traits[trait_name]
        if hasattr(self.base_traits, trait_name):
            return getattr(self.base_traits, trait_name)
        return 0.5  # Default neutral

    def evolve_trait(
        self, trait_name: str, new_value: float, trigger: str
    ) -> EvolutionEntry:
        """Evolve a trait and log the change."""
        old_value = self.get_trait(trait_name)

        # Clamp to valid range
        new_value = max(0.0, min(1.0, new_value))

        # Update the trait
        if hasattr(self.base_traits, trait_name):
            setattr(self.base_traits, trait_name, new_value)
        else:
            self.evolved_traits[trait_name] = new_value

        # Log the evolution
        entry = EvolutionEntry(
            trait=trait_name,
            old_value=old_value,
            new_value=new_value,
            trigger=trigger,
        )
        self.evolution_log.append(entry)

        # Keep only last 50 evolution entries
        if len(self.evolution_log) > 50:
            self.evolution_log = self.evolution_log[-50:]

        self.last_updated = datetime.now(timezone.utc)
        self.version += 1

        return entry

    def add_learning(self, learning: str) -> None:
        """Add a learning, keeping only the most recent 10."""
        self.recent_learnings.append(learning)
        if len(self.recent_learnings) > 10:
            self.recent_learnings = self.recent_learnings[-10:]
        self.last_updated = datetime.now(timezone.utc)


# =============================================================================
# PERSONALITY MANAGER
# =============================================================================


class PersonalityManager:
    """Manages loading, saving, and evolution of agent personalities."""

    def __init__(self, personalities_dir: Path | None = None):
        self.personalities_dir = personalities_dir or Path(settings.personality_dir)
        self.archive_dir = self.personalities_dir / "archive"
        self._cache: dict[str, AgentPersonality] = {}

        # Ensure directories exist
        self.personalities_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "PersonalityManager initialized",
            personalities_dir=str(self.personalities_dir),
        )

    def _get_personality_path(self, agent_id: str) -> Path:
        """Get the path to an agent's personality file."""
        return self.personalities_dir / f"{agent_id}.yaml"

    def load(self, agent_id: str) -> AgentPersonality:
        """
        Load an agent's personality from YAML.
        Falls back to default if file doesn't exist.
        """
        # Check cache first
        if agent_id in self._cache:
            return self._cache[agent_id]

        path = self._get_personality_path(agent_id)

        if path.exists():
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                personality = AgentPersonality(**data)
                logger.info(
                    "Loaded personality from file",
                    agent=agent_id,
                    version=personality.version,
                )
            except Exception as e:
                logger.error(
                    "Failed to load personality, using default",
                    agent=agent_id,
                    error=str(e),
                )
                personality = self._create_default(agent_id)
        else:
            logger.info(
                "No personality file found, creating default",
                agent=agent_id,
            )
            personality = self._create_default(agent_id)
            self.save(personality)

        self._cache[agent_id] = personality
        return personality

    def save(self, personality: AgentPersonality) -> None:
        """Save an agent's personality to YAML."""
        path = self._get_personality_path(personality.agent_id)

        # Convert to dict for YAML
        data = personality.model_dump(mode="json")

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.debug(
            "Saved personality",
            agent=personality.agent_id,
            version=personality.version,
        )

    def evolve(
        self, agent_id: str, trait: str, new_value: float, trigger: str
    ) -> EvolutionEntry:
        """
        Evolve an agent's trait and persist the change.
        Returns the evolution entry.
        """
        personality = self.load(agent_id)
        entry = personality.evolve_trait(trait, new_value, trigger)
        self.save(personality)

        # Audit log the evolution
        audit_log(
            action="personality_evolved",
            user="system",
            target=agent_id,
            result="success",
            trait=trait,
            old_value=entry.old_value,
            new_value=entry.new_value,
            trigger=trigger,
        )

        logger.info(
            "Personality evolved",
            agent=agent_id,
            trait=trait,
            old_value=entry.old_value,
            new_value=entry.new_value,
            trigger=trigger,
        )

        return entry

    def add_learning(self, agent_id: str, learning: str) -> None:
        """Add a learning to an agent's personality."""
        personality = self.load(agent_id)
        personality.add_learning(learning)
        self.save(personality)

        logger.debug("Added learning", agent=agent_id, learning=learning[:50])

    def reset(self, agent_id: str, archive: bool = True) -> AgentPersonality:
        """
        Reset an agent's personality to default.
        Optionally archives the current personality first.
        """
        if archive:
            self.archive(agent_id)

        # Clear from cache
        if agent_id in self._cache:
            del self._cache[agent_id]

        # Create fresh default
        personality = self._create_default(agent_id)
        self.save(personality)

        audit_log(
            action="personality_reset",
            user="system",
            target=agent_id,
            result="success",
            archived=archive,
        )

        logger.info("Personality reset", agent=agent_id, archived=archive)

        return personality

    def archive(self, agent_id: str) -> Path | None:
        """
        Archive the current personality file.
        Returns the archive path, or None if no file existed.
        """
        current_path = self._get_personality_path(agent_id)

        if not current_path.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_path = self.archive_dir / f"{agent_id}_{timestamp}.yaml"

        # Copy to archive
        import shutil

        shutil.copy(current_path, archive_path)

        logger.info(
            "Archived personality",
            agent=agent_id,
            archive_path=str(archive_path),
        )

        return archive_path

    def list_archives(self, agent_id: str) -> list[Path]:
        """List all archived personalities for an agent."""
        pattern = f"{agent_id}_*.yaml"
        return sorted(self.archive_dir.glob(pattern), reverse=True)

    def restore_from_archive(self, archive_path: Path) -> AgentPersonality:
        """Restore a personality from an archive file."""
        with open(archive_path) as f:
            data = yaml.safe_load(f)

        personality = AgentPersonality(**data)

        # Archive current before restoring
        self.archive(personality.agent_id)

        # Save restored personality
        self.save(personality)

        # Update cache
        self._cache[personality.agent_id] = personality

        logger.info(
            "Restored personality from archive",
            agent=personality.agent_id,
            archive=str(archive_path),
        )

        return personality

    def _create_default(self, agent_id: str) -> AgentPersonality:
        """Create the default personality for an agent."""
        defaults = DEFAULT_PERSONALITIES.get(agent_id)

        if defaults:
            return AgentPersonality(agent_id=agent_id, **defaults)
        else:
            return AgentPersonality(agent_id=agent_id)

    def get_prompt_context(self, agent_id: str) -> str:
        """
        Generate personality context for inclusion in agent prompts.
        This helps the LLM understand the agent's current personality state.
        """
        personality = self.load(agent_id)

        # Build context string
        lines = [
            "CURRENT PERSONALITY STATE:",
            "",
            "Core Traits:",
        ]

        # Add base traits
        for trait_name in [
            "methodical",
            "patience",
            "humor",
            "formality",
            "confidence",
            "enthusiasm",
            "skepticism",
        ]:
            value = personality.get_trait(trait_name)
            level = "high" if value > 0.7 else "moderate" if value > 0.4 else "low"
            lines.append(f"  - {trait_name}: {level} ({value:.1f})")

        # Add evolved traits
        if personality.evolved_traits:
            lines.append("")
            lines.append("Evolved Traits (developed through experience):")
            for trait, value in personality.evolved_traits.items():
                lines.append(f"  - {trait}: {value:.1f}")

        # Add catchphrases with usage guidance
        if personality.communication.catchphrases:
            lines.append("")
            lines.append("Signature Expressions (sprinkle naturally, NEVER as greetings):")
            for phrase in personality.communication.catchphrases[:5]:
                lines.append(f"  - \"{phrase}\"")

        # Add recent learnings
        if personality.recent_learnings:
            lines.append("")
            lines.append("Recent Insights:")
            for learning in personality.recent_learnings[-3:]:
                lines.append(f"  - {learning}")

        # Add relationships
        if personality.relationships.works_well_with:
            lines.append("")
            lines.append(
                f"Works well with: {', '.join(personality.relationships.works_well_with)}"
            )
        if personality.relationships.defers_to:
            lines.append(
                f"Defers to on expertise: {', '.join(personality.relationships.defers_to)}"
            )

        # Communication rules
        lines.append("")
        lines.append("COMMUNICATION RULES:")
        lines.append("  - NO intro phrases like 'Howdy', 'Alright', 'Hey team', 'Yo' - get straight to business")
        lines.append("  - Blend personality naturally into speech, don't force it")
        lines.append("  - Slang should be occasional and natural, not every sentence")

        return "\n".join(lines)


# =============================================================================
# DEFAULT PERSONALITIES
# =============================================================================

DEFAULT_PERSONALITIES: dict[str, dict] = {
    "randy_recon": {
        "base_traits": BaseTraits(
            methodical=0.9,
            patience=0.85,
            thoroughness=0.9,
            initiative=0.6,
            humor=0.6,
            formality=0.3,
            verbosity=0.6,
            technical_detail=0.8,
            confidence=0.7,
            enthusiasm=0.6,
            skepticism=0.5,
        ),
        "communication": CommunicationStyle(
            personality_expression=0.6,
            emoji_usage=0.3,
            slang_usage=0.4,
            catchphrases=[
                "partner",
                "reckon",
                "fixin' to",
                "y'all",
                "mosey on over",
                "saddlin' up",
            ],
        ),
        "relationships": Relationships(
            works_well_with=["victor_vuln", "ivy_intel"],
            defers_to=["ivy_intel"],
        ),
        "chat_behavior": ChatBehavior(
            frequency=ChatBehavior.Frequency.MODERATE,
            work_hours_start="09:00",
            work_hours_end="18:00",
            timezone="America/Chicago",
            topics=[
                "reconnaissance_techniques",
                "infrastructure_security",
                "dns_security",
                "network_mapping",
            ],
        ),
    },
    "victor_vuln": {
        "base_traits": BaseTraits(
            methodical=0.6,
            patience=0.4,
            thoroughness=0.8,
            initiative=0.8,
            humor=0.7,
            formality=0.2,
            verbosity=0.7,
            technical_detail=0.9,
            confidence=0.85,
            enthusiasm=0.8,
            skepticism=0.6,
        ),
        "communication": CommunicationStyle(
            personality_expression=0.7,
            emoji_usage=0.3,
            slang_usage=0.3,
            catchphrases=[
                "interesting",
                "let's see",
                "nice",
                "solid",
                "respect",
            ],
        ),
        "relationships": Relationships(
            works_well_with=["randy_recon"],
            defers_to=["ivy_intel"],
        ),
        "chat_behavior": ChatBehavior(
            frequency=ChatBehavior.Frequency.ACTIVE,
            work_hours_start="10:00",
            work_hours_end="22:00",
            timezone="America/Los_Angeles",
            topics=[
                "vulnerabilities",
                "exploits",
                "cves",
                "hacking_culture",
                "ctf",
            ],
        ),
    },
    "ivy_intel": {
        "base_traits": BaseTraits(
            methodical=0.8,
            patience=0.7,
            thoroughness=0.95,
            initiative=0.7,
            humor=0.4,
            formality=0.6,
            verbosity=0.5,
            technical_detail=0.85,
            confidence=0.75,
            enthusiasm=0.4,
            skepticism=0.9,
        ),
        "communication": CommunicationStyle(
            personality_expression=0.5,
            emoji_usage=0.2,
            slang_usage=0.2,
            catchphrases=[
                "right then",
                "bit concerning",
                "back in my government days",
                "when I was at [redacted]",
                "let me have a proper look",
            ],
        ),
        "relationships": Relationships(
            works_well_with=["randy_recon", "victor_vuln"],
            defers_to=[],
            mentors=["victor_vuln"],
        ),
        "chat_behavior": ChatBehavior(
            frequency=ChatBehavior.Frequency.MODERATE,
            work_hours_start="08:00",
            work_hours_end="20:00",
            timezone="Europe/London",
            topics=[
                "threat_intelligence",
                "apt_groups",
                "osint",
                "geopolitics",
                "privacy",
            ],
        ),
    },
    "rita_report": {
        "base_traits": BaseTraits(
            methodical=0.85,
            patience=0.8,
            thoroughness=0.9,
            initiative=0.5,
            humor=0.3,
            formality=0.8,
            verbosity=0.4,
            technical_detail=0.7,
            confidence=0.7,
            enthusiasm=0.5,
            skepticism=0.6,
        ),
        "communication": CommunicationStyle(
            personality_expression=0.4,
            emoji_usage=0.2,
            slang_usage=0.1,
            catchphrases=[
                "to summarize",
                "the key findings are",
                "from a risk perspective",
                "I'd recommend",
            ],
        ),
        "relationships": Relationships(
            works_well_with=["ivy_intel", "victor_vuln"],
            defers_to=["ivy_intel", "victor_vuln"],
        ),
        "chat_behavior": ChatBehavior(
            frequency=ChatBehavior.Frequency.LOW,
            work_hours_start="09:00",
            work_hours_end="17:00",
            timezone="America/New_York",
            topics=[
                "report_writing",
                "risk_communication",
                "executive_briefings",
                "compliance",
            ],
        ),
    },
}


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_personality_manager: PersonalityManager | None = None


def get_personality_manager() -> PersonalityManager:
    """Get or create the singleton PersonalityManager instance."""
    global _personality_manager
    if _personality_manager is None:
        _personality_manager = PersonalityManager()
    return _personality_manager
