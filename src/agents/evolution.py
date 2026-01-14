"""
AM-Corp Personality Evolution System

Defines triggers that cause agent personalities to evolve based on experiences.
Evolution happens automatically during agent workflows.

Evolution Triggers:
- Scan completion (success/failure patterns)
- Finding discoveries (vulnerability types, severity)
- Tool usage patterns
- Collaboration interactions
- Time-based maturation
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.agents.personality import get_personality_manager
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


# =============================================================================
# EVOLUTION TRIGGER TYPES
# =============================================================================


class TriggerType(str, Enum):
    """Types of events that can trigger personality evolution."""
    
    # Work-related
    SCAN_COMPLETED = "scan_completed"
    FINDING_DISCOVERED = "finding_discovered"
    TOOL_USED = "tool_used"
    ERROR_ENCOUNTERED = "error_encountered"
    
    # Collaboration
    HANDOFF_GIVEN = "handoff_given"
    HANDOFF_RECEIVED = "handoff_received"
    TEAMMATE_MENTIONED = "teammate_mentioned"
    
    # Learning
    NEW_PATTERN_OBSERVED = "new_pattern_observed"
    CVE_RESEARCHED = "cve_researched"
    
    # Time-based
    WORK_SESSION_COMPLETED = "work_session_completed"


@dataclass
class EvolutionTrigger:
    """A trigger event that may cause personality evolution."""
    
    agent_id: str
    trigger_type: TriggerType
    context: dict[str, Any]
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


# =============================================================================
# EVOLUTION RULES
# =============================================================================

# Define how traits evolve based on triggers
# Format: (trait_name, delta_per_occurrence, max_change_per_day)
EVOLUTION_RULES: dict[TriggerType, list[tuple[str, float, float]]] = {
    TriggerType.SCAN_COMPLETED: [
        ("thoroughness", 0.01, 0.05),  # Successful scans increase thoroughness
        ("confidence", 0.005, 0.02),   # Experience builds confidence
    ],
    TriggerType.FINDING_DISCOVERED: [
        ("enthusiasm", 0.02, 0.05),    # Finding things is exciting
    ],
    TriggerType.ERROR_ENCOUNTERED: [
        ("patience", 0.01, 0.03),      # Errors teach patience
        ("confidence", -0.01, 0.03),   # But may reduce confidence temporarily
    ],
    TriggerType.HANDOFF_GIVEN: [
        # No direct trait changes, but adds to collaboration patterns
    ],
    TriggerType.NEW_PATTERN_OBSERVED: [
        ("skepticism", 0.01, 0.03),    # Seeing patterns increases analytical thinking
    ],
}

# Trait-specific evolution rules based on context
CONTEXTUAL_RULES: dict[str, dict[str, tuple[str, float]]] = {
    # Agent-specific trait developments
    "randy_recon": {
        "dns_complexity": ("dns_expertise", 0.02),
        "large_attack_surface": ("infrastructure_focus", 0.02),
        "api_endpoints_found": ("api_security_interest", 0.03),
    },
    "victor_vuln": {
        "critical_vuln_found": ("urgency_sense", 0.03),
        "false_positive_identified": ("verification_habit", 0.02),
        "web_vuln_found": ("web_security_focus", 0.02),
        "cve_correlated": ("research_inclination", 0.02),
    },
    "ivy_intel": {
        "apt_connection_found": ("threat_awareness", 0.03),
        "historical_breach": ("paranoia", 0.02),  # Ivy's defining trait
        "geopolitical_context": ("big_picture_thinking", 0.02),
    },
    "rita_report": {
        "complex_findings": ("synthesis_skill", 0.02),
        "executive_summary": ("audience_awareness", 0.02),
    },
}


# =============================================================================
# EVOLUTION ENGINE
# =============================================================================


class EvolutionEngine:
    """
    Processes evolution triggers and updates agent personalities.
    
    Evolution is subtle and gradual - traits change by small amounts
    over many interactions, creating natural personality drift.
    """
    
    def __init__(self):
        self._pm = get_personality_manager()
        self._daily_changes: dict[str, dict[str, float]] = {}  # agent_id -> trait -> total_change
        self._last_reset: datetime = datetime.now(timezone.utc)
    
    def _reset_daily_limits_if_needed(self):
        """Reset daily change tracking at midnight."""
        now = datetime.now(timezone.utc)
        if now.date() != self._last_reset.date():
            self._daily_changes = {}
            self._last_reset = now
    
    def _get_daily_change(self, agent_id: str, trait: str) -> float:
        """Get how much a trait has changed today."""
        if agent_id not in self._daily_changes:
            self._daily_changes[agent_id] = {}
        return self._daily_changes.get(agent_id, {}).get(trait, 0.0)
    
    def _record_change(self, agent_id: str, trait: str, delta: float):
        """Record a trait change for daily limiting."""
        if agent_id not in self._daily_changes:
            self._daily_changes[agent_id] = {}
        current = self._daily_changes[agent_id].get(trait, 0.0)
        self._daily_changes[agent_id][trait] = current + abs(delta)
    
    async def process_trigger(self, trigger: EvolutionTrigger) -> list[tuple[str, float, float]]:
        """
        Process an evolution trigger and apply any personality changes.
        
        Returns list of (trait, old_value, new_value) for changes made.
        """
        self._reset_daily_limits_if_needed()
        
        changes_made = []
        
        # Apply standard rules for this trigger type
        rules = EVOLUTION_RULES.get(trigger.trigger_type, [])
        for trait, delta, max_daily in rules:
            change = await self._apply_trait_change(
                trigger.agent_id, trait, delta, max_daily, 
                f"{trigger.trigger_type.value}"
            )
            if change:
                changes_made.append(change)
        
        # Apply contextual rules based on context
        agent_rules = CONTEXTUAL_RULES.get(trigger.agent_id, {})
        for context_key, (trait, delta) in agent_rules.items():
            if context_key in trigger.context:
                change = await self._apply_trait_change(
                    trigger.agent_id, trait, delta, 0.1,
                    f"{trigger.trigger_type.value}: {context_key}"
                )
                if change:
                    changes_made.append(change)
        
        # Add learnings from context
        if "learning" in trigger.context:
            self._pm.add_learning(trigger.agent_id, trigger.context["learning"])
        
        return changes_made
    
    async def _apply_trait_change(
        self,
        agent_id: str,
        trait: str,
        delta: float,
        max_daily: float,
        trigger_reason: str,
    ) -> tuple[str, float, float] | None:
        """
        Apply a trait change if within daily limits.
        
        Returns (trait, old_value, new_value) if change was made, None otherwise.
        """
        # Check daily limit
        daily_so_far = self._get_daily_change(agent_id, trait)
        if daily_so_far >= max_daily:
            logger.debug(
                f"Daily evolution limit reached for {agent_id}.{trait}",
                daily_so_far=daily_so_far,
                max_daily=max_daily,
            )
            return None
        
        # Cap the delta to not exceed daily limit
        remaining = max_daily - daily_so_far
        actual_delta = max(-remaining, min(remaining, delta))
        
        if abs(actual_delta) < 0.001:
            return None  # Too small to matter
        
        # Get current value
        personality = self._pm.load(agent_id)
        old_value = personality.get_trait(trait)
        new_value = max(0.0, min(1.0, old_value + actual_delta))
        
        if abs(new_value - old_value) < 0.001:
            return None  # No effective change
        
        # Apply the change
        self._pm.evolve(agent_id, trait, new_value, trigger_reason)
        self._record_change(agent_id, trait, actual_delta)
        
        logger.info(
            f"Personality evolved",
            agent=agent_id,
            trait=trait,
            old_value=round(old_value, 3),
            new_value=round(new_value, 3),
            trigger=trigger_reason,
        )
        
        return (trait, old_value, new_value)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_evolution_engine: EvolutionEngine | None = None


def get_evolution_engine() -> EvolutionEngine:
    """Get or create the singleton EvolutionEngine."""
    global _evolution_engine
    if _evolution_engine is None:
        _evolution_engine = EvolutionEngine()
    return _evolution_engine


async def trigger_scan_completed(
    agent_id: str,
    target: str,
    success: bool,
    findings_count: int = 0,
    context: dict = None,
) -> list[tuple[str, float, float]]:
    """Trigger evolution after a scan completes."""
    engine = get_evolution_engine()
    
    ctx = context or {}
    ctx.update({
        "target": target,
        "success": success,
        "findings_count": findings_count,
    })
    
    if findings_count > 0:
        ctx["learning"] = f"Completed scan on {target}, found {findings_count} items"
    
    trigger = EvolutionTrigger(
        agent_id=agent_id,
        trigger_type=TriggerType.SCAN_COMPLETED,
        context=ctx,
    )
    
    return await engine.process_trigger(trigger)


async def trigger_finding_discovered(
    agent_id: str,
    finding_type: str,
    severity: str | None = None,
    details: str = "",
    context: dict = None,
) -> list[tuple[str, float, float]]:
    """Trigger evolution when a notable finding is discovered."""
    engine = get_evolution_engine()
    
    ctx = context or {}
    ctx.update({
        "finding_type": finding_type,
        "severity": severity,
        "details": details,
    })
    
    # Add contextual flags
    if severity in ("critical", "high"):
        ctx["critical_vuln_found"] = True
    if "api" in finding_type.lower() or "api" in details.lower():
        ctx["api_endpoints_found"] = True
    if "web" in finding_type.lower():
        ctx["web_vuln_found"] = True
    if "dns" in finding_type.lower():
        ctx["dns_complexity"] = True
    
    if severity:
        ctx["learning"] = f"Discovered {severity} {finding_type}: {details[:50]}"
    
    trigger = EvolutionTrigger(
        agent_id=agent_id,
        trigger_type=TriggerType.FINDING_DISCOVERED,
        context=ctx,
    )
    
    return await engine.process_trigger(trigger)


async def trigger_error_encountered(
    agent_id: str,
    error_type: str,
    error_message: str,
    recovered: bool = True,
    context: dict = None,
) -> list[tuple[str, float, float]]:
    """Trigger evolution when an error is encountered and handled."""
    engine = get_evolution_engine()
    
    ctx = context or {}
    ctx.update({
        "error_type": error_type,
        "error_message": error_message[:100],
        "recovered": recovered,
    })
    
    if recovered:
        ctx["learning"] = f"Recovered from {error_type}: {error_message[:30]}"
    
    trigger = EvolutionTrigger(
        agent_id=agent_id,
        trigger_type=TriggerType.ERROR_ENCOUNTERED,
        context=ctx,
    )
    
    return await engine.process_trigger(trigger)


async def trigger_pattern_observed(
    agent_id: str,
    pattern: str,
    significance: str = "notable",
    context: dict = None,
) -> list[tuple[str, float, float]]:
    """Trigger evolution when an agent observes a new pattern."""
    engine = get_evolution_engine()
    
    ctx = context or {}
    ctx.update({
        "pattern": pattern,
        "significance": significance,
        "learning": f"Observed pattern: {pattern}",
    })
    
    trigger = EvolutionTrigger(
        agent_id=agent_id,
        trigger_type=TriggerType.NEW_PATTERN_OBSERVED,
        context=ctx,
    )
    
    return await engine.process_trigger(trigger)


async def trigger_handoff(
    from_agent: str,
    to_agent: str,
    handoff_type: str,
    context: dict = None,
) -> None:
    """Trigger evolution for both agents in a handoff."""
    engine = get_evolution_engine()
    
    # Trigger for giving agent
    ctx_from = context.copy() if context else {}
    ctx_from["to_agent"] = to_agent
    ctx_from["handoff_type"] = handoff_type
    
    await engine.process_trigger(EvolutionTrigger(
        agent_id=from_agent,
        trigger_type=TriggerType.HANDOFF_GIVEN,
        context=ctx_from,
    ))
    
    # Trigger for receiving agent
    ctx_to = context.copy() if context else {}
    ctx_to["from_agent"] = from_agent
    ctx_to["handoff_type"] = handoff_type
    
    await engine.process_trigger(EvolutionTrigger(
        agent_id=to_agent,
        trigger_type=TriggerType.HANDOFF_RECEIVED,
        context=ctx_to,
    ))


# =============================================================================
# PERSONALITY DIFF
# =============================================================================


def get_personality_diff(agent_id: str, since_version: int = 1) -> dict:
    """
    Get a diff of personality changes since a specific version.
    
    Returns a dict with:
    - current_version: int
    - changes: list of evolution entries since that version
    - trait_summary: dict of trait -> (start_value, current_value)
    """
    pm = get_personality_manager()
    personality = pm.load(agent_id)
    
    # Filter evolution log to entries after the specified version
    relevant_entries = [
        e for e in personality.evolution_log
        # We don't track version in entries, so return all for now
    ]
    
    # Build trait summary from evolved_traits
    trait_summary = {}
    for trait, value in personality.evolved_traits.items():
        # Find the first entry for this trait to get original value
        first_entry = next(
            (e for e in personality.evolution_log if e.trait == trait),
            None
        )
        original = first_entry.old_value if first_entry else 0.5
        trait_summary[trait] = (original, value)
    
    return {
        "agent_id": agent_id,
        "current_version": personality.version,
        "changes_count": len(relevant_entries),
        "recent_changes": [
            {
                "trait": e.trait,
                "old": e.old_value,
                "new": e.new_value,
                "trigger": e.trigger,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in relevant_entries[-10:]  # Last 10 changes
        ],
        "evolved_traits": trait_summary,
        "recent_learnings": personality.recent_learnings[-5:],
    }
