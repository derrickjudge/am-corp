"""
AM-Corp Scope Approval Cache

Caches user-approved targets to avoid repeated confirmation requests.
Approvals expire after 12 hours by default.
Persists to disk to survive bot restarts.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)

# Default approval duration
APPROVAL_DURATION_HOURS = 12

# Cache file location
CACHE_FILE = Path("data/scope_cache.json")


@dataclass
class ScopeApproval:
    """Represents an approved scope entry."""
    
    target: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    scan_type: str = "any"
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "target": self.target,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "scan_type": self.scan_type,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ScopeApproval":
        """Create from dict."""
        return cls(
            target=data["target"],
            approved_by=data["approved_by"],
            approved_at=datetime.fromisoformat(data["approved_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            scan_type=data.get("scan_type", "any"),
        )


class ScopeCache:
    """
    Persistent cache for scope approvals.
    
    Targets approved by users are cached for 12 hours to avoid
    repeated confirmation requests. Cache is saved to disk to
    survive bot restarts.
    """
    
    def __init__(self, ttl_hours: int = APPROVAL_DURATION_HOURS) -> None:
        self._cache: Dict[str, ScopeApproval] = {}
        self._ttl = timedelta(hours=ttl_hours)
        self._load_from_disk()
    
    def _load_from_disk(self) -> None:
        """Load cached approvals from disk."""
        if not CACHE_FILE.exists():
            return
        
        try:
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)
            
            for target, approval_data in data.items():
                try:
                    approval = ScopeApproval.from_dict(approval_data)
                    # Only load if not expired
                    if datetime.now(timezone.utc) < approval.expires_at:
                        self._cache[target] = approval
                except Exception as e:
                    logger.warning(f"Failed to load approval for {target}: {e}")
            
            logger.info(f"Loaded {len(self._cache)} scope approvals from cache")
        except Exception as e:
            logger.warning(f"Failed to load scope cache: {e}")
    
    def _save_to_disk(self) -> None:
        """Save cached approvals to disk."""
        try:
            # Ensure data directory exists
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to serializable format
            data = {
                target: approval.to_dict()
                for target, approval in self._cache.items()
            }
            
            with open(CACHE_FILE, "w") as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save scope cache: {e}")
    
    def is_approved(self, target: str) -> bool:
        """
        Check if a target has been approved and the approval hasn't expired.
        
        Args:
            target: The target domain/IP to check
            
        Returns:
            True if target is approved and not expired
        """
        target_lower = target.lower()
        
        if target_lower not in self._cache:
            return False
        
        approval = self._cache[target_lower]
        now = datetime.now(timezone.utc)
        
        if now >= approval.expires_at:
            # Expired, remove from cache
            del self._cache[target_lower]
            logger.debug(f"Scope approval expired for {target}")
            return False
        
        return True
    
    def add_approval(
        self,
        target: str,
        approved_by: str,
        scan_type: str = "any",
    ) -> ScopeApproval:
        """
        Add or update a scope approval.
        
        Args:
            target: The approved target
            approved_by: User who approved it
            scan_type: Type of scan approved (or "any")
            
        Returns:
            The created ScopeApproval
        """
        now = datetime.now(timezone.utc)
        expires = now + self._ttl
        
        approval = ScopeApproval(
            target=target.lower(),
            approved_by=approved_by,
            approved_at=now,
            expires_at=expires,
            scan_type=scan_type,
        )
        
        self._cache[target.lower()] = approval
        
        logger.info(
            f"Scope approved for {target}",
            approved_by=approved_by,
            expires_at=expires.isoformat(),
        )
        
        audit_log(
            action="scope_approved",
            user=approved_by,
            target=target,
            result="approved",
            expires_at=expires.isoformat(),
        )
        
        # Persist to disk
        self._save_to_disk()
        
        return approval
    
    def get_approval(self, target: str) -> ScopeApproval | None:
        """Get the approval details for a target, if approved."""
        target_lower = target.lower()
        
        if not self.is_approved(target_lower):
            return None
        
        return self._cache.get(target_lower)
    
    def revoke_approval(self, target: str) -> bool:
        """
        Revoke a scope approval.
        
        Args:
            target: The target to revoke
            
        Returns:
            True if an approval was revoked, False if none existed
        """
        target_lower = target.lower()
        
        if target_lower in self._cache:
            del self._cache[target_lower]
            logger.info(f"Scope approval revoked for {target}")
            self._save_to_disk()
            return True
        
        return False
    
    def list_approved(self) -> list[ScopeApproval]:
        """Get all currently approved (non-expired) targets."""
        now = datetime.now(timezone.utc)
        
        # Clean expired entries
        expired = [
            target for target, approval in self._cache.items()
            if now >= approval.expires_at
        ]
        for target in expired:
            del self._cache[target]
        
        return list(self._cache.values())
    
    def time_remaining(self, target: str) -> timedelta | None:
        """Get time remaining on an approval, or None if not approved."""
        approval = self.get_approval(target)
        if not approval:
            return None
        
        now = datetime.now(timezone.utc)
        return approval.expires_at - now


# Singleton instance
_scope_cache: ScopeCache | None = None


def get_scope_cache() -> ScopeCache:
    """Get the global scope cache singleton."""
    global _scope_cache
    if _scope_cache is None:
        _scope_cache = ScopeCache()
    return _scope_cache

