"""
AM-Corp Input Validation and Security Checks

CRITICAL: This module enforces security rules including:
- Blocking .gov and .mil domains (NEVER scan government/military)
- Scope verification
- Input sanitization
"""

import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)

# =============================================================================
# BLOCKED DOMAINS - NEVER SCAN THESE
# =============================================================================
BLOCKED_TLDS = frozenset({
    ".gov",
    ".mil",
    ".gov.uk",
    ".mil.uk",
    ".gov.au",
    ".gov.ca",
    ".gc.ca",  # Government of Canada
    ".gov.in",
    ".gov.br",
    ".gob.mx",  # Mexico government
    ".gouv.fr",  # France government
})

BLOCKED_PATTERNS = [
    r"\.gov\.",  # Any .gov. subdomain
    r"\.mil\.",  # Any .mil. subdomain
    r"government",
    r"military",
    r"\.fed\.us",
]

# Private/internal IP ranges - don't scan without explicit approval
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),  # Link-local
]


@dataclass
class ValidationResult:
    """Result of a validation check."""
    
    is_valid: bool
    message: str
    requires_confirmation: bool = False
    blocked_reason: str | None = None


def is_government_domain(target: str) -> bool:
    """
    Check if a target is a government or military domain.
    
    CRITICAL: This check must NEVER be bypassed.
    """
    target_lower = target.lower().strip()
    
    # Check TLDs
    for tld in BLOCKED_TLDS:
        if target_lower.endswith(tld):
            return True
    
    # Check patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, target_lower):
            return True
    
    return False


def is_private_ip(target: str) -> bool:
    """Check if target is a private/internal IP address."""
    try:
        ip = ip_address(target)
        for network in PRIVATE_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        # Not an IP address
        return False


def is_localhost(target: str) -> bool:
    """Check if target refers to localhost."""
    localhost_patterns = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    ]
    return target.lower().strip() in localhost_patterns


def sanitize_target(target: str) -> str:
    """
    Sanitize a target string.
    
    - Remove protocol prefixes
    - Remove trailing slashes and paths
    - Lowercase
    - Strip whitespace
    """
    target = target.strip().lower()
    
    # Remove protocol
    for prefix in ["https://", "http://", "ftp://", "//"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    
    # Remove path/query
    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]
    
    # Remove port for domain validation
    if ":" in target and not target.startswith("["):  # Not IPv6
        target = target.split(":")[0]
    
    return target


def is_in_allowed_scope(target: str) -> bool:
    """Check if target is in the pre-approved allowed targets list."""
    allowed = settings.allowed_targets_list
    
    if not allowed:
        # No allowed list = manual approval required
        return False
    
    target_lower = target.lower()
    
    for allowed_target in allowed:
        allowed_lower = allowed_target.lower()
        # Exact match or subdomain match
        if target_lower == allowed_lower:
            return True
        if target_lower.endswith("." + allowed_lower):
            return True
    
    return False


def validate_target(target: str) -> ValidationResult:
    """
    Validate a scan target.
    
    This is the main validation function that should be called before
    any reconnaissance or scanning operation.
    
    Args:
        target: The target domain or IP to validate
        
    Returns:
        ValidationResult with validation status and details
    """
    # Sanitize input
    clean_target = sanitize_target(target)
    
    if not clean_target:
        return ValidationResult(
            is_valid=False,
            message="Target cannot be empty.",
            blocked_reason="empty_target",
        )
    
    # CRITICAL: Check for government/military domains
    if is_government_domain(clean_target):
        audit_log(
            action="target_blocked",
            target=clean_target,
            user="system",
            result="blocked",
            reason="government_military_domain",
        )
        logger.warning(
            "Blocked government/military target",
            target=clean_target,
        )
        return ValidationResult(
            is_valid=False,
            message=f"🚫 **BLOCKED:** `{clean_target}` appears to be a government or military domain. "
                    "Scanning .gov/.mil domains is strictly prohibited.",
            blocked_reason="government_military",
        )
    
    # Check for localhost
    if is_localhost(clean_target):
        return ValidationResult(
            is_valid=False,
            message=f"🚫 **BLOCKED:** Cannot scan localhost.",
            blocked_reason="localhost",
        )
    
    # Check for private IPs
    if is_private_ip(clean_target):
        audit_log(
            action="target_requires_confirmation",
            target=clean_target,
            user="system",
            result="pending",
            reason="private_ip",
        )
        return ValidationResult(
            is_valid=True,
            message=f"⚠️ `{clean_target}` is a private/internal IP address. "
                    "Confirm you have authorization to scan this network.",
            requires_confirmation=True,
        )
    
    # Check scope if verification is enabled
    if settings.enable_scope_verification:
        if is_in_allowed_scope(clean_target):
            return ValidationResult(
                is_valid=True,
                message=f"✅ `{clean_target}` is in pre-approved scope.",
                requires_confirmation=False,
            )
        else:
            audit_log(
                action="target_requires_confirmation",
                target=clean_target,
                user="system",
                result="pending",
                reason="not_in_scope",
            )
            return ValidationResult(
                is_valid=True,
                message=f"⚠️ `{clean_target}` is not in pre-approved scope. "
                        "React with ✅ to confirm authorization, or ❌ to cancel.",
                requires_confirmation=True,
            )
    
    # Scope verification disabled - allow with warning
    return ValidationResult(
        is_valid=True,
        message=f"✅ `{clean_target}` - scope verification disabled.",
        requires_confirmation=False,
    )


def validate_command(content: str) -> tuple[str | None, str | None, str | None]:
    """
    Parse and validate a command from Discord.
    
    Args:
        content: Raw message content
        
    Returns:
        Tuple of (command_name, target, error_message)
        If error_message is set, the command is invalid.
    """
    content = content.strip()
    
    if not content.startswith("!"):
        return None, None, "Not a command"
    
    parts = content[1:].split(maxsplit=1)
    if not parts:
        return None, None, "Empty command"
    
    command = parts[0].lower()
    target = parts[1] if len(parts) > 1 else None
    
    # Commands that require a target
    target_commands = {"scan", "recon", "vuln", "intel"}
    
    if command in target_commands and not target:
        return command, None, f"Command `!{command}` requires a target. Usage: `!{command} <target>`"
    
    return command, target, None

