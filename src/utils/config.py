"""
AM-Corp Configuration Management

Centralized configuration using Pydantic Settings for type-safe
environment variable loading with validation.
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # =========================================================================
    # Discord Configuration
    # =========================================================================
    # Main bot token (command handler)
    discord_bot_token: str = Field(default="", description="Discord bot token")
    discord_guild_id: str = Field(default="", description="Discord server ID")

    # Agent bot tokens (for multi-bot setup)
    discord_bot_token_randy: str = Field(default="", description="Randy Recon bot token")
    discord_bot_token_victor: str = Field(default="", description="Victor Vuln bot token")
    discord_bot_token_ivy: str = Field(default="", description="Ivy Intel bot token")
    discord_bot_token_rita: str = Field(default="", description="Rita Report bot token")

    # Channel IDs
    discord_channel_commands: str = Field(default="", description="Commands channel ID")
    discord_channel_agent_chat: str = Field(
        default="", description="Agent chat channel ID"
    )
    discord_channel_results: str = Field(default="", description="Results channel ID")
    discord_channel_alerts: str = Field(default="", description="Alerts channel ID")
    discord_channel_debug: str = Field(default="", description="Debug channel ID")
    discord_channel_thoughts: str = Field(default="", description="Thoughts channel ID")
    discord_channel_general: str = Field(default="", description="General chat channel ID")
    
    # Debug channel settings
    debug_channel_enabled: bool = Field(
        default=False, description="Enable debug output to dedicated channel"
    )
    
    # Thoughts channel settings
    thoughts_channel_enabled: bool = Field(
        default=True, description="Enable thoughts channel for agent reasoning"
    )
    thoughts_verbosity: str = Field(
        default="normal",
        description="Thoughts verbosity level: minimal, normal, verbose, all"
    )

    # Webhook URLs
    discord_webhook_agent_chat: str = Field(
        default="", description="Agent chat webhook URL"
    )
    discord_webhook_results: str = Field(default="", description="Results webhook URL")
    discord_webhook_alerts: str = Field(default="", description="Alerts webhook URL")
    discord_webhook_thoughts: str = Field(default="", description="Thoughts channel webhook URL")
    discord_webhook_general: str = Field(default="", description="General chat webhook URL")

    # =========================================================================
    # LLM Configuration
    # =========================================================================
    gemini_api_key: str = Field(default="", description="Gemini API key")
    gemini_model: str = Field(
        default="gemini-2.5-flash", description="Gemini model name"
    )

    # =========================================================================
    # n8n Configuration
    # =========================================================================
    n8n_base_url: str = Field(
        default="http://localhost:5678", description="n8n instance URL"
    )
    n8n_api_key: str = Field(default="", description="n8n API key")

    # =========================================================================
    # External APIs (Optional)
    # =========================================================================
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    virustotal_api_key: Optional[str] = Field(
        default=None, description="VirusTotal API key"
    )
    securitytrails_api_key: Optional[str] = Field(
        default=None, description="SecurityTrails API key"
    )

    # =========================================================================
    # Application Settings
    # =========================================================================
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="logs/am-corp.log", description="Log file path")
    environment: str = Field(
        default="development", description="Environment (development/test/production)"
    )

    # =========================================================================
    # Rate Limiting
    # =========================================================================
    max_concurrent_scans: int = Field(
        default=1, description="Maximum concurrent scans"
    )
    rate_limit_requests: int = Field(
        default=100, description="API rate limit requests per window"
    )
    rate_limit_window: int = Field(
        default=3600, description="Rate limit window in seconds"
    )

    # =========================================================================
    # Personality System
    # =========================================================================
    personality_dir: str = Field(
        default="config/personalities", description="Directory for personality YAML files"
    )
    personality_evolution_enabled: bool = Field(
        default=True, description="Enable personality evolution based on experiences"
    )

    # =========================================================================
    # Security Settings
    # =========================================================================
    enable_scope_verification: bool = Field(
        default=True, description="Enable target scope verification"
    )
    allowed_targets: str = Field(
        default="", description="Comma-separated allowed target domains"
    )
    enable_audit_log: bool = Field(default=True, description="Enable audit logging")
    audit_log_file: str = Field(
        default="logs/audit.log", description="Audit log file path"
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return upper_v

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment is a valid value."""
        valid_envs = {"development", "test", "production"}
        lower_v = v.lower()
        if lower_v not in valid_envs:
            raise ValueError(f"environment must be one of {valid_envs}")
        return lower_v

    @field_validator("thoughts_verbosity")
    @classmethod
    def validate_thoughts_verbosity(cls, v: str) -> str:
        """Validate thoughts verbosity is a valid level."""
        valid_levels = {"minimal", "normal", "verbose", "all"}
        lower_v = v.lower()
        if lower_v not in valid_levels:
            raise ValueError(f"thoughts_verbosity must be one of {valid_levels}")
        return lower_v

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"

    @property
    def allowed_targets_list(self) -> list[str]:
        """Get allowed targets as a list."""
        if not self.allowed_targets:
            return []
        return [t.strip() for t in self.allowed_targets.split(",") if t.strip()]

    def validate_required_for_production(self) -> list[str]:
        """Validate all required settings are present for production."""
        missing = []

        if not self.discord_bot_token:
            missing.append("DISCORD_BOT_TOKEN")
        if not self.discord_guild_id:
            missing.append("DISCORD_GUILD_ID")
        if not self.gemini_api_key:
            missing.append("GEMINI_API_KEY")

        return missing


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience alias
settings = get_settings()

