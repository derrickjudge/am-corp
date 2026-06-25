# Environment Configuration Template

Copy the contents of the code block below into a `.env` file in the project root, then fill in your values.

**Never commit `.env` to version control.**

The canonical reference for all variables, their types, and defaults is `src/utils/config.py`.

---

## Required Variables

These must be set before the bot will start.

| Variable | Description |
|----------|-------------|
| `DISCORD_BOT_TOKEN` | Main bot token (command handler) |
| `DISCORD_GUILD_ID` | Your Discord server ID |
| `DISCORD_CHANNEL_*` | Six channel IDs (see template) |
| `DISCORD_WEBHOOK_*` | Five webhook URLs (see template) |
| `GEMINI_API_KEY` | Google Gemini API key — free tier at aistudio.google.com |

## Optional Variables

These enable additional capabilities. The bot degrades gracefully without them.

| Variable | Enables |
|----------|---------|
| `DISCORD_BOT_TOKEN_RANDY/VICTOR/IVY/RITA` | Multi-bot mode (each agent appears as its own Discord user) |
| `DISCORD_CHANNEL_DEBUG` + `DEBUG_CHANNEL_ENABLED` | Debug output channel |
| `SHODAN_API_KEY` | Ivy Intel's host search capability |
| `VIRUSTOTAL_API_KEY` | Ivy Intel's malware/URL analysis |
| `SECURITYTRAILS_API_KEY` | Ivy Intel's DNS intelligence |
| `N8N_API_KEY` | n8n workflow automation (Phase 4, currently scaffolded) |

---

## Getting API Keys

| Service | Where |
|---------|-------|
| Discord Bot Token | discord.com/developers/applications → Bot → Reset Token |
| Discord Channel/Guild IDs | Right-click channel or server → Copy ID (enable Developer Mode first) |
| Discord Webhooks | Channel Settings → Integrations → Webhooks → New Webhook |
| Gemini API Key | aistudio.google.com → Get API Key |
| Shodan | account.shodan.io |
| VirusTotal | virustotal.com → My API Key |

---

## Template

```bash
# AM-Corp Environment Configuration
# Copy to .env in the project root — never commit this file

# =============================================================================
# DISCORD — REQUIRED
# =============================================================================
# Main bot token (from Discord Developer Portal → Bot)
DISCORD_BOT_TOKEN=

# Your Discord server (guild) ID
DISCORD_GUILD_ID=

# Channel IDs
# Right-click each channel → Copy Channel ID (requires Developer Mode)
DISCORD_CHANNEL_COMMANDS=
DISCORD_CHANNEL_AGENT_CHAT=
DISCORD_CHANNEL_RESULTS=
DISCORD_CHANNEL_ALERTS=
DISCORD_CHANNEL_THOUGHTS=
DISCORD_CHANNEL_GENERAL=

# Webhook URLs
# Channel Settings → Integrations → Webhooks → New Webhook → Copy URL
DISCORD_WEBHOOK_AGENT_CHAT=
DISCORD_WEBHOOK_RESULTS=
DISCORD_WEBHOOK_ALERTS=
DISCORD_WEBHOOK_THOUGHTS=
DISCORD_WEBHOOK_GENERAL=

# =============================================================================
# DISCORD — OPTIONAL: Multi-bot mode
# Each agent appears as its own Discord user instead of one shared bot.
# Leave blank to run all agents under DISCORD_BOT_TOKEN.
# =============================================================================
DISCORD_BOT_TOKEN_RANDY=
DISCORD_BOT_TOKEN_VICTOR=
DISCORD_BOT_TOKEN_IVY=
DISCORD_BOT_TOKEN_RITA=

# =============================================================================
# DISCORD — OPTIONAL: Debug channel
# =============================================================================
DISCORD_CHANNEL_DEBUG=
DEBUG_CHANNEL_ENABLED=false

# =============================================================================
# LLM — REQUIRED
# Free tier limits: 15 RPM, 1,500 RPD, 1M TPM
# =============================================================================
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash

# =============================================================================
# EXTERNAL APIs — OPTIONAL
# Ivy Intel degrades gracefully without these.
# =============================================================================
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
SECURITYTRAILS_API_KEY=

# =============================================================================
# N8N — OPTIONAL (Phase 4, currently scaffolded but not fully tested)
# =============================================================================
N8N_BASE_URL=http://localhost:5678
N8N_API_KEY=
N8N_DATA_PATH=./data/n8n
N8N_USER=admin
N8N_PASSWORD=

# =============================================================================
# LOGGING
# =============================================================================
# Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO
LOG_FILE=logs/am-corp.log

# =============================================================================
# ENVIRONMENT
# Values: development, test, production
# docker-compose.yml forces this to production at runtime.
# =============================================================================
ENVIRONMENT=development

# =============================================================================
# AGENT HANDOFFS
# Seconds between outgoing and incoming handoff messages in #agent-chat.
# Increase for more dramatic pacing, decrease to speed up the scan pipeline.
# =============================================================================
HANDOFF_PAUSE_SECONDS=3.0

# =============================================================================
# RATE LIMITING
# =============================================================================
MAX_CONCURRENT_SCANS=1
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600

# =============================================================================
# SECURITY — Keep ENABLE_SCOPE_VERIFICATION=true on any real network.
# .gov and .mil are hardcoded-blocked regardless of this setting.
# =============================================================================
ENABLE_SCOPE_VERIFICATION=true
# Comma-separated pre-approved domains. Empty = manual approval required each time.
ALLOWED_TARGETS=
ENABLE_AUDIT_LOG=true
AUDIT_LOG_FILE=logs/audit.log

# =============================================================================
# THOUGHTS CHANNEL
# Verbosity levels: minimal | normal | verbose | all
# =============================================================================
THOUGHTS_CHANNEL_ENABLED=true
THOUGHTS_VERBOSITY=normal

# =============================================================================
# PERSONALITY SYSTEM
# =============================================================================
PERSONALITY_DIR=config/personalities
PERSONALITY_EVOLUTION_ENABLED=true

# =============================================================================
# CASUAL CHAT
# Agents periodically discuss security topics in #general
# =============================================================================
CASUAL_CHAT_ENABLED=true

# =============================================================================
# TIMEZONE
# =============================================================================
TZ=UTC
```

---

## Setup Steps

1. Create the file:
   ```bash
   cp docs/ENV_TEMPLATE.md /dev/null   # template is docs-only
   touch .env
   ```
   Or copy the block above directly into `.env`.

2. Fill in all **Required** values at minimum.

3. Confirm `.env` is ignored:
   ```bash
   grep '\.env' .gitignore
   ```

4. Run preflight to validate before starting:
   ```bash
   podman-compose build
   podman exec am-corp-bot python src/preflight.py --quick
   ```
