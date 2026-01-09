# Environment Configuration Template

Copy the contents below to a `.env` file in the project root.

**⚠️ NEVER commit your `.env` file to version control!**

---

```bash
# AM-Corp Environment Configuration
# Copy this content to .env in the project root
# NEVER commit .env to version control

# =============================================================================
# DISCORD CONFIGURATION
# =============================================================================
# Bot token from Discord Developer Portal
DISCORD_BOT_TOKEN=

# Your Discord server (guild) ID
DISCORD_GUILD_ID=

# Channel IDs (right-click channel → Copy Channel ID)
DISCORD_CHANNEL_COMMANDS=
DISCORD_CHANNEL_AGENT_CHAT=
DISCORD_CHANNEL_RESULTS=
DISCORD_CHANNEL_ALERTS=

# Webhook URLs (create webhook in each channel: Edit Channel → Integrations → Webhooks)
# Agent chat webhook - for agent reasoning and status updates
DISCORD_WEBHOOK_AGENT_CHAT=

# Results webhook - for final scan outputs
DISCORD_WEBHOOK_RESULTS=

# Alerts webhook - for errors and warnings
DISCORD_WEBHOOK_ALERTS=

# =============================================================================
# LLM CONFIGURATION
# =============================================================================
# Gemini API key from Google AI Studio
GEMINI_API_KEY=

# Model selection (default: gemini-2.5-flash)
GEMINI_MODEL=gemini-2.5-flash

# =============================================================================
# N8N CONFIGURATION
# =============================================================================
# n8n instance URL
N8N_BASE_URL=http://localhost:5678

# n8n API key (generate in n8n settings)
N8N_API_KEY=

# =============================================================================
# EXTERNAL APIS (OPTIONAL)
# =============================================================================
# Shodan API key for enhanced reconnaissance
SHODAN_API_KEY=

# VirusTotal API key for threat intelligence
VIRUSTOTAL_API_KEY=

# SecurityTrails API key for DNS intelligence
SECURITYTRAILS_API_KEY=

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================
# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# Log file path
LOG_FILE=logs/am-corp.log

# Environment: development, test, production
ENVIRONMENT=development

# =============================================================================
# RATE LIMITING
# =============================================================================
# Maximum concurrent scans
MAX_CONCURRENT_SCANS=1

# API rate limit (requests per window)
RATE_LIMIT_REQUESTS=100

# Rate limit window in seconds
RATE_LIMIT_WINDOW=3600

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
# Enable scope verification (recommended: true)
ENABLE_SCOPE_VERIFICATION=true

# Allowed target domains (comma-separated, empty = manual approval required)
ALLOWED_TARGETS=

# Enable audit logging
ENABLE_AUDIT_LOG=true

# Audit log file path
AUDIT_LOG_FILE=logs/audit.log

# =============================================================================
# DOCKER CONFIGURATION (used by docker-compose)
# =============================================================================
# n8n data persistence path
N8N_DATA_PATH=./data/n8n

# n8n authentication
N8N_USER=admin
N8N_PASSWORD=

# Timezone
TZ=UTC
```

---

## How to Use

1. Create a `.env` file in the project root:
   ```bash
   touch .env
   ```

2. Copy the template above into the file

3. Fill in your values

4. Verify `.env` is in `.gitignore`:
   ```bash
   echo ".env" >> .gitignore
   ```

---

## Getting API Keys

| Service | Where to Get |
|---------|--------------|
| Discord Bot Token | [Discord Developer Portal](https://discord.com/developers/applications) |
| Gemini API Key | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| Shodan API Key | [Shodan Account](https://account.shodan.io/) |
| VirusTotal API Key | [VirusTotal API](https://www.virustotal.com/gui/my-apikey) |

