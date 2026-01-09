# AM-Corp Development Setup Guide

## Prerequisites

Before setting up AM-Corp, ensure you have the following installed:

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Podman | 4.0+ | Container runtime (preferred for macOS) |
| podman-compose | 1.0+ | Multi-container orchestration |
| Python | 3.12+ | CrewAI orchestration |
| Git | 2.40+ | Version control |

> **Note:** Use Podman instead of Docker/Rancher Desktop on macOS with corporate security tools (e.g., Netskope). Docker containers may be blocked due to SSL interception issues.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/am-corp.git
cd am-corp

# 2. Copy environment template
cp .env.example .env

# 3. Configure environment variables (see below)
nano .env

# 4. Install Python dependencies (includes podman-compose)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# 5. Build and start with Podman
podman-compose build
podman-compose up -d

# 6. Verify running
podman-compose ps
podman-compose logs -f
```

---

## Environment Configuration

Copy `.env.example` to `.env` and configure the following:

### Required Variables

```bash
# Discord Configuration
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_GUILD_ID=your_guild_id

# Gemini API
GEMINI_API_KEY=your_gemini_api_key

# n8n Configuration
N8N_BASE_URL=http://localhost:5678
N8N_API_KEY=your_n8n_api_key
```

### Optional Variables

```bash
# External APIs (optional, enhances capabilities)
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR

# Rate Limiting
MAX_CONCURRENT_SCANS=1
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
```

---

## Component Setup

### 1. Container Services

```bash
# Start all services with Podman
podman-compose up -d

# View running containers
podman-compose ps

# Check logs
podman-compose logs -f
```

**Initial n8n Setup:**
1. Create admin account on first access
2. Import workflows from `/workflows/` directory
3. Configure credentials (Discord webhook, etc.)

### 2. Discord Bot Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create new application "AM-Corp"
3. Navigate to Bot → Add Bot
4. Enable required intents:
   - Message Content Intent
   - Server Members Intent
5. Copy bot token to `.env`
6. Generate OAuth2 invite URL with permissions:
   - Send Messages
   - Embed Links
   - Read Message History
   - Add Reactions
7. Invite bot to your server

### 3. CrewAI Setup

```bash
# Activate virtual environment
source venv/bin/activate

# Install CrewAI and dependencies
pip install crewai crewai-tools

# Verify installation
python -c "from crewai import Crew; print('CrewAI installed successfully')"
```

### 4. Security Tools Setup

```bash
# Install Nmap
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates

# Verify tools
nmap --version
nuclei --version
```

---

## Project Structure

```
am-corp/
├── .env.example          # Environment template
├── .env                   # Local environment (git-ignored)
├── docker-compose.yml     # Docker services
├── requirements.txt       # Python dependencies
├── docs/
│   ├── am-corp_PRD.md    # Product Requirements
│   ├── ARCHITECTURE.md    # System architecture
│   ├── SETUP.md          # This file
│   ├── AGENTS.md         # Agent specifications
│   ├── SECURITY.md       # Security documentation
│   ├── DEPLOYMENT.md     # Production deployment
│   └── phases/           # Phase breakdowns
├── src/
│   ├── main.py           # Entry point
│   ├── agents/           # Agent definitions
│   ├── tools/            # Custom CrewAI tools
│   ├── workflows/        # n8n workflow exports
│   └── utils/            # Shared utilities
├── tests/                # Test suite
└── scripts/              # Utility scripts
```

---

## Running the Application

### Development Mode

```bash
# Terminal 1: Start Podman services
podman-compose up

# Terminal 2: Run orchestrator with hot reload
source venv/bin/activate
python src/main.py --dev
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_agents.py
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| n8n not starting | Check Docker daemon is running |
| Discord bot offline | Verify bot token and intents |
| Nmap permission denied | Run with sudo or configure capabilities |
| Gemini rate limit | Check free tier limits, implement backoff |

### Logs

```bash
# Container logs
podman-compose logs -f

# Application logs
tail -f logs/am-corp.log

# Debug mode
LOG_LEVEL=DEBUG python src/main.py
```

---

## Next Steps

1. Review [AGENTS.md](./AGENTS.md) for agent configuration
2. Review [SECURITY.md](./SECURITY.md) for security best practices
3. Import n8n workflows from `/workflows/`
4. Run first test scan against authorized target

