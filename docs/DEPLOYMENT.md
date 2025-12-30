# AM-Corp Deployment Guide

## Overview

This guide covers deploying AM-Corp to production environments. AM-Corp is designed for self-hosted deployment to maintain control over security tooling.

---

## Deployment Options

| Option | Complexity | Use Case |
|--------|------------|----------|
| **Single Server** | Low | Solo operator, small workload |
| **Docker Compose** | Medium | Team use, moderate workload |
| **Kubernetes** | High | Enterprise, high availability |

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB SSD | 50+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- Docker 24.0+
- Docker Compose 2.20+
- Linux (Ubuntu 22.04+ recommended)
- Domain name (optional, for webhooks)

---

## Docker Compose Deployment

### 1. Clone Repository

```bash
git clone https://github.com/your-org/am-corp.git
cd am-corp
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

Set production values:

```bash
ENVIRONMENT=production
LOG_LEVEL=INFO
ENABLE_AUDIT_LOG=true
ENABLE_SCOPE_VERIFICATION=true
```

### 3. Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  n8n:
    image: n8nio/n8n:latest
    container_name: am-corp-n8n
    restart: unless-stopped
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=${N8N_USER}
      - N8N_BASIC_AUTH_PASSWORD=${N8N_PASSWORD}
      - N8N_SECURE_COOKIE=true
    volumes:
      - n8n_data:/home/node/.n8n
    networks:
      - am-corp-network

  orchestrator:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: am-corp-orchestrator
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    depends_on:
      - n8n
    networks:
      - am-corp-network

  discord-bot:
    build:
      context: ./bot
      dockerfile: Dockerfile
    container_name: am-corp-discord
    restart: unless-stopped
    env_file:
      - .env
    depends_on:
      - orchestrator
    networks:
      - am-corp-network

volumes:
  n8n_data:

networks:
  am-corp-network:
    driver: bridge
```

### 4. Build and Deploy

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Verify running
docker-compose ps

# Check logs
docker-compose logs -f
```

---

## Dockerfile Examples

### Orchestrator Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN apt-get update && apt-get install -y wget \
    && wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY config/ ./config/

# Create non-root user
RUN useradd -m -u 1000 amcorp
RUN chown -R amcorp:amcorp /app
USER amcorp

CMD ["python", "src/main.py"]
```

---

## Production Hardening

### Security Checklist

- [ ] Change all default passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Set up log rotation
- [ ] Enable audit logging
- [ ] Configure backup strategy
- [ ] Set resource limits

### Firewall Configuration

```bash
# UFW example
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp  # If using reverse proxy
ufw enable
```

### Docker Security

```yaml
# docker-compose.yml additions
services:
  orchestrator:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW  # For nmap
    read_only: true
    tmpfs:
      - /tmp
    mem_limit: 2g
    cpus: 2
```

---

## Reverse Proxy Setup (Optional)

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/am-corp
server {
    listen 443 ssl http2;
    server_name am-corp.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/am-corp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/am-corp.yourdomain.com/privkey.pem;

    # n8n
    location /n8n/ {
        proxy_pass http://localhost:5678/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Webhook endpoint
    location /webhook/ {
        proxy_pass http://localhost:5678/webhook/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Monitoring

### Health Checks

```yaml
# docker-compose.yml
services:
  orchestrator:
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Logging Configuration

```python
# config/logging.py
LOGGING_CONFIG = {
    'version': 1,
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/am-corp.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
        },
        'audit': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/audit.log',
            'maxBytes': 52428800,  # 50MB
            'backupCount': 10,
        }
    }
}
```

### Metrics (Optional)

```yaml
# Prometheus metrics endpoint
services:
  orchestrator:
    environment:
      - ENABLE_METRICS=true
      - METRICS_PORT=9090
    ports:
      - "9090:9090"
```

---

## Backup Strategy

### What to Backup

| Data | Location | Frequency |
|------|----------|-----------|
| n8n workflows | Docker volume | Daily |
| Configuration | `/app/config/` | On change |
| Logs | `/app/logs/` | Weekly archive |
| Audit logs | `/app/logs/audit.log` | Daily |

### Backup Script

```bash
#!/bin/bash
# scripts/backup.sh

BACKUP_DIR="/backups/am-corp/$(date +%Y-%m-%d)"
mkdir -p $BACKUP_DIR

# Backup n8n data
docker run --rm -v am-corp_n8n_data:/data -v $BACKUP_DIR:/backup \
    alpine tar czf /backup/n8n-data.tar.gz -C /data .

# Backup config and logs
tar czf $BACKUP_DIR/config.tar.gz ./config/
tar czf $BACKUP_DIR/logs.tar.gz ./logs/

# Cleanup old backups (keep 30 days)
find /backups/am-corp -type d -mtime +30 -exec rm -rf {} +
```

---

## Updating

### Update Procedure

```bash
# 1. Pull latest changes
git pull origin main

# 2. Stop services
docker-compose down

# 3. Backup current state
./scripts/backup.sh

# 4. Rebuild images
docker-compose build --no-cache

# 5. Start services
docker-compose up -d

# 6. Verify health
docker-compose ps
docker-compose logs -f --tail=100
```

### Rollback

```bash
# If update fails
docker-compose down
git checkout <previous-tag>
docker-compose up -d
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| n8n not starting | Port conflict | Check port 5678 availability |
| Discord bot offline | Invalid token | Verify DISCORD_BOT_TOKEN |
| Scans failing | Tool not found | Rebuild Docker image |
| Memory issues | Resource limits | Increase container limits |

### Debug Mode

```bash
# Run with debug logging
docker-compose run --rm -e LOG_LEVEL=DEBUG orchestrator
```

### Container Shell Access

```bash
# Access running container
docker-compose exec orchestrator /bin/bash

# Check tool availability
nmap --version
nuclei --version
```

---

## Environment-Specific Configuration

### Development

```bash
ENVIRONMENT=development
LOG_LEVEL=DEBUG
ENABLE_SCOPE_VERIFICATION=false  # For testing
MAX_CONCURRENT_SCANS=1
```

### Staging

```bash
ENVIRONMENT=staging
LOG_LEVEL=INFO
ENABLE_SCOPE_VERIFICATION=true
ALLOWED_TARGETS=staging-targets.txt
```

### Production

```bash
ENVIRONMENT=production
LOG_LEVEL=WARNING
ENABLE_SCOPE_VERIFICATION=true
ENABLE_AUDIT_LOG=true
MAX_CONCURRENT_SCANS=3
```

