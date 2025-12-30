# AM-Corp Security Documentation

## Overview

AM-Corp handles sensitive security operations. This document outlines security controls, best practices, and responsible use guidelines.

---

## Security Principles

| Principle | Implementation |
|-----------|----------------|
| **Least Privilege** | Agents only have access to tools they need |
| **Defense in Depth** | Multiple validation layers before execution |
| **Audit Everything** | All actions logged for accountability |
| **Fail Secure** | On error, deny action rather than allow |

---

## Responsible Use Policy

### Authorized Testing Only

⚠️ **CRITICAL**: AM-Corp is designed for authorized security testing only.

Before running any scan:
1. ✅ Obtain written authorization from target owner
2. ✅ Define and document scope boundaries
3. ✅ Verify target is in scope before each scan
4. ✅ Maintain records of all testing activities

### Prohibited Activities

- ❌ Scanning targets without authorization
- ❌ Exploitation of discovered vulnerabilities
- ❌ Data exfiltration or theft
- ❌ Denial of service attacks
- ❌ Bypassing scope restrictions

---

## Access Control

### Discord Access Levels

| Role | Permissions |
|------|-------------|
| **Admin** | Full access, configuration changes |
| **Operator** | Run scans, view results |
| **Viewer** | View results only |

### Implementation

```python
# Example: Role-based command validation
ALLOWED_COMMANDS = {
    "admin": ["scan", "config", "audit", "shutdown"],
    "operator": ["scan", "status", "report"],
    "viewer": ["status", "report"]
}
```

---

## Input Validation

### Target Validation

All targets are validated before scanning:

```python
def validate_target(target: str) -> bool:
    """
    Validates target is authorized for scanning.
    
    Checks:
    1. Target format is valid (domain, IP, CIDR)
    2. Target is in allowed scope
    3. Target is not in blocklist
    4. Rate limits are not exceeded
    """
    pass
```

### Command Validation

| Check | Description |
|-------|-------------|
| Format | Command follows expected syntax |
| Permissions | User has required role |
| Scope | Target is authorized |
| Rate Limit | User hasn't exceeded limits |

---

## Scope Management

### Defining Scope

Scope is defined in environment configuration:

```bash
# .env
ALLOWED_TARGETS=example.com,*.example.com,192.168.1.0/24
```

### Scope Verification

Every scan request is verified:

```
1. Parse target from command
2. Check target against ALLOWED_TARGETS
3. If not in allowed list → require manual approval
4. Log scope verification result
```

### Blocklist

Internal blocklist prevents scanning of:
- Government domains (.gov, .mil)
- Critical infrastructure
- Known sensitive targets
- Internal network ranges (unless explicitly allowed)

---

## Secrets Management

### DO NOT

- ❌ Commit secrets to version control
- ❌ Log API keys or tokens
- ❌ Hardcode credentials in source
- ❌ Share `.env` files

### DO

- ✅ Use `.env` files (git-ignored)
- ✅ Use environment variables
- ✅ Rotate keys regularly
- ✅ Use secrets manager in production

### Secret Rotation Schedule

| Secret | Rotation Frequency |
|--------|-------------------|
| Discord Bot Token | On compromise only |
| API Keys | Quarterly |
| n8n API Key | Monthly |
| Database passwords | Quarterly |

---

## Audit Logging

### What Gets Logged

| Event | Data Captured |
|-------|---------------|
| Commands | User, command, target, timestamp |
| Scans | Start/end time, target, results summary |
| Errors | Error type, context, stack trace |
| Auth | Login attempts, permission checks |

### Log Format

```json
{
  "timestamp": "2025-12-30T10:00:00Z",
  "event_type": "scan_initiated",
  "user_id": "123456789",
  "username": "operator1",
  "target": "example.com",
  "command": "scan full",
  "request_id": "uuid-v4",
  "ip_address": "redacted"
}
```

### Log Retention

| Environment | Retention |
|-------------|-----------|
| Development | 7 days |
| Production | 90 days |
| Audit logs | 1 year |

---

## Data Handling

### Sensitive Data Classification

| Classification | Examples | Handling |
|----------------|----------|----------|
| **Critical** | Credentials, private keys | Never store, immediate redaction |
| **High** | Vulnerabilities, exploits | Encrypted storage, limited access |
| **Medium** | Scan results, configs | Standard protection |
| **Low** | Public information | Normal handling |

### Data Redaction

Sensitive data is automatically redacted from logs and Discord messages:

```python
REDACTION_PATTERNS = [
    r'password[=:]\S+',
    r'api[_-]?key[=:]\S+',
    r'token[=:]\S+',
    r'secret[=:]\S+',
]
```

---

## Network Security

### Outbound Connections

| Destination | Purpose | Required |
|-------------|---------|----------|
| Discord API | Bot communication | Yes |
| Gemini API | LLM inference | Yes |
| Target systems | Scanning | Yes |
| Shodan API | Reconnaissance | Optional |

### Firewall Rules (Production)

```bash
# Allow outbound
-A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
-A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP (for targets)

# Scanning ports (as needed)
-A OUTPUT -p tcp --dport 1-65535 -j ACCEPT  # Full port range

# Block unnecessary inbound
-A INPUT -p tcp --dport 22 -j ACCEPT  # SSH (restricted IPs)
-A INPUT -j DROP  # Default deny
```

---

## Tool Security

### Sandboxing

Security tools run in isolated environments:

```yaml
# docker-compose.yml
services:
  scanner:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW  # Required for Nmap
    read_only: true
```

### Tool Allowlist

Only approved tools can be executed:

```python
ALLOWED_TOOLS = [
    "nmap",
    "nuclei",
    "httpx",
    "subfinder",
]
```

---

## Incident Response

### Security Incident Types

| Type | Severity | Response |
|------|----------|----------|
| Unauthorized scan detected | Critical | Immediate shutdown |
| Credential exposure | Critical | Rotate all secrets |
| Rate limit abuse | High | Temporary ban |
| Agent malfunction | Medium | Disable agent, investigate |

### Response Procedure

1. **Detect** - Automated monitoring or manual report
2. **Contain** - Stop affected components
3. **Investigate** - Review logs and impact
4. **Remediate** - Fix root cause
5. **Report** - Document incident and lessons learned

---

## Vulnerability Disclosure

### Reporting Security Issues

If you discover a security vulnerability in AM-Corp:

1. **DO NOT** create a public GitHub issue
2. Email security concerns to: [security@your-domain.com]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | 24 hours |
| Initial assessment | 72 hours |
| Fix development | 7-30 days |
| Public disclosure | After fix deployed |

---

## Compliance Considerations

### Relevant Standards

| Standard | Relevance |
|----------|-----------|
| NIST CSF | Security framework guidance |
| OWASP | Secure development practices |
| PTES | Penetration testing methodology |
| Local laws | Authorized testing requirements |

### Legal Notice

This tool is provided for **authorized security testing only**. Users are responsible for:
- Obtaining proper authorization
- Complying with applicable laws
- Following responsible disclosure practices

The developers assume no liability for unauthorized use.

