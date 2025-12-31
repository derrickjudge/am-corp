"""
AM-Corp Discord Bot

Conversational interface for the AM-Corp security team. This module handles:
- Bot connection and event handling
- Command parsing (!scan, !status, etc.)
- Webhook utilities for agent messages
- Rich embed formatting for Discord

The Discord bot serves as the human interface layer, while agents post their
collaboration and findings through webhooks to maintain conversation flow.

Module Structure:
    bot.py          - Main bot class with connection handling
    commands.py     - Command handlers (!scan, !status, !abort, etc.)
    webhooks.py     - Utilities for posting agent messages
    embeds.py       - Rich embed formatters for findings and reports
    validators.py   - Input validation and scope checking

Agent Personas (defined in src/agents/):
    🔍 Randy Recon  - Reconnaissance Specialist
    ⚠️ Victor Vuln  - Vulnerability Analyst
    🧠 Ivy Intel    - Threat Intelligence Analyst
    📊 Rita Report  - Security Report Analyst
"""
