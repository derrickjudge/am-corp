#!/usr/bin/env python3
"""
AM-Corp Preflight Check

Verifies all required tools, connectivity, and configuration before starting the bot.
Run this to diagnose issues or as part of the container startup.

Usage:
    python src/preflight.py           # Run all checks
    python src/preflight.py --quick   # Skip slow network tests
    python src/preflight.py --json    # Output as JSON for automation
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class CheckStatus(str, Enum):
    """Status of a preflight check."""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CheckResult:
    """Result of a single preflight check."""
    name: str
    status: CheckStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class PreflightReport:
    """Complete preflight check report."""
    timestamp: str
    hostname: str
    all_passed: bool
    critical_passed: bool
    checks: list[CheckResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "all_passed": self.all_passed,
            "critical_passed": self.critical_passed,
            "summary": self.summary,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "details": c.details,
                    "duration_ms": c.duration_ms,
                }
                for c in self.checks
            ],
        }


class PreflightChecker:
    """Runs preflight checks for AM-Corp."""

    def __init__(self, quick_mode: bool = False):
        self.quick_mode = quick_mode
        self.results: list[CheckResult] = []

    def _run_command(self, cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -2, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)

    def _add_result(
        self,
        name: str,
        status: CheckStatus,
        message: str,
        details: dict = None,
        duration_ms: float = 0.0,
    ):
        """Add a check result."""
        self.results.append(
            CheckResult(
                name=name,
                status=status,
                message=message,
                details=details or {},
                duration_ms=duration_ms,
            )
        )

    # =========================================================================
    # TOOL CHECKS
    # =========================================================================

    def check_tool_nmap(self) -> CheckResult:
        """Check if nmap is installed and working."""
        import time
        start = time.time()
        
        path = shutil.which("nmap")
        if not path:
            self._add_result(
                "tool.nmap",
                CheckStatus.FAIL,
                "nmap not found in PATH",
                {"required": True},
            )
            return
        
        code, stdout, stderr = self._run_command(["nmap", "--version"])
        if code == 0:
            version = stdout.split("\n")[0] if stdout else "unknown"
            self._add_result(
                "tool.nmap",
                CheckStatus.PASS,
                f"nmap available: {version}",
                {"path": path, "version": version},
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            self._add_result(
                "tool.nmap",
                CheckStatus.FAIL,
                f"nmap found but failed: {stderr}",
                {"path": path, "error": stderr},
            )

    def check_tool_nuclei(self) -> None:
        """Check if nuclei is installed and has templates."""
        import time
        start = time.time()
        
        path = shutil.which("nuclei")
        if not path:
            self._add_result(
                "tool.nuclei",
                CheckStatus.FAIL,
                "nuclei not found in PATH",
                {"required": True},
            )
            return
        
        code, stdout, stderr = self._run_command(["nuclei", "-version"])
        if code != 0:
            self._add_result(
                "tool.nuclei",
                CheckStatus.FAIL,
                f"nuclei found but failed: {stderr}",
                {"path": path},
            )
            return
        
        # Parse version from output
        version = "unknown"
        for line in (stdout + stderr).split("\n"):
            if "Version" in line or "Engine" in line:
                version = line.strip()
                break
        
        # Check for templates (nuclei stores them in ~/.local/share/nuclei)
        templates_dirs = [
            Path.home() / ".local" / "share" / "nuclei",
            Path.home() / ".config" / "nuclei" / "templates",
            Path("/app/nuclei-templates"),
        ]
        template_count = 0
        templates_dir = None
        for tdir in templates_dirs:
            if tdir.exists():
                count = len(list(tdir.rglob("*.yaml")))
                if count > template_count:
                    template_count = count
                    templates_dir = tdir
        
        if template_count == 0:
            self._add_result(
                "tool.nuclei",
                CheckStatus.WARN,
                f"nuclei available but no templates found",
                {"path": path, "version": version, "templates": 0},
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            self._add_result(
                "tool.nuclei",
                CheckStatus.PASS,
                f"nuclei available with {template_count} templates",
                {"path": path, "version": version, "templates": template_count},
                duration_ms=(time.time() - start) * 1000,
            )

    def check_tool_dig(self) -> None:
        """Check if dig is installed."""
        import time
        start = time.time()
        
        path = shutil.which("dig")
        if not path:
            self._add_result(
                "tool.dig",
                CheckStatus.FAIL,
                "dig not found in PATH (install dnsutils)",
                {"required": True},
            )
            return
        
        code, stdout, stderr = self._run_command(["dig", "-v"])
        version = stderr.split("\n")[0] if stderr else stdout.split("\n")[0]
        
        self._add_result(
            "tool.dig",
            CheckStatus.PASS,
            f"dig available: {version}",
            {"path": path, "version": version},
            duration_ms=(time.time() - start) * 1000,
        )

    def check_tool_whois(self) -> None:
        """Check if whois is installed."""
        import time
        start = time.time()
        
        path = shutil.which("whois")
        if not path:
            self._add_result(
                "tool.whois",
                CheckStatus.FAIL,
                "whois not found in PATH",
                {"required": True},
            )
            return
        
        self._add_result(
            "tool.whois",
            CheckStatus.PASS,
            "whois available",
            {"path": path},
            duration_ms=(time.time() - start) * 1000,
        )

    # =========================================================================
    # CONFIGURATION CHECKS
    # =========================================================================

    def check_env_discord(self) -> None:
        """Check Discord configuration."""
        token = os.getenv("DISCORD_BOT_TOKEN", "")
        guild = os.getenv("DISCORD_GUILD_ID", "")
        commands_channel = os.getenv("DISCORD_CHANNEL_COMMANDS", "")
        
        if not token:
            self._add_result(
                "config.discord.token",
                CheckStatus.FAIL,
                "DISCORD_BOT_TOKEN not set",
                {"required": True},
            )
        else:
            # Mask token for display
            masked = token[:10] + "..." + token[-4:] if len(token) > 20 else "***"
            self._add_result(
                "config.discord.token",
                CheckStatus.PASS,
                f"DISCORD_BOT_TOKEN configured ({masked})",
                {"length": len(token)},
            )
        
        if not guild:
            self._add_result(
                "config.discord.guild",
                CheckStatus.WARN,
                "DISCORD_GUILD_ID not set (optional but recommended)",
            )
        else:
            self._add_result(
                "config.discord.guild",
                CheckStatus.PASS,
                f"DISCORD_GUILD_ID configured ({guild})",
            )
        
        if not commands_channel:
            self._add_result(
                "config.discord.commands_channel",
                CheckStatus.WARN,
                "DISCORD_CHANNEL_COMMANDS not set (bot will accept commands in any channel)",
            )
        else:
            self._add_result(
                "config.discord.commands_channel",
                CheckStatus.PASS,
                f"DISCORD_CHANNEL_COMMANDS configured ({commands_channel})",
            )

    def check_env_gemini(self) -> None:
        """Check Gemini API configuration."""
        api_key = os.getenv("GEMINI_API_KEY", "")
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        
        if not api_key:
            self._add_result(
                "config.gemini.api_key",
                CheckStatus.FAIL,
                "GEMINI_API_KEY not set (required for agent reasoning)",
                {"required": True},
            )
        else:
            masked = api_key[:8] + "..." if len(api_key) > 12 else "***"
            self._add_result(
                "config.gemini.api_key",
                CheckStatus.PASS,
                f"GEMINI_API_KEY configured ({masked})",
            )
        
        self._add_result(
            "config.gemini.model",
            CheckStatus.PASS,
            f"GEMINI_MODEL: {model}",
            {"model": model},
        )

    def check_env_webhooks(self) -> None:
        """Check webhook configuration."""
        webhooks = {
            "agent_chat": os.getenv("DISCORD_WEBHOOK_AGENT_CHAT", ""),
            "results": os.getenv("DISCORD_WEBHOOK_RESULTS", ""),
            "alerts": os.getenv("DISCORD_WEBHOOK_ALERTS", ""),
            "thoughts": os.getenv("DISCORD_WEBHOOK_THOUGHTS", ""),
            "general": os.getenv("DISCORD_WEBHOOK_GENERAL", ""),
        }
        
        configured = [k for k, v in webhooks.items() if v]
        missing = [k for k, v in webhooks.items() if not v]
        total = len(webhooks)
        
        if not configured:
            self._add_result(
                "config.webhooks",
                CheckStatus.WARN,
                "No webhooks configured (agents will use bot messages only)",
                {"configured": configured, "missing": missing},
            )
        elif missing:
            self._add_result(
                "config.webhooks",
                CheckStatus.PASS,
                f"{len(configured)}/{total} webhooks configured",
                {"configured": configured, "missing": missing},
            )
        else:
            self._add_result(
                "config.webhooks",
                CheckStatus.PASS,
                "All webhooks configured",
                {"configured": configured},
            )

    def check_env_casual_chat(self) -> None:
        """Check casual chat configuration for general channel."""
        general_channel = os.getenv("DISCORD_CHANNEL_GENERAL", "")
        general_webhook = os.getenv("DISCORD_WEBHOOK_GENERAL", "")
        casual_enabled = os.getenv("CASUAL_CHAT_ENABLED", "true").lower() == "true"
        
        if casual_enabled:
            if not general_channel and not general_webhook:
                self._add_result(
                    "config.casual_chat",
                    CheckStatus.WARN,
                    "Casual chat enabled but no general channel/webhook configured",
                    {"enabled": True, "channel": False, "webhook": False},
                )
            elif not general_webhook:
                self._add_result(
                    "config.casual_chat",
                    CheckStatus.WARN,
                    "Casual chat enabled but no general webhook (agents can't post)",
                    {"enabled": True, "channel": bool(general_channel), "webhook": False},
                )
            else:
                self._add_result(
                    "config.casual_chat",
                    CheckStatus.PASS,
                    "Casual chat configured",
                    {"enabled": True, "channel": bool(general_channel), "webhook": True},
                )
        else:
            self._add_result(
                "config.casual_chat",
                CheckStatus.PASS,
                "Casual chat disabled",
                {"enabled": False},
            )

    # =========================================================================
    # CONNECTIVITY CHECKS
    # =========================================================================

    async def check_connectivity_news_feeds(self) -> None:
        """Check news feed connectivity for casual chat."""
        if self.quick_mode:
            self._add_result(
                "connectivity.news_feeds",
                CheckStatus.SKIP,
                "Skipped in quick mode",
            )
            return
        
        import time
        start = time.time()
        
        # Check if casual chat is enabled
        casual_enabled = os.getenv("CASUAL_CHAT_ENABLED", "true").lower() == "true"
        if not casual_enabled:
            self._add_result(
                "connectivity.news_feeds",
                CheckStatus.SKIP,
                "Skipped - casual chat disabled",
            )
            return
        
        # Test Hacker News API (most reliable, free, no auth)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://hacker-news.firebaseio.com/v0/topstories.json"
                )
                if response.status_code == 200:
                    stories = response.json()
                    self._add_result(
                        "connectivity.news_feeds",
                        CheckStatus.PASS,
                        f"News feeds reachable ({len(stories)} HN stories)",
                        {"hacker_news": True, "story_count": len(stories)},
                        duration_ms=(time.time() - start) * 1000,
                    )
                else:
                    self._add_result(
                        "connectivity.news_feeds",
                        CheckStatus.WARN,
                        f"Hacker News returned {response.status_code}",
                        {"hacker_news": False},
                    )
        except Exception as e:
            self._add_result(
                "connectivity.news_feeds",
                CheckStatus.WARN,
                f"Cannot reach news feeds: {str(e)[:50]}",
                {"error": str(e)},
            )

    async def check_connectivity_discord(self) -> None:
        """Check Discord API connectivity."""
        if self.quick_mode:
            self._add_result(
                "connectivity.discord",
                CheckStatus.SKIP,
                "Skipped in quick mode",
            )
            return
        
        import time
        start = time.time()
        
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("https://discord.com/api/v10/gateway")
                if response.status_code == 200:
                    data = response.json()
                    self._add_result(
                        "connectivity.discord",
                        CheckStatus.PASS,
                        f"Discord API reachable",
                        {"gateway": data.get("url", "unknown")},
                        duration_ms=(time.time() - start) * 1000,
                    )
                else:
                    self._add_result(
                        "connectivity.discord",
                        CheckStatus.FAIL,
                        f"Discord API returned {response.status_code}",
                        {"status_code": response.status_code},
                    )
        except Exception as e:
            self._add_result(
                "connectivity.discord",
                CheckStatus.FAIL,
                f"Cannot reach Discord API: {str(e)}",
                {"error": str(e)},
            )

    async def check_connectivity_gemini(self) -> None:
        """Check Gemini API connectivity (if key configured)."""
        api_key = os.getenv("GEMINI_API_KEY", "")
        
        if not api_key:
            self._add_result(
                "connectivity.gemini",
                CheckStatus.SKIP,
                "Skipped - no API key configured",
            )
            return
        
        if self.quick_mode:
            self._add_result(
                "connectivity.gemini",
                CheckStatus.SKIP,
                "Skipped in quick mode",
            )
            return
        
        import time
        start = time.time()
        
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            
            # Try a simple model list to verify connectivity
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
                contents="Say 'OK' and nothing else.",
            )
            
            if response and response.text:
                self._add_result(
                    "connectivity.gemini",
                    CheckStatus.PASS,
                    "Gemini API reachable and responding",
                    {"response_length": len(response.text)},
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                self._add_result(
                    "connectivity.gemini",
                    CheckStatus.WARN,
                    "Gemini API reachable but empty response",
                )
        except Exception as e:
            self._add_result(
                "connectivity.gemini",
                CheckStatus.FAIL,
                f"Cannot reach Gemini API: {str(e)}",
                {"error": str(e)},
            )

    def check_connectivity_dns(self) -> None:
        """Check DNS resolution works."""
        if self.quick_mode:
            self._add_result(
                "connectivity.dns",
                CheckStatus.SKIP,
                "Skipped in quick mode",
            )
            return
        
        import time
        start = time.time()
        
        code, stdout, stderr = self._run_command(
            ["dig", "+short", "google.com", "A"],
            timeout=5,
        )
        
        if code == 0 and stdout.strip():
            ips = stdout.strip().split("\n")
            self._add_result(
                "connectivity.dns",
                CheckStatus.PASS,
                f"DNS resolution working ({len(ips)} IPs for google.com)",
                {"resolved_ips": ips},
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            self._add_result(
                "connectivity.dns",
                CheckStatus.FAIL,
                "DNS resolution failed",
                {"error": stderr},
            )

    # =========================================================================
    # FILE SYSTEM CHECKS
    # =========================================================================

    def check_filesystem_data(self) -> None:
        """Check data directory is writable."""
        data_dir = Path("/app/data") if Path("/app").exists() else Path("data")
        
        if not data_dir.exists():
            try:
                data_dir.mkdir(parents=True)
                self._add_result(
                    "filesystem.data",
                    CheckStatus.PASS,
                    f"Created data directory: {data_dir}",
                )
            except Exception as e:
                self._add_result(
                    "filesystem.data",
                    CheckStatus.FAIL,
                    f"Cannot create data directory: {e}",
                )
                return
        
        # Test write
        test_file = data_dir / ".preflight_test"
        try:
            test_file.write_text("test")
            test_file.unlink()
            self._add_result(
                "filesystem.data",
                CheckStatus.PASS,
                f"Data directory writable: {data_dir}",
            )
        except Exception as e:
            self._add_result(
                "filesystem.data",
                CheckStatus.FAIL,
                f"Data directory not writable: {e}",
            )

    def check_filesystem_logs(self) -> None:
        """Check logs directory is writable."""
        logs_dir = Path("/app/logs") if Path("/app").exists() else Path("logs")
        
        if not logs_dir.exists():
            try:
                logs_dir.mkdir(parents=True)
            except Exception as e:
                self._add_result(
                    "filesystem.logs",
                    CheckStatus.WARN,
                    f"Cannot create logs directory: {e}",
                )
                return
        
        # Test write
        test_file = logs_dir / ".preflight_test"
        try:
            test_file.write_text("test")
            test_file.unlink()
            self._add_result(
                "filesystem.logs",
                CheckStatus.PASS,
                f"Logs directory writable: {logs_dir}",
            )
        except Exception as e:
            self._add_result(
                "filesystem.logs",
                CheckStatus.WARN,
                f"Logs directory not writable: {e}",
            )

    def check_filesystem_personalities(self) -> None:
        """Check personalities directory."""
        personalities_dir = (
            Path("/app/config/personalities")
            if Path("/app").exists()
            else Path("config/personalities")
        )
        
        if not personalities_dir.exists():
            self._add_result(
                "filesystem.personalities",
                CheckStatus.WARN,
                f"Personalities directory does not exist: {personalities_dir}",
            )
            return
        
        yaml_files = list(personalities_dir.glob("*.yaml"))
        self._add_result(
            "filesystem.personalities",
            CheckStatus.PASS,
            f"Found {len(yaml_files)} personality files",
            {"files": [f.name for f in yaml_files]},
        )

    # =========================================================================
    # RUN ALL CHECKS
    # =========================================================================

    async def run_all(self) -> PreflightReport:
        """Run all preflight checks and return report."""
        import socket
        
        # Tool checks (synchronous)
        self.check_tool_nmap()
        self.check_tool_nuclei()
        self.check_tool_dig()
        self.check_tool_whois()
        
        # Config checks (synchronous)
        self.check_env_discord()
        self.check_env_gemini()
        self.check_env_webhooks()
        self.check_env_casual_chat()
        
        # Connectivity checks (async)
        await self.check_connectivity_discord()
        await self.check_connectivity_gemini()
        await self.check_connectivity_news_feeds()
        self.check_connectivity_dns()
        
        # Filesystem checks (synchronous)
        self.check_filesystem_data()
        self.check_filesystem_logs()
        self.check_filesystem_personalities()
        
        # Build report
        summary = {
            "pass": sum(1 for r in self.results if r.status == CheckStatus.PASS),
            "warn": sum(1 for r in self.results if r.status == CheckStatus.WARN),
            "fail": sum(1 for r in self.results if r.status == CheckStatus.FAIL),
            "skip": sum(1 for r in self.results if r.status == CheckStatus.SKIP),
        }
        
        # Critical checks are tools and required config
        critical_checks = [
            r for r in self.results
            if r.name.startswith("tool.") or r.details.get("required")
        ]
        critical_passed = all(r.status != CheckStatus.FAIL for r in critical_checks)
        
        return PreflightReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            hostname=socket.gethostname(),
            all_passed=summary["fail"] == 0,
            critical_passed=critical_passed,
            checks=self.results,
            summary=summary,
        )


def print_report(report: PreflightReport, use_json: bool = False) -> None:
    """Print the preflight report."""
    if use_json:
        print(json.dumps(report.to_dict(), indent=2))
        return
    
    # Header
    print("\n" + "=" * 60)
    print("AM-Corp Preflight Check Report")
    print("=" * 60)
    print(f"Timestamp: {report.timestamp}")
    print(f"Hostname:  {report.hostname}")
    print()
    
    # Status emoji mapping
    status_emoji = {
        CheckStatus.PASS: "✅",
        CheckStatus.WARN: "⚠️",
        CheckStatus.FAIL: "❌",
        CheckStatus.SKIP: "⏭️",
    }
    
    # Group checks by category
    categories = {}
    for check in report.checks:
        cat = check.name.split(".")[0]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)
    
    # Print by category
    for cat, checks in categories.items():
        print(f"\n📋 {cat.upper()}")
        print("-" * 40)
        for check in checks:
            emoji = status_emoji[check.status]
            name = check.name.split(".", 1)[1] if "." in check.name else check.name
            print(f"  {emoji} {name}: {check.message}")
            if check.duration_ms > 0:
                print(f"     ⏱️ {check.duration_ms:.0f}ms")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  ✅ Passed:  {report.summary['pass']}")
    print(f"  ⚠️ Warnings: {report.summary['warn']}")
    print(f"  ❌ Failed:  {report.summary['fail']}")
    print(f"  ⏭️ Skipped: {report.summary['skip']}")
    print()
    
    if report.critical_passed:
        print("🚀 CRITICAL CHECKS PASSED - Bot can start")
    else:
        print("🛑 CRITICAL CHECKS FAILED - Fix issues before starting")
    
    print("=" * 60 + "\n")


async def main():
    """Run preflight checks."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AM-Corp Preflight Check")
    parser.add_argument("--quick", action="store_true", help="Skip slow network tests")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--exit-code", action="store_true", help="Exit with code 1 if critical checks fail")
    args = parser.parse_args()
    
    checker = PreflightChecker(quick_mode=args.quick)
    report = await checker.run_all()
    
    print_report(report, use_json=args.json)
    
    if args.exit_code and not report.critical_passed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
