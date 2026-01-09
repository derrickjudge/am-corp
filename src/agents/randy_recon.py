"""
Randy Recon - Reconnaissance Specialist

Randy's a mid-30s Texan who grew up on a ranch outside Austin. That cowboy 
background shows in his patience, methodical nature, and occasional folksy 
expression. He takes pride in thorough, quality work but keeps things easy-going.

Tools: dig (DNS), whois (registration), nmap (port scanning)
"""

import asyncio
import json
import random
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types


# Fallback message pools for variety when Gemini is unavailable
OPENING_FALLBACKS = [
    "Alright partner, saddlin' up to scout out {target}. I'll be using {tools} for this job.",
    "Howdy! Fixin' to run some recon on {target}. Got my {tools} ready to go.",
    "Well now, let's see what we can find on {target}. Pullin' out the {tools}.",
    "Time to do some scoutin' on {target}. I'll run {tools} and holler when I find something.",
    "Alright y'all, {target} is on the docket. Let me fire up {tools} and get to work.",
    "Got {target} in my sights. Gonna use {tools} to see what's out there.",
]

DNS_FALLBACKS = [
    "DNS lookup done. Found {count} records for {target}.",
    "Well I'll be, DNS shows {count} records for {target}.",
    "Got the DNS results back - {count} records on {target}.",
    "DNS is lookin' interesting. {count} records for {target}.",
    "Alright, pulled {count} DNS records from {target}.",
]

WHOIS_FALLBACKS = [
    "WHOIS lookup complete for {target}.",
    "Got the registration info on {target}.",
    "WHOIS came back for {target}. Let's see what we got.",
    "Domain registration details are in for {target}.",
    "Pulled the WHOIS data on {target}.",
]

PORTSCAN_START_FALLBACKS = [
    "Movin' on to the port scan now...",
    "Time for the active scanning. Here we go...",
    "Alright, fixin' to scan some ports...",
    "Now for the fun part - port scanning...",
    "Passive recon done, time to knock on some doors...",
]

PORTSCAN_DONE_FALLBACKS = [
    "Port scan complete. Found {count} open ports.",
    "Well now, {count} ports are answerin' on this one.",
    "Scan's done - {count} open ports found.",
    "Got {count} ports showing as open.",
    "Finished the port scan. {count} services are listenin'.",
]

NO_PORTS_FALLBACKS = [
    "Port scan done on {target}. No open ports found on the common ports I checked.",
    "Scanned {target} but came up empty on the usual ports. Might be well-locked or filtered.",
    "No open ports on {target} from what I can see. Either tight security or different ports.",
    "Well, {target} ain't showin' much. No common ports open.",
]

SUMMARY_OPENERS = [
    "All done with the roundup on {target}!",
    "Recon complete on {target}. Here's what I found:",
    "Finished scoutin' out {target}. Let me break it down:",
    "That's a wrap on {target}. Here's the full picture:",
    "Done with {target}. Here's everything I turned up:",
    "Alright, got all the intel on {target}:",
]

SUMMARY_CLOSERS = [
    "Passin' my findings to the team. 🤠",
    "That's what I got. Y'all take it from here.",
    "Over to you, team.",
    "Happy to dig deeper if y'all need anything else.",
    "Let me know if you want me to look into anything specific.",
    "Holler if you need more details on any of this.",
]


def _random_fallback(pool: list[str], **kwargs) -> str:
    """Pick a random fallback message and format it."""
    return random.choice(pool).format(**kwargs)

from src.agents import AGENT_RANDY_RECON, AGENTS
from src.discord_bot.agent_bots import get_agent_manager, get_victor_mention
from src.tools.recon_tools import (
    ToolResult,
    dig_lookup,
    nmap_scan,
    whois_lookup,
    get_available_tools,
)
from src.utils.config import settings
from src.utils.logging import audit_log, get_logger

logger = get_logger(__name__)


RANDY_SYSTEM_PROMPT = """You are Randy Recon, a reconnaissance specialist at AM-Corp. You're a mid-30s Texan who grew up on a ranch outside Austin. That cowboy background shows in your patience, methodical nature, and the occasional folksy expression.

YOUR PERSONALITY:
- Professional but friendly and approachable - the guy everyone likes working with
- Take genuine pride in thorough, quality work - you don't cut corners
- Easy-going with dry humor - you find amusement in the little things
- Patient like a rancher waiting out a storm - recon takes time and you're okay with that
- Observant - you notice details others might miss and like pointing them out
- Humble - you let your work speak for itself

TEXAS EXPRESSIONS (use naturally, vary them, don't overuse):
- "fixin' to" (about to), "reckon" (think/suppose), "y'all" (you all)
- "all hat, no cattle" (all talk), "that dog won't hunt" (that won't work)
- "rode hard and put away wet" (worn out), "slower than molasses"
- "ain't my first rodeo", "happy as a clam at high tide"
- "well I'll be", "shoot", "dang", "howdy"
- References to weather, ranching, horses, wide open spaces

COMMUNICATION STYLE:
- Vary your greetings and sign-offs - don't always say the same thing
- Sometimes short and punchy, sometimes more detailed
- Occasionally crack a dry joke or make an observation
- Reference the time of day, weather metaphors, or ranch life naturally
- Be specific with technical details but make them accessible
- Show genuine curiosity when you find something interesting

RULES (NON-NEGOTIABLE):
1. NEVER scan .gov or .mil domains under any circumstances
2. Only scan targets that have been explicitly authorized
3. Start with passive techniques (DNS, WHOIS) before active scanning (nmap)
4. Report what you actually find - never make up or hallucinate findings
5. Never attempt exploitation - reconnaissance only

IMPORTANT: Vary your responses! Don't start every message the same way. Mix up your expressions and personality. Sometimes be brief, sometimes more chatty. Keep it fresh."""


@dataclass
class ReconResult:
    """Results from a full reconnaissance operation."""
    
    target: str
    dns_result: ToolResult | None = None
    whois_result: ToolResult | None = None
    nmap_result: ToolResult | None = None
    summary: str = ""
    raw_findings: dict[str, Any] = field(default_factory=dict)


class RandyRecon:
    """
    Randy Recon agent - handles reconnaissance operations.
    
    Uses Gemini for reasoning and personality, real tools for data gathering.
    """
    
    def __init__(self) -> None:
        self.agent_id = AGENT_RANDY_RECON
        self.name = AGENTS[AGENT_RANDY_RECON]["name"]
        self.emoji = AGENTS[AGENT_RANDY_RECON]["emoji"]
        self._client: genai.Client | None = None
        self._agent_manager = None
    
    def _get_client(self) -> genai.Client:
        """Get or initialize the Gemini client."""
        if self._client is None:
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY not configured")
            
            self._client = genai.Client(api_key=settings.gemini_api_key)
            logger.info("Gemini client initialized for Randy Recon (SSL verification disabled)")
        
        return self._client
    
    async def _post_message(self, message: str) -> None:
        """Post a message as Randy to Discord."""
        manager = get_agent_manager()
        bot = manager.get_bot(self.agent_id)
        
        if bot:
            await bot.send_message(message, channel="agent_chat")
        else:
            # Fallback to webhook
            from src.discord_bot.webhooks import get_webhook_client
            client = get_webhook_client()
            await client.post_agent_message(self.agent_id, message, "agent_chat")
    
    async def _generate_message(self, prompt: str, fallback: str = "") -> str:
        """
        Generate a message using Randy's personality via Gemini.
        
        Args:
            prompt: The prompt to send to Gemini
            fallback: Message to use if generation fails (NOT the prompt!)
        """
        try:
            logger.info(f"[GEMINI] Initializing client...")
            client = self._get_client()
            logger.info(f"[GEMINI] Sending request to Gemini API...")
            logger.debug(f"[GEMINI] Prompt preview: {prompt[:100]}...")
            
            # Use the new google.genai API
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=RANDY_SYSTEM_PROMPT,
                ),
            )
            
            logger.info(f"[GEMINI] Response received from API")
            
            # Check if response has text
            if response and response.text:
                generated_text = response.text.strip()
                logger.info(f"[GEMINI] Success - got {len(generated_text)} chars")
                logger.debug(f"[GEMINI] Response preview: {generated_text[:100]}...")
                return generated_text
            else:
                logger.warning("[GEMINI] Empty response from API, using fallback")
                logger.info(f"[FALLBACK] Randy using pre-written message (empty API response)")
                return fallback if fallback else "Working on it..."
            
        except Exception as e:
            error_msg = str(e)
            
            # Check for quota errors
            if "429" in error_msg or "quota" in error_msg.lower():
                logger.warning(f"[GEMINI] Quota exceeded, using fallback")
            elif "SSL" in error_msg or "certificate" in error_msg.lower():
                logger.error(f"[GEMINI] SSL/Certificate error: {error_msg[:300]}")
            else:
                logger.error(
                    f"[GEMINI] Generation failed",
                    error=error_msg[:300],
                    error_type=type(e).__name__,
                )
            
            # Return fallback, NOT the prompt
            logger.info(f"[FALLBACK] Randy using pre-written message due to: {type(e).__name__}")
            return fallback if fallback else "Working on it..."
    
    async def run_recon(self, target: str, verbose: bool = False) -> ReconResult:
        """
        Run full reconnaissance on a target.
        
        This is the main entry point for recon operations.
        Posts updates to Discord as work progresses.
        
        Args:
            target: Target to scan
            verbose: If True, output additional technical details
        """
        logger.info(f"Starting reconnaissance on {target}", agent=self.agent_id)
        
        # Verbose mode header
        if verbose:
            await self._post_message(
                f"**[VERBOSE MODE]** Starting recon on `{target}`\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        
        audit_log(
            action="recon_started",
            user="randy_recon",
            target=target,
            result="started",
        )
        
        result = ReconResult(target=target)
        
        # Check available tools
        available = get_available_tools()
        if not available:
            await self._post_message(
                f"Well shoot, I don't have any of my tools available on this system. "
                f"Need dig, whois, or nmap installed to do recon work."
            )
            return result
        
        # Opening message
        opening = await self._generate_message(
            f"You're starting reconnaissance on {target}. Generate a short, "
            f"friendly opening message (1-2 sentences) announcing you're starting the job. "
            f"Mention what tools you'll use: {', '.join(available)}. Vary your greeting!",
            fallback=_random_fallback(OPENING_FALLBACKS, target=target, tools=', '.join(available))
        )
        await self._post_message(opening)
        
        # Phase 1: DNS Lookup (passive)
        if "dig" in available:
            if verbose:
                await self._post_message(
                    "**Phase 1: DNS Lookup**\n"
                    "```\n"
                    f"dig +short {target} A/AAAA/MX/NS/TXT/CNAME\n"
                    "```"
                )
            
            await asyncio.sleep(1)  # Natural pacing
            result.dns_result = await dig_lookup(target)
            
            if result.dns_result.success and result.dns_result.parsed_data.get("records"):
                records = result.dns_result.parsed_data.get("records", {})
                record_count = sum(len(v) for v in records.values())
                
                # Build detailed fallback with actual data
                dns_details = []
                for rtype, values in records.items():
                    for val in values:
                        dns_details.append(f"  • {rtype}: `{val}`")
                dns_detail_str = "\n".join(dns_details) if dns_details else "  (none)"
                
                dns_summary = await self._generate_message(
                    f"You just completed DNS lookup on {target}. Here are the results:\n"
                    f"{json.dumps(records, indent=2)}\n\n"
                    f"Generate a conversational update (2-3 sentences) about what you found. "
                    f"Highlight anything interesting. Use your Texas personality - vary your expressions!",
                    fallback=f"{_random_fallback(DNS_FALLBACKS, count=record_count, target=target)}\n{dns_detail_str}"
                )
                await self._post_message(dns_summary)
        
        # Phase 2: WHOIS Lookup (passive)
        if "whois" in available:
            if verbose:
                # Extract base domain for whois
                from src.tools.recon_tools import _extract_base_domain
                base_domain = _extract_base_domain(target)
                await self._post_message(
                    "**Phase 2: WHOIS Lookup**\n"
                    "```\n"
                    f"whois {base_domain}\n"
                    "```"
                )
            
            await asyncio.sleep(1.5)
            result.whois_result = await whois_lookup(target)
            
            if result.whois_result.success and result.whois_result.parsed_data:
                whois_data = result.whois_result.parsed_data
                
                # Build detailed fallback with actual WHOIS data
                whois_details = []
                if whois_data.get("registrar"):
                    whois_details.append(f"  • Registrar: `{whois_data['registrar']}`")
                if whois_data.get("creation_date"):
                    whois_details.append(f"  • Created: `{whois_data['creation_date']}`")
                if whois_data.get("expiry_date"):
                    whois_details.append(f"  • Expires: `{whois_data['expiry_date']}`")
                if whois_data.get("name_servers"):
                    ns_list = ", ".join(whois_data["name_servers"][:3])
                    whois_details.append(f"  • Name Servers: `{ns_list}`")
                if whois_data.get("registrant_org"):
                    whois_details.append(f"  • Organization: `{whois_data['registrant_org']}`")
                
                whois_detail_str = "\n".join(whois_details) if whois_details else "  (limited info available)"
                
                whois_summary = await self._generate_message(
                    f"You just completed WHOIS lookup on {target}. Here are the key details:\n"
                    f"{json.dumps(whois_data, indent=2)}\n\n"
                    f"Generate a conversational update (2-3 sentences) about the domain registration. "
                    f"Note the registrar, age of domain, or anything notable. Vary your response!",
                    fallback=f"{_random_fallback(WHOIS_FALLBACKS, target=target)}\n{whois_detail_str}"
                )
                await self._post_message(whois_summary)
        
        # Phase 3: Port Scan (active - requires confirmation already done)
        if "nmap" in available:
            await asyncio.sleep(1)
            
            if verbose:
                await self._post_message(
                    "**Phase 3: Port Scan (Active)**\n"
                    "```\n"
                    f"nmap -sT -T4 --top-ports 500 -sV -n -Pn --open {target}\n"
                    "```\n"
                    "Flags: TCP connect, aggressive timing, top 500 ports, service detection"
                )
            else:
                scanning_msg = await self._generate_message(
                    f"You're about to start the port scan on {target}. "
                    f"Generate a short message (1 sentence) saying you're moving to active scanning. Vary it!",
                    fallback=_random_fallback(PORTSCAN_START_FALLBACKS)
                )
                await self._post_message(scanning_msg)
            
            result.nmap_result = await nmap_scan(target)
            
            if result.nmap_result.success:
                ports = result.nmap_result.parsed_data.get("ports", [])
                
                if ports:
                    # Build detailed port list
                    port_details = []
                    for p in ports:
                        service = p.get("service", "unknown")
                        port_num = p.get("port", "?")
                        version = p.get("version", "")
                        version_str = f" ({version})" if version else ""
                        port_details.append(f"  • Port `{port_num}`: {service}{version_str}")
                    port_detail_str = "\n".join(port_details)
                    
                    victor_mention = get_victor_mention()
                    nmap_summary = await self._generate_message(
                        f"You completed port scan on {target}. Open ports found:\n"
                        f"{json.dumps(ports, indent=2)}\n\n"
                        f"Generate a conversational update (2-3 sentences) about the open ports. "
                        f"Mention services you recognize and tag {victor_mention} if anything looks interesting. Vary your style!",
                        fallback=f"{_random_fallback(PORTSCAN_DONE_FALLBACKS, count=len(ports))}\n{port_detail_str}\n\n{victor_mention}, might want to take a look at these."
                    )
                else:
                    nmap_summary = await self._generate_message(
                        f"You completed port scan on {target} but found no open ports "
                        f"on the common ports you checked. Generate a brief update about this.",
                        fallback=_random_fallback(NO_PORTS_FALLBACKS, target=target)
                    )
                
                await self._post_message(nmap_summary)
        
        # Final Summary
        await asyncio.sleep(1)
        result.raw_findings = self._compile_findings(result)
        
        # Build the summary
        findings = result.raw_findings
        dns_records = findings.get("dns", {})
        whois_info = findings.get("whois", {})
        ports = findings.get("ports", [])
        
        # Build the bulleted findings section (always included)
        bullet_lines = [f"\n**{target}**"]
        
        # DNS records
        for rtype, values in dns_records.items():
            for val in values:
                bullet_lines.append(f"- {rtype}: `{val}`")
        
        # WHOIS info (key details only)
        if whois_info.get("registrar"):
            bullet_lines.append(f"- Registrar: {whois_info['registrar']}")
        
        # Ports
        if ports:
            for p in ports:
                service = p.get("service", "unknown")
                port_num = p.get("port", "?")
                bullet_lines.append(f"- Port {port_num}: {service}")
        else:
            bullet_lines.append("- Open Ports: none")
        
        bullet_section = "\n".join(bullet_lines)
        
        # Build fallback summary (conversational intro + bullets)
        dns_count = sum(len(v) for v in dns_records.values())
        port_count = len(ports)
        
        # Conversational summary with variety
        whois_phrases = [
            "got some WHOIS info",
            "pulled some registration details",
            "found the domain registration info",
            "snagged the WHOIS data",
        ]
        no_whois_phrases = [
            "couldn't rustle up any WHOIS information",
            "WHOIS came up empty",
            "no WHOIS luck on this one",
            "registration info wasn't available",
        ]
        whois_status = random.choice(whois_phrases) if whois_info else random.choice(no_whois_phrases)
        
        port_status = f"found {port_count} open port{'s' if port_count != 1 else ''}" if ports else "didn't find any open ports on the common services"
        
        opener = _random_fallback(SUMMARY_OPENERS, target=target)
        
        fallback_intro = (
            f"🔍 {opener}\n\n"
            f"Rounded up {dns_count} DNS record{'s' if dns_count != 1 else ''}, {whois_status}, "
            f"and {port_status}."
        )
        
        if ports:
            victor_mention = get_victor_mention()
            victor_tags = [
                f" {victor_mention}, might want to take a look at those open ports.",
                f" {victor_mention}, got some services here that could use your attention.",
                f" Hey {victor_mention}, some open ports for ya to poke at.",
                f" {victor_mention}, reckon you'll want to check these out.",
            ]
            fallback_intro += random.choice(victor_tags)
        
        fallback_intro += f"\n\n{random.choice(SUMMARY_CLOSERS)}"
        
        detailed_fallback = f"{fallback_intro}\n\n{bullet_section}"
        
        # Generate with AI or use fallback
        summary_prompt = self._build_summary_prompt(target, result, bullet_section)
        result.summary = await self._generate_message(
            summary_prompt,
            fallback=detailed_fallback
        )
        await self._post_message(result.summary)
        
        audit_log(
            action="recon_completed",
            user="randy_recon",
            target=target,
            result="success",
            findings=result.raw_findings,
        )
        
        logger.info(
            f"Reconnaissance completed on {target}",
            agent=self.agent_id,
            dns_records=len(result.raw_findings.get("dns", {})),
            open_ports=len(result.raw_findings.get("ports", [])),
        )
        
        return result
    
    def _compile_findings(self, result: ReconResult) -> dict[str, Any]:
        """Compile all findings into a structured format."""
        findings: dict[str, Any] = {
            "target": result.target,
            "dns": {},
            "whois": {},
            "ports": [],
        }
        
        if result.dns_result and result.dns_result.success:
            findings["dns"] = result.dns_result.parsed_data.get("records", {})
        
        if result.whois_result and result.whois_result.success:
            findings["whois"] = result.whois_result.parsed_data
        
        if result.nmap_result and result.nmap_result.success:
            findings["ports"] = result.nmap_result.parsed_data.get("ports", [])
        
        return findings
    
    def _build_summary_prompt(self, target: str, result: ReconResult, bullet_section: str) -> str:
        """Build the prompt for generating the final summary."""
        findings = result.raw_findings
        
        dns_count = sum(len(v) for v in findings.get("dns", {}).values())
        port_count = len(findings.get("ports", []))
        whois_available = bool(findings.get("whois"))
        
        victor_mention = get_victor_mention()
        
        # Pick a random style for this summary
        styles = [
            "casual and brief",
            "detailed and thorough",
            "with some dry humor",
            "focused on the interesting bits",
            "straight to the point",
        ]
        style = random.choice(styles)
        
        prompt = f"""You've completed reconnaissance on {target}. Here's what you found:

- DNS Records: {dns_count} total
- WHOIS Info: {"Available" if whois_available else "Not available"}  
- Open Ports: {port_count}

Raw data:
{json.dumps(findings, indent=2)}

Generate a final summary with TWO parts:

PART 1: A conversational summary (2-3 sentences) that:
- Mentions what you found (DNS records, WHOIS status, ports)
- Notes anything interesting, unusual, or concerning in the data
- If there are open ports, tag {victor_mention} to take a look
- Use your Texas personality but VARY your expressions - don't always say "partner" or "saddlin' up"
- Style for this one: {style}

PART 2: End your message with this exact bulleted list (already formatted for you):
{bullet_section}

IMPORTANT: 
- Your response must end with the bulleted list above. Don't modify the bullet format.
- Be creative with your opening - don't always start the same way!
- Add a brief sign-off after the bullets."""
        
        return prompt


# Singleton instance
_randy: RandyRecon | None = None


def get_randy() -> RandyRecon:
    """Get the Randy Recon agent singleton."""
    global _randy
    if _randy is None:
        _randy = RandyRecon()
    return _randy


async def run_recon(target: str, verbose: bool = False) -> ReconResult:
    """Convenience function to run recon on a target."""
    randy = get_randy()
    return await randy.run_recon(target, verbose=verbose)

