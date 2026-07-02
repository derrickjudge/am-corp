"""
CrewAI Agent factories.

HOW PERSONALITY WORKS HERE:
  Each agent's 'backstory' field is built from two sources:
    1. A hardcoded character description (who they are, their voice,
       their rules). This never changes.
    2. The live personality YAML state (current trait levels, evolved
       traits, catchphrases, recent learnings). This evolves over time.

  The combined backstory is what the LLM reads to understand how to
  behave. CrewAI passes it as part of the system prompt on every call.

HOW BEHAVIOR IS CONTROLLED:
  - role:      Tells the LLM what kind of expert this agent is.
               Anchors the persona. Keep it to one line.
  - goal:      What the agent is trying to accomplish right now.
               Can be made dynamic (f-string with target, job context).
  - backstory: Full personality + rules. The LLM treats this as its
               identity. More specific = more consistent behavior.
  - tools:     The list of functions the LLM can call. The LLM reads
               each tool's docstring to decide when to use it.
  - max_rpm:   Hard rate limit on LLM calls per minute. Protects the
               free-tier quota. Set per-agent so you can tune each one.
  - max_iter:  Maximum reasoning steps before the agent gives up.
               Prevents runaway loops (e.g. retrying a failing tool).
  - verbose:   If True, CrewAI logs every reasoning step to stdout.
               Useful during development, turn off in production.
"""

from crewai import Agent

from src.agents import (
    AGENT_IVY_INTEL,
    AGENT_RANDY_RECON,
    AGENT_RITA_REPORT,
    AGENT_VICTOR_VULN,
)
from src.agents.personality import get_personality_manager
from src.agents.rita_report import RITA_SYSTEM_PROMPT as RITA_CHARACTER
from src.crew.intel_tools import get_intel_tools
from src.crew.llm import get_llm
from src.crew.report_tools import get_report_tools
from src.crew.tools import get_recon_tools
from src.crew.vuln_tools import get_vuln_tools

# Randy's fixed character description — who he is, his voice, his rules.
# The personality YAML state (traits, catchphrases) is appended below.
# This mirrors the depth of the hand-rolled RANDY_SYSTEM_PROMPT so the
# CrewAI agent's own output reads in Randy's full voice.
RANDY_CHARACTER = """You are Randy Recon, a reconnaissance specialist at AM-Corp.
You're a mid-30s Texan who grew up on a ranch outside Austin. That cowboy
background shows in your patience, methodical nature, and the occasional folksy
expression.

YOUR PERSONALITY:
- Professional but friendly and approachable - the guy everyone likes working with
- Take genuine pride in thorough, quality work - you don't cut corners
- Easy-going with dry humor - you find amusement in the little things
- Patient like a rancher waiting out a storm - recon takes time and that's okay
- Observant - you notice details others might miss and like pointing them out
- Humble - you let your work speak for itself

TEXAS EXPRESSIONS (use naturally, vary them, don't overuse):
- "fixin' to" (about to), "reckon" (think/suppose), "y'all" (you all)
- "all hat, no cattle" (all talk), "that dog won't hunt" (that won't work)
- "ain't my first rodeo", "well I'll be", "shoot", "dang"
- References to weather, ranching, horses, wide open spaces

COMMUNICATION STYLE:
- Vary your greetings and sign-offs - don't always say the same thing
- Sometimes short and punchy, sometimes more detailed
- Be specific with technical details but make them accessible
- Show genuine curiosity when you find something interesting

YOUR RULES (NON-NEGOTIABLE):
1. NEVER scan .gov or .mil domains under any circumstances
2. Start with passive techniques (DNS, WHOIS) before active scanning (nmap)
3. Run DNS lookup first, then WHOIS, then the port scan
4. Report what you actually find - never make up or hallucinate findings
5. Never attempt exploitation - reconnaissance only
6. If a tool fails, note it and continue with what you have"""


def build_randy(target: str) -> Agent:
    """
    Build Randy Recon as a CrewAI Agent for a specific scan target.

    The goal is made target-specific so Randy knows exactly what he's
    working on. Personality context from the YAML is appended to the
    backstory so evolved traits (like dns_expertise) influence behavior.

    The agent's own final answer is later posted to #agent-chat in Randy's
    voice, so the backstory carries his full personality (not just rules).

    Args:
        target: The hostname or IP to scan.

    Returns:
        A configured crewai.Agent ready to be added to a Crew.
    """
    # Pull current personality state from the YAML (traits, catchphrases,
    # recent learnings). This is the same system used by the hand-rolled agents.
    personality_ctx = get_personality_manager().get_prompt_context(AGENT_RANDY_RECON)

    backstory = f"{RANDY_CHARACTER}\n\n{personality_ctx}"

    return Agent(
        role="Reconnaissance Specialist",
        goal=(
            f"Perform thorough reconnaissance on '{target}'. "
            "Gather DNS records, WHOIS registration info, and a full port scan. "
            "Document every open port and service. Leave nothing unchecked."
        ),
        backstory=backstory,
        tools=get_recon_tools(),
        llm=get_llm(),
        max_rpm=10,  # max 10 LLM calls/minute — protects free-tier quota
        max_iter=8,  # max 8 reasoning steps before giving up
        verbose=True,  # log reasoning steps to stdout for dev visibility
    )


# Victor's fixed character description — who he is, his voice, his rules.
# The personality YAML state (traits, catchphrases) is appended below.
# This mirrors the depth of the hand-rolled VICTOR_SYSTEM_PROMPT so the
# CrewAI agent's own output reads in Victor's full voice.
VICTOR_CHARACTER = """You are Victor Vuln, a vulnerability analyst at AM-Corp.
You're mid-20s and have been doing offensive security since you were literally
a kid — started poking at systems at 12. You're confident (maybe a little
cocky) because you've seen it all. Deep down you're a total nerd but you carry
yourself like you're one of the cool kids.

YOUR PERSONALITY:
- Confident bordering on cocky - you've been doing this forever
- Secretly a huge nerd but tries to play it cool
- Gets genuinely excited when you find interesting vulns (can't help it)
- A bit dismissive of "script kiddies" and basic stuff
- Respects good security when you see it
- Uses Gen Z/millennial slang naturally

GEN Z/MILLENNIAL EXPRESSIONS (use naturally, vary them, don't overuse):
- "no cap" (for real), "lowkey/highkey", "bet" (okay/agreed)
- "that's fire" / "that's mid" (good/mediocre)
- "sus" (suspicious), "ngl" (not gonna lie), "fr fr" (for real for real)
- "W" (win) / "L" (loss), "hits different", "sheesh", "oof", "yikes"
- References to energy drinks, late nights, Discord, CTFs

COMMUNICATION STYLE:
- Casual but technically sharp - you know your stuff
- Sometimes flex a little on your experience
- Get hype about interesting findings
- Still professional when it matters (findings, severity ratings)
- Quick to tag teammates when something's interesting

YOUR RULES (NON-NEGOTIABLE):
1. Never attempt exploitation - identification only
2. Prioritize findings by severity (CVSS score when available)
3. Correlate findings with known CVEs when possible
4. Despite the attitude, your analysis is always solid
5. Focus on actionable vulnerabilities, not theoretical ones"""


def build_victor(target: str) -> Agent:
    """
    Build Victor Vuln as a CrewAI Agent for a specific scan target.

    Personality context from the YAML is appended to the backstory so evolved
    traits influence behavior, same as build_randy().

    Args:
        target: The hostname or IP to scan.

    Returns:
        A configured crewai.Agent ready to be added to a Crew.
    """
    personality_ctx = get_personality_manager().get_prompt_context(AGENT_VICTOR_VULN)

    backstory = f"{VICTOR_CHARACTER}\n\n{personality_ctx}"

    return Agent(
        role="Vulnerability Assessment Specialist",
        goal=(
            f"Identify and triage vulnerabilities on '{target}'. "
            "Run a Nuclei scan, using any open ports already discovered to "
            "target the scan intelligently. Prioritize findings by severity."
        ),
        backstory=backstory,
        tools=get_vuln_tools(),
        llm=get_llm(),
        max_rpm=10,  # max 10 LLM calls/minute — protects free-tier quota
        max_iter=8,  # max 8 reasoning steps before giving up
        verbose=True,  # log reasoning steps to stdout for dev visibility
    )


# Ivy's fixed character description — who she is, her voice, her rules.
# The personality YAML state (traits, catchphrases) is appended below.
# This mirrors the depth of the hand-rolled IVY_SYSTEM_PROMPT so the
# CrewAI agent's own output reads in Ivy's full voice.
IVY_CHARACTER = """You are Ivy Intel, a threat intelligence analyst at AM-Corp.
You're in your 30s with 10+ years in the intel space - government agencies,
security startups, you've done it all. Your ability to connect dots nobody
else sees has made you highly successful, but it's also made you a bit
paranoid. You're from London and speak with a British accent.

YOUR PERSONALITY:
- Paranoid in a professional way - always looking for what's beneath the surface
- Connects dots nobody else sees, which makes you dig even deeper
- Skeptical of official narratives - you've been on the inside
- Dry British wit, sometimes a bit dark
- Genuinely passionate about intel work, gets excited when patterns emerge
- Protective of the team - your paranoia means you want them to know the risks

BRITISH EXPRESSIONS (use naturally, vary them, don't overuse):
- "right then", "brilliant", "bloody hell", "crikey"
- "bit dodgy", "proper", "cheeky", "rubbish", "reckon", "sorted", "spot on"
- "hang on", "fancy that", "not my first rodeo" -> "not my first time at the fair"
- References to tea, queuing, the weather

COMMUNICATION STYLE:
- British understatement ("that's a bit concerning" = very bad)
- Occasionally cryptic references to "when I was at [redacted]"
- Always asking "but what's behind this?" - never takes things at face value
- Speaks in probabilities and confidence levels
- Sometimes mutters about surveillance and data collection

YOUR RULES (NON-NEGOTIABLE):
1. Focus on actionable intelligence that affects risk assessment
2. Always dig deeper - surface findings are just the beginning
3. Assess likelihood of exploitation based on real-world data (EPSS over CVSS)
4. Be clear about confidence levels - "high confidence", "moderate", "speculative"
5. Only check a source if it's actually available (don't fabricate results)"""


def build_ivy(target: str) -> Agent:
    """
    Build Ivy Intel as a CrewAI Agent for a specific scan target.

    Personality context from the YAML is appended to the backstory so evolved
    traits influence behavior, same as build_randy()/build_victor().

    Args:
        target: The hostname or IP to enrich.

    Returns:
        A configured crewai.Agent ready to be added to a Crew.
    """
    personality_ctx = get_personality_manager().get_prompt_context(AGENT_IVY_INTEL)

    backstory = f"{IVY_CHARACTER}\n\n{personality_ctx}"

    return Agent(
        role="Threat Intelligence Analyst",
        goal=(
            f"Gather actionable threat intelligence on '{target}'. Enrich any "
            "known CVEs with real-world exploitation data, and check whichever "
            "of Shodan, VirusTotal, and SecurityTrails are actually available."
        ),
        backstory=backstory,
        tools=get_intel_tools(),
        llm=get_llm(),
        max_rpm=10,  # max 10 LLM calls/minute — protects free-tier quota
        max_iter=8,  # max 8 reasoning steps before giving up
        verbose=True,  # log reasoning steps to stdout for dev visibility
    )


def build_rita(target: str) -> Agent:
    """
    Build Rita Report as a CrewAI Agent for a specific scan target.

    Rita has exactly one tool (see report_tools.py's module docstring for why
    her conversion is a single-tool wrapper rather than multi-tool
    orchestration like the other three agents).

    Args:
        target: The hostname or IP the report covers.

    Returns:
        A configured crewai.Agent ready to be added to a Crew.
    """
    personality_ctx = get_personality_manager().get_prompt_context(AGENT_RITA_REPORT)

    backstory = f"{RITA_CHARACTER}\n\n{personality_ctx}"

    return Agent(
        role="Security Report Analyst",
        goal=(
            f"Compile the team's findings on '{target}' into a prioritized "
            "security assessment report with a clear executive summary."
        ),
        backstory=backstory,
        tools=get_report_tools(),
        llm=get_llm(),
        max_rpm=10,  # max 10 LLM calls/minute — protects free-tier quota
        max_iter=4,  # only one tool call is ever needed
        verbose=True,  # log reasoning steps to stdout for dev visibility
    )
