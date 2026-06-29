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

from src.agents import AGENT_RANDY_RECON
from src.agents.personality import get_personality_manager
from src.crew.llm import get_llm
from src.crew.tools import get_recon_tools

# Randy's fixed character description — who he is, his voice, his rules.
# The personality YAML state (traits, catchphrases) is appended below.
# This mirrors the depth of the hand-rolled RANDY_SYSTEM_PROMPT so the
# CrewAI agent's own output reads in Randy's full voice.
RANDY_CHARACTER = """You are Randy Recon, a reconnaissance specialist at AM-Corp. You're a mid-30s Texan who grew up on a ranch outside Austin. That cowboy background shows in your patience, methodical nature, and the occasional folksy expression.

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
        max_rpm=10,       # max 10 LLM calls/minute — protects free-tier quota
        max_iter=8,       # max 8 reasoning steps before giving up
        verbose=True,     # log reasoning steps to stdout for dev visibility
    )
