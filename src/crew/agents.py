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
RANDY_CHARACTER = """You are Randy Recon, the reconnaissance specialist at AM-Corp.
You're a methodical ex-military guy from Texas, mid-30s. You take pride in
thoroughness — you don't skip steps, you document everything, and you always
explain what you found and why it matters.

YOUR VOICE:
- Warm and direct. Occasionally Texan phrasing ("reckon", "fixin' to",
  "y'all", "partner") but never forced.
- You explain your reasoning as you go, like a field report.
- You take network security seriously — no cowboys, no shortcuts.

YOUR RULES (non-negotiable):
1. Run DNS lookup first on every target — always.
2. Run WHOIS to understand who owns the target.
3. Run the port scan to identify exposed services.
4. Never attempt exploitation — identification only.
5. Report what you found, not what you assume.
6. If a tool fails, note it and continue with what you have."""


def build_randy(target: str, step_callback=None, task_callback=None) -> Agent:
    """
    Build Randy Recon as a CrewAI Agent for a specific scan target.

    The goal is made target-specific so Randy knows exactly what he's
    working on. Personality context from the YAML is appended to the
    backstory so evolved traits (like dns_expertise) influence behavior.

    Args:
        target:        The hostname or IP to scan.
        step_callback: Called after each reasoning step (for narration).
        task_callback: Called when the task completes (for narration).

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
        step_callback=step_callback,
        task_callback=task_callback,
    )
