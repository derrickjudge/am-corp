"""
Narration bridge: CrewAI callbacks → Discord.

HOW CREWAI CALLBACKS WORK:
  CrewAI calls step_callback(step_output) after every agent reasoning
  step. step_output is a CrewAI AgentFinish or similar object — its
  string representation is the agent's most recent thought/action log.

  task_callback(task_output) fires when a Task completes. task_output
  contains the agent's final answer for that task.

WHY A QUEUE:
  Callbacks are called synchronously from CrewAI's worker thread.
  Discord posting is async (requires await). Bridging them directly
  would deadlock. Instead:
    - Callbacks push text onto an asyncio.Queue (thread-safe via
      loop.call_soon_threadsafe).
    - An async drainer coroutine reads from the queue and posts to
      Discord. The drainer runs on the bot's event loop alongside
      everything else.

USAGE:
  1. Call setup_narration(loop, agent_id) before starting the crew.
     This returns (step_cb, task_cb) to pass into the Agent.
  2. Call start_drainer(loop) once to launch the background drainer.
  3. The drainer runs until you call stop_drainer().
"""

import asyncio
from typing import Callable

from src.utils.logging import get_logger

logger = get_logger(__name__)

# Single shared queue for all narration messages
_narration_queue: asyncio.Queue | None = None
_drainer_task: asyncio.Task | None = None


def _get_queue() -> asyncio.Queue:
    global _narration_queue
    if _narration_queue is None:
        _narration_queue = asyncio.Queue()
    return _narration_queue


def setup_narration(
    loop: asyncio.AbstractEventLoop,
    agent_id: str,
) -> tuple[Callable, Callable]:
    """
    Build the step and task callbacks for a CrewAI Agent.

    Returns (step_callback, task_callback) ready to be passed directly
    into the Agent constructor.

    Args:
        loop:     The bot's running event loop.
        agent_id: Used to label thoughts channel messages correctly.
    """
    queue = _get_queue()

    def step_callback(step_output) -> None:
        """
        Called by CrewAI after every reasoning step.

        step_output can be various CrewAI types; str() gives the text.
        We truncate to 800 chars — thoughts channel is for reasoning
        transparency, not full dumps.
        """
        text = str(step_output).strip()
        if not text:
            return
        message = {"type": "thought", "agent_id": agent_id, "text": text[:800]}
        loop.call_soon_threadsafe(queue.put_nowait, message)

    def task_callback(task_output) -> None:
        """
        Called by CrewAI when a Task completes.

        Posts a summary to thoughts and triggers the handoff sequence.
        """
        text = str(task_output).strip()
        if not text:
            return
        message = {"type": "task_done", "agent_id": agent_id, "text": text[:1200]}
        loop.call_soon_threadsafe(queue.put_nowait, message)

    return step_callback, task_callback


async def _drain(loop: asyncio.AbstractEventLoop) -> None:
    """
    Async coroutine that reads from the narration queue and posts to Discord.

    Runs indefinitely until cancelled. One message per iteration to
    avoid flooding Discord with rapid-fire posts.
    """
    from src.discord_bot.thoughts import post_thought

    queue = _get_queue()

    while True:
        try:
            message = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break

        try:
            agent_id = message["agent_id"]
            text = message["text"]

            if message["type"] in ("thought", "task_done"):
                await post_thought(
                    agent_id=agent_id,
                    thought=text,
                    thought_type="reasoning" if message["type"] == "thought" else "summary",
                )
        except Exception as e:
            logger.error("Narration drainer error", error=str(e))

        queue.task_done()


def start_drainer(loop: asyncio.AbstractEventLoop) -> None:
    """Launch the narration drainer as a background task on the event loop."""
    global _drainer_task

    async def _launch():
        global _drainer_task
        _drainer_task = asyncio.create_task(_drain(loop))

    loop.call_soon_threadsafe(asyncio.ensure_future, _launch())


def stop_drainer() -> None:
    """Cancel the drainer task (call when the crew finishes)."""
    if _drainer_task and not _drainer_task.done():
        _drainer_task.cancel()
