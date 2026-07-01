"""
Narration bridge: CrewAI sync tools -> async Discord channels.

WHY A QUEUE:
  CrewAI tools execute synchronously in a worker thread, but Discord
  posting is async (requires await on the bot's event loop). Bridging
  them directly would deadlock. Instead, sync code pushes typed messages
  onto an asyncio.Queue via loop.call_soon_threadsafe, and an async
  drainer coroutine reads them and posts to the right channel.

CHANNEL CONTRACT (see CLAUDE.md):
  - "thought"    -> #thoughts   (reasoning transparency, categorized)
  - "agent_chat" -> #agent-chat (personality-rich conversation)

  Data-driven analytical thoughts are pushed from tools (which know what
  they found). Personality-rich agent-chat messages are posted directly
  from run.py (which is already async) — they do not use this queue.
"""

import asyncio

from src.utils.logging import get_logger

logger = get_logger(__name__)

# Single shared queue for all narration messages
_narration_queue: "asyncio.Queue[dict] | None" = None
_drainer_task: "asyncio.Task | None" = None


def _get_queue() -> "asyncio.Queue[dict]":
    global _narration_queue
    if _narration_queue is None:
        _narration_queue = asyncio.Queue()
    return _narration_queue


def push_thought(
    loop: asyncio.AbstractEventLoop,
    agent_id: str,
    text: str,
    category: str = "reasoning",
    confidence: float | None = None,
) -> None:
    """
    Push a thought to #thoughts from a sync context (e.g. inside a CrewAI tool).

    Thread-safe: schedules the enqueue on the bot's event loop. Returns
    immediately so the tool is never blocked on Discord I/O.
    """
    text = (text or "").strip()
    if not text:
        return
    message = {
        "kind": "thought",
        "agent_id": agent_id,
        "text": text,
        "category": category,
        "confidence": confidence,
    }
    loop.call_soon_threadsafe(_get_queue().put_nowait, message)


def push_agent_chat(
    loop: asyncio.AbstractEventLoop,
    agent_id: str,
    text: str,
) -> None:
    """
    Push a structured per-phase update to #agent-chat from a sync context.

    Used by the recon tools to post bulleted findings in the agent's voice
    as each lookup completes. FIFO-ordered with thoughts via the shared queue.
    """
    text = (text or "").strip()
    if not text:
        return
    message = {"kind": "agent_chat", "agent_id": agent_id, "text": text}
    loop.call_soon_threadsafe(_get_queue().put_nowait, message)


async def _drain() -> None:
    """
    Read narration messages off the queue and post them to Discord.

    Runs until cancelled. One message per iteration keeps Discord posting
    paced and avoids rate-limit bursts.
    """
    from src.discord_bot.agent_bots import get_agent_manager
    from src.discord_bot.thoughts import post_thought

    queue = _get_queue()

    while True:
        try:
            message = await asyncio.wait_for(queue.get(), timeout=1.0)
        except TimeoutError:
            continue
        except asyncio.CancelledError:
            break

        try:
            if message["kind"] == "thought":
                await post_thought(
                    agent_id=message["agent_id"],
                    thought=message["text"],
                    confidence=message.get("confidence"),
                    category=message.get("category", "reasoning"),
                )
            elif message["kind"] == "agent_chat":
                await get_agent_manager().send_as_agent(
                    message["agent_id"], message["text"], channel="agent_chat"
                )
        except Exception as e:
            logger.error("Narration drainer error", error=str(e))

        queue.task_done()


def start_drainer(loop: asyncio.AbstractEventLoop) -> None:
    """Launch the narration drainer as a background task on the event loop."""

    def _launch() -> None:
        global _drainer_task
        if _drainer_task is None or _drainer_task.done():
            _drainer_task = asyncio.create_task(_drain())

    loop.call_soon_threadsafe(_launch)


async def flush(timeout: float = 5.0) -> None:
    """Wait until all queued thoughts have been posted (bounded by timeout)."""
    try:
        await asyncio.wait_for(_get_queue().join(), timeout=timeout)
    except TimeoutError:
        logger.warning("Narration flush timed out with messages still queued")


def stop_drainer() -> None:
    """Cancel the drainer task (call when the crew finishes)."""
    global _drainer_task
    if _drainer_task and not _drainer_task.done():
        _drainer_task.cancel()
    _drainer_task = None
