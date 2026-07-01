"""Tests for the narration enqueue helpers in src/crew/narration.py.

These cover the thread-safe push logic and empty-text guards without a running
event loop or Discord — a fake loop invokes the scheduled callback inline so the
queued message can be inspected. The async drainer (Discord posting) is I/O glue
covered by integration testing, not here.
"""

import asyncio
from collections.abc import Callable
from typing import Any, cast

from src.crew import narration


class _FakeLoop:
    """Stand-in event loop that runs the scheduled callback immediately."""

    def call_soon_threadsafe(self, callback: Callable[..., Any], *args: Any) -> None:
        callback(*args)


def _loop() -> asyncio.AbstractEventLoop:
    """A fake loop typed as AbstractEventLoop for the push_* signatures."""
    return cast(asyncio.AbstractEventLoop, _FakeLoop())


def _drain_queue() -> list[dict]:
    """Pop and return everything currently on the shared narration queue."""
    queue = narration._get_queue()
    items: list[dict] = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


def test_push_thought_enqueues_full_message() -> None:
    """push_thought queues a thought message carrying category and confidence."""
    # Arrange
    _drain_queue()  # start from empty

    # Act
    narration.push_thought(
        _loop(), "randy_recon", "found something", category="finding", confidence=0.9
    )

    # Assert
    assert _drain_queue() == [
        {
            "kind": "thought",
            "agent_id": "randy_recon",
            "text": "found something",
            "category": "finding",
            "confidence": 0.9,
        }
    ]


def test_push_agent_chat_enqueues_message() -> None:
    """push_agent_chat queues an agent_chat message."""
    # Arrange
    _drain_queue()

    # Act
    narration.push_agent_chat(_loop(), "randy_recon", "hi team")

    # Assert
    assert _drain_queue() == [
        {"kind": "agent_chat", "agent_id": "randy_recon", "text": "hi team"}
    ]


def test_push_thought_ignores_blank_text() -> None:
    """Blank or whitespace-only text is dropped, not queued."""
    # Arrange
    _drain_queue()

    # Act
    narration.push_thought(_loop(), "randy_recon", "   ")
    narration.push_agent_chat(_loop(), "randy_recon", "")

    # Assert
    assert _drain_queue() == []
