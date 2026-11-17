"""Replay a fixed list of tool calls. Useful for testing a policy against a recorded session."""

from __future__ import annotations

from typing import Any

from agent_firebreak.agents.base import Step
from agent_firebreak.models import Segment, ToolCall, ToolSpec


class ReplayAgent:
    name = "replay"

    def __init__(self, calls: list[dict[str, Any]]) -> None:
        self._calls = calls

    def start(self, scenario: Any, tools: list[ToolSpec], descriptions: list[Segment]) -> None:
        self._queue = [Step(ToolCall(c["tool"], dict(c.get("args", {})))) for c in self._calls]

    async def next_step(self) -> Step | None:
        return self._queue.pop(0) if self._queue else None

    def feed(self, step: Step, text: str, segments: list[Segment], executed: bool) -> None:
        return None
