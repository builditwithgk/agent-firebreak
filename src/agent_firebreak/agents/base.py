"""The agent interface the runner drives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from agent_firebreak.models import Segment, ToolCall, ToolSpec


@dataclass
class Step:
    """What an agent wants to do next."""

    call: ToolCall
    injected: str | None = None   # id of the injection that caused this call, if any


class Agent(Protocol):
    name: str

    def start(self, scenario: Any, tools: list[ToolSpec], descriptions: list[Segment]) -> None: ...

    async def next_step(self) -> Step | None: ...

    def feed(self, step: Step, text: str, segments: list[Segment], executed: bool) -> None:
        """Report what happened to the last step. `executed` is False if the guard stopped it."""
