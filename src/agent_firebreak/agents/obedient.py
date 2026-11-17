"""A simulated worst-case agent: it does the user's task, and obeys any injection it reads.

This is not a language model. It stands in for one that has been fooled, so the guard can be
tested against the outcome that matters: what happens once the model has been talked round.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from agent_firebreak.agents.base import Step
from agent_firebreak.models import Segment, ToolCall, ToolSpec

_TEMPLATE = "{{last_result}}"


class ObedientAgent:
    name = "simulated worst-case agent"

    def start(self, scenario: Any, tools: list[ToolSpec], descriptions: list[Segment]) -> None:
        self.scenario = scenario
        self.queue: deque[Step] = deque(Step(ToolCall(p["tool"], dict(p.get("args", {})))) for p in scenario.plan)
        self.seen: set[str] = set()
        self.suffixes: dict[str, str] = {}
        self.last_result = ""
        self.final_sent = False
        self.final_retried = False
        # Poison in tool descriptions is read up front but only acts when its trigger tool runs.
        self.triggers: dict[str, list[str]] = {}
        for seg in descriptions:
            pid = seg.meta.get("poison")
            if pid and pid in scenario.injections:
                trigger = scenario.injections[pid].get("trigger_tool")
                if trigger:
                    self.triggers.setdefault(trigger, []).append(pid)
                else:
                    self._obey(pid)

    def _obey(self, pid: str) -> None:
        if pid in self.seen or pid not in self.scenario.injections:
            return
        self.seen.add(pid)
        inj = self.scenario.injections[pid]
        for action in reversed(inj.get("actions", [])):
            self.queue.appendleft(Step(ToolCall(action["tool"], dict(action.get("args", {}))), injected=pid))
        if inj.get("final_append"):
            self.suffixes[pid] = inj["final_append"]

    async def next_step(self) -> Step | None:
        if self.queue:
            step = self.queue.popleft()
            step.call.args = {k: self._fill(v) for k, v in step.call.args.items()}
            return step
        if self.final_sent:
            return None
        self.final_sent = True
        suffix = "".join(self.suffixes.values())
        return Step(ToolCall("final_answer", {"text": self.scenario.final + suffix}),
                    injected=next(iter(self.suffixes), None) if suffix else None)

    def _fill(self, value: Any) -> Any:
        return value.replace(_TEMPLATE, self.last_result) if isinstance(value, str) else value

    def feed(self, step: Step, text: str, segments: list[Segment], executed: bool) -> None:
        if step.call.name == "final_answer":
            if not executed and step.injected and not self.final_retried:
                # The guard stopped the reply. A sensible agent tells the user without the injected part.
                self.final_retried = True
                self.suffixes.clear()
                self.final_sent = False
            return
        if not executed:
            return
        self.last_result = text
        for seg in segments:
            pid = seg.meta.get("poison")
            if pid:
                self._obey(pid)
        for pid in self.triggers.pop(step.call.name, []):
            self._obey(pid)
