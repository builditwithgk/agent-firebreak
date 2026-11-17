"""Scenario definitions: a user task, a fake world, and (for attacks) the injections hidden in it."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

KINDS = ("attack", "limit", "benign")


@dataclass
class Scenario:
    id: str
    kind: str
    family: str
    title: str
    summary: str
    user_task: str
    world: dict[str, Any]
    plan: list[dict[str, Any]]
    final: str
    injections: dict[str, dict[str, Any]] = field(default_factory=dict)
    success: dict[str, Any] | None = None       # attack/limit: what counts as the attack landing
    expect: list[dict[str, Any]] = field(default_factory=list)  # benign: what must happen
    asks_expected: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        if data.get("kind") not in KINDS:
            raise ValueError(f"Scenario {data.get('id')!r}: kind must be one of {KINDS}.")
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    @property
    def is_attack(self) -> bool:
        return self.kind in ("attack", "limit")


def matches(predicate: dict[str, Any], calls: list[dict[str, Any]]) -> bool:
    """True if any executed call satisfies {tool, arg, equals | contains}."""
    for call in calls:
        if call["tool"] != predicate["tool"]:
            continue
        value = str(call["args"].get(predicate["arg"], "")).lower()
        if "equals" in predicate and value == str(predicate["equals"]).lower():
            return True
        if "contains" in predicate and str(predicate["contains"]).lower() in value:
            return True
    return False


def load_scenarios(text: str | None = None) -> list[Scenario]:
    if text is None:
        text = (resources.files("agent_firebreak") / "data" / "scenarios.json").read_text(encoding="utf-8")
    return [Scenario.from_dict(item) for item in json.loads(text)]


def get_scenario(scenario_id: str, scenarios: list[Scenario] | None = None) -> Scenario:
    for s in scenarios or load_scenarios():
        if s.id == scenario_id or s.id.split("-")[0].lower() == scenario_id.lower():
            return s
    raise KeyError(scenario_id)
