"""The rule engine: an ordered list of rules, first match wins, cautious default."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from typing import Any

from agent_firebreak.detectors import ALL_SIGNAL_IDS
from agent_firebreak.models import Effect

_ALLOWED_KEYS = {"risk", "tainted", "sensitive", "findings_any", "findings_none", "signals_any", "signals_none"}

DEFAULT_POLICY_TOML = f"""\
# agent-firebreak default policy. Rules run top to bottom; the first match wins.
# Conditions: risk, tainted, sensitive, findings_any, findings_none, signals_any, signals_none.
# Effects: allow | ask (a human can override) | block (never runs).
default_effect = "ask"

[[rule]]
id = "block-exfil-link"
when = {{ findings_any = ["EXFIL_LINK"] }}
effect = "block"
reason = "{{tool}}: a link in the output carries sensitive data to {{value}}, a destination the user never provided."

[[rule]]
id = "block-autofetch-image"
when = {{ findings_any = ["AUTOFETCH_IMAGE"] }}
effect = "block"
reason = "{{tool}}: an image from {{value}} would load automatically, and that address came from untrusted content."

[[rule]]
id = "block-untrusted-target"
when = {{ risk = ["write", "external"], findings_any = ["UNTRUSTED_SINK"] }}
effect = "block"
reason = "{{tool}}: {{param}} = {{value}} appears only in untrusted content ({{where}}); the user never provided it."

[[rule]]
id = "ask-untrusted-link"
when = {{ risk = ["read"], findings_any = ["UNTRUSTED_SINK"] }}
effect = "ask"
reason = "{{tool}}: {{value}} came from untrusted content ({{where}}); following it needs approval."

[[rule]]
id = "ask-unknown-target"
when = {{ risk = ["write", "external"], findings_any = ["NEW_SINK"] }}
effect = "ask"
reason = "{{tool}}: {{param}} = {{value}} was not given by the user and is not in anything the agent has read."

[[rule]]
id = "ask-sensitive-out"
when = {{ risk = ["external"], sensitive = true, findings_any = ["TAGGED_SINK"] }}
effect = "ask"
reason = "{{tool}}: sensitive data was read earlier, and {{param}} = {{value}} was not typed by the user ({{where}})."

[[rule]]
id = "ask-suspicious-content"
when = {{ risk = ["external"], tainted = true, signals_any = {json.dumps(ALL_SIGNAL_IDS)} }}
effect = "ask"
reason = "{{tool}}: untrusted content read earlier contained suspicious patterns ({{signals}})."

[[rule]]
id = "ask-unknown-tool"
when = {{ findings_any = ["UNKNOWN_TOOL"] }}
effect = "ask"
reason = "{{tool}}: this tool was not declared to the guard, so its risk is unknown."

[[rule]]
id = "allow-clean"
when = {{ findings_none = ["UNTRUSTED_SINK", "NEW_SINK", "EXFIL_LINK", "AUTOFETCH_IMAGE", "UNKNOWN_TOOL"] }}
effect = "allow"
reason = "{{tool}}: no untrusted value reaches a sensitive parameter."
"""


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    reason: str
    when: dict[str, Any]


@dataclass(frozen=True)
class Facts:
    risk: str
    tainted: bool
    sensitive: bool
    finding_ids: frozenset[str]
    signal_ids: frozenset[str]


def _matches(when: dict[str, Any], facts: Facts) -> bool:
    if "risk" in when and facts.risk not in when["risk"]:
        return False
    if "tainted" in when and facts.tainted != when["tainted"]:
        return False
    if "sensitive" in when and facts.sensitive != when["sensitive"]:
        return False
    if "findings_any" in when and not facts.finding_ids & set(when["findings_any"]):
        return False
    if "findings_none" in when and facts.finding_ids & set(when["findings_none"]):
        return False
    if "signals_any" in when and not facts.signal_ids & set(when["signals_any"]):
        return False
    if "signals_none" in when and facts.signal_ids & set(when["signals_none"]):
        return False
    return True


class Policy:
    def __init__(self, rules: list[Rule], default_effect: Effect = Effect.ASK) -> None:
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate rule ids in policy.")
        self.rules = rules
        self.default_effect = default_effect

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        rules = []
        for raw in data.get("rule", data.get("rules", [])):
            when = raw.get("when", {})
            unknown = set(when) - _ALLOWED_KEYS
            if unknown:
                raise ValueError(f"Rule {raw.get('id')!r}: unknown condition(s) {sorted(unknown)}.")
            rules.append(Rule(raw["id"], Effect(raw["effect"]), raw.get("reason", raw["id"]), when))
        return cls(rules, Effect(data.get("default_effect", "ask")))

    @classmethod
    def from_toml(cls, text: str) -> "Policy":
        return cls.from_dict(tomllib.loads(text))

    @classmethod
    def from_json(cls, text: str) -> "Policy":
        return cls.from_dict(json.loads(text))

    @classmethod
    def default(cls) -> "Policy":
        return cls.from_toml(DEFAULT_POLICY_TOML)

    def decide(self, facts: Facts) -> tuple[Rule | None, Effect]:
        for rule in self.rules:
            if _matches(rule.when, facts):
                return rule, rule.effect
        return None, self.default_effect

    def describe(self) -> list[dict[str, Any]]:
        return [{"id": r.id, "effect": r.effect.value, "when": r.when, "reason": r.reason} for r in self.rules]
