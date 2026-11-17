"""Core data types shared by every part of agent-firebreak."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Trust(str, Enum):
    TRUSTED = "trusted"      # what the user (or the operator's system prompt) wrote
    UNTRUSTED = "untrusted"  # everything else: emails, web pages, tool results, tool descriptions


class Risk(str, Enum):
    READ = "read"            # reads data; safe to run
    WRITE = "write"          # changes something reversible
    EXTERNAL = "external"    # sends data out or does something irreversible (email, payment, delete)
    OUTPUT = "output"        # the agent's reply to the user (links and images can leak data)


class Effect(str, Enum):
    ALLOW = "allow"
    ASK = "ask"              # a human can override
    BLOCK = "block"          # never runs


class Origin(str, Enum):
    TRUSTED = "trusted"                # the value appears in something the user wrote
    TAGGED = "tagged"                  # only in untrusted content, but in a field the tool accepts (e.g. reply-to)
    UNTRUSTED_ONLY = "untrusted_only"  # only in untrusted content
    NEW = "new"                        # not found anywhere the agent has seen


@dataclass
class Segment:
    """A labelled piece of content the agent has seen."""

    label: str
    text: str
    trust: Trust = Trust.UNTRUSTED
    tags: tuple[str, ...] = ()
    sensitive: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {"label": self.label, "text": self.text, "trust": self.trust.value,
               "tags": list(self.tags), "sensitive": self.sensitive}
        if self.meta.get("poison"):
            out["poison"] = self.meta["poison"]
        return out


@dataclass(frozen=True)
class SinkSpec:
    """A parameter that decides where data goes or what an action targets."""

    kind: str                          # recipient | url | account | amount
    allow_tags: tuple[str, ...] = ()   # untrusted fields with these tags may supply the value


@dataclass
class ToolSpec:
    name: str
    description: str
    risk: Risk
    params: dict[str, dict[str, Any]] = field(default_factory=dict)  # JSON-schema property dicts (used by LLM adapters)
    sinks: dict[str, SinkSpec] = field(default_factory=dict)
    payload: tuple[str, ...] = ()      # parameters that carry outgoing content
    returns_sensitive: bool = False

    @classmethod
    def from_annotations(cls, name: str, description: str = "", *, read_only: bool | None = None,
                         destructive: bool | None = None, open_world: bool | None = None, **kw: Any) -> "ToolSpec":
        """Derive a risk class from MCP tool annotations. Missing hints mean cautious: external."""
        if read_only is True and not destructive:
            risk = Risk.READ
        elif destructive or open_world:
            risk = Risk.EXTERNAL
        elif read_only is False:
            risk = Risk.WRITE
        else:
            risk = Risk.EXTERNAL
        return cls(name=name, description=description, risk=risk, **kw)


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str                            # UNTRUSTED_SINK | NEW_SINK | TAGGED_SINK | EXFIL_LINK | AUTOFETCH_IMAGE
    message: str
    param: str | None = None
    value: str | None = None
    origin: Origin | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "message": self.message, "param": self.param, "value": self.value,
                "origin": self.origin.value if self.origin else None, "evidence": self.evidence}


@dataclass
class Signal:
    """An advisory detector hit. Signals can only add caution; the defence never depends on them."""

    id: str
    label: str
    snippet: str
    segment: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "label": self.label, "snippet": self.snippet, "segment": self.segment}


@dataclass
class Decision:
    effect: Effect
    rule_id: str
    reason: str
    risk: Risk
    tainted: bool
    sensitive: bool
    findings: list[Finding] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"effect": self.effect.value, "rule": self.rule_id, "reason": self.reason, "risk": self.risk.value,
                "tainted": self.tainted, "sensitive": self.sensitive,
                "findings": [f.to_dict() for f in self.findings], "signals": [s.to_dict() for s in self.signals]}
