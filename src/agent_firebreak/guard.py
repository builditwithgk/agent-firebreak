"""The guard: observe what the agent sees, then decide each tool call it proposes."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from agent_firebreak.audit import AuditLog
from agent_firebreak.detectors import scan
from agent_firebreak.models import (Decision, Finding, Origin, Risk, Segment, Signal, ToolCall, ToolSpec,
                                    Trust)
from agent_firebreak.normalize import (Entity, extract_entities, flatten_strings, normalise_text, normalise_url)
from agent_firebreak.policy import Facts, Policy, Rule
from agent_firebreak.provenance import OriginIndex

_ENTITY_KIND = {"recipient": "email", "url": "url", "account": "id", "amount": "amount"}
_FINDING_FOR_ORIGIN = {Origin.UNTRUSTED_ONLY: "UNTRUSTED_SINK", Origin.NEW: "NEW_SINK", Origin.TAGGED: "TAGGED_SINK"}
_IMAGE_MARKDOWN = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
_IMAGE_HTML = re.compile(r"<img[^>]+src\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I)


def _has_stray_characters(text: str, entities: list[Entity]) -> bool:
    """True if, after removing the recognised addresses, an '@' or a non-ASCII character is left over."""
    rest = text
    for entity in entities:
        rest = rest.replace(entity.raw.lower(), " ").replace(entity.raw, " ")
    return "@" in rest or not rest.isascii()


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


class Guard:
    """Tracks provenance and session taint, and turns each proposed tool call into allow / ask / block."""

    def __init__(self, tools: list[ToolSpec], policy: Policy | None = None, *, detectors: bool = True,
                 audit: AuditLog | None = None) -> None:
        self.tools = {t.name: t for t in tools}
        self.policy = policy or Policy.default()
        self.use_detectors = detectors
        self.audit = audit
        self.index = OriginIndex()
        self.tainted = False      # the agent has read content someone else controls
        self.sensitive = False    # the agent has read confidential records
        self.signals: list[Signal] = []

    # ------------------------------------------------------------------ observing
    def observe(self, segments: Segment | list[Segment], *, tool: str | None = None) -> list[Signal]:
        """Index content the agent has seen. Returns any new advisory signals."""
        if isinstance(segments, Segment):
            segments = [segments]
        spec = self.tools.get(tool) if tool else None
        fresh: list[Signal] = []
        for seg in segments:
            if spec and spec.returns_sensitive and not seg.sensitive:
                seg = replace(seg, sensitive=True)
            self.index.add(seg)
            if seg.trust is Trust.UNTRUSTED:
                self.tainted = True
                if self.use_detectors:
                    fresh.extend(scan(seg.text, seg.label))
            if seg.sensitive:
                self.sensitive = True
        known = {(s.id, s.segment) for s in self.signals}
        fresh = [s for s in fresh if (s.id, s.segment) not in known]
        self.signals.extend(fresh)
        if self.audit:
            self.audit.append("observe", {"segments": [s.label for s in segments],
                                          "trust": sorted({s.trust.value for s in segments}),
                                          "signals": [s.id for s in fresh]})
        return fresh

    # ------------------------------------------------------------------ deciding
    def evaluate(self, call: ToolCall) -> Decision:
        spec = self.tools.get(call.name)
        risk = spec.risk if spec else Risk.EXTERNAL  # an unknown tool is treated cautiously
        findings: list[Finding] = []
        if spec:
            findings += self._check_sinks(spec, call)
            findings += self._check_payload(spec, call)
            findings += self._check_undeclared(spec, call)
        else:  # a tool nobody declared cannot be judged, so a human decides
            findings.append(Finding("UNKNOWN_TOOL", f"{call.name} is not a declared tool", call.name))
        facts = Facts(risk.value, self.tainted, self.sensitive, frozenset(f.id for f in findings),
                      frozenset(s.id for s in self.signals))
        rule, effect = self.policy.decide(facts)
        decision = Decision(effect, rule.id if rule else "default", self._reason(rule, call, risk, findings),
                            risk, self.tainted, self.sensitive, findings, list(self.signals))
        if self.audit:
            self.audit.append("decision", {"tool": call.name, "args": call.args, **decision.to_dict()})
        return decision

    def _check_sinks(self, spec: ToolSpec, call: ToolCall) -> list[Finding]:
        findings: list[Finding] = []
        for param, sink in spec.sinks.items():
            if param not in call.args:
                continue
            kind = _ENTITY_KIND.get(sink.kind, sink.kind)
            seen: set[tuple[str, str]] = set()
            for text in flatten_strings(call.args[param]):
                norm = normalise_text(text)
                entities = [e for e in extract_entities(norm) if e.kind == kind]
                if not entities and norm.strip():
                    entities = [Entity(kind, norm.strip(), text.strip())]  # unusual format: treat the whole value
                elif kind == "email" and _has_stray_characters(norm, entities):
                    # e.g. "me@corp.example@attacker.example" or "dr<cyrillic o>p@attacker.example": an address-looking
                    # fragment must not vouch for the whole value
                    entities.insert(0, Entity(kind, norm.strip(), text.strip()))
                for entity in entities:
                    if (entity.kind, entity.norm) in seen:
                        continue
                    seen.add((entity.kind, entity.norm))
                    found = self.index.lookup(entity.kind, entity.norm, sink.allow_tags)
                    finding_id = _FINDING_FOR_ORIGIN.get(found.origin)
                    if finding_id:
                        findings.append(Finding(finding_id, f"{param} = {entity.raw}", param, entity.raw,
                                                found.origin, found.evidence))
        return findings

    def _check_undeclared(self, spec: ToolSpec, call: ToolCall) -> list[Finding]:
        """An argument the spec never mentioned (a model can invent `bcc`) must not smuggle in an untrusted address."""
        findings: list[Finding] = []
        declared = set(spec.params) | set(spec.sinks) | set(spec.payload)
        for param, value in call.args.items():
            if param in declared:
                continue
            for text in flatten_strings(value):
                for entity in extract_entities(normalise_text(text)):
                    if entity.kind not in ("email", "url"):
                        continue
                    found = self.index.lookup(entity.kind, entity.norm)
                    if found.origin in (Origin.UNTRUSTED_ONLY, Origin.NEW):
                        findings.append(Finding("UNTRUSTED_SINK" if found.origin is Origin.UNTRUSTED_ONLY else "NEW_SINK",
                                                f"undeclared argument {param} = {entity.raw}", param, entity.raw,
                                                found.origin, found.evidence))
        return findings

    def _check_payload(self, spec: ToolSpec, call: ToolCall) -> list[Finding]:
        """Look for links in outgoing content that smuggle data out or auto-load from an untrusted address."""
        findings: list[Finding] = []
        for param in spec.payload:
            if param not in call.args:
                continue
            for text in flatten_strings(call.args[param]):
                norm = normalise_text(text)
                images = {normalise_url(u)[0] for u in _IMAGE_MARKDOWN.findall(norm) + _IMAGE_HTML.findall(norm)}
                for entity in (e for e in extract_entities(norm) if e.kind == "url"):
                    found = self.index.lookup("url", entity.norm)
                    if found.origin is Origin.TRUSTED:
                        continue
                    leaked = self.index.sensitive_hits(entity.raw)
                    if leaked:
                        evidence = found.evidence + [{"label": "sensitive data", "derived": None,
                                                      "snippet": "the link contains: " + ", ".join(leaked[:3])}]
                        findings.append(Finding("EXFIL_LINK", f"{param} links to {entity.raw}", param, entity.raw,
                                                found.origin, evidence))
                    elif entity.norm in images:
                        findings.append(Finding("AUTOFETCH_IMAGE", f"{param} loads an image from {entity.raw}", param,
                                                entity.raw, found.origin, found.evidence))
        return findings

    def _reason(self, rule: Rule | None, call: ToolCall, risk: Risk, findings: list[Finding]) -> str:
        if rule is None:
            return f"{call.name}: no rule matched, so the default ({self.policy.default_effect.value}) applies."
        wanted = set(rule.when.get("findings_any", []))
        primary = next((f for f in findings if f.id in wanted), findings[0] if findings else None)
        where: Any = "nowhere the agent has seen"
        if primary and primary.evidence:
            where = ", ".join(sorted({e["label"] + (f" ({e['derived']})" if e.get("derived") else "")
                                      for e in primary.evidence}))
        shown = (primary.value or "") if primary else ""
        shown = shown.encode("ascii", "backslashreplace").decode("ascii")  # make look-alike characters visible, keep logs safe
        context = _SafeDict(tool=call.name, risk=risk.value, param=primary.param if primary else "",
                            value=shown, where=where,
                            signals=", ".join(sorted({s.id for s in self.signals})))
        return rule.reason.format_map(context)
