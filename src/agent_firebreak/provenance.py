"""Value-origin tracking: where did this value first appear?

Every segment the agent sees is indexed. When a tool call arrives, each security-relevant argument
(a recipient, a URL, an account, an amount) is looked up: did the user write it, did it only come from
untrusted content, or is it new? That answer, not any attempt to read the attacker's mind, drives the policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent_firebreak.models import Origin, Segment, Trust
from agent_firebreak.normalize import (LONG_DIGITS_RE, Entity, decode_blobs, deobfuscate, extract_entities,
                                       normalise_text)

_MAX_EVIDENCE = 5
_SNIPPET_RADIUS = 70
_MAX_LITERAL = 2000


@dataclass
class OriginResult:
    origin: Origin
    evidence: list[dict[str, Any]] = field(default_factory=list)


def _snippet(text: str, entity: Entity) -> str:
    at = text.find(entity.raw)
    if at < 0:
        at = 0
    start, end = max(0, at - _SNIPPET_RADIUS), min(len(text), at + len(entity.raw) + _SNIPPET_RADIUS)
    clip = " ".join(text[start:end].split())
    return ("…" if start else "") + clip + ("…" if end < len(text) else "")


class OriginIndex:
    def __init__(self) -> None:
        self._trusted: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._untrusted: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._sensitive: dict[str, str] = {}  # lowercase value -> label of the segment it came from
        self._texts: list[tuple[bool, str, str, tuple[str, ...]]] = []  # (trusted, label, normalised text, tags)

    @staticmethod
    def _variants(segment: Segment) -> list[tuple[str | None, str]]:
        """The text as written, plus de-obfuscated and decoded forms: derived content inherits the label."""
        base = normalise_text(segment.text)
        variants: list[tuple[str | None, str]] = [(None, base)]
        plain = deobfuscate(base)
        if plain != base:
            variants.append(("deobfuscated", plain))
        for kind, decoded in decode_blobs(segment.text):
            variants.append((f"decoded {kind}", normalise_text(decoded)))
        return variants

    def add(self, segment: Segment) -> None:
        target = self._trusted if segment.trust is Trust.TRUSTED else self._untrusted
        for derived, text in self._variants(segment):
            if derived is None:
                self._texts.append((segment.trust is Trust.TRUSTED, segment.label, text, segment.tags))
            for entity in extract_entities(text):
                entries = target.setdefault((entity.kind, entity.norm), [])
                if len(entries) < _MAX_EVIDENCE:  # (compute the snippet only when it is kept: keeps indexing linear)
                    entries.append({"label": segment.label, "derived": derived, "tags": segment.tags,
                                    "snippet": _snippet(text, entity)})
        if segment.sensitive:
            base = normalise_text(segment.text)
            for entity in extract_entities(base):
                if entity.kind in ("email", "id"):
                    self._sensitive[entity.norm.lower()] = segment.label
            for digits in LONG_DIGITS_RE.findall(base):
                self._sensitive[digits] = segment.label

    def lookup(self, kind: str, norm: str, allow_tags: tuple[str, ...] = ()) -> OriginResult:
        key = (kind, norm)
        if key in self._trusted:
            return OriginResult(Origin.TRUSTED, [self._evidence(e) for e in self._trusted[key]])
        if key in self._untrusted:
            entries = self._untrusted[key]
            tagged = [e for e in entries if set(e["tags"]) & set(allow_tags)]
            if tagged:
                return OriginResult(Origin.TAGGED, [self._evidence(e) for e in tagged])
            return OriginResult(Origin.UNTRUSTED_ONLY, [self._evidence(e) for e in entries])
        return OriginResult(Origin.NEW)

    def lookup_literal(self, norm: str, allow_tags: tuple[str, ...] = ()) -> OriginResult:
        """Where does this exact value appear, as a whole word or phrase? For handles, paths and commands."""
        if not norm or len(norm) > _MAX_LITERAL:
            return OriginResult(Origin.NEW)
        pattern = re.compile(r"(?<![a-z0-9_])" + re.escape(norm) + r"(?![a-z0-9_])")
        hits = [(trusted, label, text, tags) for trusted, label, text, tags in self._texts if pattern.search(text)]
        trusted_hits = [h for h in hits if h[0]]
        if trusted_hits:
            return OriginResult(Origin.TRUSTED, self._literal_evidence(trusted_hits, norm))
        if hits:
            evidence = self._literal_evidence(hits, norm)
            if any(set(h[3]) & set(allow_tags) for h in hits):
                return OriginResult(Origin.TAGGED, evidence)
            return OriginResult(Origin.UNTRUSTED_ONLY, evidence)
        return OriginResult(Origin.NEW)

    @staticmethod
    def _literal_evidence(hits: list[tuple[bool, str, str, tuple[str, ...]]], norm: str) -> list[dict[str, Any]]:
        return [{"label": h[1], "derived": None, "snippet": norm} for h in hits[:_MAX_EVIDENCE]]

    @staticmethod
    def _evidence(entry: dict[str, Any]) -> dict[str, Any]:
        return {"label": entry["label"], "derived": entry["derived"], "snippet": entry["snippet"]}

    def sensitive_hits(self, text: str) -> list[str]:
        """Sensitive values (from confidential reads) that appear inside `text`."""
        haystack = normalise_text(text)
        return sorted(v for v in self._sensitive if v in haystack)
