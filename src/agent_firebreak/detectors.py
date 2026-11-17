"""Advisory detectors.

Cheap pattern checks that flag content which looks like an injection attempt. They are signals, not the
defence: they can only make the guard *more* cautious, and the guard works with them switched off. Attackers
can rephrase around any pattern; that is exactly why the origin check does not depend on these.
"""

from __future__ import annotations

import re

from agent_firebreak.models import Signal
from agent_firebreak.normalize import decode_blobs, normalise_text

_INVISIBLE = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
_HTML_COMMENT = re.compile(r"<!--(.{10,}?)-->", re.S)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\b|opacity\s*:\s*0\b"
    r"|color\s*:\s*(?:#fff(?:fff)?|white)\b", re.I)

_PHRASES: list[tuple[str, str, re.Pattern[str]]] = [
    ("INSTRUCTION_PHRASE", "Instruction-like phrasing aimed at an AI", re.compile("|".join([
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?)\b",
        r"\b(?:do not|don't|never)\s+(?:tell|mention|inform|alert|notify)\b[^.\n]{0,40}\b(?:user|anyone|owner)\b",
        r"\bbefore\s+(?:you\s+)?(?:summari[sz]ing|replying|responding|answering|continuing)\b[^.\n]{0,80}\b(?:call|send|email|forward|fetch|use)\b",
        r"\b(?:also|then)\s+(?:email|send|forward)\b[^.\n]{0,60}\bto\b[^.\n]{0,60}@",
    ]))),
    ("AI_ADDRESSED", "Text addressed to AI assistants", re.compile("|".join([
        r"\b(?:ai|llm)\s+(?:assistants?|agents?|models?)\b",
        r"\b(?:assistants?|agents?)\s+(?:reading|processing|summari[sz]ing)\b",
        r"\b(?:note|message|instruction)s?\s+(?:for|to)\s+(?:the\s+)?(?:ai|assistants?|agents?)\b",
    ]))),
    ("ROLE_SPOOF", "Fake system or assistant markers", re.compile(
        r"</?(?:system|assistant|instructions?)>|<\|im_start\|>|(?:^|\n)\s*(?:system|assistant)\s*:|###\s*(?:system|instruction)")),
    ("AUTHORITY_CLAIM", "Claims of authority or pressure to skip approval", re.compile("|".join([
        r"\b(?:direct\s+)?(?:instruction|message|order|request)\s+from\s+(?:the\s+)?(?:ceo|cfo|cto|admin(?:istrator)?|security\s+team|it\s+(?:department|security)|management)\b",
        r"\bdo not ask\b|\bwithout\s+(?:asking|approval|confirmation)\b",
    ]))),
    ("HINGLISH_CUE", "Hinglish instruction cue", re.compile(
        r"\b(?:ignore\s+karo|pichle\s+(?:nirdesh|instructions?)|instructions?\s+ignore\s+karo|pehle\s+ke\s+instructions?)\b")),
    ("EXFIL_LINK_PATTERN", "Image or link that carries data in its address", re.compile(
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]+\)|<img[^>]+src\s*=\s*[\"']?https?://[^\"'\s>]*\?")),
]

# The signal ids that make the default policy ask before an external action.
ALL_SIGNAL_IDS = ["HIDDEN_CHARS", "HTML_COMMENT", "HIDDEN_STYLE", "ENCODED_BLOB"] + [p[0] for p in _PHRASES]


def _clip(text: str, limit: int = 110) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def scan(text: str, segment: str) -> list[Signal]:
    """Return one signal per kind of suspicious pattern found in `text`."""
    signals: dict[str, Signal] = {}

    def add(sig_id: str, label: str, snippet: str) -> None:
        signals.setdefault(sig_id, Signal(sig_id, label, _clip(snippet), segment))

    if _INVISIBLE.search(text):
        add("HIDDEN_CHARS", "Invisible characters (zero-width or direction overrides)", "contains characters a reader cannot see")
    if (m := _HTML_COMMENT.search(text)):
        add("HTML_COMMENT", "HTML comment, invisible to a human reader", m.group(1))
    if (m := _HIDDEN_STYLE.search(text)):
        add("HIDDEN_STYLE", "Hidden or invisible styling", m.group(0))
    for kind, decoded in decode_blobs(text):
        add("ENCODED_BLOB", f"{kind} blob that decodes to readable text", decoded)
    normalised = normalise_text(text)
    for sig_id, label, pattern in _PHRASES:
        if (m := pattern.search(normalised)):
            add(sig_id, label, m.group(0))
    return list(signals.values())
