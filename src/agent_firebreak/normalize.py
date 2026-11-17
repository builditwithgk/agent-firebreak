"""Text normalisation and value extraction.

Everything the guard compares goes through here first, so that zero-width characters, percent-encoding,
HTML entities, Unicode look-alike forms, "[at]/[dot]" spellings and base64 or hex blobs cannot hide a
value from the origin check. Pure standard library: this module also runs in the browser (Pyodide).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_AT = re.compile(r"\s*[\[\(\{]\s*at\s*[\]\)\}]\s*", re.I)
_DOT = re.compile(r"\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*", re.I)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")

EMAIL_RE = re.compile(r"(?<![a-z0-9._%+\-])[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z]{2,}")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]\}]+")
ID_RE = re.compile(r"(?<![a-z0-9@./_-])[a-z]{1,6}-\d+(?:-\d+)*(?![a-z0-9@_-])")
AMOUNT_RE = re.compile(r"(?<![a-z0-9@./_-])(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?(?![a-z0-9@_-])")
LONG_DIGITS_RE = re.compile(r"\d{6,}")


@dataclass(frozen=True)
class Entity:
    kind: str          # email | url | id | amount
    norm: str          # canonical form used for comparison
    raw: str           # as it appeared (lowercased)
    query: str = ""    # URLs only: the query string


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi and other invisible format characters (Unicode category Cf)."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def normalise_text(text: str) -> str:
    """NFKC, strip invisible characters, unescape HTML entities, percent-decode (twice), lowercase."""
    text = strip_invisible(unicodedata.normalize("NFKC", text))
    if "&" in text:
        text = html.unescape(text)
    for _ in range(2):
        if _PERCENT.search(text):
            text = urllib.parse.unquote(text)
    return text.lower()


def deobfuscate(text: str) -> str:
    """Turn 'name [at] host [dot] com' into 'name@host.com'."""
    return _DOT.sub(".", _AT.sub("@", text))


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / len(data)


def decode_blobs(text: str) -> list[tuple[str, str]]:
    """Find base64 / hex blobs that decode to readable text. Returns (kind, decoded) pairs."""
    found: list[tuple[str, str]] = []
    for match in _B64.finditer(text):
        token = match.group(0)
        try:
            data = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(data) >= 8 and _printable_ratio(data) >= 0.9:
            found.append(("base64", data.decode("utf-8", "replace")))
    for match in _HEX.finditer(text):
        try:
            data = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        if len(data) >= 8 and _printable_ratio(data) >= 0.9:
            found.append(("hex", data.decode("utf-8", "replace")))
    return found


def normalise_url(raw: str) -> tuple[str, str]:
    """Return (host + path key, query string). Scheme, 'www.', fragment and a trailing slash are ignored."""
    url = raw.rstrip(".,;:!?")
    # Browsers and many HTTP clients (WHATWG rules) read a backslash as a slash and drop tabs and newlines; do the same,
    # so "https://evil.example\@good.example/" is judged by the host a browser would actually contact.
    url = url.replace("\\", "/").translate({9: None, 10: None, 13: None})
    if url.startswith("www."):
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host + parts.path.rstrip("/"), parts.query


def normalise_amount(raw: str) -> str:
    """'4,999.00' and '4999' both become '4999'."""
    try:
        return format(Decimal(raw.replace(",", "")).normalize(), "f")
    except InvalidOperation:
        return raw


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def extract_entities(text: str) -> list[Entity]:
    """Pull emails, URLs, IDs and amounts out of *normalised* text. Digits inside an earlier hit are not re-read."""
    entities: list[Entity] = []
    spans: list[tuple[int, int]] = []
    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:!?")
        key, query = normalise_url(raw)
        if key:
            entities.append(Entity("url", key, raw, query))
            spans.append((match.start(), match.start() + len(raw)))
    for match in EMAIL_RE.finditer(text):
        entities.append(Entity("email", match.group(0), match.group(0)))
        spans.append(match.span())
    masked = _mask(text, spans)
    id_spans: list[tuple[int, int]] = []
    for match in ID_RE.finditer(masked):
        entities.append(Entity("id", match.group(0).upper(), match.group(0)))
        id_spans.append(match.span())
    masked = _mask(masked, id_spans)
    for match in AMOUNT_RE.finditer(masked):
        entities.append(Entity("amount", normalise_amount(match.group(0)), match.group(0)))
    return entities


def flatten_strings(value: Any) -> Iterator[str]:
    """Yield every string (and number, as text) inside a nested argument value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        yield str(value)
    elif isinstance(value, dict):
        for item in value.values():
            yield from flatten_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from flatten_strings(item)
