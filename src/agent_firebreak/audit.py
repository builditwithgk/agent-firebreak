"""A tamper-evident audit log: every entry carries the hash of the one before it."""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, seq: int, kind: str, data: Any) -> str:
    body = json.dumps({"seq": seq, "kind": kind, "data": data}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, kind: str, data: Any) -> dict[str, Any]:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        seq = len(self.entries)
        entry = {"seq": seq, "kind": kind, "data": data, "prev": prev, "hash": _digest(prev, seq, kind, data)}
        self.entries.append(entry)
        return entry

    @staticmethod
    def verify_entries(entries: list[dict[str, Any]]) -> tuple[bool, int | None]:
        """Return (ok, index of the first bad entry)."""
        prev = GENESIS
        for i, entry in enumerate(entries):
            if entry.get("prev") != prev or entry.get("seq") != i:
                return False, i
            if entry.get("hash") != _digest(prev, i, entry.get("kind", ""), entry.get("data")):
                return False, i
            prev = entry["hash"]
        return True, None

    def verify(self) -> tuple[bool, int | None]:
        return self.verify_entries(self.entries)

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e, sort_keys=True, ensure_ascii=False, default=str) for e in self.entries) + "\n"

    @classmethod
    def from_jsonl(cls, text: str) -> "AuditLog":
        log = cls()
        log.entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        return log
