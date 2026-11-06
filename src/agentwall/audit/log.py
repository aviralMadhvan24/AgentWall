"""Append-only, hash-chained audit log of gateway decisions.

Each entry stores the hash of the previous entry, so any edit or deletion breaks the chain and
:func:`verify_chain` reports where.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev_hash: str, body: dict[str, Any]) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        self._prev = GENESIS
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        entry = json.loads(line)
                        self.entries.append(entry)
                        self._prev = entry["hash"]

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        body = {"seq": len(self.entries) + 1, "ts": round(time.time(), 3), **event}
        entry = {**body, "prev": self._prev, "hash": _digest(self._prev, body)}
        self.entries.append(entry)
        self._prev = entry["hash"]
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry


def verify_chain(entries: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (ok, index of the first bad entry)."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
        if entry.get("prev") != prev or entry.get("hash") != _digest(prev, body):
            return False, i
        prev = entry["hash"]
    return True, None
