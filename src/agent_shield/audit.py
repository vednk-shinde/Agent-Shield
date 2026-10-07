"""Tamper-evident audit log.

Every entry stores the SHA-256 of the previous entry, so editing, deleting or reordering any
record breaks the chain and `verify()` reports where. Entries hold hashes and rule names, never
the raw text that was scanned, so the log itself cannot leak the data it is protecting.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev_hash: str, seq: int, ts: float, event: dict[str, Any]) -> str:
    payload = json.dumps({"seq": seq, "ts": ts, "event": event}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def fingerprint(text: str) -> str:
    """Stable, non-reversible identifier for scanned text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | Path | None = None, max_entries: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._anchor = GENESIS  # hash that precedes the oldest retained entry
        self._path = Path(path) if path else None
        self._next_seq = 0
        if self._path and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if len(self._entries) == self._entries.maxlen:
                    self._anchor = self._entries[0]["hash"]
                self._entries.append(entry)
                self._next_seq = entry["seq"] + 1

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            prev_hash = self._entries[-1]["hash"] if self._entries else self._anchor
            ts = round(time.time(), 3)
            entry = {
                "seq": self._next_seq,
                "ts": ts,
                "event": event,
                "prev_hash": prev_hash,
                "hash": _digest(prev_hash, self._next_seq, ts, event),
            }
            if len(self._entries) == self._entries.maxlen:
                self._anchor = self._entries[0]["hash"]
            self._entries.append(entry)
            self._next_seq += 1
            if self._path:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def entries(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._entries)[-limit:]

    def __len__(self) -> int:
        return len(self._entries)

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the chain. Returns (ok, seq of the first broken entry or None)."""
        with self._lock:
            prev_hash = self._anchor
            for entry in self._entries:
                expected = _digest(prev_hash, entry["seq"], entry["ts"], entry["event"])
                if entry["prev_hash"] != prev_hash or entry["hash"] != expected:
                    return False, entry["seq"]
                prev_hash = entry["hash"]
        return True, None
