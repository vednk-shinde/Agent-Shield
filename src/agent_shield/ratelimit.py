"""Per-agent token-bucket rate limiting (in-memory, single instance)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        capacity: float = 60.0,
        refill_per_second: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = 10_000,
    ) -> None:
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("capacity and refill_per_second must be positive")
        self.capacity = capacity
        self.refill = refill_per_second
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_seen)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
            self._buckets[key] = (tokens, now)
            if len(self._buckets) > self._max_buckets:
                self._prune(now)
            return allowed

    def _prune(self, now: float) -> None:
        """Drop buckets that have fully refilled; they behave the same as a fresh one."""
        full_after = self.capacity / self.refill
        stale = [k for k, (_, last) in self._buckets.items() if now - last >= full_after]
        for key in stale:
            del self._buckets[key]
