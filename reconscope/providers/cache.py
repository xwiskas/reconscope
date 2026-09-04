"""A small TTL cache for passive-provider responses (PRD P1, P4: cache 24h).

Milestone 1 ships an in-memory cache keyed by ``provider:key``. It is process
local (cleared on restart), which is acceptable for a single local session; a
disk-backed cache can replace it later behind the same ``Cache`` protocol. The
clock is injectable so tests can advance time deterministically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol


class Cache(Protocol):
    def get(self, key: str) -> Any | None: ...
    def set(self, key: str, value: Any, ttl_seconds: float) -> None: ...


@dataclass
class _Entry:
    value: Any
    expires_at: float


@dataclass
class MemoryTTLCache:
    """In-memory cache with per-entry TTL."""

    clock: callable = time.monotonic
    _store: dict[str, _Entry] = field(default_factory=dict)

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        if self.clock() >= entry.expires_at:
            self._store.pop(key, None)
            return None
        return entry.value

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        self._store[key] = _Entry(value=value, expires_at=self.clock() + ttl_seconds)

    def clear(self) -> None:
        self._store.clear()
