"""Local rate-limit interface and a single-process implementation.

The protocol is the seam a shared store would implement. The class below
counts requests in memory. It resets when the process restarts, it is not
shared across workers, and a client can open many keys. Those are accepted
limits of this lab, not properties of a production control.
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class RateLimiter(Protocol):
    """Decide whether one more call for ``key`` is allowed."""

    def allow(self, key: str) -> bool:
        """Return ``True`` when the caller may proceed."""


@dataclass
class _Window:
    started: float
    count: int


class InMemoryFixedWindowRateLimiter:
    """Fixed-window counter kept inside one process.

    A window allows ``limit`` calls, then rejects until ``window_seconds``
    have passed. The clock is injectable so tests can move time without
    sleeping. Keys are not authenticated; callers must build them from a
    value the client cannot freely spoof. This lab uses the connection's
    peer address and does not trust ``X-Forwarded-For``.
    """

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._limit = limit
        self._window_seconds = window_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            self._prune(now)
            window = self._windows.get(key)
            if window is None or now - window.started >= self._window_seconds:
                self._windows[key] = _Window(started=now, count=1)
                return True
            if window.count >= self._limit:
                return False
            window.count += 1
            return True

    def _prune(self, now: float) -> None:
        if len(self._windows) < 1024:
            return
        expired = [
            key
            for key, window in self._windows.items()
            if now - window.started >= self._window_seconds
        ]
        for key in expired:
            del self._windows[key]
