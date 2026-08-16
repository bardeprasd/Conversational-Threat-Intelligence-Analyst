"""Process-local sliding-window limiter for protecting quota-bound services."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    """Track request timestamps per client and return an HTTP-friendly retry delay."""

    def __init__(
        self,
        requests: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.requests = requests
        self.window_seconds = window_seconds
        self.clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> tuple[bool, int]:
        now = self.clock()
        events = self._events[key]
        cutoff = now - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.requests:
            retry_after = max(1, int(self.window_seconds - (now - events[0])))
            return False, retry_after
        events.append(now)
        return True, 0
