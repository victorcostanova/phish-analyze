"""Bounded, thread-safe admission control for the single-worker public demo."""

from collections import deque
from math import ceil
from threading import Lock
from time import monotonic


class AnalysisRateLimiter:
    """Shared POST budget per process; no client identifiers or email data stored.

    Deploy with one worker/instance. Multiple processes require a shared backend
    or ingress-level limiter. This budget resets on process restart.
    """

    def __init__(self, limit=30, window_seconds=60, clock=monotonic):
        if not 1 <= limit <= 1000 or window_seconds <= 0:
            raise ValueError("Rate limit must be 1..1000 with a positive window.")
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._accepted = deque()
        self._lock = Lock()

    def admit(self):
        """Return zero if accepted, otherwise seconds until the next slot."""
        with self._lock:
            now = self.clock()
            while self._accepted and self._accepted[0] <= now - self.window_seconds:
                self._accepted.popleft()
            if len(self._accepted) >= self.limit:
                return max(1, ceil(self._accepted[0] + self.window_seconds - now))
            self._accepted.append(now)
            return 0
