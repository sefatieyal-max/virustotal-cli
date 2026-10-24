"""Client-side sliding-window rate limiter."""

import time
from collections import deque


class RateLimiter:
    """Allow at most `max_requests` within any `window_seconds` period."""

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps = deque()

    def seconds_until_available(self):
        """Return 0 if a request can be sent now, else how many seconds to wait."""
        self._drop_expired()
        if len(self._timestamps) < self.max_requests:
            return 0
        elapsed = time.monotonic() - self._timestamps[0]
        return max(0, self.window_seconds - elapsed)

    def record_request(self):
        """Remember that a request was just sent."""
        self._timestamps.append(time.monotonic())

    def used_in_window(self):
        """Return how many requests were sent in the current window."""
        self._drop_expired()
        return len(self._timestamps)

    def _drop_expired(self):
        """Forget timestamps older than the window."""
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
            self._timestamps.popleft()