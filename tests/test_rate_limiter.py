from unittest.mock import patch

import pytest

from rate_limiter import RateLimiter

MAX_REQUESTS = 4
WINDOW_SECONDS = 60


def make_full_limiter(mock_time):
    """Return a limiter that received MAX_REQUESTS requests at time 0."""
    mock_time.return_value = 0
    limiter = RateLimiter(MAX_REQUESTS, WINDOW_SECONDS)
    for _ in range(MAX_REQUESTS):
        limiter.record_request()
    return limiter


@patch("rate_limiter.time.monotonic")
def test_allows_requests_under_limit(mock_time):
    mock_time.return_value = 0
    limiter = RateLimiter(MAX_REQUESTS, WINDOW_SECONDS)
    for _ in range(MAX_REQUESTS - 1):
        limiter.record_request()
    assert limiter.seconds_until_available() == 0


@patch("rate_limiter.time.monotonic")
def test_blocks_when_window_is_full(mock_time):
    limiter = make_full_limiter(mock_time)
    mock_time.return_value = 20
    assert limiter.seconds_until_available() == 40


@patch("rate_limiter.time.monotonic")
def test_still_blocked_just_before_window_ends(mock_time):
    limiter = make_full_limiter(mock_time)
    mock_time.return_value = 59.9
    assert limiter.seconds_until_available() == pytest.approx(0.1)


@patch("rate_limiter.time.monotonic")
def test_frees_slots_after_window_passes(mock_time):
    limiter = make_full_limiter(mock_time)
    mock_time.return_value = 60
    assert limiter.seconds_until_available() == 0
    assert limiter.used_in_window() == 0