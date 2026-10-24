"""HTTP client for the VirusTotal API v3. Never prints, never asks for input."""

from http import HTTPStatus
from urllib.parse import quote
from rate_limiter import RateLimiter

import requests
import math
import time

from exceptions import (
    AuthError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    VirusTotalError,
    AnalysisTimeoutError,
)

BASE_URL = "https://www.virustotal.com/api/v3"
URL_SUBMIT_PATH = "/urls"

API_KEY_HEADER = "x-apikey"
PATH_SAFE_CHARS = ":"
NO_DETAILS = "No details provided."

IP_COLLECTION = "ip_addresses"
DOMAIN_COLLECTION = "domains"
FILE_COLLECTION = "files"
ANALYSIS_COLLECTION = "analyses"
ANALYSIS_COMPLETED = "completed"

DEFAULT_TIMEOUT_SECONDS = 15
REQUESTS_PER_WINDOW = 4
RATE_WINDOW_SECONDS = 60
POLL_INTERVAL_SECONDS = 15
POLL_TIMEOUT_SECONDS = 120

KEY_CHECK_IP = "8.8.8.8"


class VirusTotalClient:
    """Thin wrapper around the VirusTotal REST API."""

    def __init__(self, api_key, timeout=DEFAULT_TIMEOUT_SECONDS):
        self.timeout = timeout
        self.rate_limiter = RateLimiter(REQUESTS_PER_WINDOW, RATE_WINDOW_SECONDS)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            API_KEY_HEADER: api_key,
        })

    # ---------- public methods ----------

    def get_ip_report(self, ip):
        """Return the attributes of an IP address report."""
        return self._get_attributes(IP_COLLECTION, ip)

    def get_domain_report(self, domain):
        """Return the attributes of a domain report."""
        return self._get_attributes(DOMAIN_COLLECTION, domain)

    def get_file_report(self, file_hash):
        """Return the attributes of a file report (MD5, SHA-1 or SHA-256)."""
        return self._get_attributes(FILE_COLLECTION, file_hash)

    def requests_used(self):
        """Return how many requests were sent in the current rate window."""
        return self.rate_limiter.used_in_window()

    def check_api_key(self):
        """Raise AuthError if the API key is rejected. Uses one request."""
        self.get_ip_report(KEY_CHECK_IP)

    def set_api_key(self, api_key):
        """Replace the API key used for future requests."""
        self.session.headers[API_KEY_HEADER] = api_key

    def submit_url(self, url):
        """Submit a URL for scanning and return the analysis id."""
        body = self._request("POST", URL_SUBMIT_PATH, data={"url": url})
        try:
            return body["data"]["id"]
        except (KeyError, TypeError):
            raise VirusTotalError("Unexpected response format from VirusTotal.") from None

    def get_analysis(self, analysis_id):
        """Return the attributes of an analysis (status, stats, results)."""
        return self._get_attributes(ANALYSIS_COLLECTION, analysis_id)

    def wait_for_analysis(self, analysis_id, on_poll=None):
        """Poll an analysis until it completes or POLL_TIMEOUT_SECONDS passes.

        `on_poll(status)` is called after every check, so the caller can
        show progress without the client printing anything.
        """
        deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(self._poll_delay())
            analysis = self.get_analysis(analysis_id)
            status = analysis.get("status")
            if on_poll:
                on_poll(status)
            if status == ANALYSIS_COMPLETED:
                return analysis
        raise AnalysisTimeoutError(
            f"The scan did not finish within {POLL_TIMEOUT_SECONDS} seconds. "
            f"Try again later with analysis id: {analysis_id}"
        )
    # ---------- private helpers ----------

    def _get_attributes(self, collection, identifier):
        """GET one object and return its 'attributes' section."""
        path = f"/{collection}/{quote(identifier, safe=PATH_SAFE_CHARS)}"
        body = self._request("GET", path)
        try:
            return body["data"]["attributes"]
        except (KeyError, TypeError):
            raise VirusTotalError("Unexpected response format from VirusTotal.") from None

    def _request(self, method, path, **kwargs):
        """Send a request to an API path and return the parsed JSON body."""
        response = self._send(method, f"{BASE_URL}{path}", **kwargs)
        try:
            return response.json()
        except ValueError:
            raise VirusTotalError("VirusTotal returned a response that is not JSON.") from None

    def _send(self, method, url, **kwargs):
        """Full URL in, raw Response out. Raises our exceptions on failure."""
        self._reserve_request_slot()
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.Timeout:
            raise NetworkError("The request timed out.") from None
        except requests.exceptions.RequestException:
            raise NetworkError("Could not reach VirusTotal. Check your internet connection.") from None
        if not response.ok:
            self._raise_for_error(response)
        return response

    def _reserve_request_slot(self):
        """Record a request, or raise RateLimitError if the window is full."""
        wait = self.rate_limiter.seconds_until_available()
        if wait > 0:
            raise RateLimitError(
                f"Free-tier limit reached ({REQUESTS_PER_WINDOW} requests "
                f"per {RATE_WINDOW_SECONDS} seconds).",
                wait_seconds=math.ceil(wait),
            )
        self.rate_limiter.record_request()

    def _raise_for_error(self, response):
        """Translate an HTTP error response into one of our exceptions."""
        message = self._error_message(response)
        match response.status_code:
            case HTTPStatus.UNAUTHORIZED:
                raise AuthError("Invalid API key. Check the VT_API_KEY environment variable.")
            case HTTPStatus.FORBIDDEN:
                raise AuthError(f"Permission denied: {message}")
            case HTTPStatus.NOT_FOUND:
                raise NotFoundError(message)
            case HTTPStatus.TOO_MANY_REQUESTS:
                raise RateLimitError(f"VirusTotal quota exceeded: {message}")
            case HTTPStatus.BAD_REQUEST:
                raise ValidationError(f"VirusTotal rejected the request: {message}")
            case _:
                raise VirusTotalError(
                    f"VirusTotal returned an error ({response.status_code}): {message}"
                )

    @staticmethod
    def _error_message(response):
        """Extract VirusTotal's error message ({"error": {"message": ...}}) if any."""
        try:
            body = response.json()
        except ValueError:
            return response.text or NO_DETAILS
        if not isinstance(body, dict):
            return NO_DETAILS
        error = body.get("error") or {}
        return error.get("message") or NO_DETAILS

    def _poll_delay(self):
        """Seconds to wait before the next poll: the interval or the rate limit, whichever is longer."""
        return max(POLL_INTERVAL_SECONDS, self.rate_limiter.seconds_until_available())