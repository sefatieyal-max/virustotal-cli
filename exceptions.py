"""Custom exceptions raised by the VirusTotal client."""


class VirusTotalError(Exception):
    """Base class for every error raised by the VirusTotal client."""


class AuthError(VirusTotalError):
    """The API key is invalid or lacks permission."""


class NotFoundError(VirusTotalError):
    """VirusTotal has no record of the requested indicator."""


class ValidationError(VirusTotalError):
    """VirusTotal rejected the request as invalid."""


class NetworkError(VirusTotalError):
    """The request never got a response (timeout, DNS, connection)."""


class RateLimitError(VirusTotalError):
    """The request quota was exceeded."""

    def __init__(self, message, wait_seconds=None):
        super().__init__(message)
        self.wait_seconds = wait_seconds

class AnalysisTimeoutError(VirusTotalError):
    """A submitted analysis did not finish within the time limit."""