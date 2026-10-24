from unittest.mock import patch

from cli import ThreatIntelCLI
from exceptions import NotFoundError

CLEAN_IP_REPORT = {
    "country": "US",
    "reputation": 0,
    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
    "last_analysis_results": {},
}

class FakeClient:
    """Stands in for VirusTotalClient: no network, counts calls."""

    def __init__(self, ip_report=None, raise_error=None):
        self.ip_report = ip_report
        self.raise_error = raise_error
        self.calls = 0

    def get_ip_report(self, ip):
        self.calls += 1
        if self.raise_error:
            raise self.raise_error
        return self.ip_report

def test_second_lookup_uses_cache():
    client = FakeClient(ip_report=CLEAN_IP_REPORT)
    cli = ThreatIntelCLI(client)

    with patch("builtins.input", side_effect=["8.8.8.8", "8.8.8.8"]):
        cli.lookup_ip()
        cli.lookup_ip()

    assert client.calls == 1
    assert cli.history[0].from_cache is False
    assert cli.history[1].from_cache is True

def test_invalid_input_asks_again_without_calling_api():
    client = FakeClient(ip_report=CLEAN_IP_REPORT)
    cli = ThreatIntelCLI(client)

    with patch("builtins.input", side_effect=["not-an-ip", ""]):
        cli.lookup_ip()

    assert client.calls == 0
    assert cli.history == []

def test_not_found_is_recorded_in_history(capsys):
    client = FakeClient(raise_error=NotFoundError("no record"))
    cli = ThreatIntelCLI(client)

    with patch("builtins.input", side_effect=["1.2.3.4"]):
        cli.lookup_ip()

    assert cli.history[0].verdict == "NOT FOUND"
    assert "was not found" in capsys.readouterr().out

def test_same_ipv6_in_two_forms_uses_cache():
    client = FakeClient(ip_report=CLEAN_IP_REPORT)
    cli = ThreatIntelCLI(client)

    with patch("builtins.input", side_effect=["2001:4860:4860:0000:0000:0000:0000:8888","2001:4860:4860::8888"]):
        cli.lookup_ip()
        cli.lookup_ip()

    assert client.calls == 1
