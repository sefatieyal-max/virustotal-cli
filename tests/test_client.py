import pytest
import responses

from client import BASE_URL, VirusTotalClient
from exceptions import AuthError, NotFoundError, RateLimitError, VirusTotalError

IP = "1.2.3.4"
IP_URL = f"{BASE_URL}/ip_addresses/{IP}"
FAKE_KEY = "fake_api_key"



@responses.activate
def test_returns_attributes_on_success():
    responses.get(IP_URL, json={"data": {"attributes": {"country": "US"}}}, status=200)
    assert VirusTotalClient(FAKE_KEY).get_ip_report(IP) == {"country": "US"}


@responses.activate
def test_404_raises_not_found_error():
    responses.get(IP_URL, json={"error": {"message": "not found"}}, status=404)
    with pytest.raises(NotFoundError):
        VirusTotalClient(FAKE_KEY).get_ip_report(IP)


@responses.activate
def test_401_raises_auth_error():
    responses.get(IP_URL, json={"error": {"message": "wrong key"}}, status=401)
    with pytest.raises(AuthError):
        VirusTotalClient(FAKE_KEY).get_ip_report(IP)


@responses.activate
def test_429_raises_rate_limit_error_without_wait():
    responses.get(IP_URL, json={"error": {"message": "quota exceeded"}}, status=429)
    with pytest.raises(RateLimitError) as error_info:
        VirusTotalClient(FAKE_KEY).get_ip_report(IP)
    assert error_info.value.wait_seconds is None

@responses.activate
def test_html_body_raises_virus_total_error():
    responses.get(IP_URL, body="<html>oops</html>", status=200)
    with pytest.raises(VirusTotalError, match="not JSON"):
        VirusTotalClient(FAKE_KEY).get_ip_report(IP)