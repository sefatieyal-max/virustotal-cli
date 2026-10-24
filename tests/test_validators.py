import pytest

import validators


@pytest.mark.parametrize("text, expected", [
    ("8.8.8.8", "8.8.8.8"),
    ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888"),
    ("999.8.8.8", None),
    ("1.2.3", None),
    ("hello", None),
])


def test_parse_legal_ip(text, expected):
    assert validators.parse_ip(text) == expected

def test_caps_parse_hash():
    uppercase_hash = "A" * 32
    expected = "a" * 32
    assert validators.parse_hash(uppercase_hash) == expected


def test_url_no_scheme():
    assert validators.parse_url("example.com") == "http://example.com"


@pytest.mark.parametrize("domain, expected", [
    ("example.com", "example.com"),
    ("Example.com", "example.com"),
    ("localhost", None),
    ("a..com", None),
    ("-bad-.com", None),
    ("123.456", None),
])

def test_parse_domain(domain,expected):
    assert validators.parse_domain(domain) == expected