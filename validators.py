"""Pure input parsers. Each returns a normalized value, or None if invalid."""

import ipaddress
import re
from urllib.parse import urlparse

MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64
HASH_LENGTHS = {MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH}
HEX_PATTERN = re.compile(r"[0-9a-fA-F]+")
DOMAIN_PATTERN = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

MAX_URL_LENGTH = 2048
URL_SCHEMES = {"http", "https"}
DEFAULT_SCHEME = "http://"
SCHEME_SEPARATOR = "://"


def parse_ip(text):
    """Return a normalized IPv4/IPv6 address, or None."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse_domain(text):
    """Return a lowercase domain without a trailing dot, or None."""
    domain = text.lower().rstrip(".")
    return domain if DOMAIN_PATTERN.fullmatch(domain) else None


def parse_hash(text):
    """Return a lowercase MD5 / SHA-1 / SHA-256 hash, or None."""
    if len(text) in HASH_LENGTHS and HEX_PATTERN.fullmatch(text):
        return text.lower()
    return None


def parse_url(text):
    """Return a URL with a scheme (http:// added if missing), or None."""
    if len(text) > MAX_URL_LENGTH or " " in text:
        return None
    if SCHEME_SEPARATOR not in text:
        text = DEFAULT_SCHEME + text
    parsed = urlparse(text)
    if parsed.scheme not in URL_SCHEMES or not parsed.netloc:
        return None
    return text