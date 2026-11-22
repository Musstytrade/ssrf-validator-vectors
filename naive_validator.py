"""A typical hand-written URL check, as found in many code bases. Do NOT use it.

It parses the URL, blocks a few obvious names and, if the host is an IP literal,
blocks private ranges with the ipaddress module. It looks reasonable and is what
`python ssrf_vectors.py naive_validator:is_safe_url` measures.
"""
import ipaddress
from urllib.parse import urlparse

BLOCKED_NAMES = {"localhost", "metadata.google.internal"}


def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname or ""
    if host in BLOCKED_NAMES:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # "not an IP, so it is a normal domain name"
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)
