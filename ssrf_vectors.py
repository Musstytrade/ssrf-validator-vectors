#!/usr/bin/env python3
"""Run SSRF test vectors against YOUR URL validator.

Usage:
    python ssrf_vectors.py naive_validator:is_safe_url
    python ssrf_vectors.py mypackage.security:validate_url

The target is "module:function". The function receives one URL string and must
return a truthy value to ALLOW the URL, or return a falsy value / raise to REFUSE it.

Every vector below points at loopback, a private network, link-local / cloud
metadata, or carries credentials, so a safe validator refuses all of them.
A few public controls must be allowed (otherwise the validator is useless).

Offline: nothing is fetched. Hostnames such as "localhost" are only resolved if
your validator resolves them. Standard library only. MIT licence (see LICENSE).

What this does NOT test (by design): redirects, DNS rebinding between check and
fetch, and headless-browser sub-resources. Those are exactly the cases a
validator cannot cover on its own; see README.md.
"""
from __future__ import annotations

import importlib
import sys
from typing import Callable

# (url, why it must be refused)
MUST_REFUSE: list[tuple[str, str]] = [
    ("http://127.0.0.1/", "loopback"),
    ("http://localhost/", "loopback name"),
    ("http://localhost./", "loopback name with trailing dot"),
    ("http://LOCALHOST/", "loopback name, upper case"),
    ("http://127.1/", "short IPv4 form (browsers expand to 127.0.0.1)"),
    ("http://0x7f.1/", "hex + short IPv4 form"),
    ("http://0x7f000001/", "single hex number"),
    ("http://2130706433/", "single decimal number"),
    ("http://017700000001/", "single octal number"),
    ("http://0177.0.0.1/", "octal first octet"),
    ("http://0/", "0.0.0.0 short form"),
    ("http://0.0.0.0/", "unspecified address"),
    ("http://[::1]/", "IPv6 loopback"),
    ("http://[::ffff:127.0.0.1]/", "IPv4-mapped IPv6 loopback"),
    ("http://[::ffff:7f00:1]/", "IPv4-mapped IPv6 loopback, hex"),
    ("http://[0:0:0:0:0:ffff:a9fe:a9fe]/", "IPv4-mapped cloud metadata"),
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata (AWS/GCP/Azure style)"),
    ("http://[fd00:ec2::254]/", "AWS IMDS IPv6"),
    ("http://10.0.0.5/admin", "private 10/8"),
    ("http://172.16.0.1/", "private 172.16/12"),
    ("http://192.168.1.1/", "private 192.168/16"),
    ("http://100.64.0.1/", "carrier-grade NAT 100.64/10"),
    ("http://[fc00::1]/", "IPv6 unique local"),
    ("http://[fe80::1]/", "IPv6 link-local"),
    ("http://user:pw@example.com/", "credentials in URL"),
    ("http://example.com@127.0.0.1/", "userinfo confusion, real host is 127.0.0.1"),
    ("http://127.0.0.1:6379/", "internal service port (Redis)"),
    ("file:///etc/passwd", "non-HTTP scheme"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher smuggling"),
]

MUST_ALLOW: list[str] = [
    "https://example.com/",
    "http://example.com/path?q=1",
    "https://93.184.215.14/",
]


class UsageError(Exception):
    """Bad target: reported with exit code 2, never mistaken for a leak (exit 1)."""


def _load(target: str) -> Callable[[str], object]:
    module_name, sep, func_name = target.partition(":")
    if not sep or not module_name or not func_name:
        raise UsageError("target must look like module:function")
    sys.path.insert(0, ".")
    try:
        func = getattr(importlib.import_module(module_name), func_name)
    except (ImportError, AttributeError) as exc:
        raise UsageError(f"cannot load {target}: {exc}") from exc
    if not callable(func):
        raise UsageError(f"{target} is not callable")
    return func


def _allowed(func: Callable[[str], object], url: str) -> bool:
    try:
        return bool(func(url))
    except Exception:  # raising counts as refusing
        return False


def run(func: Callable[[str], object]) -> int:
    leaks = 0
    for url, why in MUST_REFUSE:
        ok = not _allowed(func, url)
        leaks += not ok
        print(f"{'refused' if ok else 'LEAKED '}  {url:<42} {why}")
    broken = 0
    for url in MUST_ALLOW:
        ok = _allowed(func, url)
        broken += not ok
        print(f"{'allowed' if ok else 'BLOCKED'}  {url:<42} public control")
    print(f"\n{leaks} of {len(MUST_REFUSE)} dangerous URLs leaked, "
          f"{broken} of {len(MUST_ALLOW)} public controls blocked.")
    print("Not covered here: redirects, DNS rebinding, headless-browser sub-resources (see README).")
    return 1 if leaks or broken else 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        func = _load(argv[1])
    except UsageError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return 2
    return run(func)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
