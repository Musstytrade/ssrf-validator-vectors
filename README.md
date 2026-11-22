# ssrf-validator-vectors

Run 29 SSRF test vectors against **your own** Python URL validator in seconds. One file, standard library only,
offline (nothing is fetched), MIT licence.

```console
git clone https://github.com/Musstytrade/ssrf-validator-vectors.git && cd ssrf-validator-vectors
python ssrf_vectors.py naive_validator:is_safe_url       # the bundled bad example
python ssrf_vectors.py yourpackage.security:is_safe      # your function: url -> truthy = allow
```

Exit code 0 = nothing leaked and all public controls were allowed, 1 = a vector leaked or a control was blocked,
2 = usage error (bad target, import failure). Use it in CI. Tested with CPython 3.11.

> **Disclosure:** I also sell a paid product for the part a validator cannot fix (below):
> [Egress Guard Kit, USD 39 on Gumroad](https://starsoftware.gumroad.com/l/egress-guard-kit). This repository
> contains none of its code and is useful without it.

## Recorded result: a typical hand-written check

`naive_validator.py` is the pattern seen in many code bases: block `localhost`, parse IP literals with `ipaddress`,
treat everything else as a domain. Real output (CPython 3.11.2, Linux, 2026-11-22), showing only the leaked lines and
the summary; the full run also prints the 19 refused vectors and the 3 public controls:

```console
LEAKED   http://localhost./                         loopback name with trailing dot
LEAKED   http://127.1/                              short IPv4 form (browsers expand to 127.0.0.1)
LEAKED   http://0x7f.1/                             hex + short IPv4 form
LEAKED   http://0x7f000001/                         single hex number
LEAKED   http://2130706433/                         single decimal number
LEAKED   http://017700000001/                       single octal number
LEAKED   http://0177.0.0.1/                         octal first octet
LEAKED   http://0/                                  0.0.0.0 short form
LEAKED   http://100.64.0.1/                         carrier-grade NAT 100.64/10
LEAKED   http://user:pw@example.com/                credentials in URL
10 of 29 dangerous URLs leaked, 0 of 3 public controls blocked.
```

On that interpreter the naive check refused the IPv4-mapped IPv6 vectors. How `ipaddress` classifies such addresses
has changed between CPython releases, so run the vectors on the version you deploy rather than trusting this output.

## What no validator can fix

Even a validator that refuses all 29 vectors still loses in three ordinary situations, because the check and the
fetch are two separate steps:

```python
if is_safe_url(url):   # check: resolves the host, sees a public address
    fetch(url)         # fetch: resolves AGAIN or follows a redirect -> internal address
```

1. **Redirects.** The checked URL answers `302 Location: http://169.254.169.254/latest/meta-data/`.
2. **DNS rebinding.** The second lookup returns a private address (2026 example: CVE-2026-41488, langchain-openai
   before 1.1.14 validated image URLs and then fetched them with an independent DNS resolution).
3. **Headless browsers.** A rendered page loads images, iframes, `fetch()` calls and WebSockets your check never
   saw. Chromium also skips a configured proxy for loopback unless you change its bypass list. Page loaders are
   easy to leave outside the check altogether (CVE-2026-91938: in Flowise before 3.1.4 the Cheerio, Playwright and
   Puppeteer document loaders bypassed its SSRF protection).

The fix is to enforce at connect time: resolve once, refuse unless every address is public, connect to exactly that
address, on every hop. Free options if you use a single client (not affiliated; licences as listed on PyPI):
`requests-hardened` (requests, BSD-3-Clause) and `drawbridge` (httpx, MIT).

## The paid kit (disclosed)

Egress Guard Kit is one stdlib proxy on `127.0.0.1` that every HTTP client and headless Chromium goes through.
Recorded from the published release `egress_guard_kit-0.1.1.zip` (not edited):

```text
$ python -m egress_guard check http://169.254.169.254/latest/meta-data/
{"allowed": false, "code": "destination_not_public"}
$ python -m egress_guard check http://0x7f.1/
{"allowed": false, "code": "destination_not_public"}
$ python -m egress_guard check http://2130706433/
{"allowed": false, "code": "destination_not_public"}
$ python -m egress_guard check http://user:pw@example.com/
{"allowed": false, "code": "credentials_in_url"}
$ python -m egress_guard check https://example.com/
{"allowed": true, "scheme": "https", "host": "example.com", "port": 443}

$ python -m egress_guard serve --port 8899 &
$ fetch http://169.254.169.254/latest/meta-data/ via http://127.0.0.1:8899
HTTP 403  X-Egress-Code: destination_not_public
$ fetch http://10.0.0.5/admin via http://127.0.0.1:8899
HTTP 403  X-Egress-Code: destination_not_public
$ fetch https://example.com/ via http://127.0.0.1:8899
HTTP 200
```

Run through this repository's vectors (`egress_guard check` as the function), the kit refused 29 of 29 and allowed
all 3 public controls.

| Your situation | Use |
|---|---|
| Only `requests` | `requests-hardened` (free) may be enough |
| Only `httpx` | `drawbridge` (free) may be enough |
| Headless Chromium, subprocesses, several clients | one enforcing proxy, e.g. the kit |
| Fixed list of APIs | a static allowlist, no kit needed |

Kit limits: guards only traffic that goes through it · public destinations are allowed by design · no TLS
interception · HTTP/1.x proxy + CONNECT only, no UDP/QUIC · tested on Linux/CPython 3.11 with urllib and headless
Chromium · no independent third-party audit.

## Contributing

New vectors are welcome as issues or pull requests: one line, the URL and why it must be refused.

## Licence

MIT (see `LICENSE`) for the files in this repository only. Egress Guard Kit is a separate, paid product under its own
licence and is not included here.
