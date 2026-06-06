# surblclient

A small client library for querying [SURBL](http://www.surbl.org/), URIBL,
and other RBL-style blocklists over DNS.

Give it a domain (or URL host, or IP address) and it tells you whether the
domain is listed, and on which sub-lists.

## Installation

```sh
uv add surblclient
```

Or, from a checkout:

```sh
uv pip install .
```

## Usage

```python
>>> from surblclient import surbl
>>> "test.surbl.org" in surbl
True
>>> surbl.lookup("test.surbl.org")
('test.surbl.org', ['ph', 'mw', 'abuse', 'cr'])
>>> "google.com" in surbl
False
```

`lookup` resolves the base domain before querying, so subdomains work too:

```python
>>> surbl.lookup("foo.bar.baz.test.surbl.org")
('test.surbl.org', ['ph', 'mw', 'abuse', 'cr'])
```

It returns a `(base_domain, lists)` tuple on a hit, `False` when the domain is
confirmed **not** listed, and `None` when the answer is **unknown** — a
temporary DNS error, or the service refusing the query (see below).

The same interface is available for URIBL:

```python
>>> from surblclient import uribl
>>> "test.uribl.com" in uribl
True
```

Note that `in` can only return a bool, so it collapses the `None`
(unknown/refused) case into `False`. If you need to distinguish "not listed"
from "couldn't check", use `lookup()` and test for `None`:

```python
result = surbl.lookup(domain)
if result is None:
    ...        # unknown — do NOT treat as clean (often a blocked resolver)
elif result is False:
    ...        # confirmed not listed
else:
    base, lists = result   # listed
```

## Resolver requirements

SURBL and URIBL **refuse queries that arrive via public/shared DNS resolvers**
(Google Public DNS, OpenDNS, Cloudflare, and most ISP caching resolvers) and
rate-limit heavy users. A refused query comes back as `127.0.0.1`, which this
library reports as `None` (unknown) — so on a public resolver every lookup
silently returns "unknown" and the library can't do its job.

This is the services' documented anti-abuse policy, not a bug in this library:

- URIBL — *"All queries that we refuse, we return a 127.0.0.1 response to …
  Public DNS providers such as OpenDNS or Google Public DNS are effected due to
  the high volume of queries they generate, as are many other internet service
  providers (ISP) that use caching nameservers …"*
  ([uribl.com/refused.shtml](http://uribl.com/refused.shtml))
- SURBL — *"If you get a result of 127.0.0.1 when doing a DNS query into the
  public nameservers, then it means your access is blocked … A good
  administrative solution is to run a local caching nameserver …"*
  ([surbl.org/faq/guidelines](https://www.surbl.org/faq/guidelines))

To use this library reliably, run your **own recursive resolver** (e.g.
[unbound](https://nlnetlabs.nl/projects/unbound/)) on the machine doing the
checks and point it at the DNS roots, then resolve through `127.0.0.1`. High
volume use needs a [data feed](https://www.surbl.org/data-feed) /
[datafeed](http://uribl.com/datafeed.shtml) instead of the public DNS mirrors;
the free public service has [usage limits](https://www.surbl.org/usage-policy)
(broadly, fewer than 1,000 users or 250,000 messages/day).

## Development

This project is managed with [uv](https://docs.astral.sh/uv/).

```sh
uv sync                      # set up the environment
uv run python -m unittest -v # run the tests (mocked; no network)
uv build                     # build the wheel and sdist
```

The default test run mocks DNS, so it is deterministic and offline. The live
integration tests in `tests/test_live.py` hit the real services and are skipped
unless you opt in — and they only pass through a non-public resolver (see
[Resolver requirements](#resolver-requirements)):

```sh
SURBL_LIVE_TESTS=1 uv run python -m unittest -v
```

## License

MIT — see [LICENSE](LICENSE).
