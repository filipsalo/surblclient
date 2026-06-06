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
not listed, and `None` on a temporary lookup error.

The same interface is available for URIBL:

```python
>>> from surblclient import uribl
>>> "test.uribl.com" in uribl
True
```

## Development

This project is managed with [uv](https://docs.astral.sh/uv/).

```sh
uv sync                      # set up the environment
uv run python -m unittest -v # run the tests
uv build                     # build the wheel and sdist
```

## License

MIT — see [LICENSE](LICENSE).
