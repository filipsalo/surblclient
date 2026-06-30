# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-30

### Added

- URIBL support alongside SURBL, with the same `in` / `lookup()` interface.
- Spamhaus DBL support, distinguishing `"bad"` from `"abused-legit"` hits per
  the service's two return-code ranges.
- Type hints throughout the public API.

### Changed

- A lookup now combines **all** returned `127.0.0.x` records rather than only
  the first, per [RFC 5782](https://www.rfc-editor.org/rfc/rfc5782.html) §6
  (bit masks for SURBL/URIBL, value-range tests for the DBL).
- `lookup()` now returns `None` for an unknown/refused answer (temporary DNS
  error or a refusal from a public resolver), `False` only for a confirmed
  non-listing, and a `(base_domain, lists)` tuple on a hit.
- Requires Python 3.10+.
- Project now uses `importlib.resources` to load the bundled TLD data.

### Tooling

- Moved to [uv](https://docs.astral.sh/uv/) for environment and build
  management, Codeberg for hosting, and Forgejo Actions for CI/release.
- Tests mock DNS, so the default suite is deterministic and offline; live
  integration tests are opt-in via `SURBL_LIVE_TESTS=1`.

[0.2.0]: https://codeberg.org/filipsalo/surblclient/releases/tag/v0.2.0
</content>
</invoke>
