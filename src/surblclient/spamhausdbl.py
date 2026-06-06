#!/usr/bin/env python
#
# Copyright (c) 2026 Filip Salo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Spamhaus DBL domain blocklist."""

from typing import Literal

from .surbl import SURBL


class SpamhausDBL(SURBL):
    """Client for the Spamhaus DBL (dbl.spamhaus.org) domain blocklist.

    Unlike SURBL/URIBL, the DBL does not pack independent lists into a bitmask.
    It returns a single enumerated code in the 127.0.1.x range:

      * 127.0.1.2  - 127.0.1.99  -> listed; "inherently bad" / safe to block
      * 127.0.1.102 - 127.0.1.199 -> "abused-legit": otherwise-good domains
        observed in abuse (e.g. compromised sites); meant for scoring, not
        outright blocking.

    Error answers live in the 127.255.255.x range and mean the query could not
    be served -- reported as unknown (None):

      * 127.255.255.252 -> typing error / direct test
      * 127.255.255.254 -> query came via a public/open resolver
      * 127.255.255.255 -> excessive number of queries

    Like SURBL/URIBL, Spamhaus blocks queries from public/open resolvers and
    rate-limits; see the README's "Resolver requirements" section.

    Spamhaus documents only the two listing *ranges* as stable, so this client
    classifies by range rather than by individual code.

    Refs: https://www.spamhaus.org/faqs/dnsbl-usage/ and
    https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html
    """

    domain = "dbl.spamhaus.org."
    # DBL's test point (dbltest.com) is a normal registered domain, so the
    # inherited base-domain reduction already resolves subdomains to it; no
    # pseudo-TLD entries are needed.
    test_domains: set[str] = set()
    flags: list[tuple[int, str]] = []

    def _decode(
        self, domain: str, ip_addresses: list[str]
    ) -> tuple[str, list[str]] | Literal[False] | None:
        # The DBL's codes are enumerated, so decode with value-range tests
        # rather than a bitmask (both are sanctioned by RFC 5782 section 6).
        labels: list[str] = []
        for ip_address in ip_addresses:
            octets = ip_address.split(".")
            # Listings are 127.0.1.x. Anything else (the 127.255.255.x error
            # range, or anything unexpected) means we couldn't get a real
            # answer for this query at all.
            if octets[:3] != ["127", "0", "1"]:
                return None
            code = int(octets[3])
            if 2 <= code <= 99:
                label = "bad"
            elif 102 <= code <= 199:
                label = "abused-legit"
            else:
                continue
            if label not in labels:
                labels.append(label)
        if not labels:
            return False
        return (domain, labels)
