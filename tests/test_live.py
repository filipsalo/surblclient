#!/usr/bin/env python
"""Live integration tests against the real SURBL/URIBL services.

These hit the network and only work when the host's DNS goes through a
non-public recursive resolver -- SURBL and URIBL refuse queries from public
resolvers and rate-limit heavy users, returning 127.0.0.1 ("blocked"), so a
public resolver makes every assertion here flap. See the README's "Resolver
requirements" section.

They are therefore skipped unless SURBL_LIVE_TESTS is set in the environment:

    SURBL_LIVE_TESTS=1 uv run python -m unittest -v
"""

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

import os
from unittest import TestCase, skipUnless

from surblclient import spamhausdbl, surbl, uribl

LIVE = skipUnless(
    os.environ.get("SURBL_LIVE_TESTS"),
    "live network test; set SURBL_LIVE_TESTS=1 (needs a non-public resolver)",
)


@LIVE
class LiveSurblTestCase(TestCase):
    """Real lookups against multi.surbl.org."""

    def test_surbl_pass(self):
        """Domains that are not listed in SURBL"""
        for domain in ["google.com", "yahoo.com", "apple.com"]:
            self.assertNotIn(domain, surbl)
            self.assertFalse(surbl.lookup(domain))

    def test_surbl_test_points(self):
        """Known listed SURBL test domains"""
        lists = ["ph", "mw", "abuse", "cr"]
        self.assertIn("test.surbl.org", surbl)
        self.assertEqual(surbl.lookup("test.surbl.org"), ("test.surbl.org", lists))
        self.assertIn("test.multi.surbl.org", surbl)
        self.assertEqual(
            surbl.lookup("test.multi.surbl.org"),
            ("test.multi.surbl.org", lists),
        )
        self.assertIn("foo.bar.baz.test.surbl.org", surbl)
        self.assertEqual(
            surbl.lookup("foo.bar.baz.test.surbl.org"),
            ("test.surbl.org", lists),
        )

    def test_surbl_domain_is_ip(self):
        """IP address lookup"""
        self.assertIn("127.0.0.2", surbl)
        result = surbl.lookup("127.0.0.2")
        self.assertEqual(result[0], "127.0.0.2")
        self.assertEqual(result[1], ["ph", "mw", "abuse", "cr"])


@LIVE
class LiveUriblTestCase(TestCase):
    """Real lookups against multi.uribl.com."""

    def test_uribl_pass(self):
        """Domains that are not listed in URIBL"""
        for domain in ("google.com", "yahoo.com", "apple.com", "domain.tld"):
            self.assertNotIn(domain, uribl)
            self.assertFalse(uribl.lookup(domain))

    def test_uribl_test_points(self):
        """Known listed URIBL test domains"""
        self.assertIn("test.uribl.com", uribl)
        self.assertIn("foo.bar.baz.test.uribl.com", uribl)

    def test_uribl_domain_is_ip(self):
        """IP address lookup"""
        self.assertIn("127.0.0.2", uribl)
        result = uribl.lookup("127.0.0.2")
        self.assertEqual(result[0], "127.0.0.2")
        self.assertEqual(result[1], ["black", "grey", "red"])
        self.assertIs(uribl.lookup("127.0.0.1"), False)


@LIVE
class LiveSpamhausDBLTestCase(TestCase):
    """Real lookups against dbl.spamhaus.org."""

    def test_dbl_pass(self):
        """Domains that are not listed in the DBL"""
        for domain in ("google.com", "yahoo.com", "apple.com"):
            self.assertNotIn(domain, spamhausdbl)
            self.assertFalse(spamhausdbl.lookup(domain))

    def test_dbl_test_points(self):
        """Known listed DBL test domain (and a subdomain of it)"""
        self.assertIn("dbltest.com", spamhausdbl)
        self.assertIn("foo.bar.baz.dbltest.com", spamhausdbl)
