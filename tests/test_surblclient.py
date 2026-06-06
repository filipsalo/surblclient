#!/usr/bin/env python
"""Deterministic unit tests for surblclient.

These tests mock the DNS layer so they exercise the library's own logic
(flag decoding, base-domain extraction, IP reversal, blocked/not-listed
handling) without touching the live SURBL/URIBL services. The live services
block public resolvers and rate-limit, so they make a poor test fixture; the
real round-trip is covered separately in test_live.py (opt-in).
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

import socket
from unittest import TestCase, mock

from surblclient.surbl import SURBL
from surblclient.uribl import URIBL


def fake_resolver(responses):
    """Return a `socket.gethostbyname` stand-in backed by a {query: ip} map.

    `query` is the exact name the library looks up, i.e. the candidate domain
    (or reversed IP) with the blocklist zone appended. Any name not in the map
    raises gaierror(EAI_NONAME), exactly as a real "not listed" answer does.
    """

    def _resolve(name):
        try:
            return responses[name]
        except KeyError:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    return _resolve


def query(blacklist, name):
    """The exact name `blacklist` will hand to gethostbyname for `name`."""
    return f"{name}.{blacklist.domain}"


class SurblDecodingTestCase(TestCase):
    """SURBL flag decoding and lookup logic, with DNS mocked."""

    def setUp(self):
        # Fresh instance per test so the per-instance lookup cache never leaks.
        self.surbl = SURBL()

    def lookup_with(self, responses, domain):
        with mock.patch("socket.gethostbyname", side_effect=fake_resolver(responses)):
            return self.surbl.lookup(domain), domain in self.surbl

    def test_listed_all_flags(self):
        """A response with every SURBL bit set decodes to every label."""
        responses = {query(self.surbl, "test.surbl.org"): "127.0.0.254"}
        result, contained = self.lookup_with(responses, "test.surbl.org")
        self.assertEqual(result, ("test.surbl.org", ["ph", "mw", "abuse", "cr"]))
        self.assertTrue(contained)

    def test_listed_subset_flags(self):
        """Only the bits present are decoded (8 | 16 -> ph, mw)."""
        responses = {query(self.surbl, "test.surbl.org"): "127.0.0.24"}
        result, _ = self.lookup_with(responses, "test.surbl.org")
        self.assertEqual(result, ("test.surbl.org", ["ph", "mw"]))

    def test_not_listed(self):
        """NXDOMAIN means not listed: lookup() is False, `in` is False."""
        result, contained = self.lookup_with({}, "example.com")
        self.assertIs(result, False)
        self.assertFalse(contained)

    def test_blocked(self):
        """127.0.0.1 (bit 0x1) means the query was refused / we can't tell.

        lookup() returns None (unknown), and `in` necessarily collapses that
        to False -- which is exactly why callers must not rely on `in` alone.
        See the "Resolver requirements" section of the README.
        """
        responses = {query(self.surbl, "example.com"): "127.0.0.1"}
        result, contained = self.lookup_with(responses, "example.com")
        self.assertIsNone(result)
        self.assertFalse(contained)

    def test_base_domain_extraction(self):
        """A deep subdomain is reduced to its base domain before lookup."""
        responses = {query(self.surbl, "example.com"): "127.0.0.254"}
        result, _ = self.lookup_with(responses, "deep.sub.example.com")
        self.assertEqual(result[0], "example.com")

    def test_ip_address_is_reversed(self):
        """An IP is reversed octet-wise before the zone is appended."""
        responses = {query(self.surbl, "2.0.0.127"): "127.0.0.254"}
        result, contained = self.lookup_with(responses, "127.0.0.2")
        self.assertEqual(result[0], "127.0.0.2")
        self.assertTrue(contained)

    def test_userinfo_and_port_are_stripped(self):
        """user@host:port is reduced to the bare host before lookup."""
        responses = {query(self.surbl, "example.com"): "127.0.0.254"}
        result, _ = self.lookup_with(responses, "user@deep.example.com:8080")
        self.assertEqual(result[0], "example.com")


class UriblDecodingTestCase(TestCase):
    """URIBL reuses SURBL's logic but with its own zone and flag set."""

    def setUp(self):
        self.uribl = URIBL()

    def lookup_with(self, responses, domain):
        with mock.patch("socket.gethostbyname", side_effect=fake_resolver(responses)):
            return self.uribl.lookup(domain), domain in self.uribl

    def test_listed_all_flags(self):
        """2 | 4 | 8 decodes to black, grey, red."""
        responses = {query(self.uribl, "test.uribl.com"): "127.0.0.14"}
        result, contained = self.lookup_with(responses, "test.uribl.com")
        self.assertEqual(result, ("test.uribl.com", ["black", "grey", "red"]))
        self.assertTrue(contained)

    def test_listed_subset_flags(self):
        """A single bit decodes to a single label."""
        responses = {query(self.uribl, "test.uribl.com"): "127.0.0.2"}
        result, _ = self.lookup_with(responses, "test.uribl.com")
        self.assertEqual(result, ("test.uribl.com", ["black"]))

    def test_not_listed(self):
        result, contained = self.lookup_with({}, "example.com")
        self.assertIs(result, False)
        self.assertFalse(contained)
