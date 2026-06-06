#!/usr/bin/env python
"""Test suite for surblclient"""

# Copyright (c) 2022 Filip Salomonsson
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

from unittest import TestCase, mock

from surblclient import surbl, uribl  # , spamhausdbl


class TestSurblclientTestCase(TestCase):
    """General tests for the surbl blocklist"""

    def test_surbl_pass(self):
        """Domains that are not listed in SURBL"""
        domains = ["google.com", "yahoo.com", "apple.com"]
        for domain in domains:
            self.assertNotIn(domain, surbl)
            self.assertFalse(surbl.lookup(domain))

    def test_surbl_test_points(self):
        """Known listed SURBL test domains"""
        lists = ["ph", "mw", "abuse", "cr"]
        self.assertIn("test.surbl.org", surbl)
        self.assertEqual(
            surbl.lookup("test.surbl.org"),
            ("test.surbl.org", lists),
        )
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
        self.assertIn("foo.bar.baz.test.multi.surbl.org", surbl)
        self.assertEqual(
            surbl.lookup("foo.bar.baz.test.multi.surbl.org"),
            ("test.multi.surbl.org", lists),
        )

    def test_surbl_domain_is_ip(self):
        """IP address lookup"""
        self.assertTrue("127.0.0.2" in surbl)
        result = surbl.lookup("127.0.0.2")
        self.assertEqual(result[0], "127.0.0.2")
        self.assertEqual(result[1], ["ph", "mw", "abuse", "cr"])

    def test_client_blocked(self):
        """Error bit set in response"""
        with mock.patch("socket.gethostbyname", return_value="127.0.0.1"):
            self.assertNotIn("somedomain.tld", surbl)
            result = surbl.lookup("somedomain.tld")
        self.assertIsNone(result)

    def test_uribl_pass(self):
        """Domains that are not listed in URIBL"""
        domains = ("google.com", "yahoo.com", "apple.com", "domain.tld")
        for domain in domains:
            self.assertFalse(domain in uribl)
            self.assertFalse(uribl.lookup(domain))

    def test_uribl_test_points(self):
        """Known listed URIBL test domains"""
        self.assertTrue("test.uribl.com" in uribl)
        self.assertTrue("foo.bar.baz.test.uribl.com" in uribl)

    def test_uribl_domain_is_ip(self):
        """IP address lookup"""
        self.assertTrue("127.0.0.2" in uribl)
        result = uribl.lookup("127.0.0.2")
        self.assertEqual(result[0], "127.0.0.2")
        self.assertEqual(result[1], ["black", "grey", "red"])
        self.assertIs(uribl.lookup("127.0.0.1"), False)

    # def test_spamhaus_pass(self):
    #     domains = ("google.com", "yahoo.com", "apple.com")
    #     for domain in domains:
    #         self.assertFalse(domain in spamhausdbl)
    #         self.assertFalse(uribl.lookup(domain))

    # def test_spamhaus_test_points(self):
    #     self.assertTrue("dbltest.com" in spamhausdbl)
    #     self.assertTrue("foo.bar.baz.dbltest.com" in spamhausdbl)
