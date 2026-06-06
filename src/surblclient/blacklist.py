#!/usr/bin/env python
#
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

"""Main class for the blacklists"""

import socket
from typing import Literal


def is_ip_address(domain) -> bool:
    """Return True if `domain` is an IP address"""
    return all(part.isdigit() for part in domain.split("."))


class Blacklist:
    """An RBL blacklist"""

    domain = ""
    flags = []

    def __init__(self) -> None:
        self._cache = (None, None)

    def get_base_domain(self, domain: str) -> str:
        """Return the base domain to use for RBL lookup"""
        return domain

    def _lookup_exact(
        self, domain: str
    ) -> tuple[str, list[str]] | Literal[False] | None:
        """Like 'lookup', but checks the exact domain name given.
        Not for direct use.
        """
        cached_domain, flags = self._cache
        if cached_domain != domain:
            try:
                lookup_domain = domain
                if is_ip_address(domain):
                    lookup_domain = ".".join(reversed(domain.split(".")))
                ip_address = socket.gethostbyname(lookup_domain + "." + self.domain)
                flags = int(ip_address.split(".")[-1])
            except socket.gaierror as err:
                if err.errno in (socket.EAI_NONAME, socket.EAI_NODATA):
                    # No record found
                    flags = None
                    self._cache = (domain, flags)
                    return False
                # Unhandled error, pass test for now
                return None
            except OSError:
                # Not sure if this can happen. Timeouts?
                return None
            self._cache = (domain, flags)
        if flags:
            if flags & 1:
                # Blocked from making queries
                return None
            return (domain, [s for (n, s) in self.flags if flags & n])
        return False

    def lookup(self, domain: str) -> tuple[str, list[str]] | Literal[False] | None:
        """Extract base domain and check it against SURBL.
        Return (basedomain, lists) tuple, where basedomain is the
        base domain and lists is a list of strings indicating which
        blacklists the domain was found in.
        If there was no match, return False.
        If unsure (temporary error), return None.
        """
        # Remove userinfo
        if "@" in domain:
            domain = domain[domain.index("@") + 1 :]

        # Remove port
        if ":" in domain:
            domain = domain[: domain.index(":")]

        if not is_ip_address(domain):
            domain = self.get_base_domain(domain)
        return self._lookup_exact(domain)

    def __contains__(self, domain: str) -> bool:
        """Return True if base domain is listed in this blacklist;
        False otherwise.
        """
        return bool(self.lookup(domain))
