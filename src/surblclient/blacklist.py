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
        cached_domain, ip_addresses = self._cache
        if cached_domain != domain:
            try:
                lookup_domain = domain
                if is_ip_address(domain):
                    lookup_domain = ".".join(reversed(domain.split(".")))
                # An RBL may return several A records (e.g. one per list); read
                # them all rather than just the first, which gethostbyname does.
                _, _, ip_addresses = socket.gethostbyname_ex(
                    lookup_domain + "." + self.domain
                )
            except socket.gaierror as err:
                if err.errno in (socket.EAI_NONAME, socket.EAI_NODATA):
                    # No record found
                    self._cache = (domain, None)
                    return False
                # Unhandled error, pass test for now
                return None
            except OSError:
                # Not sure if this can happen. Timeouts?
                return None
            self._cache = (domain, ip_addresses)
        if ip_addresses is None:
            return False
        return self._decode(domain, ip_addresses)

    def _decode(
        self, domain: str, ip_addresses: list[str]
    ) -> tuple[str, list[str]] | Literal[False] | None:
        """Interpret the 127.0.0.x answer(s) for `domain`.

        A DNSxL may return one A record per sublist, and a client "MUST
        interpret any returned A record as meaning that an address or domain is
        listed" -- hence we consider every record, not just the first
        (RFC 5782 sections 2.3 and 6).

        The default OR-combines the last octet of every returned record into a
        single bitmask over `self.flags` (the "bit masks" approach of RFC 5782
        section 6), with bit 0x1 meaning the query was refused (reported as
        unknown/None). Subclasses whose service uses a different encoding
        override this.
        """
        flags = 0
        for ip_address in ip_addresses:
            flags |= int(ip_address.split(".")[-1])
        if not flags:
            return False
        if flags & 1:
            # Blocked from making queries
            return None
        return (domain, [s for (n, s) in self.flags if flags & n])

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
