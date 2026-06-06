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

"""SURBL multi blocklist"""

import importlib.resources

from .blacklist import Blacklist


def domains_from_resource(filename: str) -> set:
    """Return the domains listen in a data resource file"""
    resource_file = importlib.resources.files(__package__) / filename
    with resource_file.open("r", encoding="utf-8", errors="strict") as resource_fp:
        return set(resource_fp.read().split())


class SURBL(Blacklist):
    """Client for the multi.surbl.org blocklist"""

    domain = "multi.surbl.org."
    test_domains = {"surbl.org", "multi.surbl.org"}
    flags = [(8, "ph"), (16, "mw"), (64, "abuse"), (128, "cr")]

    def __init__(self) -> None:
        super().__init__()
        self._pseudo_tlds = (
            domains_from_resource("surbl-two-level-tlds")
            | domains_from_resource("surbl-three-level-tlds")
            | self.test_domains
        )

    def get_base_domain(self, domain: str) -> str:
        while domain.count(".") > 1:
            _, _, rest = domain.partition(".")
            if rest in self._pseudo_tlds:
                return domain
            domain = rest
        return domain
