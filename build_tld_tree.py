#!/usr/bin/env python
from __future__ import print_function

import sys
from collections import defaultdict

tree = {}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split(".")
    t = tree
    for part in parts[::-1]:
        if part not in t:
            t[part] = {}
        t = t[part]


def print_tree(tree, level=0):
    for key in sorted(tree):
        print(" " * level + key)
        print_tree(tree[key], level + 1)

# import json
# print(json.dumps(tree, indent=2))
# print_tree(tree)

