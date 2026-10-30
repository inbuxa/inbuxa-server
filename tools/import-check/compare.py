#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Diff two fixture snapshots. Every difference is printed; the ones listed in
the known-differences file (what inbuxa adds on start) are marked and don't
fail the check, and a listed one that no longer happens is reported too.

    compare.py expected.json actual.json [known-differences.txt]
"""
import json, sys


def differences(x, y, path=""):
    if isinstance(x, dict) and isinstance(y, dict):
        for k in sorted(set(x) | set(y)):
            p = f"{path}/{k}"
            if k not in x:
                yield f"+ {p}"
            elif k not in y:
                yield f"- {p}"
            else:
                yield from differences(x[k], y[k], p)
    elif isinstance(x, list) and isinstance(y, list) and all(isinstance(v, str) for v in x + y):
        for v in sorted(set(x) - set(y)):
            yield f"- {path} {v}"
        for v in sorted(set(y) - set(x)):
            yield f"+ {path} {v}"
    elif x != y:
        yield f"~ {path} {json.dumps(x)} => {json.dumps(y)}"


expected, actual = (json.load(open(f)) for f in sys.argv[1:3])
known = set()
if len(sys.argv) > 3:
    known = {line.strip() for line in open(sys.argv[3]) if line.strip() and not line.startswith("#")}

found = list(differences(expected, actual))
unexpected = [d for d in found if d not in known]
for d in found:
    print(("  known " if d in known else "  NEW   ") + d)
for d in sorted(known - set(found)):
    print("  GONE  " + d)
print(f"{len(found)} difference(s), {len(unexpected)} not known, {len(known - set(found))} known but gone")
sys.exit(1 if unexpected else 0)
