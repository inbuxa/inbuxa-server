#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-only
"""
Fail when the upstream project's name turns up in a new Rust string literal.

    tools/fork/name-check.py            # check; exit 1 on anything new
    tools/fork/name-check.py --list     # print every finding, allowlist format

The name belongs only in copyright notices and the lineage line. Everything
else a user or operator can see -- messages, the version string, service
names, descriptions -- carries INBUXA's. Merging an upstream release brings
new strings in with the name, and the merge itself can't tell, so this runs
in CI on every push and pull request.

Scope: string literals in `crates/**/*.rs`, test directories excluded.
Comments are skipped, so copyright headers and doc comments never match.
Some literals have to keep the name -- key-derivation contexts, wire-protocol
identifiers, defaults that read an upstream installation -- and those are
listed in `name-allowlist.txt` beside this script, each under the reason it
stays. A finding is matched by file and literal text, not line number, so
the allowlist survives code moving around.

When the check fails, rename the string. If it genuinely has to stay, add
the line `--list` prints for it to the allowlist under a reason.
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'name-allowlist.txt')
NAME = re.compile(r'stalwart|stalw\.art', re.IGNORECASE)
SKIP_DIRS = {'tests', 'benches', 'target', '.git'}
CHAR = re.compile(r"'(?:\\u\{[0-9a-fA-F]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'")
RAW = re.compile(r'b?r(#*)"')


def literals(src):
    """Yield the text of every string literal in `src`, comments skipped."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            i = src.find('\n', i)
            if i < 0:
                return
        elif src.startswith('/*', i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith('/*', i):
                    depth, i = depth + 1, i + 2
                elif src.startswith('*/', i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif c in 'br' and (m := RAW.match(src, i)) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')):
            end = '"' + m.group(1)
            j = src.find(end, m.end())
            if j < 0:
                return
            yield src[m.end():j]
            i = j + len(end)
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            yield src[i + 1:j]
            i = j + 1
        elif c == "'":
            # A char literal, or else a lifetime / label, which is skipped.
            m = CHAR.match(src, i)
            i = m.end() if m else i + 1
        else:
            i += 1


def findings():
    found = set()
    crates = os.path.join(ROOT, 'crates')
    for dirpath, dirnames, filenames in os.walk(crates):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            if not f.endswith('.rs'):
                continue
            path = os.path.join(dirpath, f)
            with open(path, encoding='utf-8', errors='replace') as fh:
                for lit in literals(fh.read()):
                    if NAME.search(lit):
                        found.add((os.path.relpath(path, ROOT), lit))
    return found


def fmt(entry):
    return f'{entry[0]}\t{json.dumps(entry[1], ensure_ascii=False)}'


def allowlist():
    allowed = set()
    with open(ALLOWLIST, encoding='utf-8') as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            path, sep, lit = line.partition('\t')
            try:
                allowed.add((path, json.loads(lit)))
            except (ValueError, TypeError):
                sys.exit(f'{ALLOWLIST}:{n}: expected "path<TAB>json string", got {line!r}')
            if not sep:
                sys.exit(f'{ALLOWLIST}:{n}: expected "path<TAB>json string", got {line!r}')
    return allowed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0].strip())
    ap.add_argument('--list', action='store_true', help='print every finding in allowlist format and exit')
    args = ap.parse_args()

    found = findings()
    if args.list:
        for entry in sorted(found):
            print(fmt(entry))
        return 0

    allowed = allowlist()
    new = sorted(found - allowed)
    stale = sorted(allowed - found)
    for entry in stale:
        # Gone from the code: harmless, but the list should shrink with it.
        print(f'stale allowlist entry, no longer in the code: {fmt(entry)}')
    if new:
        print(f'\n{len(new)} string literal(s) carry the upstream name. Rename them, or if one must stay,')
        print(f'add its line to {os.path.relpath(ALLOWLIST, ROOT)} under the reason:\n')
        for entry in new:
            print(fmt(entry))
        return 1
    print(f'name check: clean ({len(found)} allowlisted literal(s)).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
