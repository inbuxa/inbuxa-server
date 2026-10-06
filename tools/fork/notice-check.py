#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Fail when an upstream file the fork changed doesn't say so (AGPL section 5(a)).

    tools/fork/notice-check.py          # check; exit 1 on a missing notice
    tools/fork/notice-check.py --fix    # add the notice where it's missing

The AGPL asks a modified work to carry a prominent notice that it was
modified, with a date. Every upstream file this fork changes carries one
beneath upstream's own notice:

     * Modified by Coffey Labs in 2026 for INBUXA.

"Changed" is measured against the newest stripped snapshot this tree has
merged, a commit on the `upstream` branch (docs/spec/SPEC.md §2.2a), so the
list is what actually differs rather than a guess. It's found in the tree's
own history, by the strip's commit subject, not taken from the branch head:
a branch that merges a new release is checked against it, and every other
branch against the release it's built on, whenever the `upstream` branch
moves. A file counts as
upstream's when its header names Stalwart Labs as a copyright holder; files
the fork wrote carry their own copyright and need nothing. Files with no
comment header at all (README, manifests) are covered by the README's prose.
"""
import argparse
import datetime
import re
import subprocess
import sys

HEADER_LINES = 15
UPSTREAM_HOLDER = re.compile(r'SPDX-FileCopyrightText:.*Stalwart Labs')
NOTICE = re.compile(r'Modified by Coffey Labs in \d{4}')
LICENSE_LINE = re.compile(r'^(\s*(?:\*|//|#)\s*)SPDX-License-Identifier:.*$')


def git(*args):
    return subprocess.run(['git', *args], check=True, capture_output=True, text=True).stdout


def snapshot_ref():
    ref = git('log', '-1', '--format=%h', '--grep=^Import upstream v',
              '--grep=^Re-import upstream v', 'HEAD').strip()
    if not ref:
        sys.exit('notice-check: no upstream snapshot in this history; fetch it in full first')
    return ref


def changed_upstream_files(ref):
    # Against the working tree, not HEAD, so it also checks work not yet
    # committed; in CI the two are the same.
    for path in git('diff', '--name-only', '--diff-filter=M', ref).splitlines():
        try:
            head = open(path, encoding='utf-8').read().split('\n')[:HEADER_LINES]
        except (OSError, UnicodeDecodeError):
            continue
        if any(UPSTREAM_HOLDER.search(line) for line in head):
            yield path, head


def add_notice(path):
    """Put the notice under the license line, in that comment's own style."""
    lines = open(path, encoding='utf-8').read().split('\n')
    for n, line in enumerate(lines[:HEADER_LINES]):
        m = LICENSE_LINE.match(line)
        if m:
            prefix = m.group(1)
            blank = prefix.rstrip()
            year = datetime.date.today().year
            lines[n + 1:n + 1] = [blank, f'{prefix}Modified by Coffey Labs in {year} for INBUXA.']
            open(path, 'w', encoding='utf-8').write('\n'.join(lines))
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0].strip())
    ap.add_argument('--fix', action='store_true', help='add the notice to every file missing it')
    args = ap.parse_args()

    ref = snapshot_ref()
    checked, missing = 0, []
    for path, head in changed_upstream_files(ref):
        checked += 1
        if not any(NOTICE.search(line) for line in head):
            missing.append(path)

    if args.fix:
        unfixable = [p for p in missing if not add_notice(p)]
        for p in sorted(set(missing) - set(unfixable)):
            print(f'added: {p}')
        missing = unfixable

    if missing:
        print(f'{len(missing)} upstream file(s) changed against {ref} without the modification notice:\n')
        for p in missing:
            print(f'  {p}')
        print('\nAdd "Modified by Coffey Labs in <year> for INBUXA." under the license line, '
              'or run tools/fork/notice-check.py --fix.')
        return 1
    print(f'notice check: clean ({checked} changed upstream file(s), all marked; against {ref}).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
