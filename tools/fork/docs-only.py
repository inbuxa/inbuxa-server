#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Say whether a branch changes only documentation, so CI can skip its build.

    tools/fork/docs-only.py        # prints docs_only=true or docs_only=false

Under GitHub Actions the answer also goes to $GITHUB_OUTPUT.

The whole branch is compared with where it left main, not just its latest
push. A newer push cancels the run for the older one, so a documentation commit
on top of a code commit must still build.

Only top-level *.md files and docs/ count. Markdown elsewhere can be compiled
in: vendor/calcard and vendor/sieve-rs include their READMEs as doc comments.

main always builds. A push to main cancels the run before it, so a documentation
merge skipping its build would leave the merge before it unchecked. When there's
any doubt, the answer is false: a needless build only costs time.
"""
import os
import re
import subprocess
import sys

BASE = "origin/main"
MAIN_REF = "refs/heads/main"
DOCS = re.compile(r"(?:[^/]+\.md|docs/.+)", re.S)


def is_docs_only(paths):
    return bool(paths) and all(DOCS.fullmatch(p) for p in paths)


def changed_paths(base=BASE, cwd=None):
    """The branch's files, or None if git can't say. A rename lists both ends."""
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", f"{base}...HEAD"],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return None
    return [p for p in result.stdout.split("\0") if p]


def answer(ref, base=BASE, cwd=None):
    if ref == MAIN_REF:
        return False
    paths = changed_paths(base, cwd)
    if paths is None:
        return False
    for path in paths:
        print(f"changed: {path}")
    return is_docs_only(paths)


def main():
    line = f"docs_only={str(answer(os.environ.get('GITHUB_REF', ''))).lower()}"
    print(line)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write(line + "\n")


if __name__ == "__main__":
    main()
