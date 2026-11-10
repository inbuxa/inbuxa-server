#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail when CHANGELOG.md has no entry for the 2026 series' current version.

    tools/release/changelog-check.py

The version is brand_version! in crates/types/src/branding.rs; the entry is a
`## [VERSION]` heading. The version PR that sets a version adds its entry, and
fork-checks runs this so one without it can't merge. main does the same with
tools/release/version.py --changelog.

Standard library only.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def brand_version(text):
    m = re.search(r'macro_rules! brand_version \{\s*\(\) => \{\s*"([^"]+)"', text)
    if not m:
        raise ValueError("no brand_version! in branding.rs")
    return m.group(1)


def changelog_versions(text):
    return re.findall(r"(?m)^## \[([^\]]+)\]", text)


def main():
    shown = brand_version((ROOT / "crates/types/src/branding.rs").read_text())
    if shown not in changelog_versions((ROOT / "CHANGELOG.md").read_text()):
        print(f"CHANGELOG.md has no entry for {shown}. Add a `## [{shown}] - YYYY-MM-DD`", file=sys.stderr)
        print("section to the version PR that sets it.", file=sys.stderr)
        return 1
    print(shown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
