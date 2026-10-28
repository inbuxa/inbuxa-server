#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""inbuxa's version, for the release workflows and for cutting a release by hand.

The one version is [workspace.package] in Cargo.toml: 27.1.0 for a series,
27.1.3 for its patches, 27.1.0-rc.1 for a release candidate. Tags, images and
`--version` name it without the series' .0: v27.1, v27.1.3, v27.1-rc.1. The
server works that out with the display_version proc macro
(crates/utils/proc-macros/src/version.rs); display() here is the same mapping,
tested with the same cases.

  version.py                   the displayed version (27.1-rc.1)
  version.py --cargo           the Cargo version (27.1.0-rc.1)
  version.py --tag TAG         check that TAG is v<displayed>, then print it
  version.py --image-tags      the image tags for this version, one per line
  version.py --prerelease      exit 0 for a release candidate, 1 otherwise
  version.py --set VERSION     set the version (Cargo form) in Cargo.toml and
                               Cargo.lock: a release candidate, or a series
                               bump, is cut this way by hand

Standard library only: the weekly release runs it in a plain python image.
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NUMBER = r"(?:0|[1-9][0-9]*)"
CARGO = re.compile(rf"^({NUMBER})\.({NUMBER})\.({NUMBER})(?:-rc\.([1-9][0-9]*))?$")


def parse(cargo):
    """(major, minor, patch, rc or None), or ValueError for anything that
    isn't YY.M.N or YY.M.0-rc.N."""
    m = CARGO.match(cargo)
    if not m or (m.group(4) and m.group(3) != "0"):
        raise ValueError(f"{cargo!r} is not YY.M.N or YY.M.0-rc.N")
    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    # A two-digit year and a month: 2026.10.28 is the old dated scheme.
    if not (10 <= major <= 99 and 1 <= minor <= 12):
        raise ValueError(f"{cargo!r}: the series is a two-digit year and a month, as in 27.1")
    return major, minor, patch, int(m.group(4)) if m.group(4) else None


def display(cargo):
    major, minor, patch, rc = parse(cargo)
    series = f"{major}.{minor}"
    if rc is not None:
        return f"{series}-rc.{rc}"
    return series if patch == 0 else f"{series}.{patch}"


def is_prerelease(cargo):
    return parse(cargo)[3] is not None


def image_tags(cargo):
    """A release candidate gets its own tag and the series' moving -rc tag,
    never :latest. A release gets its own tag, the series tag and :latest."""
    major, minor, _, rc = parse(cargo)
    series = f"{major}.{minor}"
    if rc is not None:
        return [display(cargo), f"{series}-rc"]
    return list(dict.fromkeys([display(cargo), series, "latest"]))


def next_patch(cargo):
    """What the weekly release cuts next: the next patch of a released
    series, or None during release candidates, which are cut by hand."""
    major, minor, patch, rc = parse(cargo)
    return None if rc is not None else f"{major}.{minor}.{patch + 1}"


def members(root=ROOT):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    names = set()
    for member in workspace["members"]:
        names.add(tomllib.loads((root / member / "Cargo.toml").read_text())["package"]["name"])
    # Path dependencies inside the workspace are members too (proc_macros).
    for lock in tomllib.loads((root / "Cargo.lock").read_text())["package"]:
        if "source" not in lock and lock["name"] in names | {"proc_macros"}:
            names.add(lock["name"])
    return names


def cargo_version(root=ROOT):
    return tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]


def set_version(new, root=ROOT):
    """Rewrite the version in Cargo.toml and every workspace entry of
    Cargo.lock, as `cargo update -w` would, without needing cargo. Returns
    {path: new text} so a caller can write the files or send them elsewhere."""
    parse(new)
    old = cargo_version(root)
    names = members(root)

    toml_path = root / "Cargo.toml"
    toml = toml_path.read_text()
    section = re.search(r"(?ms)^\[workspace\.package\]\n.*?(?=^\[|\Z)", toml)
    body, hits = re.subn(r'(?m)^version = "[^"]*"$', f'version = "{new}"', section.group(0), count=1)
    if hits != 1:
        raise ValueError("no version line in [workspace.package]")
    toml = toml[: section.start()] + body + toml[section.end() :]

    lock_path = root / "Cargo.lock"
    lock = lock_path.read_text()
    bumped = 0

    def package(m):
        nonlocal bumped
        block = m.group(0)
        name = re.search(r'(?m)^name = "([^"]+)"$', block).group(1)
        if name in names and "\nsource = " not in block:
            block, hits = re.subn(rf'(?m)^version = "{re.escape(old)}"$', f'version = "{new}"', block, count=1)
            bumped += hits
        return block

    lock = re.sub(r"(?s)\[\[package\]\]\n.*?(?=\n\n|\Z)", package, lock)
    # A member that shares its name with a registry crate (http) is named
    # with its version in dependency lists.
    for name in names:
        lock = lock.replace(f'"{name} {old}"', f'"{name} {new}"')
    if bumped != len(names):
        raise ValueError(f"bumped {bumped} of {len(names)} workspace packages in Cargo.lock")
    return {toml_path: toml, lock_path: lock}


def main(argv):
    cargo = cargo_version()
    if not argv:
        print(display(cargo))
    elif argv == ["--cargo"]:
        print(cargo)
    elif argv[0] == "--tag" and len(argv) == 2:
        if argv[1] != f"v{display(cargo)}":
            print(f"Tag {argv[1]} names a commit whose version is {display(cargo)} (Cargo {cargo}).", file=sys.stderr)
            print("Refusing to publish an image that would report the wrong version.", file=sys.stderr)
            return 1
        print(display(cargo))
    elif argv == ["--image-tags"]:
        print("\n".join(image_tags(cargo)))
    elif argv == ["--prerelease"]:
        return 0 if is_prerelease(cargo) else 1
    elif argv[0] == "--set" and len(argv) == 2:
        for path, text in set_version(argv[1]).items():
            path.write_text(text)
        print(f"{cargo} -> {argv[1]} ({display(argv[1])})")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
