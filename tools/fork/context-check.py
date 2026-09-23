#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every path Cargo patches has to be in the image's build context.

Cargo.toml's [patch.crates-io] can point at a directory in this repository,
and the Dockerfile builds from a context that .dockerignore prunes to almost
nothing. Those two facts met on 2026-09-23: a vendored, patched sieve-rs
landed, CI stayed green -- it builds from a checkout, where the directory is
simply there -- and the release build failed on

    failed to load source for dependency `sieve-rs`
    failed to read /build/vendor/sieve-rs/Cargo.toml

after a tag had already been pushed. This is seconds, and it runs beside the
other fork checks rather than waiting for a release to find out.
"""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]


def patched_paths(manifest: Path) -> list[str]:
    """Directories named by a [patch...] section's `path = "..."` entries."""
    out, in_patch = [], False
    for line in manifest.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_patch = stripped.startswith("[patch")
            continue
        if not in_patch:
            continue
        m = re.search(r'path\s*=\s*"([^"]+)"', stripped)
        if m:
            out.append(m.group(1))
    return out


def allowed(dockerignore: Path) -> set[str]:
    """The first path segment of every re-inclusion rule."""
    keep = set()
    for line in dockerignore.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("!"):
            keep.add(stripped[1:].strip("/").split("/")[0])
    return keep


def main() -> int:
    paths = patched_paths(root / "Cargo.toml")
    if not paths:
        print("no patched paths to check")
        return 0
    keep = allowed(root / ".dockerignore")
    bad = []
    for p in paths:
        top = p.strip("/").split("/")[0]
        if top not in keep:
            bad.append((p, top))
        elif not (root / p).is_dir():
            bad.append((p, None))
    for path, top in bad:
        if top is None:
            print(f"Cargo.toml patches {path}, which does not exist", file=sys.stderr)
        else:
            print(
                f"Cargo.toml patches {path}, but .dockerignore does not re-include {top!r}:\n"
                f"  the image build would not see it, and cargo would fail on it.\n"
                f"  Add `!{top}` to .dockerignore.",
                file=sys.stderr,
            )
    if bad:
        return 1
    print(f"build context includes every patched path: {', '.join(paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
