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

Being in the context isn't enough on its own: the Dockerfile cooks the
dependencies (`cargo chef cook`) before it copies the tree in, from a recipe
that carries only the workspace's manifests. So each patched path must also be
copied into that stage before the cook step, or the same error comes back
there -- as it did for 2026.9.24.2, the first tag after the context fix.
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


def copied_before_cook(dockerfile: Path) -> list[str] | None:
    """Sources COPY'd into the stage that runs `cargo chef cook`, before it.

    None when no stage cooks. A `COPY . .` covers everything.
    """
    stage: list[str] = []
    for line in dockerfile.read_text().splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^FROM\s", stripped):
            stage = []
            continue
        if "cargo chef cook" in stripped:
            return stage
        m = re.match(r"(?i)^COPY\s+(?!--from)(.+)$", stripped)
        if m:
            parts = m.group(1).split()
            stage.extend(p.strip("./").split("/")[0] or "." for p in parts[:-1])
    return None


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
    copied = copied_before_cook(root / "Dockerfile")
    if copied is not None and "." not in copied:
        for p in paths:
            top = p.strip("/").split("/")[0]
            if top not in copied:
                print(
                    f"Cargo.toml patches {p}, but the Dockerfile doesn't copy {top!r} into the\n"
                    f"  stage that runs `cargo chef cook` before that step, so cooking the\n"
                    f"  dependencies fails on it. Add `COPY {top}/ {top}/` before the cook.",
                    file=sys.stderr,
                )
                bad.append((p, top))
    if bad:
        return 1
    print(f"build context and cook stage include every patched path: {', '.join(paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
