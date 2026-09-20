# Contributing

Patches, bug reports and questions are welcome.

## Before a pull request

**Open an issue first for anything substantial.** A feature or a refactor is
worth agreeing on before it is written, because this is a fork that tracks
upstream: a change that moves code around costs a conflict on every import,
and it should be worth that.

Small fixes — a bug, a typo, a test — need no ceremony. Send them.

## How a change lands

`main` is protected. It cannot be force-pushed or deleted, and a change
reaches it through a pull request whose `build` check has passed. No approving
review is required — this is a small project and a gate nobody can pass is not
a gate — but the build is not optional.

So the shape of a change is: a branch, a pull request, a green CI run, a merge.
Branches are deleted on merge. Repository administrators can bypass the rule,
which exists so the maintainer can correct the tree quickly, not so that the
ordinary path can be skipped; use it for an emergency, not for convenience.

Releases are cut weekly from `main` by `.github/workflows/release.yml`, on
Monday morning UTC, and nothing is released on a quiet week. That is the reason
the rule matters: whatever is on `main` when the run starts is what ships, so
`main` is expected to be releasable at all times rather than at the end of a
piece of work. A change that is not finished should be behind something that
defaults to off, or it should not be on `main` yet.

## What this repository is

INBUXA is a fork of Stalwart, taken under the AGPL-3.0-only half of its dual
licence, with nine features rebuilt independently. Two things follow:

- **The clean room is real.** The rebuilt features in `crates/features` were
  written from specifications in `docs/spec/features/`, by people who had not
  read Stalwart's Enterprise source. If you have read it, say so in the pull
  request and it will be reviewed with that in mind, or declined for the parts
  it touches. Nothing about this is personal: the project's defence of
  independent creation is a record, and the record has to be true.
- **Upstream files stay recognisable.** Changes to files that came from
  upstream are kept small and marked with an `inbuxa:` comment saying which
  requirement they serve, so the next import merges cleanly and a reader can
  tell fork from base. New work belongs in the fork's own crates where it can.

## Licence and provenance

Contributions are under AGPL-3.0-only. Keep upstream's copyright headers where
they are; if you change a file that came from upstream, leave its "Modified by
Coffey Labs" line in place. New files carry:

```
/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
```

If you bring in code from another project, it stays under its own licence and
its notice goes in `THIRD-PARTY.md`. `tools/fork/strip.py` reports any file
that is missing from there on every import.

## Running the tests

`cargo test -p tests` runs what needs nothing but a store on disk. The rest
need containers, a particular backend, or a copy of real data, and are
`#[ignore]`d:

- `docs/spec/container-tests.md` — the suites that need containers, with the
  `STORE` each one wants and what a plain regression leaves failing.
- `docs/spec/compat-tests.md` — the compatibility set, which needs a copy of a
  real server's data.

Run one suite at a time. They bind fixed ports, and the timing checks flake if
two run at once.

## Commit messages

Say what changed and why, in prose, wrapped at 72 characters or so. The why is
the part that is hard to recover later. No tool trailers.
