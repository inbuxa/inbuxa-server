# Contributing

Patches, bug reports and questions are welcome.

## Before a pull request

**Open an issue first for anything substantial.** A feature or a refactor is
worth agreeing on before it is written, because this is a fork that tracks
upstream: a change that moves code around costs a conflict on every import,
and it should be worth that.

Small fixes — a bug, a typo, a test — need no ceremony. Send them.

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
