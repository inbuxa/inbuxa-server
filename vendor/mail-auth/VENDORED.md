# mail-auth, vendored

The published [mail-auth](https://crates.io/crates/mail-auth) **0.13.3**,
taken from crates.io (`.crate` sha256
`8505122ba86e1f4adeb664196c1e787c3f29bb6e7c128e4a366d47d209911440`, the
checksum the server's `Cargo.lock` had for it) under Apache-2.0 OR MIT.
INBUXA takes it under MIT. The root `Cargo.toml` patches it in with
`[patch.crates-io]`, so every crate in the build that checks SPF, DKIM, ARC
or DMARC uses this copy.

Left out: the top-level `resources/` (test keys and sample messages),
`tests/`, `examples/` and `.github/`, which the server never builds, and
`Cargo.lock`, `Cargo.toml.orig`, `.cargo_vcs_info.json` and `.cargo-ok`.
`Cargo.toml` drops the `[[example]]` and `[[test]]` targets that pointed at
them. The crate's own tests need `resources/` and dev-dependencies the server
doesn't otherwise use, so they aren't run here; the server's tests cover the
changes below.

## Changes

None yet: this is the published crate as it was.

## Updating

When the server's `Cargo.lock` moves mail-auth to a new version, Cargo stops
using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `mail-auth` entry with a `source` line. Re-vendor the new
version from `~/.cargo/registry/src/*/mail-auth-*`, leaving out what's listed
above, repeat the changes, and update the version here and in the root
`Cargo.toml` comment.
