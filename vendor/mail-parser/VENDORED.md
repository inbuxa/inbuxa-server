# mail-parser, vendored

The published [mail-parser](https://crates.io/crates/mail-parser) **0.11.9**,
taken from crates.io (`.crate` sha256
`4ec00bda90c6e645a54506c630c2820cd6b1890cfd2b0a169b50f74b2b8c7c86`, the
checksum the server's `Cargo.lock` had for it) under Apache-2.0 OR MIT.
INBUXA takes it under MIT. The root `Cargo.toml` patches it in with
`[patch.crates-io]`, so every crate in the build that parses mail (the
server's own and its dependencies, such as sieve-rs and mail-auth) uses this
copy.

Left out: the top-level `resources/` (5 MB of sample messages), `tests/`,
`examples/`, `.github/` and `flamegraph.sh`, which the server never builds,
and `Cargo.lock`, `Cargo.toml.orig`, `.cargo_vcs_info.json` and `.cargo-ok`.
`Cargo.toml` drops the `[[example]]` and `[[test]]` targets that pointed at
them. The crate's own tests need `resources/` and dev-dependencies the server
doesn't otherwise use, so they aren't run here; the server's tests cover the
changes below.

## Changes

None yet.

## Updating

When the server's `Cargo.lock` moves mail-parser to a new version, Cargo
stops using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `mail-parser` entry with a `source` line. Re-vendor the new
version from `~/.cargo/registry/src/*/mail-parser-*`, leaving out what's
listed above, repeat the changes, and update the version here and in the root
`Cargo.toml` comment.
