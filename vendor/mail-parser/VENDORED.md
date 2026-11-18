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

Every changed file carries a Coffey Labs notice in its header.

- `src/parsers/message.rs`: message/rfc822 (and message/global) parts
  without a Content-Transfer-Encoding nest at most `MAX_NESTED_MESSAGES`
  (20) deep in one parse. A part deeper than that is kept as an attachment
  (`PartType::Binary`, its raw bytes) and not parsed. Upstream limited only
  encoded nested messages (`MAX_NESTED_ENCODED`, 3); unencoded ones nested to
  any depth, each a `Message` inside its parent, and dropping the tree took
  a stack frame per level. A 1.6 MB message nested 50,000 deep overflowed a
  2 MiB thread stack in a release build and aborted the server, once when
  SMTP finished with it and again on every attempt to deliver it to a
  mailbox with a Sieve script. With both limits no tree is more than 80
  deep. The `deeply_nested_messages_drop_on_a_small_stack` test in
  `crates/email` covers it.

## Updating

When the server's `Cargo.lock` moves mail-parser to a new version, Cargo
stops using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `mail-parser` entry with a `source` line; the test
above also fails once a version without the limit is in use. Re-vendor the new
version from `~/.cargo/registry/src/*/mail-parser-*`, leaving out what's
listed above, repeat the changes, and update the version here and in the root
`Cargo.toml` comment.
