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

Every changed file carries a Coffey Labs notice in its header.

- `src/spf/parse.rs`: an unknown SPF modifier's value runs to the next
  space, so a `/` in it no longer fails the record. RFC 7208 §4.6.1 gives an
  unknown modifier's value as a macro-string, whose literals are any visible
  character but `%` (§7.1), and §6 says unknown modifiers are ignored.
  Upstream read the value with the domain-spec reader, which stops at the
  `/` that starts a CIDR length; anything after it was a parse error, so
  `v=spf1 ip4:192.0.2.1 foo=bar/baz -all` was a permerror and mail from that
  domain failed SPF (and could fail DMARC). The value's macros are still
  checked, so `foo=%x` stays a syntax error, and `a`, `mx`, `ip4` and `ip6`
  still stop at `/`. The `spf_unknown_modifiers_are_ignored` and `mail`
  tests in `tests/src/smtp/inbound/mail.rs` cover it.

## Updating

When the server's `Cargo.lock` moves mail-auth to a new version, Cargo stops
using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `mail-auth` entry with a `source` line; the tests above
also fail once a version without the changes is in use. Re-vendor the new
version from `~/.cargo/registry/src/*/mail-auth-*`, leaving out what's listed
above, repeat the changes, and update the version here and in the root
`Cargo.toml` comment.
