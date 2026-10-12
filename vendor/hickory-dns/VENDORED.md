# hickory-dns, vendored

`hickory-proto`, `hickory-net` and `hickory-resolver` 0.26.3 as upstream
builds them since v0.16.26: from its patched branch of
[hickory-dns](https://github.com/hickory-dns/hickory-dns), `stalwart/0.26`
at commit `f8b92b17fa6c7d09a6959672592106ca1410937b` (2026-10-11), under
MIT OR Apache-2.0. INBUXA takes them under MIT. The root `Cargo.toml`
patches them in with `[patch.crates-io]`, so builds never fetch from
upstream's repositories.

That branch is hickory's own `release/0.26` (unreleased work after 0.26.3,
including DS lookups that check the parent zone when an answer carries no
insecure proof) plus nine DNSSEC commits: finding the zone cut with DS
queries, accepting opt-out DS proofs for the next closer name, setting the
CD bit while validating, searching ancestors when a DS lookup fails,
wildcard validation for all RRsets, and a TCP retry for a late truncated
UDP answer.

## Changes

None. Each directory is `cargo package --no-verify` of that commit (the
manifest normalized, so it builds outside hickory's workspace), without
`Cargo.lock` and `Cargo.toml.orig`. `.cargo_vcs_info.json` records the
commit.

Both answers hickory 0.26.3 called bogus in production (an insecure
delegation below an unsigned zone, and a signed CNAME to a name without the
type asked for) validate with this copy: the `--ignored` tests at the end of
`crates/smtp/src/outbound/dane/dnssec.rs` show it, the TLSA one through
Hetzner's resolver (2026-10-12). `validated_lookup` there still rechecks
answers hickory calls bogus, as a fallback.

## Updating

When upstream moves its hickory pin, or hickory publishes a release that
carries these fixes, re-vendor: clone the branch at the new commit, run
`cargo package --no-verify -p hickory-proto -p hickory-net -p
hickory-resolver`, unpack each `.crate` here, and drop `Cargo.lock` and
`Cargo.toml.orig`. If the version changes, Cargo stops using these copies
and only warns that the patch went unused, so check `Cargo.lock` has no
`hickory-*` entry with a `source` line. Update the commit above.
