# sieve-rs, vendored

The published [sieve-rs](https://crates.io/crates/sieve-rs) **0.7.3**, taken
from crates.io under AGPL-3.0-only, with the upstream project's name taken
out of the identifiers it spells into the Sieve language (docs/spec/SPEC.md
§2.4). The root `Cargo.toml` patches it in with `[patch.crates-io]`.

## Changes

Every changed file carries the AGPL 5(a) notice in its header.

- `src/compiler/grammar/mod.rs`: the extensions scripts `require` and
  ManageSieve advertises are `vnd.inbuxa.while` and
  `vnd.inbuxa.expressions`.
- `src/runtime/mod.rs`: the default `environment "name"` is `inbuxa Sieve`
  (the server sets its own name on both of its runtimes anyway), and the
  test-only capability is `vnd.inbuxa.testsuite`.
- `src/lib.rs`: the test-suite environment variables are `vnd.inbuxa.*`.
- `Cargo.toml`: the example target is dropped, with the top-level
  `examples/` and `tests/`, which the server never builds. (`src/` keeps its
  own `tests` modules: the crate declares them.)

## Updating

When the server's `Cargo.lock` moves sieve-rs to a new version, Cargo stops
using this copy and only warns that the patch went unused. The unit test
`sieve_extensions_carry_the_fork_name` in `crates/common` fails when that
happens. Re-vendor the new version from `~/.cargo/registry/src/*/sieve-rs-*`,
dropping the top-level `tests/` and `examples/` (only those: `rsync
--exclude /tests --exclude /examples`), `Cargo.lock` and `Cargo.toml.orig`, repeat
the changes above, and update the version here and in the root `Cargo.toml`
comment. `tools/fork/name-check.py` covers `vendor/` too, so a rename missed
in a new version fails CI.
