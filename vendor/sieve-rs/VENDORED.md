# sieve-rs, vendored

The published [sieve-rs](https://crates.io/crates/sieve-rs) **0.7.3**, taken
from crates.io under AGPL-3.0-only, with the upstream project's name taken
out of the identifiers it spells into the Sieve language (docs/spec/SPEC.md
§2.4). The root `Cargo.toml` patches it in with `[patch.crates-io]`.

## Changes

Every changed file carries the AGPL 5(a) notice in its header.

- `src/compiler/grammar/mod.rs`: the extensions scripts `require` and
  ManageSieve advertises are `vnd.inbuxa.while` and
  `vnd.inbuxa.expressions`. The pre-rename `vnd.stalwart.*` spellings are
  still accepted, never advertised, so a script written for upstream compiles
  when it's edited. Without them, the name is treated as an unknown extension
  and `let` or `eval` fails with "Undeclared capability". The
  `legacy_extension_names` tests cover both.
- `src/runtime/mod.rs`: the default `environment "name"` is `inbuxa Sieve`
  (the server sets its own name on both of its runtimes anyway), and the
  test-only capability is `vnd.inbuxa.testsuite`.
- `src/lib.rs`: the test-suite environment variables are `vnd.inbuxa.*`.
- `src/runtime/tests/comparator.rs`, `src/compiler/grammar/mod.rs`: every
  `:regex` pattern is built through `build_regex`, which holds the compiled
  matcher and its lazy DFA to 1 MiB each (fancy-regex's default is 10 MiB),
  and a pattern built from variables is compiled once per run (`RegexCache`,
  32 patterns, a field of `Context` in `src/lib.rs` and
  `src/runtime/context.rs`) instead of once for every value it is tested
  against. Every caller of `Comparator::regex` passes the cache. The
  `sieve_regexes_are_size_limited` and `sieve_variable_patterns_compile_once`
  tests in `crates/common` cover both.
- `src/runtime/context.rs`, `src/lib.rs`, `src/runtime/tests/test_header.rs`,
  `test_address.rs`, `test_body.rs`, `test_string.rs`, `test_exists.rs`,
  `src/runtime/actions/action_editheader.rs`: the bytes that tests scan count
  against the cpu limit, one instruction for every 64 KiB
  (`SCAN_BYTES_PER_INSTRUCTION`). Header, address, body and string tests and
  `deleteheader` charge each value they compare times the number of keys, and
  every search for a header charges the part's header block; the total is
  `Context::scanned_bytes`. A test stops scanning once the run is over the
  limit, and the run fails with `CPULimitReached` as it does for too many
  instructions (`deleteheader` then deletes nothing). The `scan_limit_tests`
  in `context.rs` cover it; they run from this directory with `cargo test
  --offline --target-dir ../../target/sieve-rs-tests scan_limit` (the crate's
  `test_suite` and `parse_rfc` need upstream's `tests/`, which isn't kept).
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
