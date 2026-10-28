# opentelemetry-rust, vendored

`opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`,
`opentelemetry-proto`, `opentelemetry-http` and
`opentelemetry-semantic-conventions` 0.33.0 as upstream builds them: from its
fork of [opentelemetry-rust](https://github.com/open-telemetry/opentelemetry-rust)
at commit `ae66e97b140f70e477ab710686aafce665cc2f8b` (2026-09-26), under
Apache-2.0 (`LICENSE` here is the project's). The root `Cargo.toml` patches
them in with `[patch.crates-io]`, so builds never fetch from upstream's
repositories.

That commit is opentelemetry-rust's own `main` at `b7852a8c` (2026-09-24,
after the 0.33.0 release candidate) plus one change: public constructors for
the metrics data types (`ResourceMetrics`, `ScopeMetrics`, `Metric`, the
gauge, sum and histogram types and their data points) and a public
`SdkLogRecord::new()` with a `Default`. Nothing else differs.

## Changes

None. Each directory is `cargo package --no-verify` of that commit (the
manifest normalized, so it builds outside the project's workspace), without
`Cargo.lock`, `Cargo.toml.orig` and `.cargo_vcs_info.json`.

## Updating

When upstream moves its pin, or opentelemetry-rust releases the
constructors, re-vendor: clone the repository at the new commit, run `cargo
package --no-verify` for the six crates, unpack each `.crate` here, and drop
`Cargo.lock` and `Cargo.toml.orig`. If the version changes, Cargo stops
using these copies and only warns that the patch went unused, so check
`Cargo.lock` has no `opentelemetry*` entry with a `source` line. Update the
commit above.
