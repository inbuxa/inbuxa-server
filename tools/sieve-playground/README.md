<!--
SPDX-FileCopyrightText: 2026 Coffey Labs LLC

SPDX-License-Identifier: AGPL-3.0-only
-->

# Sieve playground

A browser-only playground for Sieve scripts, shipped inside inbuxa Admin: the
**Debug** button on a Sieve script opens it there with a copy of the script.
It compiles and runs scripts with this repository's own Sieve interpreter,
compiled to WebAssembly, so a script behaves as it does on the server: the
same sieve-rs (`vendor/sieve-rs`, with the `vnd.inbuxa.*` extensions) and the
same expression functions an account script can call. Scripts, messages and
settings stay in the browser.

Ported from the playground in the upstream sieve-rs repository's `web/`
directory (commit `549a2d57f7`), which targets sieve-rs 1.x.

## Layout

- `src/lib.rs`: the module's one export, `playground_call`, JSON in and out:
  `version`, `capabilities`, `defaults`, `compile` and `run`.
- `src/run.rs`: compiles the main script and the include tabs and drives the
  interpreter's event loop the way the server's delivery does, carrying on
  after a runtime error.
- `src/handler.rs`: answers the interpreter's events from the settings and
  records the actions.
- `src/functions/`: the server's own function modules
  (`crates/common/src/scripts/functions`), included by path; tests fail if the
  playground's list stops matching the server's account-script list.
- `src/settings.rs`: compiler and runtime options. The defaults are
  permissive; the server's limits for account scripts are lower.
- `site/`: the static page and its ES modules. `worker.js` runs the module off
  the main thread and gives it the WASI calls it makes.
- `shim/gethostname`: stands in for a crate with no WASI build.

## Why WASI

sieve-rs 0.7 and mail-builder read the clock with `SystemTime::now()`, which
panics on `wasm32-unknown-unknown`. Built for `wasm32-wasip1`, they ask the
host for the time instead, and `worker.js` answers with the playground's
current-time setting, so `currentdate` and the `Date` of a vacation reply
follow it. The module needs six WASI calls, all in `worker.js`.

0.7 does not count the instructions a run executes, and has no memory limit,
so the playground shows neither.

## Build

```sh
./build.sh                          # target/site
./build.sh --admin ../inbuxa-admin  # inbuxa-admin/sieve-playground
```

It runs the tests, builds the module and stages it with `site/`. It needs the
`wasm32-wasip1` Rust target. inbuxa Admin's build copies the staged directory,
with Monaco from its own `node_modules`, into a directory named after a hash
of its contents, so an Admin release never serves a stale copy.

When `vendor/sieve-rs` or the server's function modules change, rebuild with
`--admin` and commit the result in inbuxa-admin.
