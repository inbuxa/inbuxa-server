#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds the Sieve playground: the server's Sieve interpreter for
# wasm32-wasip1, beside the static site in site/. Monaco is not included:
# inbuxa Admin's build adds it from its own node_modules.
#
#   ./build.sh                  stage into target/site
#   ./build.sh --admin <dir>    stage into <dir>/sieve-playground, an
#                               inbuxa-admin checkout, with SOURCE.md naming
#                               the commit it was built from
set -euo pipefail

cd "$(dirname "$0")"

out="target/site"
admin=""
if [ "${1:-}" = "--admin" ]; then
  admin="${2:?--admin needs the inbuxa-admin directory}"
  [ -f "$admin/package.json" ] || { echo "$admin is not an inbuxa-admin checkout." >&2; exit 1; }
  out="$admin/sieve-playground"
elif [ -n "${1:-}" ]; then
  echo "Usage: $0 [--admin <inbuxa-admin directory>]" >&2
  exit 1
fi

cargo test --quiet
cargo build --release --target wasm32-wasip1

rm -rf "$out"
mkdir -p "$out"
cp -r site/. "$out/"
cp target/wasm32-wasip1/release/sieve_playground.wasm "$out/"

if [ -n "$admin" ]; then
  commit="$(git rev-parse HEAD)"
  dirty=""
  git diff --quiet HEAD -- . ../../vendor/sieve-rs ../../crates/common/src/scripts || dirty=" (with uncommitted changes)"
  version="$(sed -n 's/^version = "\(.*\)"/\1/p' ../../vendor/sieve-rs/Cargo.toml | head -1)"
  cat > "$out/SOURCE.md" <<EOF
# Sieve playground

Generated: do not edit. This directory is built by
\`tools/sieve-playground/build.sh --admin\` in inbuxa-server, from commit
\`$commit\`$dirty, with the server's vendored sieve-rs $version. Change the
source there, rebuild, and commit the result here.

The WebAssembly module is that commit's \`tools/sieve-playground\` crate, built
for \`wasm32-wasip1\`; its source, and the site's, are in that directory under
AGPL-3.0-only.
EOF
fi

echo "Built the Sieve playground into $out ($(du -h "$out/sieve_playground.wasm" | cut -f1) of WebAssembly)."
