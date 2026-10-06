#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the compat tests against a copy of INBUXA's RocksDB store.
#
#   tools/fork/run-compat.sh --store /srv/inbuxa-copy/rocks.db \
#       --admin 'admin@example.org:PASSWORD' --recordings ~/compat
#
# Each test opens $TMPDIR/<its own name>/rocks.db and several of them write:
# monitoring_compat purges the history it reads, undelete_compat restores
# what it finds. So every test gets its own copy of the store, made fresh
# here and removed after, and the source is only ever read.
#
# The source must be a copy already: take it from a stopped server or a
# snapshot, never from under a running one, and never point this at the
# live store (docs/spec/compat-tests.md).
set -u

REPO=$(cd "$(dirname "$0")/../.." && pwd)
STORE= ADMIN= RECORDINGS= ONLY= KEEP=no LOG=
while [ $# -gt 0 ]; do
    case $1 in
        --store) STORE=$2; shift 2 ;;
        --admin) ADMIN=$2; shift 2 ;;
        --recordings) RECORDINGS=$2; shift 2 ;;   # where record-compat.py wrote its files
        --only) ONLY=$2; shift 2 ;;               # one test name, e.g. tenant_compat
        --keep) KEEP=yes; shift ;;                # leave each copy behind for a post-mortem
        --log) LOG=$2; shift 2 ;;                 # the test server's own logging, e.g. --log error
        *) echo "run-compat: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$STORE" ] && [ -n "$ADMIN" ] || {
    echo "run-compat: --store and --admin are required" >&2; exit 2; }
[ -d "$STORE" ] || { echo "run-compat: $STORE is not a directory" >&2; exit 2; }

# name | full path | what it needs beyond the store
TESTS=(
  "tenant_compat|system::tenant::tenant_compat|INBUXA_COMPAT_EXPECTED=expected.json"
  "branding_compat|system::branding::branding_compat|"
  "ai_compat|system::ai::ai_compat|"
  "monitoring_compat|system::monitoring::monitoring_compat|"
  "scim_compat|scim::scim_compat|"
  "per_domain_directory_compat|directory::per_domain::per_domain_directory_compat|"
  "masked_email_compat|system::masked_email::masked_email_compat|INBUXA_COMPAT_MASKS=masks.json"
  "undelete_compat|system::undelete::undelete_compat|INBUXA_COMPAT_ARCHIVED=archived.json"
)

BASE="$REPO/target/tmp/compat"
mkdir -p "$BASE"
failed=0 ran=0

for entry in "${TESTS[@]}"; do
    IFS='|' read -r name path needs <<< "$entry"
    [ -n "$ONLY" ] && [ "$ONLY" != "$name" ] && continue

    env_extra=()
    if [ -n "$needs" ]; then
        variable=${needs%%=*}; file=${needs#*=}
        if [ -z "$RECORDINGS" ] || [ ! -f "$RECORDINGS/$file" ]; then
            echo "SKIP $name: needs $variable ($file from record-compat.py)"
            continue
        fi
        env_extra=("$variable=$RECORDINGS/$file")
    fi

    dir="$BASE/$name"
    rm -rf "$dir"; mkdir -p "$dir"
    cp -a "$STORE" "$dir/rocks.db" || { echo "run-compat: copying $STORE failed" >&2; exit 2; }

    echo "=== $name ($(date +%H:%M:%S)) ==="
    [ -n "$LOG" ] && env_extra+=("LOG=$LOG")
    ( cd "$REPO" && env CARGO_TARGET_DIR=target TMPDIR="$BASE" RUST_MIN_STACK=8388608 \
        STORE=RocksDb NO_INSERT=1 INBUXA_COMPAT_ADMIN="$ADMIN" "${env_extra[@]}" \
        cargo test -p tests "$path" -- --exact --ignored --nocapture )
    rc=$?
    ran=$((ran + 1))
    [ $rc -ne 0 ] && { failed=$((failed + 1)); echo "FAILED $name (exit $rc)"; }
    [ "$KEEP" = no ] && rm -rf "$dir"
done

echo
echo "ran $ran, failed $failed"
[ $failed -eq 0 ] || echo "A failure here is a cutover blocker unless compat-tests.md says otherwise."
exit $((failed > 0))
