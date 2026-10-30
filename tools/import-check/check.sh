#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Check that an inbuxa image still reads a Stalwart 0.16.27 store:
#
#   tools/import-check/check.sh registry.coffeylabs.org/inbuxa/inbuxa-server:27.1-rc.5
#
# Imports tests/resources/import-0.16.27/export into a fresh store with
# `inbuxa --import`, starts the image on it, and compares what it serves with
# what 0.16.27 served (expected.json, less known-differences.txt). Then it
# checks what happens after the move: mail delivered through the imported
# Sieve filter, search over imported mail once the reindex has run (up to
# five minutes), re-saving a filter that uses a pre-rename extension name, and
# the 0.16 web interface switched off with its record kept.
# Run it on every release candidate; see docs/spec/import-0.16.md.
#
# Needs docker, python3, loopback ports 18091 and 18025, and DNS (delivery
# runs the SPF/DKIM/DMARC checks).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export FIXTURE="${FIXTURE:-$ROOT/tests/resources/import-0.16.27}"
IMAGE=${1:?usage: check.sh <inbuxa image>}
NAME=inbuxa-import-check URL=http://127.0.0.1:18091
WORK=$(mktemp -d)
trap 'docker rm -f $NAME >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/etc" "$WORK/data" && chmod 777 "$WORK/etc" "$WORK/data"
echo '{"@type":"RocksDb","path":"/var/lib/inbuxa/"}' > "$WORK/etc/config.json" && chmod 644 "$WORK/etc/config.json"

docker run --rm -v "$WORK/etc:/etc/inbuxa" -v "$WORK/data:/var/lib/inbuxa" -v "$FIXTURE/export:/import:ro" \
  $IMAGE --config /etc/inbuxa/config.json --import /import | tail -1
# Basic auth on JMAP is refused by default (contract C-23); the check signs in
# with the fixture's passwords. GitHub stays unreachable, so an image from
# before the 0.16 web interface was switched off on import never fetches it.
docker run -d --name $NAME -e INBUXA_HTTP_BASIC_AUTH=all --add-host github.com:127.0.0.1 \
  -p 127.0.0.1:18091:8080 -p 127.0.0.1:18025:25 \
  -v "$WORK/etc:/etc/inbuxa" -v "$WORK/data:/var/lib/inbuxa" $IMAGE >/dev/null
for _ in $(seq 1 60); do curl -sf -o /dev/null $URL/healthz/live && break; sleep 1; done
sleep 5

python3 -I "$HERE/snapshot.py" $URL > "$WORK/actual.json"
status=0
python3 -I "$HERE/compare.py" "$FIXTURE/expected.json" "$WORK/actual.json" "$FIXTURE/known-differences.txt" || status=1
python3 -I "$HERE/after.py" $URL || status=1
docker logs $NAME 2>&1 | grep -E " (ERROR|WARN) " | grep -vE "resource.error|tls.no-certificates|DnsResolver" | head -20 || true
exit $status
