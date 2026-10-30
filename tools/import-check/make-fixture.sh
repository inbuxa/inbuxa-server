#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build the Stalwart 0.16.27 import fixture in tests/resources/import-0.16.27/:
# a fresh 0.16.27 server from the official image, set up and filled over JMAP
# (populate.py), snapshotted (expected.json), then exported with its own
# --export. The export is what an operator moving from 0.16.27 hands to
# `inbuxa --import`.
#
# The server gets no internet: GitHub resolves to loopback and DNS goes
# nowhere, so the web interface and data files it fetches at first start
# never land in the fixture. Only needed when the fixture itself changes;
# check.sh is what runs against a release.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
export FIXTURE="${FIXTURE:-$ROOT/tests/resources/import-0.16.27}"
IMAGE=stalwartlabs/stalwart@sha256:c429b311c93db5606598abc1c68225a85a6953183848ae01bee9c6a98885836c # v0.16.27
NAME=inbuxa-import-fixture PORT=18090 URL=http://127.0.0.1:18090
WORK=$(mktemp -d)
trap 'docker rm -f $NAME >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/etc" "$WORK/data" "$WORK/export" && chmod 777 "$WORK"/*
export BOOT_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')

wait_live() {
  for _ in $(seq 1 60); do curl -sf -o /dev/null $URL/healthz/live && return; sleep 1; done
  echo "server never came up" >&2; docker logs $NAME | tail -20 >&2; exit 1
}
run() {
  docker rm -f $NAME >/dev/null 2>&1 || true
  docker run -d --name $NAME --dns 127.0.0.1 --add-host github.com:127.0.0.1 \
    --add-host objects.githubusercontent.com:127.0.0.1 -p 127.0.0.1:$PORT:8080 \
    -v "$WORK/etc:/etc/stalwart" -v "$WORK/data:/var/lib/stalwart" "$@" $IMAGE >/dev/null
  wait_live
}

run -e STALWART_RECOVERY_ADMIN="admin:$BOOT_PASSWORD"
python3 -I "$HERE/bootstrap.py" $URL
run
python3 -I "$HERE/populate.py" $URL
python3 -I "$HERE/snapshot.py" $URL > "$FIXTURE/expected.json"
docker rm -f $NAME >/dev/null
docker run --rm -v "$WORK/etc:/etc/stalwart" -v "$WORK/data:/var/lib/stalwart" -v "$WORK/export:/export" \
  $IMAGE --config /etc/stalwart/config.json --export /export >/dev/null
rm -rf "$FIXTURE/export" && cp -r "$WORK/export" "$FIXTURE/export"
echo "fixture written: $(du -sh "$FIXTURE/export" | cut -f1) export, expected.json, admin.json"
