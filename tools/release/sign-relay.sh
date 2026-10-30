#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Sign an inbuxa-relay release binary (relay spec, RL-29):
#
#   tools/release/sign-relay.sh KEY.pem BINARY VERSION TARGET
#
# KEY.pem is the inbuxa release key (Ed25519, PKCS#8 PEM, as
# `openssl genpkey -algorithm ed25519` makes it). VERSION is the Cargo
# version the binary's `--version` prints (27.1.0-rc.5), TARGET its target
# (x86_64-linux-musl). Writes BINARY.sig, which the relay checks against the
# key's public half compiled into crates/relay-proto/src/release.rs.
#
#   tools/release/sign-relay.sh --public KEY.pem
#
# prints that public half, base64url, for RELEASE_KEYS.
#
# openssl 3 and coreutils only, so it runs in a plain release image.

set -euo pipefail

b64url() { basenc --base64url -w0 | tr -d '='; }

if [ "${1:-}" = "--public" ] && [ $# -eq 2 ]; then
    # The raw key is the last 32 bytes of the DER public key
    openssl pkey -in "$2" -pubout -outform DER | tail -c 32 | b64url
    echo
    exit 0
fi

if [ $# -ne 4 ]; then
    sed -n '5,19p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

key=$1 binary=$2 version=$3 target=$4
sha=$(sha256sum "$binary" | cut -d' ' -f1)
signed=$(mktemp)
trap 'rm -f "$signed"' EXIT
printf 'inbuxa-relay release 1\nversion %s\ntarget %s\nsha256 %s\n' \
    "$version" "$target" "$sha" > "$signed"
signature=$(openssl pkeyutl -sign -inkey "$key" -rawin -in "$signed" | b64url)
{ cat "$signed"; printf 'signature %s\n' "$signature"; } > "$binary.sig"
echo "$binary.sig"
