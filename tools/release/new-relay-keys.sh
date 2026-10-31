#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Make the inbuxa relay release keys (relay spec, RL-29):
#
#   tools/release/new-relay-keys.sh DIR
#
# Writes two Ed25519 keys into DIR, which must not exist yet and is made
# readable by you alone:
#
#   ci.pem       goes into the inbuxa-server Actions secret
#                RELAY_RELEASE_KEY; publish.yml signs every relay binary
#                with it. Delete this copy once the secret is set.
#   offline.pem  stays offline (a password manager, or a USB key in a
#                drawer). It signs a release by hand with sign-relay.sh
#                when the CI key has to be replaced.
#
# Prints only the two public halves, for RELEASE_KEYS in
# crates/relay-proto/src/release.rs. Neither private key is printed.

set -euo pipefail

if [ $# -ne 1 ]; then
    sed -n '5,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
dir=$1
if [ -e "$dir" ]; then
    echo "$dir exists: choose a new directory" >&2
    exit 1
fi

umask 077
mkdir -p "$dir"
here=$(dirname "$0")
for name in ci offline; do
    openssl genpkey -algorithm ed25519 -out "$dir/$name.pem"
    printf '%-8s %s\n' "$name" "$("$here/sign-relay.sh" --public "$dir/$name.pem")"
done
echo
echo "Set the secret from $dir/ci.pem, move $dir/offline.pem offline, then delete $dir."
