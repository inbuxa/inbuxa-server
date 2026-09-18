#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 John Coffey
# SPDX-License-Identifier: AGPL-3.0-only
#
# Upstream's install.sh downloads Stalwart's release binaries from GitHub, so
# it would install Stalwart, not INBUXA. It's replaced with this notice until
# INBUXA publishes releases of its own.

echo "INBUXA has no releases yet, so there is nothing to install." >&2
echo "Build from source instead:  cargo build --release -p inbuxa" >&2
echo "See https://inbuxa.org once it's up." >&2
exit 1
