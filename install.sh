#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Upstream's install.sh downloads Stalwart's release binaries from GitHub, so
# it would install Stalwart, not INBUXA. It is replaced with this notice.
#
# A single-command installer is specified (docs/spec/SPEC.md 6.1) and is still
# to be built. Until it lands there is no unattended install to run, and this
# script says so rather than half-doing one: an installer that is trusted with
# a mail host is not a thing to improvise.

echo "INBUXA has no unattended installer yet." >&2
echo >&2
echo "Build the server from source:" >&2
echo "    cargo build --release -p inbuxa" >&2
echo >&2
echo "Or build the container image from this tree:" >&2
echo "    docker build -t inbuxa ." >&2
echo >&2
echo "A server started with no configuration comes up in bootstrap mode;" >&2
echo "INBUXA Admin's setup wizard completes first boot over JMAP." >&2
echo >&2
echo "Releases:  https://git.coffeylabs.org/inbuxa/inbuxa-server/releases" >&2
echo "Docs:      https://docs.inbuxa.org/install/fresh/" >&2
exit 1
