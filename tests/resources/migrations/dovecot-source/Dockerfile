# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# The IMAP source for migration_real_engine_tests: two accounts and a
# master login. `python3 seed.py PORT` puts their mail in.

FROM debian:bookworm-20260518-slim
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dovecot-imapd && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --gid 5000 vmail && \
    adduser --system --no-create-home --uid 5000 --gid 5000 vmail && \
    mkdir -p /var/vmail && chown -R vmail:vmail /var/vmail
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
COPY masters /etc/dovecot/masters
EXPOSE 143
CMD ["dovecot", "-F"]
