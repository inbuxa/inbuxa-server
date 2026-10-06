<!--
SPDX-FileCopyrightText: 2026 Coffey Labs LLC
SPDX-License-Identifier: AGPL-3.0-only
-->

# The synthetic cutover rehearsal

`docs/spec/cutover.md` as a script, against data this makes up rather than
INBUXA's. It rehearses the **sequence** — stop, copy, start the fork beside
it, check, roll back — not the data, which is what the compat tests cover
(`docs/spec/compat-tests.md`).

Nothing here touches INBUXA's production server. Two containers stand in for
the two installs, both unprivileged with `CAP_NET_BIND_SERVICE` so the mail
ports are bound the way the systemd unit binds them:

| | binary | stands for |
|---|---|---|
| `cutover-old` | `target/debug/stalwart` | the Enterprise install running today |
| `cutover-new` | `target/debug/inbuxa` | what it is cut over to |

## Running it

Needs `target/debug/stalwart` and `target/debug/inbuxa`, and Docker.

```sh
tools/fork/cutover-rehearsal/phase1.py   # build the old install, record before.json
tools/fork/cutover-rehearsal/phase2.py   # the cutover sequence, and its checks
tools/fork/cutover-rehearsal/phase3.py   # the rollback, and the reverse-compat probe
```

Phase 1 destroys anything from an earlier run, so the three are repeatable
from nothing. State lives under `target/cutover/`; the containers are named
`cutover-old`, `cutover-new` and `cutover-reverse`.

## What it covers, and what it does not

Covered, and observed rather than assumed:

- the fork opens and serves a store the previous build wrote;
- every account signs in with the password it had, over JMAP and over IMAP;
- mail is byte-for-byte the same set, and an alias still delivers;
- a tenant administrator sees exactly its own accounts and domains, and
  still cannot read listeners — the thing `tenant_compat` could not check,
  because `tenantAdmins` was empty on the real run;
- ports 25, 465 and 993 bound by an unprivileged process;
- the `STALWART_*` → `INBUXA_*` fallback warnings of SPEC.md §2.5;
- the rollback, timed, including what it leaves behind.

**Not covered.** The rehearsal is containers, not the host:

- systemd. `inbuxa.service`, `AmbientCapabilities`, and above all
  `systemctl disable stalwart` — the step that stops a reboot putting two
  servers on one set of ports — have no analogue here.
- ACME and certificate renewal. This runs with
  `requestTlsCertificate: false`, so the certificate on 443 and 993 is a
  self-signed fallback. Renewal remains the open question it was.
- Load. One message at a time, not INBUXA's traffic.
- The front ends. INBUXA Admin and ihasmail are not started.
- INBUXA's own data. That is `compat-tests.md`, and a rehearsal on a real
  snapshot is still owed.
