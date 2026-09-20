# Cutting INBUXA over to the fork

Status: draft, 2026-09-19. Nothing here has been rehearsed yet.

SPEC.md §7 step 4. Steps 1 to 3 are met: the fork builds and its suites pass
(`container-tests.md`), and all eight compat tests pass against a copy of
INBUXA's store (`compat-tests.md`). What is left is running it as the mail
server.

## What the fork has never done

Everything proven so far was proven in a test harness. On the day, the fork
has to do things nothing has yet asked of it:

- hold INBUXA's ports (25, 465, 587, 143, 993, 110, 995, 443) under load,
  as an unprivileged user with `CAP_NET_BIND_SERVICE`;
- keep certificates renewing. ACME renewal was found broken and fixed
  (`309835b`), and the remaining test failure is unexplained
  (`container-tests.md`, "What a plain regression leaves failing"). A
  certificate that fails to renew is a 90-day fuse, not an outage on the
  day, so it is the first thing to watch and the least likely to announce
  itself;
- write to a store that the Enterprise build wrote until an hour earlier.

The rehearsal below exists to turn those from assumptions into observations.

## The clock

The Enterprise subscription ends at 30 days' notice, and the server falls
back to the Community Edition 15 days after that (SPEC.md §7). So the fork
must be carrying INBUXA before anything triggers that notice, and the
rehearsal has to happen before the cutover, not instead of it.

Anything that has to be recorded from the Enterprise server — the tenant
administrators' view, which `tenant_compat` still hasn't checked — has to be
captured before the cutover, because afterwards there is nothing to record
from (`compat-tests.md`).

## Before the day

1. **Build the artifact.** `cargo build --release -p inbuxa`, on the same
   glibc as the host or in the container image. `inbuxa --version` must read
   `2026.9.18 (Stalwart 0.16.22)`, naming the upstream base the data belongs
   to (SPEC.md §2.6).
2. **Rehearse on a copy.** Restore a snapshot of `/opt/stalwart/data` onto a
   spare host or container, point the fork at it, and put it through what a
   mail server does: receive over SMTP, read over IMAP and JMAP, send,
   sign in to both front ends, let a queued message deliver. Then throw the
   copy away. This is the step that turns "the data opens" into "the server
   runs on it".
3. **Decide the rollback, and write down its cost.** See below: rolling back
   is only clean up to the moment the fork accepts its first message.
4. **Read the boot warnings.** `INBUXA_*` settings fall back to their
   `STALWART_*` names with a warning to rename them (SPEC.md §2.5). The
   Enterprise license object in the registry has no meaning to the fork,
   which has no licence concept at all; the compat runs booted on a copy
   without complaining about it, but on the host, read the startup log
   rather than assume.

## The sequence

The install is native: `/opt/stalwart` with its data in `/opt/stalwart/data`
and a `stalwart.service` unit. The fork ships `inbuxa.service` with the same
shape, including `AmbientCapabilities=CAP_NET_BIND_SERVICE`, which is what
lets an unprivileged process hold port 25.

1. Announce the window. Mail will queue at the sending side while the server
   is down; nothing is lost, but delivery is delayed.
2. `systemctl stop stalwart`.
3. Snapshot `/opt/stalwart/data` — the whole directory, from the stopped
   server. This is the rollback.
4. Install the fork's binary and unit. Keep the Enterprise binary where a
   rollback can reach it without a download.
5. Start the fork. Watch the log before opening the ports to the world.
6. Work through the checks below.
7. Let mail flow.

## Before letting mail flow

- The version string names the right upstream base.
- Every listener is up, and the certificate served on 443 and 993 is the
  current one, not a self-signed fallback.
- An account signs in over IMAP, over JMAP, and through both front ends.
- A message sent from outside arrives; a message sent from inside leaves.
- The tenant's administrator can still see its own accounts and domains, and
  nobody else's.
- The queue is draining, and the task queue has no new permanent failures.

## Rollback

Restoring the snapshot from step 3 and starting the Enterprise build returns
the server to exactly where it was, and loses every message accepted since.
That is clean while the window is short and nothing has been accepted.

**Rolling back after the fork has been serving is not a snapshot restore.**
The fork writes objects its own features own — SCIM's event ids and the
rebuilt features' records — into a store the Enterprise build would then
read. Whether it tolerates them has never been tested, and testing it is
worth an hour before the day rather than an argument at 2am. Until it is
tested, treat the cutover as forward-only once mail has been accepted, and
make the decision to roll back early rather than late.

## The first week

- **Certificate renewal.** The one thing that fails quietly and late. Watch
  for the first renewal rather than waiting for an expiry.
- **The task queue**, for work that retries forever rather than failing.
- **The queue**, for mail that leaves more slowly than it did.
- **The logs**, for the `STALWART_*` fallback warnings, which name settings
  worth renaming while nobody is under pressure.

## Open

- Whether the Enterprise build can read a store the fork has written, which
  decides whether rollback stays available after mail has been accepted.
- Whether ACME renewal works on the host, which the test suite has not been
  able to settle (`container-tests.md`).
- Whether the front ends need anything at cutover, or follow separately
  (SPEC.md §5).
