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
  (`309835b`), and the test that still fails here fails for a reason local
  to this machine: `ufw` drops the port pebble validates against
  (`container-tests.md`). That is not evidence the renewal works on the
  host, only that the failure isn't the fork's. A certificate that fails to
  renew is a 90-day fuse, not an outage on the day, so it is the first thing
  to watch and the least likely to announce itself;
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

Side by side, not in place (John, 2026-09-19). The Enterprise install stays
where it is, untouched, and the fork goes in beside it with a copy of the
data. That makes the rollback a service swap rather than a restore, and it
is the main reason to prefer this shape.

The install is native: `/opt/stalwart`, its data in `/opt/stalwart/data`,
a `stalwart.service` unit, and ihasmail in a container beside it. The fork
ships `inbuxa.service` with the same shape, including
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, which is what lets an
unprivileged process hold port 25.

1. Announce the window. Mail queues at the sending side while the server is
   down; nothing is lost, but delivery is delayed.
2. Stop `stalwart.service` and the ihasmail container. **Disable the unit
   too**, so a reboot can't bring the Enterprise build back onto the ports
   while the fork is serving. Two servers on one set of ports, each with its
   own store, is the one failure this plan can produce that the in-place
   swap can't.
3. Copy `/opt/stalwart/data` to the fork's store path. A copy, not a move:
   the original is the rollback. Budget the disk for two full copies, and
   take it from the stopped server, never from under a running one.
4. Install the fork at its own path with its own config, pointing at the
   copied store. Most settings travel inside the store — they live in the
   registry — so the config file is mainly the store path and the hostname.
   New installs default to `/var/lib/inbuxa`; an existing install keeps
   whatever its configuration names (SPEC.md §2.5), so this is a free
   choice as long as the config and the unit agree.
5. Start the fork. Read the log before opening the ports.
6. Bring up INBUXA Admin and the new webmail. Both talk to the server over
   JMAP and OAuth, and neither runs on the mail host's web interface
   (SPEC.md §5.3); beside it in containers is fine.
7. Work through the checks below.
8. Let mail flow.

### What the front ends need

Their OAuth client registrations live in the store, so they travel with the
copy. A front end that reuses the old client id and redirect URIs keeps
working; one deployed under a new hostname, or registered afresh, needs its
client set up and its redirect URIs to match, or sign-in fails in a way that
looks like an account problem and isn't. Settle which of the two it is
before the day, not during it.

## Before letting mail flow

- The version string names the right upstream base.
- Every listener is up, and the certificate served on 443 and 993 is the
  current one, not a self-signed fallback.
- An account signs in over IMAP, over JMAP, and through both front ends.
- A message sent from outside arrives; a message sent from inside leaves.
- The tenant's administrator can still see its own accounts and domains, and
  nobody else's.
- The queue is draining, and the task queue has no new permanent failures.
- **Every account still works**, which is the plan's own test: each one
  signs in with the password it had, its mail is there, its aliases still
  receive, and app passwords and OAuth sessions are accepted. Nothing in
  the move touches credentials — they are in the store that was copied —
  so a failure here means the copy or the front ends, not the accounts.
- Nothing is listening on the old install's ports but the fork, and
  `stalwart.service` is disabled.

## Rollback

The Enterprise install and its data are untouched, so rolling back is: stop
the fork, re-enable and start `stalwart.service`, bring the old ihasmail
container back. Minutes, and no restore.

What it costs is everything the fork accepted while it served: the two
stores diverge from the moment the fork starts. Mail delivered to the fork's
store is not in the Enterprise one, and rolling back leaves it behind. So
the decision to roll back is worth making early and deliberately, and the
window between "started" and "letting mail flow" is where a rollback is
free.

**Rolling the data back is a different thing, and untested.** Pointing the
Enterprise build at the store the fork has been writing to would ask it to
read objects the fork's own features own. Whether it tolerates them has
never been checked, and checking it is worth an hour beforehand rather than
an argument at 2am. Until it is checked, treat the fork's store as
forward-only.

## The first week

- **Certificate renewal.** The one thing that fails quietly and late. Watch
  for the first renewal rather than waiting for an expiry.
- **The task queue**, for work that retries forever rather than failing.
- **The queue**, for mail that leaves more slowly than it did.
- **The logs**, for the `STALWART_*` fallback warnings, which name settings
  worth renaming while nobody is under pressure.

## Open

- Whether the Enterprise build can read a store the fork has written. With
  the side-by-side plan this only matters if the fork's store has to be
  carried back, since the rollback path is the old store, untouched.
- Whether ACME renewal works on the host, which the test suite has not been
  able to settle (`container-tests.md`).
- Whether the front ends need anything at cutover, or follow separately
  (SPEC.md §5).
