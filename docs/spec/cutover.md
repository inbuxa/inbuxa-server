# Cutting INBUXA over to the fork

Status: draft, 2026-09-19. The sequence has been rehearsed once, on
synthetic data ("The rehearsal", below). INBUXA's own data has not been
through it.

SPEC.md §7 step 4. This run is also the first run of the migration tool
INBUXA will ship (`migration.md`): what is done by hand here is what that
tool automates, including its rollback.

Steps 1 to 3 are met: the fork builds and its suites pass
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

   **Copy it in two passes, or the window is the whole store.** The host is
   ext4, so there is no filesystem snapshot to take and the naive sequence
   makes every byte part of the downtime. Instead:

   ```sh
   rsync -aH --delete /opt/stalwart/data/ /var/lib/inbuxa/    # server up
   systemctl stop stalwart && systemctl disable stalwart      # the window opens
   rsync -aH --delete /opt/stalwart/data/ /var/lib/inbuxa/    # only the delta
   ```

   The first pass is deliberately inconsistent and that is fine: it exists
   only to move the bulk while mail is still flowing. The second pass, after
   the server has fully exited, is what makes the copy consistent, and it
   moves very little — a RocksDB store is mostly immutable SST files, so
   what changes between the passes is the WAL, the MANIFEST and whatever
   compaction has just written. Wait for the process to exit, not just for
   `systemctl stop` to return.

   Time both passes during the rehearsal. The second one is the number that
   matters: it is the window.

   **Then make the original read-only, before the fork exists on this host**
   (`chmod -R a-w`, or `chattr +i` on the directory, or keep it on a
   read-only bind mount). Until this moment the running server's own RocksDB
   lock was what stopped anything else opening that store; stopping it takes
   that away exactly when a store path is about to be typed. A read-only
   original refuses the fork harmlessly and still starts under the
   Enterprise build — measured, `tools/fork/cutover-rehearsal/probe_guard.py`.
   Undo it only if you are rolling back.
4. Install the fork at its own path, with **its own copy** of the config —
   not a reference to the old one. Most settings travel inside the store —
   they live in the registry — so the config file is mainly the store path
   and the hostname.

   The store path is **not** a free choice, because `/opt/stalwart` is to be
   removed once the migration is confirmed ("Retiring the old install",
   below). Nothing the fork runs on may live under it: the store goes to the
   fork's own path (`/var/lib/inbuxa` for a new install), the config beside
   it, and neither may name a path inside `/opt/stalwart`. Check that before
   starting, not after deleting.
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

## Retiring the old install

`/opt/stalwart` goes away once the migration is confirmed (John,
2026-09-19). It holds the old binary, its config and its data, and nothing
else the fork needs: ACME account keys and issued certificates live in the
registry, inside the store, so they came across with the copy
(`crates/common/src/network/acme/`). Removing the directory strands nothing.

What it does end is the rollback, permanently, so it is worth being exact
about when.

**The rollback stops being a rollback long before this.** From the moment
mail flows, going back to the old store means losing everything that
arrived since. After a day, `/opt/stalwart` is not something anyone would
actually switch to — it is a cold copy of the pre-cutover state. The
decision is therefore not "when do we stop being able to roll back", which
answers itself within hours, but "when do we stop keeping a copy of what
was there before".

**The gate.** Keep it until the fork has renewed a certificate. That is the
one thing in "The first week" that fails quietly and late, and the only
check whose failure would send anyone back. Waiting for it naturally means
waiting most of 90 days; forcing a renewal instead closes the gate in a
day, and is worth doing for that reason alone.

**Archive before removing.** A compressed copy of the pre-cutover store,
kept off the host, costs little and answers "what did this look like
before" for as long as anyone asks. Deleting the directory is fine; being
left with no copy of the pre-migration state is a different thing, and not
what is being asked for here.

Only then: remove the unit file, `/opt/stalwart`, and the old ihasmail
container and image. Until then the unit stays installed and disabled, and
the store stays read-only (step 3).

## After: stock ihasmail against the fork

Once the migration is done, point an **unmodified public ihasmail**
container at the new server — it can run on a laptop, since it talks JMAP
and OAuth over the network (SPEC.md §5.3) — and work through what it can
do. It needs an OAuth client it is allowed to use and a reachable URL for
the server, nothing else.

This is the one check that comes from outside the fork's own world. Public
ihasmail is Stalwart-facing by design (SPEC.md §5) and knows nothing about
INBUXA, so whatever it can no longer do is one of two things, and both are
worth knowing:

- a **regression**: the fork broke something upstream's clients rely on,
  which the fork's own suites wouldn't catch because they test the fork;
- a **gap by design**: a feature that now needs INBUXA's own front ends,
  which belongs in the contract (SPEC.md §5.2) and in the release notes
  rather than being discovered by a user.

Write down which of the two each difference is. Do it after mail is
flowing, not as a gate: it informs the contract, it doesn't block the
cutover.

## The first week

- **Certificate renewal.** The one thing that fails quietly and late. Watch
  for the first renewal rather than waiting for an expiry.
- **The task queue**, for work that retries forever rather than failing.
- **The queue**, for mail that leaves more slowly than it did.
- **The logs**, for the `STALWART_*` fallback warnings, which name settings
  worth renaming while nobody is under pressure.

## The rehearsal, 2026-09-19

`tools/fork/cutover-rehearsal/` runs this document against data it makes up:
upstream 0.16.22 in a container as the install running today, the fork beside
it, both unprivileged with `CAP_NET_BIND_SERVICE`. It rehearses the sequence,
not the data — the data is `compat-tests.md`. **27 of 27 checks passed, and
the rollback took 1.5 seconds.**

What it turned from assumption into observation:

- The fork opens and serves a store the previous build wrote. Every account
  signed in with the password it had, over JMAP and over IMAP; mail read
  back as the same set; an alias still delivered.
- A tenant administrator saw exactly its own accounts and domains and still
  could not read listeners — across the copy, unchanged. That is the shape
  of the check `tenant_compat` could not make, `tenantAdmins` being empty on
  the real run. It is not INBUXA's tenant, but the mechanism holds.
- Ports 25, 465 and 993 were bound by an unprivileged process.
- The `STALWART_*` fallback warnings of SPEC.md §2.5 fire, naming each
  setting to rename. A third warning is worth knowing about in advance:
  with the server configured and not in recovery mode,
  `INBUXA_RECOVERY_ADMIN` is **ignored**, and the log says to remove it.
- The rollback restored the exact pre-cutover state and left behind only
  what the fork had accepted — the documented cost, measured rather than
  asserted.

Two things to carry into the day, neither of them a fault:

- **Set the fixture up right or the tenant check is vacuous.**
  `memberTenantId` does not come down from the domain, and is refused on
  create (`invalidForeignKey`); it has to be set afterwards. An account
  without one is server-wide, so a tenant "admin" without one is a server
  administrator and sees everything.
- **IMAP's INBOX is not JMAP's account.** Mail from an unauthenticated
  sender is filed as spam, so INBOX counts and message counts differ, before
  and after alike. Compare each against itself on the day, or a faithful
  move will look like a loss.

## Answered: the Enterprise build cannot read the fork's store

This was open. It is now settled, and the answer is no.

Pointed at a store the fork had opened, upstream 0.16.22 refuses to start:

```
⚠️ Startup failed: Failed to open database:
   Error { message: "Invalid argument: Column families not opened: _" }
```

The fork adds one RocksDB column family for masked email
(`SUBSPACE_INBUXA: u8 = b'_'`, `crates/store/src/lib.rs`) and opens the
database with `create_missing_column_families(true)`, so it creates `_` on
first open. Upstream has no descriptor for it, and RocksDB will not open a
database holding a column family it was not told about.

The mistake is worth guarding mechanically rather than carefully, because
the guard that exists today is removed by step 2. Three states, measured
(`probe_guard.py`):

| The original store is | The fork | The rollback |
|---|---|---|
| held by the running server | refused by RocksDB's lock | intact |
| stopped, read-only | refused while rotating its own log | intact |
| stopped, writable | **opens, and adds `_`** | **gone** |

So the window of exposure opens the moment `stalwart.service` stops and
closes when the original is made read-only. Keep it short.

Three consequences:

- The failure is a hard one, at startup, exit code 1, **before any data is
  read**. That is the good version: it is loud and immediate, not a slow
  corruption.
- **"A copy, not a move" is load-bearing, and more so than step 3 says.**
  One open by the fork is enough: the store gains `_` and upstream can never
  open it again. Pointing the fork at the original even once — to "just
  check" — destroys the rollback path. The copy is the only thing that keeps
  the Enterprise install able to start.
- The side-by-side plan is not merely preferable, it is the only shape with
  a rollback at all. An in-place swap would have no way back.

## Open

- Whether ACME renewal works on the host, which the test suite has not been
  able to settle (`container-tests.md`). Untouched by the rehearsal, which
  runs with `requestTlsCertificate: false`.
- Whether the front ends need anything at cutover, or follow separately
  (SPEC.md §5). The rehearsal does not start them.
- What the sequence does on the host rather than in containers: systemd,
  `AmbientCapabilities`, and above all `systemctl disable stalwart`, which
  has no analogue in the rehearsal and is the one step guarding against two
  servers on one set of ports.
- Whether INBUXA's own data survives the sequence, as opposed to opening
  under it. That needs a snapshot and a repeat of "Before the day" step 2.
