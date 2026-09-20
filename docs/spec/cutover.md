# Cutting INBUXA over to the fork

Status: 2026-09-20. **Done.** INBUXA was cut over to the fork on the morning
of 20 September in a 78-second window ("The run", below). This page is no
longer a plan; it is kept as the record of one, and as the source for the
migration tool that automates it (`migration.md`).

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

   **Then chown it.** `rsync -a` preserves ownership, so the copy arrives
   owned by the old service user while `inbuxa.service` runs as `User=inbuxa`
   — the fork will not be able to write its own store. `chown -R
   inbuxa:inbuxa` the copied tree before starting anything.

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
the fork, **make the original store writable again**, re-enable and start
`stalwart.service`, bring the old ihasmail container back. Minutes, and no
restore.

The writable step is easy to forget and the guard of step 3 is what makes it
necessary: the same read-only flag that stops the fork opening the original
by mistake also stops the Enterprise build starting on it. Undo it first, or
the rollback fails at the worst possible moment with what looks like a
permissions problem and isn't.

What it costs is everything the fork accepted while it served: the two
stores diverge from the moment the fork starts. Mail delivered to the fork's
store is not in the Enterprise one, and rolling back leaves it behind. So
the decision to roll back is worth making early and deliberately, and the
window between "started" and "letting mail flow" is where a rollback is
free.

**Rolling the data back is a different thing, and impossible.** Pointing the
Enterprise build at the store the fork has been writing to does not work and
cannot be made to: it refuses to start on it at all (below). The fork's
store is forward-only. The rollback is the old store or nothing.

## Retiring the old install

**Done, 2026-09-20.** `/opt/stalwart` and its unit were removed the same day
as the cutover, at the operator's decision and before the gate proposed
below. The section is kept because it describes the shape of the decision,
and because the migration tool has to offer it.

What was done, in order: the fork was confirmed to hold nothing open under
the old tree and to name it in neither its config nor its unit; the whole of
`/opt/stalwart` was archived and the archive verified off-host by checksum;
then the tree, `stalwart.service` and its drop-in were removed. The
`stalwart` user was **left alone** — `redis-server` runs as it, which
`pgrep -u stalwart` had already shown.

Two things worth carrying into `migration.md`:

- **The unit is not inside the tree.** `/opt/stalwart` does not contain
  `/etc/systemd/system/stalwart.service` or its drop-in, so an archive of the
  tree alone is not a restorable rollback. Both were saved separately beside
  the tarball. A tool that archives before retiring has to take them too.
- **Retiring changes what a rollback is.** Up to that moment it was a service
  swap against a store still on disk: stop one unit, start the other, minutes
  and no restore. Afterwards it is an untar, a chown, a unit to reinstate and
  a webmail image that no longer exists locally. Still possible, materially
  slower, and no longer the thing the Rollback section describes.

The rest of this section is what was decided beforehand, and stands as the
recommendation for anyone else.


**The new stack depends on nothing in the old one.** That is the point of
the shape, not a side effect of it: `/opt/stalwart` is a reference, and
everything the fork needs — the store, the config, anything else found along
the way — is copied to new paths under its own tree. When the old directory
goes, nothing should notice.

Nothing in the fork works against that. `inbuxa.service` substitutes its own
prefix and no path in the tree names `/opt/stalwart`; certificates and ACME
account keys live in the registry inside the store. The dependency, if one
appears, will have been created by hand during the move — a store path left
where it was, a config that still names the old tree, a webmail container
with a volume under it.

So prove it rather than assert it, and prove it reversibly:

- Nothing open: `lsof +D /opt/stalwart` against the running fork returns
  nothing, and neither does its config or unit mention the path.
- **Then rename it.** `mv /opt/stalwart /opt/stalwart.retired` and leave it
  a day under real traffic. If anything depended on it, that is when it
  says so, and the fix is one `mv` back. Deleting proves the same thing and
  cannot be undone; renaming is the same test with a way out.


The old install is **kept, shut down**, not removed (John, 2026-09-19). Its
unit stays installed and disabled and its store stays read-only, so it costs
a stopped service and the disk its data sits on, and nothing else. If a
rollback is ever wanted it is started again (see Rollback).

When it stops being worth keeping, that is the operator's call and the tool
**asks** rather than decides: keep it, or delete it. The tool never removes
the thing its own rollback depends on without being told to
(`migration.md`).

**Budget for two full copies indefinitely, not temporarily.** Step 3's
second copy is not reclaimed on a schedule; it is reclaimed when somebody
answers the prompt, which may be never.

Deleting it, when that is the answer, strands nothing else the fork needs:
ACME account keys and issued certificates live in the registry, inside the
store, so they came across with the copy
(`crates/common/src/network/acme/`). `/opt/stalwart` holds the old binary,
its config and its data, and that is all.

**When to ask.** Not on a timer. The signal worth waiting for is the fork
renewing a certificate, which is the one item in "The first week" that fails
quietly and late and the only failure that would genuinely send anyone back.
Waiting for it to happen naturally means most of 90 days; forcing a renewal
closes the question in a day, and is worth doing for that reason alone.

**Archive before deleting**, if deleting is the answer. A compressed copy of
the pre-cutover store, kept off the host, costs little and answers "what did
this look like before" for as long as anyone asks. Losing the last copy of
the pre-migration state is a different decision from reclaiming a directory,
and worth making separately.

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

## Source, and AGPL section 13

The fork is a modified AGPL program, so everyone who interacts with it over
a network has to be offered its Corresponding Source. That obligation starts
when the fork begins serving, which is the cutover, not the announcement.

Settled (John, 2026-09-19): the source is released after the cutover and the
links go live then. In between, the only people the server serves are the
operator's household, so the set of users owed an offer and the set of
people holding the repository are the same set. A migration by anyone else
inherits the obligation on their own first day, which is worth saying in the
migration tool's output rather than leaving them to find it
(`migration.md`).

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

## The run, 2026-09-20

INBUXA was cut over to the fork on the morning of 20 September. **The window
was 78 seconds**, from the stop at 09:38:32 to the fork serving on all nine
ports at 09:39:50. Mail queued at senders for that time and nothing was lost.
Both front ends followed within the hour, and the rollback was never needed.

| | | |
|---|---|---|
| Stop issued | 09:38:32 | |
| Old server stopped and disabled | 09:38:~40 | |
| Webmail stopped | 09:39:18 | |
| Store copied, 2.2 G | 09:39:22 | **1.4 s** |
| Chowned | 09:39:22 | |
| Original made immutable | 09:39:43 | |
| Fork started | 09:39:44 | |
| Serving on nine ports | 09:39:50 | **78 s total** |

2.2 G copied in 1.4 seconds, onto the same filesystem. The two-pass rsync of
step 3 would have bought nothing here; it earns its place on a store large
enough that copying dominates. Most of the 78 seconds was the operator
reading output, which is the right thing for it to be spent on.

### What step 0 was worth

Reading `systemctl cat stalwart` before touching anything found four things
the plan did not know, and one of them would have been a bad night.

**The server runs in a network namespace.** The unit carries
`NetworkNamespacePath=/run/netns/mail`, `Requires=mail-netns.service` and a
bind mount of that namespace's `resolv.conf`, with its own comment: Stalwart
owns 443 on the mail addresses while nginx keeps 443 on the web addresses. A
unit written from `resources/systemd/inbuxa.service` as this document
described would have started in the root namespace.

That is two failures, not one. It would have collided with nginx on 443 —
loud, and quickly understood. It would *also* have egressed from the host's
main address rather than `157.180.98.170`, which is the address the provider
granted port 25 on. Inbound would have looked healthy while outbound failed
at every receiver, with no local symptom and, as it turned out, no logs to
find it in. Verified after the fact: the namespace still holds the same two
addresses, traffic from inside it egresses from them, and public DNS for
`mail.inbuxa.com` resolves to the same pair. The mail addresses are
unchanged by the migration because the fork joined the existing namespace
rather than building one.

The namespace script itself needed nothing: `/usr/local/sbin/mail-netns.sh`
is pure networking — veth pair, addresses, routing, proxy NDP, sysctls — with
no path, user or chown that belongs to Stalwart.

**The hardening drop-in named the old tree.** `ProtectSystem=strict` with
`ReadWritePaths=/opt/stalwart`. Carried over unchanged, the fork would have
been sandboxed away from the store it had just been given.

**A reboot costs more than the plan assumed.** Mail and the website are the
same machine, which also carries Mastodon, ihasvpn, and a dozen other sites —
some two dozen containers. Step 9's reboot was costed as "a few minutes at
this scale"; it is an outage for everything hosted. It was still done,
deliberately, because it is the only honest proof that the fork comes up on
boot and the old unit does not.

**A pre-existing oddity**, not ours and not fixed: the old unit is
conditional on `/opt/stalwart/etc/config.toml` while it execs with
`--config=…/config.json`. The `.toml` is a 3.5 K fossil from March. The
fork's unit conditions on the file it actually uses.

### What the copied store brought with it

Three times over, in three different guises, the store carried configuration
that pointed back at the old world. This is the pattern to look for on any
migration, and it is worth a deliberate sweep rather than waiting to be bitten.

**The logs stopped.** The registry's tracer still named `/opt/stalwart/logs`,
which `ProtectSystem=strict` refuses, and the server tolerated the failure in
silence: the unit's journal had only systemd's own line, the old log file
stopped at the moment of the stop, and nothing new appeared anywhere. Not a
blocker for mail — but it meant the first week's advice to watch the logs
could not be followed, and nobody would have noticed.

**Stalwart's own web interface was being served.** The registry's
`Application` entries made the fork download `webui.zip` from
`stalwartlabs/webui` and serve it at `/admin` and `/account`, so signing in
at `mail.inbuxa.com` produced a Stalwart-branded interface. Not a regression
— the old server did the same — but it breaks §2.4 and §5.3 both. Removed;
the host now serves JMAP and OAuth only.

**And the same mistake from the other direction.** The new webmail's
environment was built by copying the old one's variable names. The fork has
been de-Stalwarting its configuration and renamed `STALWART_URL` to
`MAIL_SERVER_URL`, which defaults to `https://mail.example.com` when unset.
It started cleanly, reported healthy, and pointed at a placeholder. Worth
remembering that **a front end reporting healthy is not a front end talking
to the right server**: the health check passed in both states.

### What this document had wrong

**`systemctl mask` does not work here.** Masking puts a `/dev/null` symlink
where the unit file lives, and this unit lives in `/etc/systemd/system`, so
it fails outright. `disable` alone is what we have and it is sufficient: the
`WantedBy` symlink is gone, nothing `Requires` it, and `mail-netns.service`'s
`Before=` is ordering only. It is also the better answer, since the rollback
needs `systemctl enable --now stalwart` and hiding the unit file would have to
be undone first.

**There is no "let mail flow" gate.** This document separates starting the
fork from letting mail flow, and treats the space between as the window where
a rollback is free. There is no such space: the fork binds port 25 as it
starts, so mail began arriving at 09:39:44. The free-rollback window closes at
the start, not at the end of the checks. Either the sequence should say so, or
the design needs an actual valve — starting with the mail listeners disabled
and enabling them once the checks pass.

**IMAP's INBOX is not JMAP's account**, so the two counts differ before and
after alike; mail from unauthenticated senders is filed as spam. Compare each
against itself, or a faithful move looks like a loss.

### The bug this found

INBUXA Admin, hosted off the mail server as §5.3 requires, signed in and then
failed with "Failed to load the admin panel configuration". Every other
endpoint worked from the same origin with the same token; only `/api/schema`
failed, and a schema-driven interface cannot do without it.

It was Chrome's cache, not CORS. Measured from the page: a normal fetch
failed while `cache: "reload"`, `cache: "no-store"` and a cache-busted URL all
returned 200. The server never sees the failing request, which is why the logs
had nothing and why it read as a CORS fault for so long.

The response was `public, max-age=31536000, immutable` although it is served
behind authentication and its CORS headers vary by `Origin`, on a hash-named
URL that never changes; and `Vary: Origin` was only emitted when an origin
list existed, so anything cached before the front ends were configured carried
neither CORS headers nor `Vary`. Both fixed in `7c4add8`.

Nobody had met this before because the admin has always been served from the
mail host at `/admin`, where it is same-origin and no CORS applies. **The
first deployment that follows §5.3 meets it immediately** — which is exactly
what a first cutover is for.

### Method notes

Three things cost real time and none of them were the mail server.

- **Stale negative DNS.** A resolver asked for a name before its record
  existed caches the NXDOMAIN for the zone's negative TTL — 1800 s here. It
  appeared three times in three guises, including Chrome failing while Firefox
  worked on the same machine, because Firefox resolves over its own DoH and
  Chrome asks the OS. `dig @<authoritative-ns>` and `curl --resolve` settle it
  in seconds.
- **`grep` silently swallows binary output.** Piping `curl -i` of a gzipped
  body through `grep` printed nothing, which reads exactly like "the server
  returned no response" and produced a confident, false reproduction. Use
  `curl -o /dev/null -D -`.
- **`docker restart` does not re-read `--env-file`.** The container has to be
  recreated. This cost time twice in one morning.

### What the run did not settle

The checks that decide a cutover are the ones only its users can make. At the
time of writing the operator had signed in to both front ends and confirmed
mail flowing; the second account, the mailbox comparison against
`record-before.py`'s recording, and the printer were still outstanding. The
printer is the one account that cannot report its own fault.

ACME is untouched: the certificate renews itself around 28 October, since the
default `R12` renews at the halfway point of a 90-day certificate rather than
near its end. `/opt/stalwart` stays, stopped and read-only, until somebody
deliberately retires it.

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

- Whether ACME renewal works on the host, which neither the test suite
  (`container-tests.md`) nor the run has settled. The certificate renews
  itself around **28 October**: the default `AcmeRenewBefore::R12` renews at
  the halfway point of a 90-day certificate, not near its end, and no setting
  brings that forward. Either wait for it, or prove the path on a throwaway
  name whose DNS points at the mail addresses.
- Whether the front ends need anything at cutover, or follow separately
  (SPEC.md §5). The rehearsal does not start them.
- Whether ihasmail-inbuxa and INBUXA Admin behave under real use, rather
  than at first sign-in. Both were verified as far as signing in and, for the
  webmail, mail flowing.
- The checks only users can make: the second account, the mailbox comparison
  against the recording, and the printer.
