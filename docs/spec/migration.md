# Migrating a Stalwart install to INBUXA

Status: draft, 2026-09-19. Decided in outline (John, 2026-09-19); nothing
built.

Two ways in, and they are different workflows:

- **Fresh installation.** ihasmail-oneshot's `deploy`: a new stack, new
  domain, nothing to preserve (SPEC.md §6.1).
- **Migration.** An existing Stalwart server becomes an INBUXA one, keeping
  everything. This page is that one.

INBUXA's own cutover is the first run of it (`cutover.md`). The tool is what
that run leaves behind, so the second operator doesn't repeat it by hand.

## What the operator is responsible for

The tool moves a running mail server. Nobody should be in any doubt about
that while it is happening, so it says so rather than relying on the licence
to have said it. AGPL-3.0 §15 and §16 already disclaim warranty and
liability, and nothing here narrows or replaces them; this is the same thing
at the moment it matters, in words an operator can act on.

**Before it touches anything, the tool states plainly:**

- It stops the mail server, copies its data store, and starts a different
  server on the copy. Mail queues at the sending side while it runs; it is
  not lost, but it is delayed.
- **Backups, snapshots and recovery are the operator's.** The tool keeps the
  source install intact and can roll back to it, and that is not a backup:
  it is one copy, on one machine, of one moment. A disk that fails, a
  filesystem that fills, or a `rm` in the wrong directory takes both copies
  at once. Anyone without a backup they have actually restored from should
  stop and get one.
- It can fail in ways it cannot undo. The rollback returns the service; it
  does not return mail the fork accepted before the rollback was called, and
  the tool says how many messages that is rather than leaving it to be
  discovered.
- Nobody else is responsible for the outcome. Not the authors, not the
  project.

**What the tool does to earn that, rather than just asserting it:**

- `--dry-run` first, on a copy, with the timings, and the real run refuses
  to start until one has succeeded on that host. A disclaimer nobody read
  is worth less than a rehearsal nobody could skip.
- It never writes to what it migrates from, so the source stays a rollback.
- Verification before mail flows, and automatic rollback when it fails.
- The old install is kept until the operator retires it deliberately.
- Every phase timed and reported, so "how long will this take" is answered
  before the window rather than during it.

The confirmation the tool asks for names the host and the store path being
moved. `--yes` skips the prompt, not the dry run.

## What "transparent" means here

Everything that defines the server lives in its data store, so a migration
that copies the store carries it all: accounts and their passwords, app
passwords, OAuth clients and live sessions, aliases and mailing lists,
tenants, domains, DNS records and the DNS provider settings, certificates
and ACME state, Sieve scripts, the queue, and the mail itself.

Nothing is re-entered and nothing is re-issued. Users are not asked to
change a password, re-authorize a client, or re-point a DNS record. That is
the promise the tool makes, and the verification below is what checks it
rather than assuming it.

The store format is upstream's and unchanged (SPEC.md §2.6), which is what
makes this a copy rather than a conversion. A migration that also crosses an
upstream version is that upgrade first, then this.

## Shape

Side by side. The existing install is stopped but left standing, the fork
goes in at its own path with a copy of the data, and the old install is what
a rollback returns to. `stalwart-migrator` upgrades in place and says
plainly that it cannot undo one; this tool can, because it never writes to
what it migrates from.

It reads the source install and writes only to the new one. The source's
store is copied, never moved, never opened for writing.

## Phases, each timed

1. **Preflight**, with nothing stopped yet: the source's version and store
   backend, disk for a second copy of the store, the target path empty, the
   ports the fork will want, the front ends' plan, and a snapshot the
   operator confirms exists. Anything wrong here costs no downtime.
2. **Stop**: the mail server, then the webmail container. The unit is
   disabled as well as stopped, so a reboot can't put two servers on one set
   of ports with two diverging stores.
3. **Copy** the store to the fork's path.
4. **Configure**: the fork's config and unit, pointing at the copy.
5. **Start** the fork, and wait for it to answer.
6. **Front ends**: INBUXA Admin and the webmail, against the same store's
   OAuth clients.
7. **Verify** (below). This is the gate, not a formality.
8. **Report**.

**Downtime is phases 2 to 7**, and it is the number worth advertising — not
the total, which preflight and the copy dominate and which nobody
experiences. The report gives both, per phase, and writes them as JSON
beside the human-readable summary so a release note can quote them
honestly. A migration of a small server should be minutes; the number that
gets published should be one this tool measured, on a stated store size and
account count, not an estimate.

## Verification, before mail flows again

The same checks as `cutover.md`, run by the tool rather than by hand:

- the fork answers on every listener the source had, with the certificate
  the source was serving;
- an account signs in over IMAP, JMAP and both front ends, with the
  credential it already had;
- a message arrives from outside and one leaves;
- aliases still receive; a tenant administrator sees its own accounts and
  domains and no others;
- the queue drains and the task queue gains no permanent failures;
- nothing but the fork is listening on those ports.

A failed check is a failed migration, and the tool rolls back rather than
leaving a half-migrated server for the operator to reason about at 2am.

## After a migration: the stock client

A migration that passes its own verification has proved the fork works for
the fork. Pointing an **unmodified public ihasmail** at the migrated server
proves something else: that a client which knows nothing about INBUXA still
works against it. It runs anywhere — JMAP and OAuth over the network — and
needs only an OAuth client it may use.

Each difference it turns up is either a regression against upstream's
contract or a feature that now expects INBUXA's own front ends. The tool
doesn't run this; it belongs in the release notes and the contract
(SPEC.md §5.2). It is named here so the first migration doesn't skip it.

## Rollback

A first-class path, not an appendix.

- **Automatic** when verification fails, unless the operator asked for the
  tool to stop and wait instead. A server that half-works is worse than one
  that is back where it started.
- **On demand** afterwards, for as long as the old install is still there:
  `rollback` stops the fork, re-enables and starts the original unit, and
  brings the old webmail container back.
- **What it costs**: everything the fork accepted while it served. The two
  stores diverge from the moment the fork starts, so a rollback after mail
  has flowed leaves that mail in the fork's store. The tool says how many
  messages that is rather than letting the operator find out.
- **What it never does**: point the old server at the store the fork has
  been writing. That is not a recovery path and cannot be made into one —
  the old build refuses to open a store the fork has touched at all
  (`cutover.md`).
- **What it undoes first**: the read-only flag on the original store. The
  guard that stops the fork opening it by mistake also stops the old build
  starting on it.
- The old install is kept until the operator retires it deliberately. The
  tool does not delete the thing its rollback depends on, and when the
  operator is done with it the tool **asks** — keep, or delete — rather
  than deciding. Nothing the fork runs on may be inside it by then, which
  `verify` checks: no open file under the old tree, and no path in the
  fork's config or unit naming it.

## Rehearsal

`--dry-run` does everything but the stop: copies the store to a scratch
path, brings the fork up against it on alternate ports, runs what it can of
the verification, reports the timings, and removes the copy. It answers "how
long will this take, and will it work" without touching the running server,
and it is what the operator should run first.

## Open

- Where it lives: a command in ihasmail-oneshot, a sibling to
  `stalwart-migrator`, or the fork's own binary (SPEC.md §8's open question
  about the installer's repository).
- Whether it handles container installs as well as native ones, which
  changes "stop the unit" into "stop the stack".
- Whether it migrates a Community-edition install too. Nothing about the
  copy is Enterprise-specific, and a Community server has fewer objects
  rather than different ones, so this is likely a documentation question
  rather than a code one.
- What it does when the source is mid-upgrade, or its store format is older
  than the fork's base.
