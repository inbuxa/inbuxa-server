# Feature spec: inbuxa's own store layout, changed in steps

Status: approved direction, 2026-11-08 (John: "follow your recommendations").
Not a rebuild (SPEC.md §4): inbuxa's own design.

## Provenance

| Source | Used for |
|---|---|
| The store-independence decision (2026-10-29) and `docs/spec/import-0.16.md` | inbuxa owns its layout from 27.1. The Stalwart 0.16.27 layout is a frozen import format, not a promise |
| This server's store mark (`INBUXA_STORE_VERSION`, key `Vs` in `_`, `crates/migration`) | Where a store's layout version lives, and the refusal of a newer one |
| This server's in-memory store on SQL (`crates/store/src/dispatch/lookup.rs`) and the fork's subspace (`SUBSPACE_INBUXA`) | The two changes this spec makes |

Nothing here comes from Enterprise code or from upstream's 1.0 layout.

## What it is

Today a store is at layout version 1, which is the 0.16 layout plus the fork's
`_` subspace. This spec adds the machinery to move a store from one layout
version to the next in place, at boot. It also defines the first two steps:

- **1 → 2:** rate-limit counters on PostgreSQL, MySQL and SQLite keep their
  expiry in the counter's own row.
- **2 → 3:** the fork's large data (the audit log, the journal, holds and
  undelete notes) moves out of `_` into subspaces of its own.

A layout step stops rollback to any build that reads only an older version.
So a step is a breaking change and ships at a series: 27.1 if it is ready
before January, else 27.7. Release candidates may carry it before then.

## Requirements

### The runner

- **SL-1.** `crates/migration` holds one function per step, keyed by the
  version it starts from. At boot the runner reads the mark, treats a
  missing mark on an existing store as 1, and runs every step from there up
  to `INBUXA_STORE_VERSION`. It writes the mark right after each step's last
  write; SL-2 makes a step that stopped before the mark safe to run again. A
  new install is marked at `INBUXA_STORE_VERSION` straight away. The steps
  are in `crates/migration/src/layout.rs`.
- **SL-2.** Every step can run twice safely. A step interrupted half-way
  runs again from the start on the next boot and comes to the same result.
- **SL-3.** One node runs the steps. Before the first step a node takes a
  lease: an `AssertValue` compare-and-set on key `Vm` in `_`, holding the
  node id and an expiry 10 minutes ahead, renewed every minute while steps
  run. A node that can't take the lease waits, re-reads the mark every 10
  seconds, and goes on booting once the mark reaches its own version. A
  lease left by a node that died expires and the next node takes it over.
  A node also takes over a lease held under its own node id, which a run of
  its own that stopped left behind. A node whose renewal finds the lease
  taken stops before writing the mark.
- **SL-4.** A newer mark than the build's own is refused before anything is
  written, as now.
- **SL-5.** A running node re-reads the mark every 60 seconds. When it finds
  a version above its own, it logs why, stops taking connections and exits
  non-zero. Then a node left on the old build during an upgrade can't keep
  writing the old layout. This ships in the release before the first step
  that isn't rolling-safe (SL-6). It ships with the runner.
- **SL-6.** Each step says whether it is rolling-safe: whether nodes on the
  build before it can keep running, unharmed, against the new layout. A
  step that isn't refuses to start while another node shows as active
  (`cluster_node_list`, status Active). A stopped node stops showing as
  active three minutes after its last heartbeat (`UNRESPONSIVE_NODE_TIMEOUT`).
  The step waits, re-checking every 10 seconds, and logs every minute that
  the other nodes must be stopped first. Only other node ids on other hosts
  count, so a single-node install never waits, even on an id of its own
  from before a restart.
- **SL-7.** Each step logs when it starts and when it ends, with counts of
  what it changed. The startup log states the store's layout version.
- **SL-8.** Before a step runs, the server logs that the upgrade can't be
  rolled back without a backup, and where the docs are. The upgrade docs
  tell operators to take a database dump right before the upgrade, because
  the nightly dump isn't enough.

### Reading what a newer build wrote

- **SL-9.** Stored lists and map keys of enum values (permissions, events,
  and others) skip a value the build doesn't know instead of failing the
  whole object. This is needed before the first step, and on release/2026,
  so that a rollback still loads its roles. It shipped as its own change
  (registry `Pickle::unpickle_item`).

### Step 1 → 2: counters keep their own expiry (SQL backends)

- **SL-10.** On PostgreSQL, MySQL and SQLite, the counter table `y` gets a
  nullable expiry column `e`. A counter with an expiry is written as one
  row, `(k, v, e)`, instead of a counter row in `y` plus an expiry marker
  row in `m`. RocksDB and FoundationDB keep today's form, and the step does
  nothing there except write the mark.
- **SL-11.** The column is added at boot by every build that has it, before
  any step runs, so a node is never without it. The step fills `e` from each
  counter's marker (an upsert adding 0 and keeping the later expiry), then
  deletes those markers. A counter whose marker has already run out is
  deleted with it. Locks, greylist entries, Sieve duplicate ids and other keys
  in `m` stay where they are.
- **SL-12.** The purge deletes expired counters with one statement per table
  (`DELETE FROM y WHERE e <= now`). Rows with a NULL `e`, written by a node on
  the old build during a roll, are purged the old way.
- **SL-13.** Rolling-safe. An old node's counter upsert still works with the
  column there.
- **SL-14.** Also, on every backend: write the expiry marker only when the
  counter's bucket is new, not on every increment. That half of the gain
  needs no step and may land first. Each process remembers the markers it
  has written; an increment leaves the marker out only once that write is
  in and its expiry is at least the one asked for. A counter that comes back
  equal to the amount added was just created, so if its marker was left out
  (another node reset or purged the bucket) it is written straight after:
  a counter is never left without a marker, which would keep it for good.

### Step 2 → 3: the fork's data gets its own subspaces

- **SL-15.** Subspaces get names, not only bytes. Each one has an id byte and
  a name, and the SQL table and RocksDB column family come from the name.
  Upstream's subspaces keep their one-letter names, so nothing changes for
  them. New ones take id bytes from 0x80 up, which are never letters, and
  names starting `ib_`. Every place that builds a table or column family
  name from the byte uses the name instead.
- **SL-16.** The audit log, the journal, holds and undelete notes each move
  to a subspace of their own, dropping the feature prefix byte from each key.
  The small single keys (the store mark, the lease, settings marks) stay in
  `_`. The step's design first lists every key prefix in `_` and its owner.
  A prefix nobody claims stops the step.
- **SL-17.** For each moved prefix the step copies the rows, compares counts,
  and for the audit log also compares the chain head, before it deletes the
  originals. Any mismatch aborts the step with nothing deleted. On
  PostgreSQL the copy is done server-side (`INSERT … SELECT`).
- **SL-18.** Not rolling-safe (SL-6). On RocksDB an old binary can't open a
  store with column families it doesn't know.
- **SL-19.** The moved data travels in exports in a family of its own,
  included by default, so a configuration export can leave it out. Importing
  an export taken at version 1 or 2 runs the steps after the import.
- **SL-20.** The legacy `v` and `c` column families, which nothing writes,
  are dropped in the same step.

### Imports and checks

- **SL-21.** A Stalwart 0.16 store has no mark, so it goes through every step.
  `tools/import-check/check.sh` runs on each RC that adds a step.
- **SL-22.** Tests for each step: on every backend it changes, the step on a
  seeded store at the version before (data kept, mark written, a second run
  changes nothing); two nodes starting together on PostgreSQL (one runs the
  step); a build that reads only the older version refusing the store; and
  `tests/src/store_version.rs` extended to the new version.

## Order

1. SL-9 (skip unknown enum values), on main and release/2026.
2. SL-14 (marker only for a new bucket), no step.
3. The runner (SL-1 to SL-8) with step 1 → 2 (SL-10 to SL-13). It is
   rolling-safe, so prod can roll it node by node.
4. Step 2 → 3 (SL-15 to SL-20), after step 1 → 2 has run on prod. SL-5 has
   to be on every node before it, and prod stops all three nodes for it.

## Measure first

On the PostgreSQL leader, before and after each step:
`pg_stat_user_tables` for `m`, `y` and `_` (live rows, inserts, updates);
WAL bytes over an hour; and
`SELECT get_byte(k,0), count(*), sum(length(v)) FROM "_" GROUP BY 1`
for the size of step 2 → 3.
