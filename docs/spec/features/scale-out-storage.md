# Feature spec: scale-out storage

Status: draft, 2026-09-18. Feature 8 in SPEC.md §4. Lowest priority of the
eight.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `resources/schema/schema.json.gz` and `crates/registry/src/schema/*.rs` in this repository (v0.16.22) | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | The config objects and fields, what upstream flags as Enterprise, which variants may be shard members |
| This repository's AGPL code after the strip: `crates/store` (`lib.rs`, `build/`, `dispatch/`, `backend/{postgres,mysql}/main.rs`, `write/blob.rs`, `query/log.rs`), `crates/services/src/task_manager/maintenance.rs`, `crates/types` (`blob_hash.rs`, `type_state.rs`), `crates/trc` event names, `tests/src/store` | AGPL-3.0-only (Enterprise code was stripped before commit) | The seams, what's missing, how blobs and change ids are keyed today |
| The strip report, `docs/fork/strip-reports/v0.16.22.json` | Ours | Which files and how many snippets were removed. It records counts and paths only, no removed text |
| Stalwart documentation (`website` repo): `docs/storage/backends/composite/{index,sql-replica,sharded-blob,sharded-in-memory}.md`, the same four under `docs/0.15/`, the "Read replicas" sections of `docs/storage/backends/{postgresql,mysql}.md`, and `docs/ref/object/{data-store,blob-store,in-memory-store,search-store}.md` | Unlicensed public documentation: facts used, prose not copied | What each composite store does, which variants it takes, the "keep the shard list stable" rule, where `readReplicas` applies |
| PostgreSQL documentation: "Hot Standby" and "System Administration Functions" (current) | PostgreSQL License | Standby visibility, recovery conflicts, `pg_is_in_recovery()`, `pg_last_wal_replay_lsn()`, `pg_current_wal_lsn()` |
| MySQL 8.4 Reference Manual: `SHOW REPLICA STATUS`, replica options | Public documentation: facts used | `Seconds_Behind_Source` and when it's NULL, the `REPLICATION CLIENT` privilege, `replica_preserve_commit_order` |

No Enterprise-only file or snippet was used. The drafting session is a fresh
one that never saw Enterprise code, upstream's or anyone else's. The removed
files are known here only by their paths in the strip report. Nothing in this
spec describes how upstream implements any of it. Where a behavior couldn't be
settled from these sources, it's marked **Decision** or listed under "Open
questions / to observe".

Disclosure: the drafting session saved its own listing of the documentation
repository's file tree under `/tmp/claude-1000/`, a path the rules bar because
upstream checkouts live there. It grepped that one file, its own `gh api`
output, then deleted it, and read nothing else under that path.

There is no "Observed" section. INBUXA runs a single store, so there is no
live Enterprise deployment of these features to probe.

## What it is

Three ways to spread storage over more than one backend, for installs too
large for one database or one bucket:

- **SQL read replicas.** A PostgreSQL or MySQL store gets a list of replicas.
  Writes go to the primary. Some reads go to the replicas, which takes load
  off the primary.
- **Sharded blob store.** Message bodies, attachments and other blobs are
  spread over two or more blob backends. Each blob lives on one of them,
  chosen from its key.
- **Sharded in-memory store.** Short-lived data (rate-limit counters, locks,
  temporary tokens) is spread over two or more Redis-type backends the same
  way. The same object serves a sharded lookup store.

Upstream ships these only in its Enterprise Edition. inbuxa-server ships them
to everybody, with no edition check.

**Priority.** INBUXA runs one store and doesn't need any of this. It's the
last feature in SPEC.md §4, and nothing else waits on it. It matters for one
reason beyond scale: configs written for upstream Enterprise that use these
fields must open in inbuxa-server and do what they say, rather than being
silently ignored (see "What the fork has today").

## What the fork has today

The strip removed four whole files under `crates/store/src/backend/composite/`
(`mod.rs`, `read_replica.rs`, `sharded_blob.rs`, `sharded_lookup.rs`) and
snippets from these files: `lib.rs` (6), `backend/mod.rs` (1),
`backend/mysql/main.rs` (1), `backend/postgres/main.rs` (1), `build/blob.rs`
(2), `build/lookup.rs` (1), `build/memory.rs` (2), `dispatch/blob.rs` (6),
`dispatch/lookup.rs` (10), `dispatch/mod.rs` (1), `dispatch/search.rs` (6),
`dispatch/store.rs` (8). This spec doesn't guess what they held. What remains:

- **The config is complete.** The registry schema and its generated Rust
  types still carry every field: `readReplicas` on `x:PostgreSqlStore` and
  `x:MySqlStore`, the `Sharded` variant of `x:BlobStore`, `x:InMemoryStore` and
  `x:LookupStore`, and `x:ShardedBlobStore` / `x:ShardedInMemoryStore`. The
  server accepts and stores them.
- **Replicas are connected to, then dropped.** `PostgresStore::open` and
  `MysqlStore::open` build a connection pool for each `readReplicas` entry
  and put them in a local `replicas` list. Nothing uses the list, and `open`
  returns the primary alone. Replica pools inherit everything from the primary's
  config except host, port, database, user, secret (and `options` on
  PostgreSQL). Both drivers connect lazily, so today a configured replica
  costs nothing and does nothing. The one exception is a bad replica secret,
  which fails `open`. **The replicas are ignored without a warning.**
- **Sharded stores fail to build.** `BlobStore::build`,
  `InMemoryStore::build` and `LookupStores::parse_stores` have no arm for
  `Sharded`. It falls to the catch-all, which reports "Binary was not compiled
  with the selected … backend". That message is wrong: no build option
  provides it.
- **The store enums have no composite variant.** `Store`, `BlobStore` and
  `InMemoryStore` in `lib.rs` list only single backends. Every method in
  `dispatch/{store,blob,lookup,search}.rs` is a `match` over those variants.
  Those matches are the seams where composite variants go.
- **Leftovers from the strip, to clean up when this lands:**
  - `lib.rs`, `Store::is_same`, still has an arm for
    `Store::SQLReadReplica` under `#[cfg(all(feature = "enterprise", …))]`.
    The variant doesn't exist. It compiles only because the feature is off.
  - `crates/store/Cargo.toml` still declares `enterprise = []`. SPEC.md §2.3
    says the feature is gone.
  - `build/lookup.rs` gets an unused-import warning for `LookupStore`. It's one
    of the six in SPEC.md §2.2b. The `inbuxa` binary's default features are
    `["rocks"]` only. In that build every remaining arm that names
    `LookupStore` is behind a backend feature (`postgres`, `mysql`, `sqlite`,
    `redis`), so the import is unused. A `Sharded` arm needs no backend
    feature, so it uses the import again. Leave the warning until then. Don't
    silence it.
  - Also in `build/lookup.rs`, `LookupStore::RedisSentinel` has no arm either,
    even with `redis` on. Whether that's upstream's own gap isn't known. It
    isn't part of this feature. Noted for triage.
- **Related, and unaffected:** blob purging already works in 256 slices by
  the first byte of the blob hash (`purge_blobs`, and `shardIndex` on
  `x:TaskStoreMaintenance`). That's slicing of the purge task, not store
  sharding, and it isn't flagged Enterprise.

**Where the code goes.** SPEC.md §2.3 puts rebuilt features in a fork-owned
crate. That doesn't work here. The composite variants must be variants of
`store`'s own enums, and a separate crate that depends on `store` can't also
be depended on by it. **Decision:** the rebuild lives in `crates/store` in new
fork-owned files (AGPL-3.0-only headers) under
`crates/store/src/backend/scaleout/`, with one variant added to each enum and
one arm to each dispatch `match`. It isn't put back under `backend/composite/`,
because that path belongs to upstream's stripped files and would collide on
every sync.

## Data model

Unchanged from upstream, so existing configs open as they are. No field is
added. Upstream flags only two fields as Enterprise, and in inbuxa-server
they're ordinary: `x:MySqlStore.readReplicas` and
`x:PostgreSqlStore.readReplicas`. The sharded variants and objects aren't
flagged in the schema at all, though upstream's documentation calls them
Enterprise.

### Read replicas

`readReplicas` is a list on `x:PostgreSqlStore` (entries `x:PostgreSqlSettings`)
and `x:MySqlStore` (entries `x:MySqlSettings`). Each entry has `host`, `port`,
`database`, `authUsername`, `authSecret`, and on PostgreSQL `options`. Defaults
match the store's: user and database `stalwart`, port 5432 or 3306.

A PostgreSQL or MySQL store object can appear as the `x:DataStore`,
`x:BlobStore`, `x:SearchStore`, a `x:StoreLookup` store, a member of a sharded
blob store, and the `x:TracingStore` or `x:MetricsStore`. The field is the same
in every place.

Upstream's 0.15 documentation describes an older standalone
`sql-read-replica` store type naming a primary and replica store ids. The 0.16
registry has no such type. It's out of scope. Configs from before 0.16 go
through upstream's own migration.

### Sharded stores

| Object | Field | Type | Members may be |
|---|---|---|---|
| `x:ShardedBlobStore`, as `x:BlobStore` `@type: "Sharded"` | `stores` | list of `x:BlobStoreBase`, at least 2 | `S3`, `Azure`, `FileSystem`, `FoundationDb`, `PostgreSql`, `MySql` |
| `x:ShardedInMemoryStore`, as `x:InMemoryStore` `@type: "Sharded"` | `stores` | list of `x:InMemoryStoreBase`, at least 2 | `Redis`, `RedisCluster`, `RedisSentinel` |
| `x:ShardedInMemoryStore`, as a `x:StoreLookup`'s `store`, `@type: "Sharded"` | `stores` | as above | as above |

The base types leave out `Default` and `Sharded`, so a shard can't be the data
store by reference and shards can't nest. A member can still be a PostgreSQL or
MySQL store with its own `readReplicas`.

Permissions are the existing `sysBlobStore*`, `sysInMemoryStore*`,
`sysDataStore*`, `sysSearchStore*` ones. Nothing new.

## Required behavior

Each requirement has an ID, and tests name the IDs they check.

### General

- **ST-1.** Off unless configured. An install with no `readReplicas` entries
  and no `Sharded` variant behaves exactly as it does today: the same
  connections, queries, events and code paths, and no extra work per request.
  An empty `readReplicas` list is the same as none.
- **ST-2.** Existing configs open unchanged, with no edition check. A config
  with `readReplicas` or `Sharded` either works as this spec says, or the
  server reports why at startup (ST-15, ST-23, ST-29). Silently ignoring a
  configured replica or shard, as the fork does today, isn't allowed.
  **Decision** (2026-09-19): built in two steps. Sharded stores (ST-16 to
  ST-29) come first; read-replica routing (ST-5 to ST-15) follows after
  per-domain directories (feature 9). Until then each configured replica is
  reported at startup with an error event naming it, saying replicas aren't
  used yet, and every operation goes to the primary.
- **ST-3.** Composite stores are transparent. Every check on what kind of
  backend a store is answers as its primary does (for replicas) or as its
  members do (for shards): `Store::id()`, `is_sql()`, `is_pg_or_mysql()`,
  `SearchStore::is_postgres()` / `is_mysql()`, `InMemoryStore::is_redis()`.
  So a SQL directory on a data store with replicas is still a SQL directory,
  and PostgreSQL full-text search still uses PostgreSQL's syntax.
- **ST-4.** No new Cargo feature. **Decision:** composite stores are always
  compiled. A composite is usable whenever its member backends are compiled
  in. A member whose backend isn't compiled gets the existing "not compiled"
  build error, naming the member's position in the list.

### Read replicas: routing

- **ST-5.** The primary is the default. Every operation goes to the primary
  unless ST-6 names it. That includes:
  - every write: `write` batches, `delete_range`, `delete_documents`,
    `purge_store`, `create_tables`, account destruction;
  - every read that feeds a write: value assertions, counters read back from
    a write (`add_and_get`), document-id assignment, `try_lock`'s read of the
    current lock, quota checks;
  - the in-memory store when it's the data store (`InMemoryStore::Store`):
    rate limits, locks, tokens;
  - the registry and settings, bootstrap, recovery mode, cluster membership
    and the task queue;
  - maintenance, purges, migrations, reindexing, backup and export;
  - `sql_query`. **Decision:** the statement is operator-written (SQL
    directories, lookup stores, Sieve and expression queries), so the server
    can't tell a read from a write. It always goes to the primary.
- **ST-6.** Replica-eligible reads are opted into at the call site, never
  inferred by the store. **Decision:** the store keeps its current API, which
  always means the primary, and adds an explicit read handle for a given
  account (see "Interfaces"). The first call sites to use it:
  - JMAP `/get`, `/query`, `/changes` and `/queryChanges` on account data,
    and blob download;
  - IMAP `FETCH`, `SEARCH`, `STATUS` and `LIST`, and POP3 `RETR` and `TOP`;
  - WebDAV, CalDAV and CardDAV `GET`, `PROPFIND` and `REPORT`;
  - full-text search queries (`SearchStore::query_account`, `query_global`)
    on a PostgreSQL or MySQL search store;
  - blob reads from a PostgreSQL or MySQL blob store (ST-9).

  A read in a request that also writes goes to the primary: every method in a
  JMAP request after its first `/set`, `/copy` or `/import`, and every read
  inside an IMAP command that writes (`STORE`, `COPY`, `MOVE`, `APPEND`,
  `EXPUNGE`).
- **ST-7.** Read-your-writes. After a write for an account returns to the
  client, every later read for that account sees it, on any node. The
  mechanism, a **Decision**:
  1. Every write for an account produces a change id (the per-account
     counter already returned by the write, `AssignedIds`). Each node keeps,
     per account, the highest change id it has written or heard of (its
     *high-water mark*). It learns of other nodes' writes from the
     `StateChange` broadcasts it already receives, which carry the account and
     change id.
  2. When the server runs more than one node, a write also records the
     account's high-water mark in the in-memory store, with an expiry of twice
     the lag limit (ST-11). This happens before the write's result goes back
     to the client, so no node can answer from a replica before it can see the
     mark. A single node keeps the mark in memory only.
  3. Before an account's read goes to a replica, the server compares the
     replica's latest change id for that account with the mark: the local
     mark, and the shared one when there is one. If the replica is behind, the
     read goes to the primary. The replica's figure may be cached per request.
  4. A state the client presents raises the mark for that read: JMAP
     `sinceState` and `ifInState`, EventSource and push resumption, IMAP
     `CONDSTORE` mod-sequences and `QRESYNC`.

  So after `Email/set` creates a message, the next `Email/get` finds it,
  `Email/changes` from the old state lists it, and a renamed mailbox reads
  back with its new name, whichever node answers.
- **ST-8.** A miss on a replica isn't final. An id that a replica reports
  missing is looked up on the primary before the server answers `notFound`,
  or its equivalent in other protocols. This backs ST-7 up at the cost of one
  primary read per miss.
- **ST-9.** Blobs on a SQL store with replicas. Reads may go to a replica
  (ST-6). A blob the replica doesn't have is read from the primary. Writes and
  deletes go to the primary. Most blob keys are content hashes and never
  change. The few named blobs that are overwritten (the spam classifier model
  and training data, installed app resources) may read stale for up to the lag
  limit. That's accepted.

### Read replicas: lag, failure and validation

- **ST-10.** Lag is measured, not assumed. Each node samples every replica
  once a second (**Decision**):
  - **PostgreSQL:** the replica must answer `pg_is_in_recovery()` true. The
    node samples the primary's `pg_current_wal_lsn()` with a timestamp, and the
    replica's `pg_last_wal_replay_lsn()`. The lag is the age of the oldest
    primary sample the replica hasn't yet replayed. This stays correct when
    the primary is idle, which a replay timestamp doesn't.
  - **MySQL with GTIDs:** the same scheme, comparing the primary's
    `@@global.gtid_executed` samples with the replica's using `GTID_SUBSET()`.
  - **MySQL without GTIDs:** `Seconds_Behind_Source` from
    `SHOW REPLICA STATUS`, which needs the `REPLICATION CLIENT` privilege.
    NULL means replication is stopped, and the replica is unhealthy.
- **ST-11.** Lag limit. A replica more than 5 seconds behind gets no reads. It's
  admitted again once it's under 2.5 seconds. **Decision:** fixed values in the
  first version, because configuring them needs a new field, and new fields
  wait for the fork's namespace (SPEC.md §8). A replica whose lag can't be
  measured (missing privilege, unsupported server) gets no reads, and the
  server logs why once at startup.
- **ST-12.** Replica failure never fails a request. A connection error, a
  timeout, or a query cancelled by the standby (PostgreSQL cancels queries
  that conflict with replay, subject to `max_standby_streaming_delay`) retries
  that read once on the primary. The replica is marked down, gets no reads, and
  is probed again every 10 seconds (**Decision**). Down and up are logged as
  events.
- **ST-13.** Choosing a replica. Reads go round-robin across the replicas
  that are up and under the lag limit. Each replica has its own pool, sized by
  the primary's pool settings, as today.
- **ST-14.** Primary failure. Writes fail as they do today with one database.
  The server doesn't fail over or promote a replica: that's the database's job,
  behind the host name the primary entry points at. While the primary is down,
  replica-eligible reads whose check in ST-7 passes keep working. Everything
  else fails as it does today.
- **ST-15.** Validation at startup, per replica. A replica is left out, with
  an error event naming it, and the server runs on the rest (primary alone if
  need be), when:
  - it's the primary itself: the same host, port and database;
  - it isn't read-only: PostgreSQL `pg_is_in_recovery()` is false, or MySQL
    has neither `read_only` nor `super_read_only` on;
  - it isn't a copy of this primary. **Decision:** at startup the node writes
    a random marker value to the primary, and the replica must show it within
    the lag limit. This catches a replica of some other database;
  - MySQL applies in parallel without preserving commit order (parallel
    workers above 0 and `replica_preserve_commit_order` off). Out-of-order
    commits would break the change-id check in ST-7.

  A replica that fails later checks is handled by ST-12, not left out for good.
  The primary's checks are unchanged.

### Sharded blob store

- **ST-16.** Placement. A blob's *home* is `xxh3_64(key) mod N`: the 64-bit
  XXH3 hash, seed 0, over the full key bytes, where N is the number of entries
  in `stores`, in the order listed. The hash crate is already a dependency.
  **Decision**, fixed forever once shipped. Upstream's documentation says only
  "hash and modulus", so this doesn't claim to match upstream's placement. Keys
  are usually 32-byte content hashes, but some are names (the spam classifier's
  keys), which is why the whole key is hashed rather than its first bytes.
- **ST-17.** Reads. A read goes to the home shard. If the home shard doesn't
  have the blob, the other shards are tried in list order. If one has it, the
  blob is returned and a misplaced-blob event is logged with the key and the
  shard it was found on. Nothing is moved automatically. If no shard has it, the
  result is "not found", as today. A blob is only read after the data store
  says it exists, so this probing happens only for blobs placed under an
  earlier shard list, or ones that really are lost.
- **ST-18.** Writes and deletes. A write goes to the home shard only. A
  delete goes to the home shard. If the home shard reports that it didn't have
  the blob, the other shards are tried until one deletes it. Blob purging
  (`purge_blobs`) needs no change: it deletes through the same call.
- **ST-19.** Changing the shard list. Appending a shard, or reordering, keeps
  every existing blob readable, through ST-17, at the cost of extra lookups for
  blobs whose home moved. A named blob overwritten after its home moved leaves
  its old copy behind on the old shard. That's accepted: the new home is read
  first. **Moving blobs to their new home (resharding, rebalancing) is out of
  scope.**
- **ST-20.** Layout record. The first time a sharded blob store opens, the
  server stores a description of the list in the data store: each member's
  kind and location (bucket, container, path, host and database), never its
  secrets. On every later start:
  - the same list: nothing to do;
  - members added or reordered: a warning event naming what changed, and the
    record is updated;
  - a recorded member missing from the list: the blob store refuses to open,
    naming the missing member, because blobs on it would be unreachable.
    **Decision.** How an operator confirms that a removal is intended is an
    open question.
- **ST-21.** One shard failing. Operations whose home is the failing shard
  fail with that backend's usual error, and the rest carry on. A read whose home
  shard errors (rather than reporting a miss) returns the error without probing
  the others. A write whose home shard is down fails, so local delivery answers
  with a temporary failure and the message stays queued, as it would with a
  single blob store down. **Decision:** writes aren't redirected to another
  shard. A redirected named blob would leave an older copy on its recovered
  home, and that copy would be read first.
- **ST-22.** Validation. At least two members (the schema already requires
  it). Two members pointing at the same place (the same bucket and prefix, the
  same directory, the same database) are refused. Every member must open at
  startup, or the blob store fails to build with an error naming the member's
  position.

### Sharded in-memory and lookup stores

- **ST-23.** Placement. Every single-key operation goes to the key's home,
  chosen as in ST-16 over the full key, prefix byte included: `key_set`,
  `key_get`, `key_exists`, `key_delete`, `counter_incr`, `counter_get`,
  `counter_delete`, rate limits, `try_lock` and `remove_lock`. A lock and its
  release therefore always meet on the same member.
- **ST-24.** Operations over many keys go to every member:
  `key_delete_prefix` and `purge_in_memory_store`. They succeed only if every
  member does, and a failure names the member.
- **ST-25.** No fallback reads. ST-17 doesn't apply here. Probing other members
  would break locks and counters. Changing the member list moves keys, and data
  on the old home is abandoned until it expires: rate-limit windows start
  again, and temporary tokens and greylist entries may be lost. That's accepted
  for short-lived data. Locks are the risk: two nodes with different lists
  could both take the same lock. So:
- **ST-26.** Every node must use the same member list. As in ST-20, the list
  is recorded in the data store. A node starting with a different list logs an
  error event naming the difference, then runs with its own list.
  **Decision:** it doesn't refuse, because the data is short-lived and
  refusing would block a planned change. Operators change the list by
  restarting every node together.
- **ST-27.** One member failing. Operations on its keys fail as they would
  with that single Redis down today. Other keys are unaffected. What callers do
  with that error (rate limits, locks, greylisting) is today's behavior,
  unchanged (see "Open questions").
- **ST-28.** A sharded lookup store (`x:StoreLookup` with a `Sharded` store)
  behaves as ST-23 to ST-27. The existing rule that each namespace appears once
  still applies. `into_store()` returns none, as for Redis, so SQL queries
  against it stay unsupported.
- **ST-29.** Validation as ST-22: at least two members, no duplicates, and
  every member opens.

### Observability

- **ST-30.** **Decision:** no new event names in the first version, because
  new names belong in the fork's namespace (SPEC.md §8). Replica and shard
  problems are logged with the existing events (`store.postgresql-error`,
  `store.mysql-error`, `store.redis-error`, `store.s3-error`,
  `store.azure-error`, `store.filesystem-error`, `store.pool-error`), with
  details naming the replica host or the shard's position. Replica down and up,
  lag over the limit, and misplaced blobs are logged the same way.

## Interfaces

- **Config, unchanged:** the fields and variants under "Data model", through
  `x:DataStore`, `x:BlobStore`, `x:InMemoryStore`, `x:SearchStore` and
  `x:StoreLookup`, with their existing permissions.
- **Inside the server, new:** a read handle for replica-eligible reads, for
  example `store.replica_read(account_id)`. It carries the account's
  high-water mark (ST-7). On a store with no replicas it's the store itself, so
  call sites don't branch (ST-1). Every existing `Store` method keeps meaning
  "primary".
- **Inside the server, new:** the per-account high-water mark, fed by write
  results and `StateChange` broadcasts, shared through the in-memory store when
  there's more than one node.
- **Data store keys, new:** the shard layout records (ST-20, ST-26), under a
  key in the fork's namespace.
- **JMAP, IMAP, SMTP and the rest:** no change visible to clients.
- **ihasmail:** nothing required. The storage settings forms come from the
  schema, which doesn't change. No new ihasmail strings, so no translation
  work.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code, with the
backend features the test needs (`postgres`, `mysql`, `redis`, `s3`). The
default `inbuxa` build compiles only RocksDB.

**Needs nothing extra:**

1. A single-store install (RocksDB, and PostgreSQL with no replicas) opens no
   extra connections, and the existing store suites in `tests/src/store` pass
   unchanged (ST-1).
2. Sharded blob store over three `FileSystem` members: each blob lands on
   exactly one member, on its ST-16 home. The existing blob suite
   (`tests/src/store/blob.rs`) passes against it (ST-16, ST-18).
3. Append a fourth `FileSystem` member: every existing message still
   downloads over JMAP and IMAP. New blobs land by the new mapping. Reads of
   moved blobs log the misplaced-blob event (ST-17, ST-19, ST-20).
4. Remove a member: the blob store refuses to open and names it (ST-20).
5. Make one member's directory unreadable: blobs on the others still read.
   Delivery of a message whose home is that member fails temporarily and stays
   queued (ST-21).
6. Purge after deleting messages: unlinked blobs are removed from whichever
   member holds them, including misplaced ones (ST-18).
7. Two members naming the same directory: refused (ST-22).
8. A config with `Sharded` no longer reports "not compiled" (ST-2).

**Needs a PostgreSQL primary with a streaming replica:**

9. An upstream-written config with `readReplicas` opens. JMAP `Email/get`
   and IMAP `FETCH` are served by the replica, and the replica's statement log
   shows no writes, locks or rate-limit traffic (ST-2, ST-5, ST-6).
10. With replay paused (`pg_wal_replay_pause()`): `Email/set` creates a
    message, and a separate `Email/get` finds it. `Mailbox/set` renames a
    mailbox, and `Mailbox/get` shows the new name. `Email/changes` from the
    old state lists the new message (ST-7, ST-8).
11. Two nodes, replay paused: `/set` through node A, then `/get` through node
    B straight away, sees the change (ST-7).
12. Replay paused for 10 seconds: the replica gets no reads, then gets them
    again after replay resumes and catches up (ST-10, ST-11).
13. Replica stopped: requests keep succeeding, and the down and up events are
    logged. Replica restarted: back in use within about 10 seconds (ST-12).
14. Replica entry pointing at a writable, unrelated database: left out at
    startup with an error, and the server runs on the primary (ST-15).
15. A SQL directory on the data store with replicas still authenticates, and
    PostgreSQL full-text search works with the search store on a replica
    (ST-3, ST-6).
16. Primary stopped: eligible reads still answer, and writes fail as with a
    single database (ST-14).

**Needs a MySQL source with a replica:**

17. Tests 9, 10 and 12 with GTIDs on (ST-10).
18. With GTIDs off, with and without `REPLICATION CLIENT`: lag comes from
    `Seconds_Behind_Source` in the first case, and the replica is left out with
    a logged reason in the second (ST-10, ST-11).
19. Parallel replica with `replica_preserve_commit_order` off: left out at
    startup (ST-15).

**Needs two or more Redis servers:**

20. Sharded in-memory store over two Redis servers: rate limits, locks and
    the `resetRateLimiters` and `removeLock*` maintenance types behave as with
    one Redis. A prefix delete clears keys on both (ST-23, ST-24).
21. One Redis stopped: keys homed on the other still work (ST-27).
22. Two nodes started with different member lists: the second logs the
    difference (ST-26).
23. A sharded lookup store serves reads and writes to its namespace (ST-28).

**Needs S3 or Azure (optional):** test 2 with mixed members (S3, FileSystem
and PostgreSQL), to show members of different kinds work together (ST-16).

## Open questions / to observe

- **Placement compatibility with upstream.** Upstream's hash isn't public,
  so ST-16 is the fork's own. An install coming from upstream Enterprise with
  a sharded blob store would read every blob through ST-17's probing, which
  works but is slow. Is a one-off relocation tool worth building? There's no
  such install to observe: INBUXA doesn't shard.
- **Configurable limits.** The lag limit, probe interval and re-probe interval
  (ST-10 to ST-12) are fixed until the fork's namespace (SPEC.md §8) allows new
  fields.
- **New event names** for replica down and up, lag and misplaced blobs
  (ST-30). Same dependency on the namespace.
- **Cost of the shared high-water mark** (ST-7, step 2): one in-memory write
  per account write and one read per request, on multi-node installs only.
  Measure it against sticky sessions at the load balancer, which would make it
  unnecessary.
- **SQL directory queries on replicas.** Sign-in lookups are a large share of
  read load, but ST-5 keeps `sql_query` on the primary. A per-directory
  opt-in would need a new field.
- **MariaDB, Galera, AlloyDB.** Upstream's documentation lists them. MariaDB's
  GTIDs differ from MySQL's, so ST-10 falls back to `Seconds_Behind_Master`
  there. None of them is tested.
- **Confirming a removed shard** (ST-20): how an operator says "yes, drop it"
  without a new field. Perhaps a recovery-mode command (SPEC.md §6.3).
- **Callers' behavior on in-memory errors** (ST-27): whether a rate-limit
  check, lock or greylist lookup that errors lets the request through or
  refuses it. To observe on a stock build with Redis stopped, before any code
  changes.
- **Replicas on the tracing and metrics stores.** They're feature 6's objects.
  ST-4 to ST-15 apply as written, but nothing reads them on a request path yet.
- **`LookupStore::RedisSentinel` has no build arm** in `build/lookup.rs`. It's
  outside this feature. Check a stock build to see whether a sentinel lookup
  store works at all.

## Implementation status

Built 2026-09-19 from this spec, clean-room, under the multi-tenancy hand-off
brief's rules, in `crates/store/src/backend/scaleout/` (as decided above),
with one variant added to `Store`, `BlobStore` and `InMemoryStore` and one
arm to each dispatch and build `match`, marked `inbuxa:`. Sharded stores
came first; read replicas followed per-domain directories (the ST-2
Decision).

- **ST-1 to ST-30:** built, with the limits below.
- **Read replicas.** A data store with `readReplicas` becomes
  `Store::Replicated`. The read handle of "Interfaces" is a read scope that
  the call sites ST-6 names open around a request (`replica_read`), and that
  spawned work carries along. Only account data (properties, indexes,
  change logs, counters, ACLs, blobs, the search index) is read from a
  replica; the registry, in-memory values, the task queue and everything
  else go to the primary (ST-5).
- **Tests.** `store::scaleout::scaleout_blob_tests` covers tests 2 to 7 on
  three and four FileSystem members, opening the store directly against the
  data store. The existing blob suite passes against a sharded store with
  `BLOB_STORE=Sharded` (three FileSystem members), which is test 8 and the
  second half of test 2. `scaleout_memory_tests`, built with `redis`, covers
  tests 20, 22 and 23 over two databases of one Redis server, which the store
  treats as two members. `store::replica::replica_tests`, built with
  `postgres` and run with `STORE=PostgreSqlReplicated`, runs a primary and a
  streaming hot standby in containers and covers tests 9, 10, 12, 13, 14
  and 15. Test 1 is the existing store, blob and protocol suites passing
  unchanged.
- **Not exercised:** test 3's downloads over JMAP and IMAP after a restart
  (the same blob reads are checked at the store), test 5's queued delivery
  (the failing write is checked), test 21 (one of two Redis servers stopped),
  the `resetRateLimiters` and `removeLock*` maintenance types (the store
  operations they use are checked), test 11 (two nodes), test 16 (the
  primary stopped), and tests 17 to 19: the MySQL code (GTID and
  `Seconds_Behind_Source` lag, the read-only and commit-order checks) is
  built but hasn't run against a MySQL replica. Test 9 checks that the
  replica served the reads, not the replica's statement log, and test 15
  checks full-text search, not a SQL directory.
- **Settled from the code, not a change of intent:**
  - The FileSystem backend reports any unreadable file as missing, so a
    FileSystem member that can't be read looks like a miss (ST-17's search
    of the other members), not ST-21's error. Its blobs still aren't
    returned, and writes homed on it fail.
  - Member lists are recorded under the fork's own keys (`_` subspace,
    `Sb` for the blob store, `Sm` for the in-memory store, `Sl` and the
    namespace for a lookup store). An in-memory list that differs is
    recorded as the new one after the error is logged, so a planned change
    made by restarting every node settles.
  - A misplaced blob is logged as `store.unexpected-error`, naming the
    member it was found on and its home.
  - Any write made inside a read scope (a first mailbox read creating the
    default mailboxes, an IMAP `FETCH` setting `\Seen`) sends the rest of
    the scope to the primary, as ST-6 asks of requests that write.
  - A replica that hasn't shown the startup marker within the lag limit is
    tried again at each 10-second probe, and left out after six misses: at
    startup a replica can still be replaying a burst of writes.
  - Shared high-water marks (ST-7, step 2) go through the in-memory store
    only when it's Redis; a cluster whose in-memory store is the data store
    relies on the state-change broadcasts and ST-8.
- **Known limits, not requirements of this spec:**
  - Placement is the fork's own (ST-16), so an install coming from a
    sharded upstream deployment reads through ST-17's search (open
    question).
  - ST-7's step 4 raises the mark from a JMAP `sinceState` only; IMAP
    `CONDSTORE` and `QRESYNC` values and push resumption don't yet.
  - The store's `enterprise` Cargo feature stays: other crates' feature
    lists name it.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), read-only, as a server-level administrator and the throwaway test
account. No upstream code was read.

INBUXA runs a single RocksDB data store, with the default blob, in-memory
and search stores. No replicas, and no sharded stores. Nothing to carry
over, and nothing here affects its cutover.
