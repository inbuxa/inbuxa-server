# Feature spec: a snapshot of the store, without stopping the server

Status: building, 2026-11-09 (inbuxa-server #323). Not a rebuild (SPEC.md
§4): inbuxa's own design.

## Provenance

| Source | Used for |
|---|---|
| Forum topic 238 | The need: a backup that stops the server, copies the store cold and starts it again, an outage each time |
| RocksDB's checkpoint (`rocksdb::checkpoint::Checkpoint`, rocksdb 0.25) | A consistent copy of every column family at once, by hard links on the same filesystem |
| This server's blob writes and purge (`crates/store/src/write/blob.rs`, `crates/store/src/backend/fs/mod.rs`) | Why a snapshot of the data store, then of the blobs, holds every blob its data links to |
| The store check (`features/store-check.md`) | How the object, its permission and its run are built |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

An administrator asks the server for a snapshot of its store. The server
writes a consistent copy into a directory on its own machine, while mail
keeps flowing, and says when it's done. A backup tool then copies that
directory however it likes. Encryption, off-site copies and how long
backups are kept stay with the backup tool. The server keeps only its
latest two snapshots.

A snapshot is a cold copy that was taken hot. Restoring one is copying it
back while the server is stopped.

## Requirements

- **SN-1.** A snapshot is an `inbuxa:StoreSnapshot` under `urn:inbuxa:jmap`.
  It needs RocksDB as the data store. With any other data store a create
  is refused, and the refusal says to use the database's own backup:
  PostgreSQL's or MySQL's, or FoundationDB's.
  While a change of blob store is unresolved, a create is refused too:
  some blobs may still be only in the old store, which the snapshot
  leaves out (blob-store-change spec, BM-8).
- **SN-2.** What it holds:
  - **The data store**: a RocksDB checkpoint of every column family, taken
    at one point in time. Blobs kept in the data store (the default) are
    in it too.
  - **Blobs in a separate filesystem blob store**, copied after the
    checkpoint. Blobs are written before anything links to them, and the
    blob purge is held while the snapshot is taken (SN-4), so every blob
    the checkpoint links to is there to copy. A blob written after the
    checkpoint may be copied as well; nothing in the snapshot links to it.

  A blob directory that holds the data store's directory is fine: the
  copy leaves the data store's directory out. Blobs in the data store's
  own directory are refused, since they can't be told from its files.
  Any other blob store (S3, Azure, a sharded set, a SQL database) is
  refused: a copy of the data store alone would point at blobs a later
  purge could take away before the backup tool copied them.

  Not in it: the search index when it's kept outside the data store
  (Meilisearch, Elasticsearch, ...), rebuilt after a restore; and the
  in-memory store (rate limits, locks), which a restarted server doesn't
  need.
- **SN-3.** Where: under `snapshots/` in the RocksDB directory, one
  directory per snapshot named for when it was taken (UTC), like
  `snapshots/20261109T013000Z/`, with `data/`, `blobs/` when there are
  separate blobs, and `snapshot.json`. Being on the store's own
  filesystem, RocksDB and the blob copy hard-link their files, so a snapshot
  is quick and at first takes almost no space. Where they can't link
  (another filesystem), they copy. The location is fixed: a request can't
  name a path.

  A snapshot is written as `snapshots/.<name>.partial/` and renamed when
  complete, so a directory with the plain name is always whole.
  `snapshots/latest` is a link to the newest complete one.
- **SN-4.** While a snapshot takes blobs from a filesystem blob store, the
  blob purge waits. A purge already running is let finish first. A purge
  task that comes due meanwhile is put off by five minutes.
- **SN-5.** `snapshot.json` says when it was taken and finished, by whom,
  the server version, what it holds (`data`, `blobs`), the data and blob
  stores' paths, its size, and how to restore it.
- **SN-6.** One snapshot is made at a time; another create is refused
  while one runs. When one completes, the oldest beyond the latest two are
  deleted.
- **SN-7.** A snapshot is `running`, then `done`, or `failed` with the
  error and its partial directory removed. One the server stopped in the
  middle of leaves a partial directory, removed when the server next
  starts, and isn't listed.

  The complete snapshots on disk are the record: `get` lists those, read
  from each one's `snapshot.json`, and, until the server restarts, the one
  being taken or the last one that failed.
- **SN-8.** Only administrators take snapshots: `sysStoreSnapshot`, in the
  built-in Administrator role and granted to existing administrator roles.
  A snapshot holds every account's data, so a tenant administrator is
  refused. Taking and destroying a snapshot are audited.
- **SN-9.** Destroying a snapshot deletes its directory. A running one
  can't be destroyed.
- **SN-10.** A filesystem blob store writes each blob to a temporary file
  in the same directory and renames it into place. Before, it rewrote a
  file in place, which would also have changed the copy a snapshot holds
  by hard link, and left a half-written blob behind if the server stopped
  mid-write.

## The object

| Property | Type | |
|---|---|---|
| `id` | Id | |
| `status` | String | `running`, `done`, `failed` |
| `createdAt`, `finishedAt` | UTCDate | |
| `createdBy` | String | Who took it |
| `node` | String | The node that took it |
| `name` | String | Its directory under `snapshots/` |
| `path` | String | Its full path on the server's machine |
| `holds` | String[] | `data`, and `blobs` when they're separate |
| `size` | UnsignedInt | Bytes in its files |
| `blobFiles` | UnsignedInt | Blob files copied |
| `error` | String | Why a `failed` snapshot failed |

A create takes no properties.

## Restoring

1. Stop the server.
2. Move the RocksDB directory's contents aside, except `snapshots/`, and
   copy the snapshot's `data/` into it.
3. With a separate filesystem blob store, do the same with its directory
   and the snapshot's `blobs/`.
4. Start the server. A search index kept outside the data store isn't in
   the snapshot; reindex the accounts once it's running.

A backup tool copying the store cold should leave out `snapshots/`, or
the store is copied twice.

## Tests

- `system::store_snapshot` (`tests/src/system/store_snapshot.rs`), against
  a real server with RocksDB, run with blobs in the data store and again
  with `BLOB_STORE=FileSystem`: a snapshot taken while mail is in the
  store; the directory, its name, `latest` and the manifest; a RocksDB
  store opened from its `data/` has the messages and their blobs (in it,
  or in `blobs/`), and not a message that came after; no properties at
  create, no updates; with separate blobs, one at a time and no destroy
  while one is taken (the test holds the purge gate); only the latest two
  kept; destroy; the audit events; a user's and a tenant administrator's
  refusal.
- Unit tests: the filesystem blob store's writes (SN-10), the tree copy
  and what it leaves out, the purge gate, snapshot names and the manifest.

## Not yet

- The console's page and an `inbuxa-cli` command a backup tool can call
  and wait on.
- SQLite as the data store (`VACUUM INTO` would do it).
