# Feature spec: changing the blob store

Status: building, 2026-11-09 (inbuxa-server #333). Not a rebuild (SPEC.md
§4): inbuxa's own design.

## Provenance

| Source | Used for |
|---|---|
| Forum topic 238 | The need: a server moved its blobs to a filesystem store, took one message by SMTP, and went back to the data store a minute later. The message's metadata stayed; its blob was left in the filesystem store, and reading it failed from then on |
| This server's blob store build and dispatch (`crates/store/src/build/blob.rs`, `crates/store/src/dispatch/blob.rs`) | Where the blob store comes from, and that a change takes effect at start-up |
| The store check (`features/store-check.md`) and its blob index walk (`crates/store/src/write/blob_check.rs`) | Which blobs the data holds, how a blob proves its content, and how the object, permission and run are built |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

The blob store setting (`x:BlobStore`) says where blobs go: in the data
store, in a directory, in a bucket. Changing it changes where the server
writes and reads them from the next start-up. It moves nothing. Before
this spec, every blob written under the old setting was left behind,
in either direction, and a message whose blob was left behind failed to
read with nothing to say why.

Now the server notices the change when it starts. It keeps reading what
it can't find from the old store and copies each blob it reads that way
into the new one. An administrator has it copy everything else, and the
change is resolved once the new store has every blob. Nothing is ever
deleted from the old store; that stays the administrator's to do.

## Requirements

- **BM-1.** Where a blob store is, without its credentials or tuning:
  - the data store (`Default`);
  - a filesystem store: its path and depth (the depth decides each blob's
    path, so a new depth is a new place);
  - S3: the region or endpoint, the bucket and the key prefix;
  - Azure: the storage account, the container and the key prefix;
  - PostgreSQL or MySQL: the host, port and database;
  - FoundationDB: the cluster file;
  - a sharded set is one place. The set moves blobs between its members
    itself (scale-out spec, ST-16 to ST-22).
- **BM-2.** At start-up, a node compares where its blob store is (BM-1)
  with where the store last said it was. When they differ, it records an
  `inbuxa:BlobStoreChange` with both places, the time and the node, and
  keeps the old store's settings in it so the old store can still be
  read. It logs a warning that names both places. The first node to start
  with the new setting records the change; the others find it recorded.
  The first start of a server, or of a store from before this spec, only
  records where the blob store is.
- **BM-3.** **Reading through.** While a change is unresolved (BM-5), a
  blob the blob store doesn't have is looked for in the change's old
  store. When it's there, it's returned and written to the current store
  under the same key, with the event `store.blob-read-through` naming the
  key and the change. Several unresolved changes are tried newest first.
  Writes and deletes go to the current store only. An old store that
  can't be opened at start-up is left out, with a warning, and the change
  stays unresolved.
- **BM-4.** **Back where it was.** A change back to a store that an
  earlier unresolved change moved away from (A to B, then back to A)
  resolves that earlier change by itself: its old store is the current
  one again. Its status is `reverted`. The new change (B to A) is the one
  to copy from.
- **BM-5.** **Copying.** An update with `action: "copy"` starts a copy on
  the node that takes it. One copy runs at a time across the server; a
  second is refused while one runs. It goes through the blob index in its
  256 slices and takes every committed blob that something holds: a
  document, a queued message, a kept deleted item, or a link that hasn't
  expired. It also takes the spam classifier's two files, which the
  server keeps under fixed names. For each blob:
  - already in the current store: counted as `alreadyThere`;
  - in neither store: a `missing` problem;
  - a blob a document, a queued message or a kept deleted item holds is
    named by the hash of its content; when what the old store has doesn't
    hash to its name, it isn't copied and is a `damaged` problem. Other
    blobs (uploads, cached app bundles, the spam files) aren't named by
    their content and are copied as they are;
  - an error from either store: an `unreadable` problem, with the error;
  - otherwise it's written to the current store as the old store has it,
    compression and all: `copied`.

  It's throttled like a store check (store-check spec, SV-6): by default
  1,000 blobs and 20 MB a second, set with `blobsPerSecond` and
  `bytesPerSecond` alongside the action; 0 is no limit.
- **BM-6.** A copy ends:
  - `copied`: nothing was missing, damaged or unreadable. The change is
    resolved: every node stops reading through it within a minute
    (BM-10);
  - `incomplete`: some blobs couldn't be copied. The first 1,000 problems
    are kept, and every one is logged as `store.data-corruption`. The
    change stays unresolved and can be copied again;
  - `stopped`, by an update with `action: "stop"`; `failed`, with the
    error; `interrupted`, when its node restarted or went quiet for five
    minutes. Each leaves the change unresolved.
- **BM-7.** **Dismissing.** Destroying a change forgets it and the old
  store's settings it kept, and reading through it stops. Nothing is
  deleted from either store. A change whose copy runs can't be destroyed;
  stop the copy first.
- **BM-8.** While a change is unresolved, a store snapshot is refused
  (store-snapshot spec): it would leave out the blobs only the old store
  has. The refusal says to copy or dismiss the change first.
- **BM-9.** Only the server's administrators see and act on changes:
  `sysBlobStoreChange`, in the built-in Administrator role and granted
  once to existing administrator roles. A tenant administrator is
  refused. Copying, stopping and dismissing are audited; reading isn't.
  `get` never returns the old store's settings, only where it is (BM-1).
- **BM-10.** On a cluster, every node reads the unresolved changes at
  start-up and again every minute, so one that's resolved or dismissed
  on any node stops being read through everywhere. During a rolling
  restart the nodes still on the old setting write to the old store;
  reading through covers that until the copy, which should start once
  every node runs the new setting.

## The object

| Property | Type | |
|---|---|---|
| `id` | Id | |
| `from`, `to` | String | Where the old and the new blob store are (BM-1) |
| `changedAt` | UTCDate | When the first node started with the new setting |
| `node` | String | That node |
| `status` | String | `pending`, `copying`, `copied`, `incomplete`, `stopped`, `failed`, `interrupted`, `reverted` |
| `copyStartedAt`, `copyFinishedAt` | UTCDate | The latest copy |
| `copyStartedBy` | String | Who started it |
| `copyNode` | String | The node it runs on |
| `blobsPerSecond`, `bytesPerSecond` | UnsignedInt | Its limits |
| `progress` | Number | 0 to 1 |
| `blobsChecked`, `copied`, `alreadyThere`, `bytesCopied` | UnsignedInt | |
| `missing`, `damaged`, `unreadable` | UnsignedInt | Counts of each problem |
| `problems` | Object[] | The first 1,000 of the latest copy |
| `error` | String | Why a `failed` copy failed |
| `action` | String | Write-only: `copy` or `stop` |

A problem is `{kind, blobId, holder, accountId, objectId, detail}`:
`holder` is `email`, `file`, `queuedMessage`, `archivedItem`, `temporary`
or `fixed`, for the first thing found holding the blob.

## Tests

- Store level (`crates/store/src/write/blob_move.rs`): with two filesystem
  stores, a blob only the old one has reads through and is then in the
  new one; one in neither reads as absent; writes and deletes touch only
  the new one; dropping the old store stops reading through.
- Where a store is (BM-1): credentials and tuning don't change it; a path,
  depth, bucket or prefix does.
- Model (`crates/features/src/blob_move/`): recording a change, a change
  back reverting the earlier one, and the copy's bookkeeping.
- `system::blob_store_change` (`tests/src/system/blob_store_change.rs`),
  against a real server: a message delivered while a filesystem store is
  set, the setting changed back and the server rebuilt; the message reads
  through, the change is listed, a copy resolves it, and a damaged blob
  in the old store is reported, not copied. Over JMAP: the refusals, stop,
  the destroy rules, a tenant administrator's refusal.

## Not yet

- The console's page, and a warning on the blob store settings form
  that existing blobs stay where they are.
- An `inbuxa-cli` command.
- Copying ahead of a change (the old store to a new one before the
  setting changes): `features/blob-store-copy-ahead.md` (approved, #341).
