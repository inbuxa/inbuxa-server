# Feature spec: cleaning up the old store after a blob store change

Status: building, 2026-11-10 (inbuxa-server #342). Approved 2026-11-10
(PR #357), with the answers under [Settled](#settled). Not a rebuild (SPEC.md
§4): inbuxa's own design. It extends `features/blob-store-change.md`
(BM-1 to BM-10) and `features/blob-store-copy-ahead.md` (CA-1 to CA-9),
which it doesn't change except where it says so.

## Provenance

| Source | Used for |
|---|---|
| inbuxa-server #342, after #333 and forum topic 238 | The need: once a change is resolved, every blob is in the new store, but the old one keeps all of them for good (BM-7) |
| The blob store change (`features/blob-store-change.md`, `crates/features/src/blob_move/`, `crates/services/src/inbuxa_blob_move.rs`) | The change record, the old store's settings and where they're dropped today (at `copied`), the copy's walk, hash check, throttle and one-run-at-a-time lock |
| The store snapshot (`features/store-snapshot.md`) | What a snapshot holds, by hard link, and so what space a cleanup can't free while it exists |
| This server's blob dispatch (`crates/store/src/dispatch/blob.rs`) | Deleting a blob's data from a store without touching the blob index |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

After a change is resolved, the old store still holds a copy of every
blob that was in it. For a directory or a bucket of its own, the
administrator can delete it. For the data store (`Default`), or a bucket
prefix shared with other things, they can't do that by hand: the blobs
sit among things that must stay.

With this, an administrator has the server delete from the old store the
blobs it has checked are in the new one. It's a separate, explicit step,
taken when the administrator is ready, never as part of the copy. It can
be previewed first, and it can be run again.

The hard part isn't the deleting, it's what still depends on the old
store after the change is resolved: backups taken before the change, a
node that hasn't restarted, a snapshot. The requirements below are mostly
about those.

## Requirements

- **OC-1.** **The old store is kept.** At `copied` (BM-6), a change keeps
  its old store's settings instead of dropping them. Reading through
  still stops then (BM-3, BM-10); the settings are kept only for a
  cleanup. They go when the cleanup ends `done` (OC-6) or the change is
  dismissed (BM-7). Changes resolved before this spec have no settings
  left, and their cleanup is refused (OC-3).
- **OC-2.** **Each node says where its blob store is.** When a node reads
  the changes (BM-10, every minute), it also records where its own blob
  store is (BM-1) and the time, under its node id. A node not heard from
  for ten minutes is left out of OC-3's check.
- **OC-3.** **Starting a cleanup.** An update with `action: "cleanUp"` on
  a change starts a cleanup of its old store on the node that takes it.
  It's refused when:
  - the change isn't `copied`. A `reverted` change has no old store to
    clean: it's the current one again (BM-4);
  - its old store's settings aren't kept (OC-1);
  - its `to` isn't where the current blob store is, or its `from` is.
    After A to B, then B to A, cleaning A would delete the blob store
    itself;
  - a node recorded under OC-2 has a blob store anywhere but `to`: it may
    still write to or read from the old store (BM-10);
  - the two stores overlap: one is a sharded set with the other as a
    member, or a probe written under a reserved key in the new store can
    be read from the old one. Deleting from the old store would then
    delete from the new;
  - a planned change's `to` is the old store's place (CA-1): its copy
    ahead would write what the cleanup deletes;
  - any copy, copy ahead or cleanup runs: one at a time across the
    server, as BM-5;
  - it isn't confirmed (OC-8).

  The old store must open, as it must for a copy; an error opening it is
  the refusal.
- **OC-4.** **What it deletes.** It goes through the blob index as a copy
  does (BM-5): the same 256 slices, the same blobs (documents, queued
  messages, kept deleted items, unexpired links, the spam classifier's
  two files). For each blob:
  - not in the old store: counted as `notThere`;
  - not in the new store: kept in the old one, and a `missing` problem;
  - a blob named by the hash of its content whose copy in the new store
    doesn't hash to its name: kept, and a `damaged` problem;
  - any other blob whose copy in the new store isn't byte for byte the
    old one's: kept, and a `different` problem;
  - an error from either store: kept, and an `unreadable` problem;
  - otherwise deleted from the old store: `deleted`, with its size added
    to `bytesFreed`.

  Only the blob's data is deleted from the old store, through that
  store's own delete. The blob index and everything that links to the
  blob are the data store's and stay as they are. Each problem is
  logged as `store.data-corruption`, since it's a blob the new store
  should have and doesn't. Throttled as BM-5, with `blobsPerSecond` and
  `bytesPerSecond` alongside the action.
- **OC-5.** **A preview.** `dryRun: true` alongside the action runs the
  same walk and checks and deletes nothing. It counts what would be
  deleted, the bytes, and the problems, and its result is kept as the
  cleanup's (with `dryRun` set) until the next run. A preview needs no
  confirmation (OC-8).
- **OC-6.** **How it ends**, as a copy does (BM-6):
  - `done`: no problems. Everything the server holds was checked in the
    new store and deleted from the old. The old store's settings go
    (OC-1), and the change can't be cleaned again;
  - `incomplete`: some blobs were kept (OC-4). The first 1,000 problems
    are kept. It can be run again; blobs already deleted count as
    `notThere`;
  - `stopped`, by `action: "stop"`; `failed`, with the error;
    `interrupted`, when its node restarted or went quiet for five
    minutes. Each can be run again.

  A preview ends the same way and changes nothing about the change.
- **OC-7.** **What it doesn't delete.** Only blobs the blob index names
  are looked for. Anything else in the old store stays: blobs nothing
  held when the change was made, a filesystem store's empty directories,
  other things sharing a bucket or prefix. `done` means every blob the
  server knows about is out of the old store, not that the old store is
  empty. For a directory or bucket of its own, the docs say the
  administrator can delete what's left once the cleanup is `done`.
- **OC-8.** **Backups taken before the change.** A backup of the data
  store from before the change, restored, has the old blob store setting
  and reads its blobs from the old store, which the cleanup empties.
  The server can't see a backup tool's backups, so a cleanup that
  deletes needs `confirm` set to the change's id alongside the action,
  and the refusal without it says: backups of the data store taken
  before the change was resolved need the old store's blobs to restore
  in full; keep the old store until those backups have aged out. A
  restored server whose blobs are gone can be pointed at the new store
  instead: a change from the old store to the new one is recorded
  (BM-2), and every blob that was still held when the cleanup ran is
  there. Blobs deleted from the new store since then aren't.
- **OC-9.** **Snapshots.** A cleanup and a snapshot (store-snapshot spec)
  can run at once: the snapshot takes the current store, and the cleanup
  deletes only from the old one. A snapshot taken before the change
  holds the old store's blobs by hard link (a filesystem store) or in its
  checkpoint (the data store), so their space comes back only when that
  snapshot is destroyed. The cleanup's result says how many snapshots
  older than the change are on disk.
- **OC-10.** **Freed space** depends on the store: RocksDB frees it as it
  compacts; PostgreSQL and MySQL after a vacuum or optimize; a versioned
  bucket keeps old versions until its own lifecycle rules remove them.
  The docs say so; the server doesn't vacuum or compact for it.
- **OC-11.** **Forgetting.** A change waiting on a cleanup counts among
  the 20 kept (`MAX_CHANGES`), and forgetting it forgets its old store's
  settings. Changes whose settings are gone are forgotten first. A change
  whose cleanup runs isn't forgotten, and can't be dismissed (as BM-7).
- **OC-12.** Permissions as BM-9: `sysBlobStoreChange`. Starting,
  previewing and stopping a cleanup are audited, and so is each run's
  end with its counts.

## The object

`inbuxa:BlobStoreChange` gains:

| Property | Type | |
|---|---|---|
| `oldStoreKept` | Boolean | Whether the old store's settings are kept for a cleanup (OC-1) |
| `cleanup` | Object | The latest cleanup or preview, null before the first |
| `action` | String | Write-only: also `cleanUp` |
| `dryRun` | Boolean | Write-only, with `cleanUp` (OC-5) |
| `confirm` | Id | Write-only, with `cleanUp`: the change's own id (OC-8) |

`cleanup` is `{status, dryRun, startedAt, startedBy, finishedAt, node,
blobsPerSecond, bytesPerSecond, progress, blobsChecked, deleted,
bytesFreed, notThere, missing, damaged, different, unreadable, problems,
snapshotsBefore, error}`, with `status` one of `running`, `done`,
`incomplete`, `stopped`, `failed`, `interrupted`. A problem is as BM-5's,
with `different` as a kind. Once a change has a cleanup, its problems are the
cleanup's, under `cleanup.problems`, and the top-level `problems` is empty.

## Tests

- Model (`crates/features/src/blob_move/`): settings kept at `copied`
  and dropped at a cleanup's `done` or a dismiss; each refusal in OC-3;
  forgetting order (OC-11); a preview leaving the change as it was.
- Store level, with two filesystem stores: a delete from the old one
  leaves the new one and the blob index untouched; the overlap probe
  finds two stores on the same directory and depth through different
  settings.
- `system::blob_store_change`, against a real server: messages
  delivered on a filesystem store, the setting changed to the data
  store, copied and resolved. A preview counts every blob and deletes
  none; `cleanUp` without `confirm` is refused; with it, the old
  directory loses those blobs and every message still reads. A blob
  removed from the new store by hand, and one altered there, are kept
  in the old store and reported, and the run ends `incomplete`; put
  back, a second run ends `done` and the old settings are gone. A node
  recorded on the old store refuses the cleanup. Over JMAP: stop,
  destroy while running, a tenant administrator's refusal.

## Settled

Approved 2026-11-10 with every recommendation:

1. **Guarding backups:** the confirmation naming the change (OC-8), and
   no wait after resolution. The refusal and the console say plainly
   what deleting costs; the preview and a store check let the
   administrator look first.
2. **Checking the new store:** every blob is read back and checked
   before its old copy is deleted (OC-4), at the cost of a read per blob,
   which on S3 or Azure is a request and egress each.
3. **Each node's place** is recorded with the minute poll (OC-2).
4. **A dismissed plan's target** isn't cleaned by this spec (CA-8 is
   unchanged).

## Not yet

- The console: **Clean up the old store…** on a resolved change, with
  the preview's numbers, the backup warning and the confirmation
  (inbuxa-admin), and `inbuxa-cli store` commands to preview, clean up
  and stop.
- Docs: a "Cleaning up the old store" section in docs.inbuxa.org's
  `run/store.md`, with OC-7, OC-8 and OC-10.
