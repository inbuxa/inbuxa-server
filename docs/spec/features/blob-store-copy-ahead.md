# Feature spec: copying blobs ahead of a blob store change

Status: building, 2026-11-10 (inbuxa-server #341). Approved 2026-11-10
(PR #354), with the answers under [Settled](#settled). Not a rebuild (SPEC.md
§4): inbuxa's own design. It extends `features/blob-store-change.md`
(BM-1 to BM-10), which it doesn't change except where it says so.

## Provenance

| Source | Used for |
|---|---|
| inbuxa-server #341, after forum topic 238 | The need: on a large store, the copy after a change takes long, and until it ends many reads go to the old store, each first read slower |
| The blob store change (`features/blob-store-change.md`, `crates/features/src/blob_move/`, `crates/store/src/write/blob_move.rs`, `crates/common/src/manager/blob_moves.rs`) | The object, where a store is (BM-1), how the old store's settings are kept (`Location.settings`, an `x:BlobStore` value), the copy and its throttle (BM-5) |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

Today a blob store change starts when a node starts with the new
setting. Everything is then read through from the old store until a copy
has moved it all (BM-3, BM-5). For a store of millions of blobs, that
copy runs for hours, and every first read of an old blob meanwhile goes
to the old store.

With this, an administrator **plans** the change first: gives the new
store's settings, and has the server copy everything from the current
store into it while the current store is still the blob store. Nothing
reads from or writes to the new store yet, apart from the copy. When the
setting then changes to that store, the planned change becomes the
change (BM-2), and its copy is a last pass that picks up only what was
written in between.

## Requirements

- **CA-1.** **Planning.** A create of `inbuxa:BlobStoreChange` with a
  `target` (an `x:BlobStore` value, as the blob store setting takes it)
  records a **planned** change: `stage` is `planned`, `from` is where the
  current blob store is and `to` is where the target is (BM-1). The
  server keeps the target's settings in the change, as it keeps an old
  store's (BM-2). `get` never returns them, only `to` (BM-9). The create
  is refused:
  - when `to` is where the current blob store is;
  - when another change is planned: one at a time;
  - when a change is unresolved (BM-6): copying ahead reads the current
    store only, so it would miss the blobs only an older store has. The
    refusal says to copy or dismiss that change first;
  - when the target can't be opened, or a probe written under a
    reserved key can't be read back and deleted. The refusal carries the
    store's error.
- **CA-2.** **Copying ahead.** `action: "copy"` on a planned change copies
  from the current store to the target, exactly as BM-5 copies from an
  old store to the current one: the same walk, the same blobs, the same
  hash check, the same throttle and the same one-copy-at-a-time rule
  across the server (a copy ahead and a copy after a change can't run at
  once). It ends as BM-6 says, with one difference: `copied` doesn't
  resolve anything, since nothing is reading through. `stop` stops it,
  and copying again skips what the target has.
- **CA-3.** **Nothing else changes while it's planned.** Writes and reads
  go to the current store only. A planned change isn't read through
  (BM-3) and doesn't refuse a snapshot (BM-8). On a cluster, every node
  reads planned changes with the unresolved ones (BM-10), for CA-4.
- **CA-4.** **Deletes follow.** While a change is planned, a blob the
  server deletes from the current store (the blob cleanup, an expired
  upload) is also deleted from the target, so the target doesn't keep
  blobs nothing holds any more. An error from the target is logged with
  the change's id and doesn't fail the delete. A blob deleted while a
  copy is reading it can still reach the target; it's a leftover that
  costs space and nothing else.
- **CA-5.** **The switch.** When a node starts with a blob store whose
  place (BM-1) is a planned change's `to`, and the last recorded place is
  its `from`, that planned change becomes the change instead of a new one
  being recorded (BM-2): `stage` becomes `changed`, `changedAt` and
  `node` are set, and `status` starts again at `pending`. The copy
  ahead's numbers are kept in `copiedAhead` (below). From then on it's an
  ordinary change: read through, refusing snapshots, copied and
  resolved as BM-3 to BM-10 say. A start with any other blob store
  records a new change as before, and the planned one stays planned.
- **CA-6.** **The last pass** is the copy after the switch (BM-5). It
  still checks every blob, but most are already in the new store
  (`alreadyThere`), so it transfers only what was written between the
  copy ahead and the switch. Checking a blob in the new store costs one
  lookup, so on S3 or Azure the last pass is a request per blob, at the
  same throttle.
- **CA-7.** **Making it the setting.** `action: "apply"` on a planned
  change whose latest copy ahead ended `copied` writes its target's
  settings to the blob store setting (`x:BlobStore`), as an update to the
  setting would, with its secrets, so nobody types the credentials twice
  and the setting can't name a different place by mistake. It takes
  effect when the nodes restart, as the blob store setting always does.
  It's refused for any other status, and once applied, a second `apply`
  is refused.
- **CA-8.** **Dismissing.** Destroying a planned change forgets it and
  its target's settings. Nothing is deleted from the target; what was
  copied there stays, and removing it is the administrator's job (as in
  BM-7). A planned change whose copy runs can't be destroyed; stop the
  copy first.
- **CA-9.** Permissions as BM-9: `sysBlobStoreChange`. Planning, copying
  ahead, applying and dismissing are audited.

## The object

`inbuxa:BlobStoreChange` gains:

| Property | Type | |
|---|---|---|
| `stage` | String | `planned` or `changed`. Changes recorded before this spec are `changed` |
| `target` | Object | Write-only, on create: the new store's settings (CA-1). Never returned |
| `copiedAhead` | Object | `{startedAt, finishedAt, status, copied, alreadyThere, bytesCopied, problems}` of the last copy ahead, kept at the switch (CA-5); null for a change that wasn't planned |
| `appliedAt`, `appliedBy` | UTCDate, String | When and by whom `apply` wrote the setting (CA-7) |
| `action` | String | Write-only: `copy`, `stop` or, on a planned change, `apply` |

While `stage` is `planned`, `status` and the copy properties describe the
copy ahead, and `changedAt` and `node` are null.

## Tests

- Model (`crates/features/src/blob_move/`): planning and its refusals;
  the switch turning a planned change into the change, keeping
  `copiedAhead`; a start with another store leaving it planned; `apply`
  only after `copied`, and once.
- Store level (`crates/store/src/write/blob_move.rs`): with two
  filesystem stores, a delete from the current store also removes the
  key from a planned target; an error from the target doesn't fail the
  delete.
- `system::blob_store_change`, against a real server: messages
  delivered, a filesystem target planned and copied ahead, more mail
  delivered, `apply`, the server rebuilt on the new setting. The
  planned change is now the change; reading through returns the late
  messages; the last pass copies only those (the rest `alreadyThere`)
  and resolves it. Over JMAP: each refusal in CA-1 and CA-7, destroy
  while copying, a tenant administrator's refusal.

## Settled

Approved 2026-11-10 with every recommendation:

1. **Deletes follow** the current store to the planned target (CA-4).
2. **Writes don't follow.** The target stays off the mail path; the last
   pass and reading through cover the gap.
3. **`apply`** writes the target's settings to the blob store setting
   (CA-7).
4. **Planning is refused** while another change is unresolved (CA-1).

## Not yet

- The console: a **Plan a change** form on the Blob Store Changes page
  with the blob store form's fields, **Copy ahead** and **Make it the
  blob store** on a planned change (inbuxa-admin), and the matching
  `inbuxa-cli store` commands.
- Docs: a "Planning a change" section in docs.inbuxa.org's
  `run/store.md`.
