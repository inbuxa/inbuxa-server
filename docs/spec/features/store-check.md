# Feature spec: checking the store's blobs

Status: building, 2026-11-08 (inbuxa-server #322). Not a rebuild (SPEC.md
§4): inbuxa's own design.

## Provenance

| Source | Used for |
|---|---|
| Forum topic 238 | The need: a mail whose metadata was there and whose blob wasn't, on a server that looked healthy, and a backup that copied it |
| This server's blob links (`crates/store/src/write/blob.rs`) and `BlobHash` (`crates/types/src/blob_hash.rs`) | What a document holds on to, and how a blob proves its content |
| This server's `inbuxa:HoldExport` and `inbuxa:Migration` | How a fork object, a background job and their permission are built |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

An administrator asks the server to check that the blobs its data needs are
in the blob store, and, if asked, that each one is intact. The check
reports what it finds and changes nothing. It runs inside the server, on
the node the administrator reached, against the stores every node shares.
So it works while mail flows, on one machine or a cluster, whatever the
stores are. An offline command couldn't: RocksDB lets one process open the
store, and a cluster's data store and blob store may be on other machines.

## Requirements

- **SV-1.** A check is an `inbuxa:StoreCheck` under `urn:inbuxa:jmap`. It's
  kept in the fork's subspace under `Vc` and its problems under `Vp`,
  never in the registry. The latest 20 checks are kept; starting a 21st
  forgets the oldest.
- **SV-2.** Creating one starts it. Its `mode` is:
  - `quick`: every blob the check covers (SV-3) is in the blob store;
  - `full`: also, each one reads back whole and its BLAKE3 hash is its id.
    Blob ids are the hash of their content, so this proves the content,
    not just that something is stored under the id.

  One check runs at a time across the server; another create is refused
  while one runs.
- **SV-3.** What it covers:
  - **Links.** Every blob a document holds (`BlobLink::Document`: mail,
    files, Sieve scripts and the rest, by collection), every blob a queued
    message holds (`BlobLink::Id`), and every blob a kept deleted item
    holds (a temporary link that names the archived item, not yet
    expired). A blob several documents share is read once and reported
    for each of them.
  - **Mail metadata.** Each message's stored metadata names its blob. The
    check finds the message's own link to it. A message that names a blob
    without a link is a problem even when the blob is there, because
    nothing stops the blob from being purged.

  Not covered: uploads nothing holds yet (they expire on their own), and
  files the server keeps under fixed names (spam model, app bundles).
- **SV-4.** A problem is one of:
  - `missing`: the blob store has nothing under the id;
  - `damaged` (full only): the content's hash isn't its id, or it doesn't
    decompress;
  - `unlinked`: a message's metadata names a blob it holds no link to,
    with whether the blob is still there;
  - `unreadable`: the blob store answered with an error, which is kept.

  Each says the account (id and name), the object (`email`, `file`,
  `sieveScript`, `calendarEvent`, `contactCard`, `queuedMessage`,
  `archivedItem`, or the collection's number for any other), its id, the
  blob id, and whether the store still has the blob's commit marker. A
  missing blob with its marker was committed and lost afterwards; one
  without it never finished being written.
- **SV-5.** A check keeps its first 1,000 problems. The counts cover all of
  them. Every problem is also logged as an event (`store.data-corruption`),
  with the account, collection, document and blob id, so problems past the
  first 1,000 are in the log.
- **SV-6.** It's throttled, so a full check of a big store doesn't hold up
  mail: by default at most 1,000 blobs a second and, in full mode, 20 MB a
  second read. `blobsPerSecond` and `bytesPerSecond` set other limits at
  create; 0 means no limit.
- **SV-7.** Progress: the share of the blob index done (it goes through it
  in 256 slices), blobs and links checked, bytes read, problems by kind,
  and accounts whose mail metadata was checked. It's saved at least every
  10 seconds, which is also its heartbeat.
- **SV-8.** A check ends:
  - `done`, problems or none;
  - `stopped`, by an update with `action: "stop"`, which any node can
    take: the running node sees it at its next save;
  - `failed`, with the error, when the check itself couldn't go on;
  - `interrupted`: its node restarted while it ran, or the node has been
    quiet for five minutes.
- **SV-9.** Only administrators check the store: `sysStoreCheck`, in the
  built-in Administrator role and granted once to existing administrator
  roles. It reads every account's data, so a tenant administrator is
  refused. Starting and stopping a check are audited; reading one isn't.
- **SV-10.** A finished check can be destroyed. A running one can't; stop
  it first.

## The object

| Property | Type | |
|---|---|---|
| `id` | Id | |
| `mode` | String | `quick` or `full`, set at create |
| `blobsPerSecond`, `bytesPerSecond` | UnsignedInt | Limits, set at create (SV-6) |
| `status` | String | `running`, `done`, `stopped`, `failed`, `interrupted` |
| `createdAt`, `finishedAt` | UTCDate | |
| `createdBy` | String | Who started it |
| `node` | String | The node it runs on |
| `progress` | Number | 0 to 1 |
| `blobsChecked`, `linksChecked`, `bytesRead`, `messagesChecked` | UnsignedInt | |
| `missing`, `damaged`, `unlinked`, `unreadable` | UnsignedInt | Counts of each kind |
| `problems` | Object[] | The first 1,000 (SV-4, SV-5) |
| `error` | String | Why a `failed` check failed |

A problem is `{kind, accountId, accountName, object, objectId, blobId,
committed, detail}`.

## Tests

- `system::store_check` (`tests/src/system/store_check.rs`), against a real
  server: a clean store reported clean; then blobs deleted from under
  messages (missing, including a blob two messages share, reported once per
  message), a blob overwritten with other content (damaged in full mode, not
  in quick), and a message whose link was taken away (unlinked, with the
  blob still there). Over JMAP: the refusal while one check runs, stop,
  the destroy rules, bad input, the audit events, a user's refusal and a
  tenant administrator's.

## Not yet

- The console's page and an `inbuxa-cli` command.
- A test with a queued message and a kept archived item holding a blob.
- Metadata for files and Sieve scripts, as for mail (SV-3): their links are
  checked, but not that each one holds the blob its record names.
- Mail metadata of an account that holds no link at all and isn't in the
  registry any more.
