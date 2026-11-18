# Feature spec: setting up a new store from a file (`--seed`)

Status: approved direction, 2026-11-18 (John chose "a setup file the server
reads" over a chart job that drives recovery mode). Kubernetes item K-S8.
Not a rebuild (SPEC.md §4): inbuxa's own design.

## Provenance

| Source | Used for |
|---|---|
| The Kubernetes recipe's chart work (inbuxa-charts K-C2) | The gap: a chart can name the data store, but nothing declarative creates the registry objects a cluster needs |
| This server's `--upgrade-store` (K-S3, `crates/main/src/main.rs`) | The one-shot shape: boot without listeners, do one thing, exit with 0, 1 or 2 |
| This server's JMAP request handler and `x:*/set` (`crates/jmap`) | How the seed's calls run: the same validation, password hashing and follow-up tasks as the API |
| RFC 8620 §3.3 and §5.3 | The request body the seed is, and its creation-id references (`#d`) |

Nothing here comes from Enterprise code or from upstream.

## What it is

A server reads only `config.json`, which holds the data store, plus some
environment variables. Everything else lives in the registry, inside the
store, and is set through the API or the console. An install that is
declared rather than clicked through has to put the first objects there: the
domain, the administrator, the blob store, the coordinator and the cluster
roles. A Helm chart is that kind of install.

`inbuxa --seed <PATH>` does it. The file is a JMAP request body. The server
applies it once, to a new store, and exits.

## Requirements

- **SD-1.** `--seed <PATH>` boots as `--upgrade-store` does: no listeners, no
  services, no spam model. It also refuses bootstrap mode and recovery mode.
  It upgrades the store's layout first. If that doesn't end at this
  release's layout, it exits with `--upgrade-store`'s code and applies
  nothing.
- **SD-2.** The safe defaults a first start writes (roles, listeners, queue
  settings and the rest) go in before the seed. So the seed run leaves the
  store as a first start would, plus the seed. Pods started after it find
  their cluster role, and don't race each other to write the defaults of an
  empty store.
- **SD-3.** The file is a JMAP request body: `using` plus `methodCalls`, the
  body an administrator would POST to `/jmap`. Its calls run through the
  server's request handler as the system administrator, in order, with
  creation-id and result references. A seed may hold up to 1,000 calls.
- **SD-4.** A value written `{"$file": "<PATH>"}`, an object with that one
  key, is replaced by the file's contents, with trailing line breaks taken
  off. This happens before the calls run. Secrets stay in mounted files, and
  the seed can live in a ConfigMap or in git. A `$file` that can't be read
  fails the run before anything is written.
- **SD-5.** A seed applies once, to a new store. "New" is the defaults'
  test: no roles yet, or a first start that never finished. The store keeps
  a note under key `Ks` in the fork's subspace:
  - `started <sha256 of the file>` is written before the calls run;
  - `applied <sha256>` once every call succeeded.

  A later run finds `applied` and does nothing. If the file changed since,
  it says so: after the first run, the registry is the source of truth.
- **SD-6.** Exit codes:

  | Code | When |
  |---|---|
  | 0 | Applied, or applied before to this store |
  | 1 | Failed: a call returned an error, or something wasn't created, updated or destroyed. The store may hold part of the seed |
  | 2 | Refused: the store was set up another way, or an earlier seed run stopped partway (a `started` note). Nothing written |

  The message names each failed call and error type, never the values sent.
- **SD-7.** A partial seed isn't retried: running it again would create
  objects twice. The operator finishes the setup in the console or starts
  again from an empty store. A Kubernetes Job runs the seed with
  `backoffLimit: 0` for the same reason.

## Out of scope

- Applying a seed again to bring the registry back in line with the file
  (reconciliation). A later spec can add that, if operators ask for it.
- Serialising the defaults of an empty store between nodes that all start
  at once without a seed. With the seed (SD-2) they don't start on an empty
  store.
