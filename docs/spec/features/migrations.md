# Feature spec: migrations into this server

Status: building, 2026-10-30. Not a rebuild (SPEC.md §4): inbuxa's own
design, approved by John on 2026-10-30.

## Provenance

| Source | Used for |
|---|---|
| inbuxa-migrate's `guide`, `plan --answers` and `migrate --progress json` | The questions, the plans, the engine and its progress |
| This server's `inbuxa:HoldExport` and `inbuxa:Relay` | How a fork object, a background job and their permissions are built |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

An administrator moves a whole domain into this server from inbuxa Admin,
without a machine of their own to run inbuxa-migrate on. The console asks
the guide's questions. The server keeps the answers as an
`inbuxa:Migration` and runs the bundled inbuxa-migrate on them, as a child
process of the node the administrator reached.

## Requirements

- **MG-1.** A migration is an `inbuxa:Migration` under `urn:inbuxa:jmap`.
  It's kept in the fork's subspace under `I`, never in the registry.
- **MG-2.** Its source is IMAP (a login that names each account, such as
  `{email}*master`), JMAP (an administrator or an API key), Microsoft 365
  (an Entra app's tenant and client id) or Google Workspace (a service
  account's key). Maildir isn't offered, because the folders would have to
  be on the node.
- **MG-3.** Its accounts are addresses, lowercased, without duplicates, at
  most 10,000. It can create the accounts this server doesn't have yet. It
  moves 1 to 16 accounts at once, 4 by default.
- **MG-4.** The target is always this server. A run writes the answers into
  the migration's work directory, `$INBUXA_MIGRATIONS_DIR/<id>`, or
  `migrations/<id>` in the server's working directory (the image's data
  volume). `inbuxa-migrate plan` turns them into plans, so there's one
  engine and one plan builder. The binary is `$INBUXA_MIGRATE_BIN`, or the
  one the image carries at `/usr/local/bin/inbuxa-migrate`.
- **MG-5.** An update's `action` runs it:
  - `preview`: a dry run;
  - `move`: the move, which resumes if run again;
  - `finalPass`: the move with `--again`, only after a move;
  - `stop`;
  - `passwords` (MG-13);
  - `close` (MG-14).

  One run at a time per migration. Its answers change only while nothing
  runs, and its source not at all once accounts were moved.
- **MG-6.** A run ends:
  - `done`;
  - `unfinished`: some account didn't finish (the engine's exit 5);
  - `failed`, with the end of what the engine said;
  - `stopped`;
  - `interrupted` (MG-11).

  Its report goes into a blob of whoever started the migration.
- **MG-8.** A run's progress comes from `--progress json`: accounts finished
  of the total, items read and written, and failures. It's saved as each
  account ends, and at least every 30 seconds with a heartbeat.
- **MG-9.** A migration keeps the latest 200 accounts that didn't finish,
  each with its step and why.
- **MG-10.** Only administrators run migrations: `sysMigrationRun`, in the
  built-in Administrator role and granted once to existing administrator
  roles. A tenant administrator is refused. The child writes into this
  server as the administrator who started the migration:
  - It uses a run token that this node holds in memory only. The token is
    taken only from loopback, ends with the run, and is never stored, not
    even hashed.
  - It reaches this node through one of its HTTP listeners on loopback.
    That's a listener bound to loopback or every address, and not expecting
    the PROXY protocol there. It's given `--stay-on-url`, and
    `--allow-invalid-certs` for a TLS listener, since its certificate
    doesn't name 127.0.0.1. `$INBUXA_MIGRATIONS_URL` overrides the choice.
  - What the token does is audited as `via: migration`. A run token can't
    manage migrations.
- **MG-11.** A migration's work directory is on the node its first run was
  on, and its runs happen there. An action that reaches another node is
  refused, naming the node; sealing it over to the right node is the next
  step. At start-up, a node's runs from before are `interrupted`. So is a
  run whose node has been quiet for five minutes.
- **MG-12.** The source's secret is given with an action, held in the
  node's memory between runs, and passed to the child in its environment:
  `MIGRATE_SOURCE_SECRET`, beside `MIGRATE_INBUXA_TOKEN`. The child's
  environment holds those two and `PATH` only. After a restart the next run
  needs the secret again. The secret is never stored, and the audit log
  redacts it.
- **MG-13.** New accounts' passwords are in the work directory, readable by
  the server only. The `passwords` action hands them over once, as a blob
  of the administrator who takes them, and deletes the file.
- **MG-14.** Closing a migration deletes its work directory, archives
  included, and forgets its secret. A closed migration stays listed;
  destroy is refused.

## Tests

- `system::migration::migration_tests`: every requirement above, with a
  stand-in engine (`tests/resources/migrations/fake-inbuxa-migrate`).
- `system::migration::migration_real_engine_tests`, on demand: the real
  inbuxa-migrate against a Dovecot (`tests/resources/migrations/dovecot-source`).
- `tests/resources/migrations/live-image-test.py IMAGE`, on demand: a server
  image's own inbuxa-migrate, from a Dovecot, with a restart in the middle
  of the move (MG-11), the move carried on with the secret given again
  (MG-12), then the final pass and close.

## Not yet

- Actions sealed over to the node a migration runs on (MG-11).
- Accounts set up from a JMAP source's own directory (`--source-directory`).
  For now, a created account is a plain user.
