# Running the compat tests against a copy of INBUXA's data

Status: 2026-09-19 (dry run below; still unrun against INBUXA data).

Each feature spec has one **(compat)** acceptance test: the check that
INBUXA's own data opens in inbuxa-server and reads back as it did on the
Enterprise server (SPEC.md §7). They are written, `#[ignore]`d, and unrun,
because the repository has no copy of that data.

The fork's other `#[ignore]`d suites, the ones that need containers rather
than INBUXA's data, are in `container-tests.md`.

**Run them against a copy, never against the live server.** Two of them
delete data as part of what they check: `monitoring_compat` purges the
telemetry history it has just read, and `per_domain_directory_compat` reads
only, but the monitoring one is enough reason to treat the whole set as
destructive. The brief bars touching INBUXA's production server, and these
tests are not an exception.

## What you need

1. A copy of the data store, opened with the same `STORE` backend the copy
   was taken from. **`TMPDIR` is the copy's parent, not the copy.** The
   harness opens `$TMPDIR/<test name>` (`tests/src/utils/temp_dir.rs`), so
   the copy for `tenant_compat` has to sit at `$TMPDIR/tenant_compat`, the
   one for `scim_compat` at `$TMPDIR/scim_compat`, and so on. Point `TMPDIR`
   at the copy itself and the harness quietly creates an empty store beside
   it and the test reports INBUXA's data as missing — a cutover blocker that
   isn't one. Each test wants its own copy anyway: `monitoring_compat`
   purges what it reads.
2. `NO_INSERT=1`, which stops the harness resetting and seeding the store.
   Every one of the eight refuses to run without it, before the store is
   touched (verified, "The dry run" below).
3. `INBUXA_COMPAT_ADMIN`, as `name:password`, for a server-level
   administrator in that copy.
4. For `tenant_compat` only: `INBUXA_COMPAT_EXPECTED`, a JSON file recorded
   from the Enterprise server before the move:

   ```json
   {
     "tenants": {"<id>": {"name": "...", "quotas": {}, "members": ["<id>"]}},
     "tenantAdmins": {"<name>": {"password": "...", "accounts": ["<id>"],
                                  "domains": ["<id>"]}}
   }
   ```
5. For `masked_email_compat` only: `INBUXA_COMPAT_MASKS`, recorded the same
   way:
   `[{"id": "...", "accountId": "...", "email": "...", "enabled": true}]`.
6. For `undelete_compat` only: `INBUXA_COMPAT_ARCHIVED`, the
   `x:ArchivedItem/get` results, each with its `id` and `accountId`:
   `[{"id": "...", "accountId": "..."}]`.

## Recording the three files

`tools/fork/record-compat.py` writes all three, and has to run while the
Enterprise server is still up — after the cutover there is nothing left to
record from, and SPEC.md §7 gives that 45 days from the notice.

```
tools/fork/record-compat.py --server https://mail.example.org \
    --admin 'admin@example.org:PASSWORD' --out ./compat \
    --tenant-admin 'tenant-admin@example.org:PASSWORD'
```

It **only reads**: it issues `/get` and `/query` and refuses to send
anything else, so it is safe against the live server that the hand-off
brief otherwise bars touching. It is the one thing that has to run there
rather than on a copy.

Pass `--tenant-admin` once for each tenant administrator whose view should
be checked: the script signs in as each and records the accounts and
domains that administrator can see, which is what `tenant_compat` compares
against. Without any, `tenantAdmins` is empty and the test checks only the
tenants themselves. `expected.json` holds those passwords and is written
`0600`. `--insecure` skips certificate verification.

It was exercised on 2026-09-19 against the fork's own test server, which
answers the same JMAP: it recorded 3 tenants with their members, 8 masked
addresses and 3 archived items, in the shapes above.

## Running them

`tools/fork/run-compat.sh` copies the store for each test and runs it:

```
tools/fork/run-compat.sh --store /srv/inbuxa-copy/rocks.db \
    --admin 'admin@example.org:PASSWORD' --recordings ~/compat
```

It takes `--only <test name>` for one, and `--keep` to leave each copy
behind for a post-mortem. A test whose recording is missing is skipped by
name rather than run against nothing.

**The source copy has to be pristine.** Several of these write to the store
they open — `monitoring_compat` purges the history it reads,
`undelete_compat` restores what it finds — and the harness adds its own
listeners on the way in, so a copy that a run has already touched is not a
copy of INBUXA's data any more. The script copies from the source for each
test and removes the copy afterwards, so the source stays clean; take it
from a stopped server or a snapshot, never from under a running one.

**Why the copy's own listeners are ignored.** A real server listens on 25,
443, 993 and the rest. Nothing in a test run is root, so every one of those
fails to bind and the run died before reading any data, with eight
`Permission denied (os error 13)` errors and nothing about what to do.
Under `NO_INSERT` the harness now drops build errors belonging to listeners
it did not add itself, and keeps every other error, including a bind that
fails on one of its own (`tests/src/utils/server.rs`). The copy is not
edited to achieve this; its listeners are simply not what a compat run
needs.

**Why the copy's task queue is ignored.** A real server's pending tasks come
with its store: ACME renewals due months from now, work that can never run
on this machine. The harness waits for tasks to drain, so the first run
against INBUXA's copy sat printing `Waiting for pending task
AcmeRenewal(...)` until it was interrupted. Under `NO_INSERT` it now skips
tasks that aren't due and ones that have failed for good, and gives up
after a minute with the task printed, so the test fails on its own
assertion instead of spinning.

**Why `compat-` listeners appear in the copy.** The harness needs listeners
on its own ports, and the registry keys listeners by name. A real server
has its own, and a production listener called `jmap` or `imap` collided
with the harness's, killing every compat test at startup with `Primary key
conflict on property "name"` before it checked anything. Under `NO_INSERT`
the harness now names its listeners `compat-jmap` and so on
(`tests/src/utils/server.rs`), out of the way of whatever the copy holds.

## Running one

```
# the copy is at $TMPDIR/<test name>, e.g. /srv/compat/tenant_compat
NO_INSERT=1 STORE=<backend> TMPDIR=/srv/compat \
INBUXA_COMPAT_ADMIN='admin@example.org:<password>' \
RUST_MIN_STACK=8388608 \
cargo test -p tests --features <backends> <test name> -- --ignored --exact
```

`<test name>` is the full path, such as `system::tenant::tenant_compat`.
Run them one at a time: each starts a server on fixed ports.

## The eight tests

| Test | Feature | What it checks |
|---|---|---|
| `system::tenant::tenant_compat` | 1, multi-tenancy | Tenants, their members and quotas read back unchanged, and each tenant administrator sees what it saw before (needs `INBUXA_COMPAT_EXPECTED`) |
| `system::masked_email::masked_email_compat` | 2, masked email | Existing masked addresses still deliver, and their state reads back |
| `system::undelete::undelete_compat` | 3, undelete | Archived items are still listed and restorable |
| `system::branding::branding_compat` | 4, branding | Every domain's and tenant's logo, `logoUrl` and the three templates read back as stored |
| `system::ai::ai_compat` | 5, AI spam | The twelve `LLM_*` tags and their scores |
| `system::monitoring::monitoring_compat` | 6, monitoring | Retention, stores and `indexTelemetry` as observed; old history in the stripped encoding is skipped, not an error, and is gone after one purge (**deletes history**) |
| `scim::scim_compat` | 7, SCIM | No domain open to SCIM, and no account with an `externalId`, as observed |
| `directory::per_domain::per_domain_directory_compat` | 9, per-domain directories | No directory, no server default, and no domain with its own directory: any domain with one is a cutover blocker |

## The dry run

None of the eight has ever run against INBUXA's data, so on 2026-09-19 all
eight were run against an empty store with synthetic inputs, to prove the
plumbing before the day the copy exists. What that established:

- **`NO_INSERT` protects the copy.** A sentinel file was left in each store
  directory. Every run kept it, and the run without `NO_INSERT` stopped at
  "NO_INSERT must be set, or the copy of INBUXA's data is wiped" before the
  harness deleted anything. The guard is ahead of the store in all eight.
- **`TMPDIR` is the parent.** The store appeared at
  `$TMPDIR/<test name>/rocks.db` in every run, which is where the finding in
  "What you need" comes from.
- **The documented JSON shapes parse.** The three files above, written
  exactly as this page gives them, were read without complaint by
  `tenant_compat`, `masked_email_compat` and `undelete_compat`.
- **A bad administrator now says so.** Each test authenticates once before it
  asserts anything, and fails with `INBUXA_COMPAT_ADMIN did not authenticate
  as <name>` and the 401 body. Before that check the first call simply
  panicked with "Missing list in response", which reads like INBUXA's data is
  wrong when the login is what's wrong.

What it can't establish is anything about INBUXA's data: every run ended at
the authentication check, since an empty store holds no such administrator.

## What was recorded, 2026-09-19

`record-compat.py` ran against the live Enterprise server as a server-level
administrator and saw 8 accounts, which is what the dashboard reports, so it
reached all of them. It recorded:

| File | Contents |
|---|---|
| `expected.json` | 1 tenant, with its quotas and members. `tenantAdmins` empty: no `--tenant-admin` was passed |
| `masks.json` | nothing |
| `archived.json` | nothing |

The two empty files are right, not a short recording: INBUXA has no masked
addresses and deleted-mail retention is off (John, 2026-09-19). So
`masked_email_compat` and `undelete_compat` iterate over an empty list.
**They pass without comparing anything, and a green run from either proves
nothing about compatibility** — the same standing as `scim_compat` and
`per_domain_directory_compat`, which assert INBUXA uses neither feature.

That leaves one recording that carries weight, `expected.json`, and it is
made. Should either feature be switched on before the cutover, record again:
the files are a picture of the day they were taken.

## What a failure means

- `tenant_compat`, `branding_compat`, `ai_compat`: the fork reads that data
  differently from the Enterprise server. Treat as a cutover blocker and fix
  before moving.
- `masked_email_compat` and `undelete_compat` would mean the same, but as of
  2026-09-19 they have nothing to read: see "What was recorded" above. They
  can only fail once INBUXA has masked addresses or retention on.
- `monitoring_compat`: old telemetry that can't be decoded is expected and
  is skipped; a failure here means the settings differ from what was
  observed.
- `scim_compat` and `per_domain_directory_compat`: they assert what was
  observed on 2026-09-18, that INBUXA uses neither feature. A failure means
  it has started to, and that feature's cutover notes then apply.
