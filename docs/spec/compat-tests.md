# Running the compat tests against a copy of INBUXA's data

Status: 2026-09-19.

Each feature spec has one **(compat)** acceptance test: the check that
INBUXA's own data opens in inbuxa-server and reads back as it did on the
Enterprise server (SPEC.md §7). They are written, `#[ignore]`d, and unrun,
because the repository has no copy of that data.

**Run them against a copy, never against the live server.** Two of them
delete data as part of what they check: `monitoring_compat` purges the
telemetry history it has just read, and `per_domain_directory_compat` reads
only, but the monitoring one is enough reason to treat the whole set as
destructive. The brief bars touching INBUXA's production server, and these
tests are not an exception.

## What you need

1. A copy of the data store, opened with the same `STORE` backend the copy
   was taken from, and a `TMPDIR` pointing at it. `NO_INSERT=1` stops the
   harness from resetting or seeding it.
2. `INBUXA_COMPAT_ADMIN`, as `name:password`, for a server-level
   administrator in that copy.
3. For `tenant_compat` only: `INBUXA_COMPAT_EXPECTED`, a JSON file recorded
   from the Enterprise server before the move:

   ```json
   {
     "tenants": {"<id>": {"name": "...", "quotas": {}, "members": ["<id>"]}},
     "tenantAdmins": {"<name>": {"password": "...", "accounts": ["<id>"],
                                  "domains": ["<id>"]}}
   }
   ```

## Running one

```
NO_INSERT=1 STORE=<backend> TMPDIR=/path/to/copy \
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

## What a failure means

- `tenant_compat`, `masked_email_compat`, `undelete_compat`,
  `branding_compat`, `ai_compat`: the fork reads that data differently from
  the Enterprise server. Treat as a cutover blocker and fix before moving.
- `monitoring_compat`: old telemetry that can't be decoded is expected and
  is skipped; a failure here means the settings differ from what was
  observed.
- `scim_compat` and `per_domain_directory_compat`: they assert what was
  observed on 2026-09-18, that INBUXA uses neither feature. A failure means
  it has started to, and that feature's cutover notes then apply.
