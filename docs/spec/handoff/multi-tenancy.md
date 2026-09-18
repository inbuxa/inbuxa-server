# Hand-off: build multi-tenancy

Status: ready, 2026-09-18. For the implementer of feature 1 in SPEC.md §4.

This brief is everything an implementer needs besides the repository. The
spec it builds from is `docs/spec/features/multi-tenancy.md`, committed
before any implementation (SPEC.md §3, rule 3). Read that first, then this.

## Who may do this

SPEC.md §3, rule 2: the implementer must never have read Stalwart
Enterprise-only code. For an AI session that means **a new session**, with no
access to the one that wrote the specs. That session had seen Enterprise
snippets.

Start it in `/run/media/john/PROJECTS/inbuxa-server`, not in the parent
folder, so it doesn't load the spec session's memory.

### What the implementer may read

- This repository, all of it. Every file is AGPL: the strip step removed
  everything Enterprise-only before the code was committed, and upstream's
  git history was never imported (SPEC.md §2.2a).
- `docs/spec/`: the specs, the contract, this brief.
- RFCs and IETF drafts.
- The running behavior of a server built from this repository.

### What the implementer must not read

- Any checkout, archive, fork or web view of `stalwartlabs/stalwart` (any
  branch, tag or commit). Upstream's own files still carry the Enterprise
  snippets inline.
- Any folder holding an upstream checkout or a strip work tree. That includes
  every `…/scratchpad/stalwart` and `…/scratchpad/strip-*` under
  `/tmp/claude-1000/`.
- Transcripts of other sessions, under `~/.claude/projects/`.
- Stalwart Enterprise binaries, and the license portal.
- INBUXA's production server. Its behavior is already recorded in the spec's
  "Observed" section. Build against the spec and local test servers.

If the implementer reaches a question the spec doesn't answer, they stop and
ask. The answer goes into the spec as a **Decision** and is committed before
the code that depends on it. They never go looking for how upstream does it.

## What exists today

- **Data model: complete.** The stripped build keeps every tenancy object and
  field: `x:Tenant`, `TenantStorageQuota`, `memberTenantId` on every type the
  spec lists, `Authentication.defaultTenantRoleIds`, the `TenantMaintenance`
  task, the `resetTenantQuotas` maintenance type, the `limit.tenant-quota`
  event and the permission names. They live in the generated registry code
  (`crates/registry/src/schema/`) and `resources/schema/schema.json.gz`. At
  first boot, `x:Tenant/query` answered an empty list.
- **Behavior: missing or partial.** Upstream's enforcement was
  Enterprise-only, and the strip step removed it. Some checks may survive in
  shared code; the foreign-key checks, for example, are general-purpose.
  Nobody has measured what's left. Test each requirement against the spec,
  and treat any tenancy behavior you find as a starting point to check, not
  as the reference.
- **Signposts.** `rg "inbuxa:"` lists the hooks left for rebuilding. The two
  for tenancy:
  - `crates/common/src/auth/permissions.rs`: the tenant permission ceiling
    (MT-13).
  - `crates/common/src/lib.rs`: the logo lookup (MT-22).
- **Where code was removed.** `docs/fork/strip-reports/v0.16.22.json` lists,
  file by file, how many Enterprise snippets were taken out. It gives
  locations, not code. For tenancy, the surrounding AGPL code in these files
  shows the seams:

  | Area | Files |
  |---|---|
  | Principals and access | `crates/common/src/auth/{authentication,mod,permissions}.rs`, `crates/common/src/cache/{principals,directory,invalidate}.rs` |
  | JMAP registry | `crates/jmap/src/registry/{get,query,set}.rs` |
  | JMAP mappings | `crates/jmap/src/registry/mapping/{principal,queued_message,task}.rs` |
  | HTTP permissions | `crates/http/src/auth/permissions.rs` |
  | Quotas | `crates/common/src/storage/quota.rs` |
  | Tasks | `crates/services/src/task_manager/maintenance.rs` |

  Not every snippet in those files is about tenancy. Some belong to other
  features.
- **Tests.** The integration suite (`tests/`) gates Enterprise tests behind
  the `pending-rebuild` Cargo feature. `tests/src/system/mod.rs` still calls
  `tenant::test`, but upstream's `tenant.rs` was Enterprise-only and is gone.
  Its `mod tenant;` declaration went with it. Write a new
  `tests/src/system/tenant.rs` from the spec's acceptance tests, declare the
  module again, and remove the gate on the call when it passes.

## Where the code goes

SPEC.md §2.3: rebuilt features live in **one new crate of the fork's own**,
`crates/features` (package `inbuxa-features`). License it `AGPL-3.0-only`,
with the header used in `crates/types/src/branding.rs`. Keep upstream files'
changes to the smallest hooks that call into it. Mark each hook with an
`inbuxa:` comment naming the requirement (`// inbuxa: MT-13`). The crate is
where later features go too, one module each: masked email, undelete and the
rest.

Pick the smallest hook that works over restructuring an upstream file. Every
upstream re-import merges into these files, so small hooks mean small
conflicts.

## What "done" means

1. Every requirement MT-1 to MT-23 is implemented, or deliberately deferred
   with a line in the spec saying so. The branding and quota warnings for
   ihasmail can wait for ihasmail-inbuxa.
2. Acceptance tests 1 to 14 pass as integration tests
   (`tests/src/system/tenant.rs`), with the `pending-rebuild` gate removed
   from the tenant call.
3. Test 15 (**compat**, INBUXA's own data) needs a copy of production data
   from John. Write it so it can run against a data directory, and leave it
   unrun until he provides one.
4. The whole workspace builds, and every unit test and every non-gated
   integration test that passed before still passes.
5. A local end-to-end check: a first boot of the debug binary with two
   tenants, their admins and users, and mail between them. Use the container
   recipe in "Working rules".

## Working rules

- **Commits:** plain messages, no AI attribution, no co-author trailers and
  no session links. Each names the requirement IDs it implements. Commit to
  `main` in small steps. This repository is local only and has no remote.
- **Builds** go to the repository's `target/` with
  `CARGO_TARGET_DIR=target TMPDIR=$PWD/target/tmp`. `/tmp` is a 46 GB
  tmpfs, and a full build fills it.
- **`http` is ambiguous** for `cargo -p`. Use `-p http@0.16.22`.
- **Local server:** run `target/debug/inbuxa` in a container, with the
  `stalwartlabs/stalwart:v0.16.22` image as a Debian runtime only:

  ```
  docker run -d --name inbuxa-dev --entrypoint /usr/local/bin/inbuxa \
    -v $PWD/target/debug/inbuxa:/usr/local/bin/inbuxa:ro \
    -v $DIR/etc:/etc/inbuxa -v $DIR/data:/var/lib/inbuxa \
    -e INBUXA_RECOVERY_ADMIN=admin:<password> \
    -p 127.0.0.1:18080:8080 stalwartlabs/stalwart:v0.16.22 \
    --config /etc/inbuxa/config.json
  ```

  An empty `etc` starts it in bootstrap mode. `x:Bootstrap/set` over JMAP
  (`serverHostname`, `defaultDomain`, `requestTlsCertificate: false`)
  returns the permanent admin. Restart it without the recovery admin
  variable, then create tenants, domains and accounts over JMAP (`x:Tenant`,
  `x:Domain`, `x:Account` with `@type: User`). Delete the container and its
  folders afterwards.
- **Never print or commit a password.** Generate test passwords, keep them in
  files under `target/`, and remove them along with the test server.
- **Don't touch INBUXA's production server** or anything on the hosts. This
  work is local.

## Starting prompt

For the new session, pasted as its first message:

> You're implementing multi-tenancy in inbuxa-server, the local AGPL fork of
> Stalwart in this folder. Read `docs/spec/handoff/multi-tenancy.md` and
> follow it exactly, starting with its clean-room rules, then
> `docs/spec/features/multi-tenancy.md`. Don't read anything the brief rules
> out. If the spec doesn't answer something, stop and ask me.
