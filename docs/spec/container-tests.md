# Running the suites the plain regression doesn't reach

Status: 2026-09-19.

`cargo test -p tests` runs everything that needs nothing but a store on
disk. The fork's own feature suites are `#[ignore]`d on top of that,
because each one needs something the plain run hasn't got: a container, a
`STORE` the harness only builds on request, or, for the eight `*_compat`
tests, a copy of INBUXA's data. A green regression therefore says nothing
about them, and they have to be run by name.

The compat eight have their own runbook, `compat-tests.md`. This one
covers the rest.

## Before any of them

- Docker, for every suite whose "Needs" column names a container. The
  suites start and reuse their own containers through the `ensure_*`
  helpers in `tests/src/utils/containers.rs`; nothing has to be started by
  hand.
- `RUST_MIN_STACK=8388608`, or `smtp::inbound::data::data` and some suites
  overflow the 2 MiB test-thread stack.
- `CARGO_TARGET_DIR=target TMPDIR=$PWD/target/tmp`, a fresh `TMPDIR` per
  run.
- **One at a time.** Each suite starts a server on the same fixed ports,
  and the machine is CPU-bound: a second suite, or a build running
  alongside, makes the timing checks flake.

## The suites

| Suite | Feature | Needs | `STORE` |
|---|---|---|---|
| `scim::scim_tests` | 7, SCIM | Nothing (`SCIM_CONFORMANCE=1` adds the third-party clients, in a container) | default |
| `scim::scim_oidc_tests` | 7 and 9 (test 5) | Keycloak | default |
| `directory::per_domain::per_domain_directory_tests` | 9, per-domain directories | Nothing; needs the `sqlite` feature | default |
| `store::scaleout::scaleout_blob_tests` | 8, scale-out storage (tests 2 to 8) | Nothing: the members are directories | default |
| `store::scaleout::scaleout_memory_tests` | 8 (tests 20, 22, 23) | Redis; needs the `redis` feature | default |
| `store::replica::replica_tests` | 8 (tests 9, 10, 12 to 15) | PostgreSQL primary and hot standby | `PostgreSqlReplicated` |
| `store::replica_cluster::replica_cluster_tests` | 8 (test 11) | The same pair, and Redis | `PostgreSqlReplicated` |
| `store::replica_mysql::mysql_replica_tests` | 8 (test 17) | MySQL source and replica, GTIDs | `MySqlReplicated` |
| `store::replica_mysql::mysql_replica_position_tests` | 8 (tests 18, 19) | MySQL source and replica, by binary log position | `MySqlReplicatedPosition` |

`system::{ai,branding,masked_email,monitoring,tenant,undelete}_tests` are
also `#[ignore]`d, but only as a way to run one suite alone: the same code
runs inside `system_tests`, which the regression does run.

## Running one

```
CARGO_TARGET_DIR=target TMPDIR=$PWD/target/tmp RUST_MIN_STACK=8388608 \
STORE=<store> cargo test -p tests --features <backends> <suite> -- --ignored
```

`<suite>` is the test's name, such as `scim_tests` or `replica_tests`, and
`--exact` with its full path if the name matches more than one. The three
replicated `STORE` values are the harness's own (`tests/src/utils/storage.rs`);
they bring up the pair they name and point the server at the primary.

For example:

```
STORE=PostgreSqlReplicated cargo test -p tests --features postgres,redis \
    replica_cluster_tests -- --ignored
```

## When one fails

The containers are reused between runs, so a suite that fails in a way its
own assertions don't explain is worth re-running once against fresh ones:
`docker rm -f` the containers it names (they are all prefixed
`inbuxa-test-`) and run it again. A replica pair left paused or stopped by
an interrupted run is the usual cause — `replica_tests` pauses WAL replay,
and `mysql_replica_position_tests` changes the replica's parallel-apply
settings, both of which they restore only if they finish.
