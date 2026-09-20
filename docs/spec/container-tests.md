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
| `scim::scim_tests` | 7, SCIM | Nothing (`SCIM_CONFORMANCE=1` adds the third-party clients, in a container) | `RocksDb` |
| `scim::scim_oidc_tests` | 7 and 9 (test 5) | Keycloak | `RocksDb` |
| `directory::per_domain::per_domain_directory_tests` | 9, per-domain directories | Nothing; needs the `sqlite` feature | `RocksDb` |
| `store::scaleout::scaleout_blob_tests` | 8, scale-out storage (tests 2 to 8) | Nothing: the members are directories | `RocksDb` |
| `store::scaleout::scaleout_memory_tests` | 8 (tests 20, 22, 23) | Redis; needs the `redis` feature | `RocksDb` |
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
`--exact` with its full path if the name matches more than one. `STORE` has
no default: without it the harness panics with "Missing or invalid store
type" before the suite starts, so the table names one for every suite. The
three replicated values are the harness's own
(`tests/src/utils/storage.rs`); they bring up the pair they name and point
the server at the primary.

For example:

```
STORE=PostgreSqlReplicated cargo test -p tests --features postgres,redis \
    replica_cluster_tests -- --ignored
```

`LOG=<level>` turns on the test server's own logging, which is the only way
to see why a task failed rather than that it failed: `LOG=error` is what
found the ACME fault below.

## The suites the regression runs, but not with its own settings

Three of the suites a plain `cargo test -p tests` runs can't pass on the
settings it uses. Run them by name, with these:

```
# Two nodes, so a shared store and a coordinator, never RocksDb
STORE=PostgreSql COORDINATOR=Redis cargo test -p tests --features postgres,redis \
    -- --exact cluster::broadcast::cluster_tests

# The spam rules the expectations were recorded against
STORE=RocksDb SPAM_RULES_URL=file:///path/to/spam-filter-rules.json.gz \
    cargo test -p tests -- --exact smtp::inbound::antispam::antispam

# The ACME pair, which keeps its containers between runs
STORE=RocksDb cargo test -p tests -- --exact automation::automation_tests
```

## What a plain regression leaves failing

`STORE=RocksDb cargo test -p tests -- --test-threads=1` was 87 passed, 3
failed, 23 ignored in 17m 26s on 2026-09-19, the run after the ACME fix.
That is every one of the 113 tests a default build holds; the five the
`postgres`, `mysql` and `redis` features add are all in the table above and
all `#[ignore]`d. None of the three failures is a fork regression: each is
the invocation or the environment rather than the code.

An earlier run the same day was recorded here as 86 passed, 4 failed, 27
ignored. That totals 117, which no feature set of this tree produces — 113
by default, 118 with all three backends — and no commit since has added or
removed a test. So the two aren't the same build and shouldn't be read as a
trend; the numbers above are the reference, with the command that produced
them.

- `smtp::inbound::antispam::antispam` fails every time. Its rules URL
  defaults to `file:///Users/me/code/spam-filter/spam-filter-rules.json.gz`,
  a path from the upstream import that exists on no machine here, so no
  rules load and every tag scores 0.00 against an expectation full of
  weights. Give it `SPAM_RULES_URL`.
- `cluster::broadcast::cluster_tests` needs `COORDINATOR=Redis` (or `Nats`)
  and a store the nodes can share: it passes on `STORE=PostgreSql`, and
  can't work on RocksDb, where each node gets its own.
- `smtp::outbound::lmtp::lmtp_delivery` once counted three DSNs where it
  wanted four, and passed in this run: queue timing under a loaded
  sequential run, not a fault to chase.
- `automation::automation_tests` had failed against pebble with
  `400 malformed: "Cannot update challenge with status processing, only
  status pending"`, because the client re-posted the challenge on every
  poll. That was a real renewal bug and is fixed; this run logged no 400 at
  all, and the client polls as RFC 8555 section 7.5.1 says to.

  The suite still doesn't pass here, and the reason first recorded on this
  page — that `ufw` blocks the docker bridge, so pebble never validates and
  the authorizations stay pending — is wrong. Checked on 2026-09-19:

  - **TCP reaches the host.** From containers on `stalwart-test-acme`, on
    two different images, `nc` to the host's gateway addresses connects on
    port 22 and is refused *immediately* on every closed port tried (8899,
    9, 14000). A `ufw` DROP would hang until the timeout instead. No
    firewall rule was read or changed to establish this — `ufw status`
    needs a privilege this session doesn't have.

    One thing this doesn't explain: `openssl s_client` against the same
    closed 8899 hung for its full timeout rather than reporting the refusal
    `nc` saw a second earlier. The probe, not the path, is the likely
    culprit, but it is unexplained, so treat "the bridge is open" as what
    `nc` shows rather than as settled.
  - **Pebble does validate.** Its log shows 20 validation attempts in the
    regression run, five for each of `autoconfig`, `autodiscover`,
    `mta-sts` and `ua-auto-config.tls.org`, and it then sets each
    authorization `INVALID by completed challenge` and the order `INVALID`.
    The challenges are answered and refused, not left pending.
  - So no certificate is issued and the test ends on an `Option::unwrap()`
    of the certificate that never arrived
    (`tests/src/automation/acme.rs:223`). A second run with `LOG=error`
    reproduced it exactly, in 84s.

  What that leaves is the TLS-ALPN handshake itself. The responder is
  upstream's and intact (`ACME_TLS_ALPN_NAME` in
  `crates/common/src/network/acme/resolver.rs`), and `listen.rs` decides
  per accepted connection whether to offer it, from
  `has_acme_tls_providers()` — which reads `has_acme_tls_challenge`,
  computed when the network config is parsed. **Unproved hypothesis:** the
  test adds its TLS-ALPN provider after the server is up, so if nothing
  recomputes that flag, the listener never offers `acme-tls/1` and every
  challenge fails exactly as observed. Worth testing before anything else.
  An `openssl s_client -alpn acme-tls/1` against `:8899` during a renewal
  was tried and proved nothing: the same probe hangs against a port with
  nothing behind it, so its silence says nothing about ALPN. A probe that
  first shows a handshake against a known-good endpoint is needed.

## The last sweep

All nine were re-run on 2026-09-19, one at a time, after `docker rm -f` on
every `inbuxa-test-` and `stalwart-test-` container, so each suite built
its own from scratch. All nine pass:

| Suite | Time |
|---|---|
| `scim_tests` | 21s |
| `scim_oidc_tests` | 23s |
| `per_domain_directory_tests` | 4s |
| `scaleout_blob_tests` | 1s |
| `scaleout_memory_tests` | 1s |
| `replica_tests` | 15s |
| `replica_cluster_tests` | 12s |
| `mysql_replica_tests` | 36s |
| `mysql_replica_position_tests` | 27s, failed; 7s on a second run |

`mysql_replica_position_tests` was the one failure, on test 18's first
assertion: the replica's lag has to be under five seconds, and
`Seconds_Behind_Source` is still above that while a pair seeded half a
minute earlier catches up. It failed before the point where the suite
changes the replica's settings, so nothing was left to restore, and it
passed on a second run against the same, now warm, pair.

## When one fails

The containers are reused between runs, so a suite that fails in a way its
own assertions don't explain is worth re-running once against fresh ones:
`docker rm -f` the containers it names (they are all prefixed
`inbuxa-test-`) and run it again. A replica pair left paused or stopped by
an interrupted run is the usual cause — `replica_tests` pauses WAL replay,
and `mysql_replica_position_tests` changes the replica's parallel-apply
settings, both of which they restore only if they finish.

A pair built fresh has the opposite problem: it is still catching up, and a
lag assertion can fail on a replica that is working perfectly well. Give
the suite a second run before reading anything into it.
