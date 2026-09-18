# inbuxa-server: specification (draft)

inbuxa-server is the project. Whether the product it ships carries that name
or another inside the INBUXA brand is still open (§8). Not published: no
remote, and nothing public before the cutover in §7.

## 1. What this is

An AGPL-3.0-only fork of the Stalwart mail server that ships every feature
under the AGPL, with nothing held back for a paid edition. ihasmail is built
in as the product's web front end: webmail, account self-service and
administration. Stalwart's own web interface is dropped.

**Goals**

- Everything Stalwart's Enterprise Edition adds is available to everybody,
  under the AGPL, rebuilt clean-room.
- One product: server, webmail and administration installed and versioned as
  a pair.
- No web interface on the mail host. Administration happens over JMAP from
  ihasmail, which can run beside the server or on another machine.
- Stay close enough to upstream that its releases can be taken quickly.

**Non-goals**

- Carrying, adapting or reading Stalwart Enterprise code (see §3).
- Using Stalwart's name or logo anywhere in the product (see §2.4).
- Changing Stalwart's storage formats beyond what upstream changes. Existing
  Stalwart 0.16 data, including data written by Enterprise features, must
  open unchanged (see §7).

## 2. The fork itself

### 2.1 What is taken

Every upstream file licensed `AGPL-3.0-only OR LicenseRef-SEL` is taken under
the AGPL. Nothing licensed only `LicenseRef-SEL` is taken.

Upstream marks Enterprise-only code two ways, and both must go:

- **Whole files** whose SPDX header is `LicenseRef-SEL` alone. At upstream
  `d9dee0a` (2026-09-15) that is 63 files, about 21,000 lines, 5,500 of them
  tests.
- **Snippets** inside dual-licensed files, between `SPDX-SnippetBegin` and
  `SPDX-SnippetEnd`, whose identifier is `LicenseRef-SEL` alone. At the same
  commit that is 117 snippets in 50 files, about 1,700 lines.

### 2.2 The strip step

Upstream publishes its own remover, `resources/scripts/ossify.py`, licensed
AGPL-3.0-only. It deletes Enterprise-only files and snippets by their markers,
which is this step's core. The fork runs it on every sync, wrapped by a
script of its own that:

1. Runs `ossify.py` over `crates/` and `tests/`.
2. Checks independently that no `LicenseRef-SEL`-only marker survives
   anywhere in the tree, not just in `.rs` files.
3. Fails the sync if a marker is malformed, e.g. a snippet with no end, a
   file whose header can't be read, or a new license identifier.
4. Writes a report listing what was removed and where, committed with the
   sync.

It reads only the SPDX markers, never the code between them. That keeps the
people running it outside the clean room's restrictions. The removed code is
never committed to any branch of the fork, including history.

The wrapper is `tools/fork/strip.py`. Beyond `ossify.py` it:

- exports the release with `git archive`, never a checkout, so no upstream
  history comes with it;
- checks every snippet's begin and end markers pair up before anything is
  stripped (`ossify.py` would swallow an unterminated snippet to the end of the
  file without saying so). Markers are matched anywhere on a line, because
  upstream often ends a snippet with a trailing `} // SPDX-SnippetEnd`;
- turns the `enterprise` Cargo feature off where it's switched on. At
  `v0.16.22` that's `crates/main`'s default features and 13 dependencies in
  `tests/Cargo.toml`: 14 edits. `ossify.py` doesn't touch manifests, so without
  this the stripped tree can't build;
- removes `mod` declarations left pointing at deleted Enterprise files. They
  sit just outside the snippets `ossify.py` removes, so they survive it. At
  `v0.16.22` there are 5: one in `common`, behind the test features, and four
  in the integration tests. The normal build never meets them, but the tests
  don't compile until they're gone;
- verifies the result across every text file, not just Rust, and reports what
  was removed, the Cargo edits, upstream's Enterprise flags, and the feature
  gates left for §2.3 to replace.

### 2.2a Snapshots, not a git fork

Upstream's git history contains the Enterprise code, so the fork can never
share it. There's no `git fork`, and no upstream remote in the fork's
repository. Instead:

- An **`upstream`** branch holds one commit per upstream release: the
  stripped tree, and its strip report in the commit message (release tag,
  upstream commit, counts, verification result). Nothing else is ever
  committed there.
- **`main`** is the fork. A new release arrives by stripping it onto
  `upstream`, then merging `upstream` into `main`. Git's three-way merge then
  does what a fork's rebase would, without the history.
- The upstream clone the tool reads from lives outside the fork's repository
  and is never pushed anywhere.
- Each import's full strip report is committed on `main` under
  `docs/fork/strip-reports/<ref>.md` (and `.json`), beside the merge that
  brought the release in.
- The snapshot includes upstream's `.github/` workflows, release automation
  included. They're kept on `upstream` as upstream shipped them, but must be
  disabled or replaced on `main` before the repository is ever pushed
  anywhere that runs them.

### 2.2b What the first import proved (v0.16.22, 2026-09-18)

- The stripped tree builds (`cargo build -p stalwart`, 3 min 14 s on 16
  cores) and the binary runs. There are 6 warnings, all unused imports left
  where Enterprise snippets were cut out.
- Every crate's unit tests pass: 263 passed, 0 failed, 2 ignored. They build
  with the integration crate in the build, because that's what switches on the
  test features the unit tests rely on, and run from each crate's own directory
  (`dav-proto` loads fixtures by relative path).
- The integration crate (`tests/`) compiles once the shared tests of
  unrebuilt features are gated behind its `pending-rebuild` feature, off by
  default: the OIDC-directory, tenant and archiving suites; the four
  telemetry suites (alerts, metrics, tracing, webhooks); and the LLM parts of
  the spam-filter suite. Each gate carries an `inbuxa: pending-rebuild` comment
  and comes off when its feature is rebuilt.
- Those gated suites are shared, AGPL test code that exercises Enterprise
  behavior. That makes them a clean source for the feature specs, and ready-made
  acceptance tests for the rebuilds.
- First boot (2026-09-18): the stripped debug binary, run in a local
  container with the upstream `v0.16.22` image used only as a Debian runtime
  (its glibc 2.41 covers the binary's 2.39), through ihasmail-oneshot's
  sequence over JMAP. Every step worked:
  - it started in bootstrap mode on port 8080;
  - `x:Bootstrap/get` confirmed bootstrap mode, and `x:Bootstrap/set` returned
    a permanent admin and wrote `config.json`;
  - after a restart, the admin signed in, the server reported edition `oss`
    (Enterprise reports `enterprise`) with 637 permissions against
    Enterprise's 641, and the domain existed with DKIM keys generated;
  - two users were created, and the DNS zone exported;
  - one user's message went over SMTP submission (465), was DKIM-signed, and
    was read by the other over IMAP (993) and JMAP;
  - `x:MaskedEmail` and `x:ArchivedItem` answered `forbidden` with an
    Enterprise upsell (`crates/jmap/src/registry/mod.rs`), and `x:Tenant/query`
    answered an empty list.
- Not yet run: the integration suite itself, which needs its database
  services.

Layout on `main`: the server source at the root, exactly as upstream lays it
out (so merges line up), the specs under `docs/spec/`, strip reports under
`docs/fork/`, and the fork tooling under `tools/fork/`. Upstream has no
top-level `docs/` or `tools/`, so these never collide.

### 2.3 Where the rebuilt features go

Upstream's published registry schema (`resources/schema/schema.json.gz`)
flags every Enterprise object and field with `"enterprise": true`: 9 objects
and 30 fields at `d9dee0a`. That list is the checklist for §4, and the wrapper
in §2.2 reports it on every sync, so a newly flagged field is noticed.


Rebuilt features live in one new crate of the fork's own, licensed
AGPL-3.0-only, plus the smallest possible hooks in upstream files. The hooks
sit where upstream's `enterprise` Cargo feature and `is_enterprise_edition()`
checks already are: 30 checks across 18 files at the commit above. That keeps
each sync's conflicts few and predictable.

The `enterprise` Cargo feature and every edition check are removed. There is
one edition.

### 2.4 Name and marks

- No "Stalwart" in product names, binaries, images, UI text, packaging or
  domains.
- Factual statements are allowed and required: "a fork of Stalwart",
  "compatible with Stalwart 0.16 data". Upstream copyright notices stay on
  every file they cover.
- Protocol identifiers stay as upstream has them, for example the JMAP
  capability `urn:stalwart:jmap` and the `x:` object names. They're
  interoperability, not branding, and renaming them breaks every existing
  client. Anything the fork adds uses its own namespace (open: which one).

## 3. Clean room

INBUXA runs on a paid Stalwart Enterprise license, so its maintainer is a
licensee with access to the Enterprise code. That license forbids publishing
derivative works of it, so the burden of showing independent creation falls
on this project. Rules:

1. **Spec writers** may use Stalwart's public documentation, the RFCs and
   drafts, the published JMAP and registry schema (dual-licensed, so
   available under the AGPL), and the observed behavior of a running server.
   They may not use Enterprise source, snippets, private documentation,
   support correspondence or anything from the license portal.
2. **Implementers** work only from the written specs in `features/`. They
   must never have read Enterprise-only files or snippets. An AI session that
   has seen Enterprise code (including the one that drafted this document)
   doesn't implement.
3. **Records.** Each feature spec is dated and committed before its
   implementation starts, and names its sources. Implementation PRs link the
   spec they build from.
4. **Behavioral compatibility, not code compatibility.** Where existing data
   has to keep working (masked addresses already handed out, archived items
   already held), the behavior is specified from stored records and observed
   results, not from how upstream implements it.
5. Legal review before anything is published.

## 4. Features to rebuild

In order. Each gets its own clean-room spec under `features/` before any code
is written.

| # | Feature | What an operator gets | Notes |
|---|---|---|---|
| 1 | Multi-tenancy | Tenants with their own domains, admins, quotas and queue visibility | Needed for anybody hosting mail for others. ihasmail already has a Tenants screen. |
| 2 | Masked email | Per-sender disposable addresses that deliver to the account | Existing addresses must keep delivering (§3.4). |
| 3 | Undelete | Deleted mail held for a set period and restorable | Existing archived items must stay restorable. |
| 4 | Branding and templates | Operator logo, and the text of calendar alarm and invitation emails | INBUXA's branding is the default. |
| 5 | AI spam classification | An optional model's opinion as one spam signal, and a Sieve function that asks a model | Local and auditable model only: no hosted API by default. |
| 6 | Monitoring history, live tracing, alerts | Stored metrics and traces, a live trace view, and threshold alerts | ihasmail's dashboard shows them. |
| 7 | SCIM 2.0 provisioning | Accounts and groups managed by an identity provider | From RFC 7643 and RFC 7644. The largest piece. |
| 8 | Scale-out storage | SQL read replicas; sharded blob and in-memory stores | For large installs only. |
| — | Seat limits, license keys | Nothing: there's no license | Removed, not rebuilt. |

## 5. ihasmail as the product's web front end

### 5.1 Shape

ihasmail stays a separate process: its Node server and its web app, run as a
container. It can run:

- **on the same host**, on a private network or loopback, which is the
  default the installer sets up; or
- **on another host**, for operators who want no web front end near the mail
  store.

It isn't compiled into the server. Its server side (sessions, image and
calendar-link proxies, push relay, rate limits, settings policy) would have to
be rewritten in Rust and would put a web front end back on the mail host,
which this design exists to avoid.

### 5.2 The contract between them

Versioned, and advertised in the JMAP session so either side can check it.

- **Discovery.** The server's session names its webmail URL and the contract
  version it speaks. ihasmail refuses a server outside its supported range,
  with a clear message. Its current Stalwart 0.16 check becomes this check.
- **Sign-in by OAuth.** The server pre-registers ihasmail as a first-party
  OAuth client (authorization code with PKCE). ihasmail holds tokens, never
  passwords. Today it signs in with Basic auth and keeps the password in its
  session.
- **Token revocation.** The server can revoke individual tokens and every
  token for a client. Upstream's tokens are stateless and can only be revoked
  by changing the password. ihasmail's "sign out other sessions" relies on
  this.
- **Two-factor.** Handled in the OAuth flow, not by appending codes to
  passwords.
- **Admin lane.** Administrative JMAP calls can be limited to ihasmail's
  address or network, so an admin credential is useless from anywhere else.
- **Push.** Unchanged: JMAP push with VAPID, as ihasmail uses today.

### 5.3 Stalwart's web interface is removed

Upstream installs its web interface at first boot, serving `/admin` and
`/account`, by inserting a default web application that downloads a release
of `stalwartlabs/webui`. The fork:

- inserts no default web application, and never fetches `webui`;
- keeps the generic web-application mechanism for operators who want it,
  documented as unsupported;
- therefore carries no part of `webui`, which has its own Enterprise-only
  parts.

What the web interface did moves to ihasmail:

| Was | Becomes |
|---|---|
| `/account`: password, app passwords, two-factor | ihasmail Settings: password and app passwords today; its two-factor work is written but backlogged |
| `/admin`: server administration | ihasmail Administration (§5.4) |
| First-boot setup | the installer and a setup screen in ihasmail (§6) |
| Fixing a server the web front end can't reach | the host-side CLI (§6.3) |

### 5.4 Administration at full coverage

The server's registry has about 125 object types. ihasmail Administration
uses 18 today: accounts, domains, groups, mailing lists, roles, tenants, the
dashboard, credentials and a few supporting types.

- **Hand-built screens** for what operators change often: domains and DNS,
  DKIM, certificates and ACME, spam settings, the queue, tenants and quotas,
  reports.
- **Schema-generated forms** for the rest. Upstream already publishes a
  complete UI schema, `resources/schema/schema.json.gz`, with objects, fields
  (with descriptions), forms, lists, enums, dashboards and layouts. It's what
  Stalwart's own web interface draws from, and it ships under the repository's
  dual license, so the fork has it under the AGPL. The fork serves it over
  JMAP, and ihasmail renders a correct, if plain, editor for any object type
  from it. New types upstream
  adds then appear without an ihasmail release.
- Everything stays permission-gated, as Administration is today.

## 6. First boot, setup and recovery

### 6.1 The installer

ihasmail-oneshot is the starting point: a Go binary using only the standard
library, which drives `docker compose`. Its commands and options carry over.

Commands: `deploy`, `certs`, `destroy`, `version`.

`deploy` options:

| Option | Default | Meaning |
|---|---|---|
| `--domain` | (required; `example.test` with `--local`) | Mail domain |
| `--mail-host` | `mail.DOMAIN` | Mail server's hostname |
| `--webmail-host` | `webmail.DOMAIN` | Webmail's hostname |
| `--email` | `postmaster@DOMAIN` | ACME contact |
| `--local` | off | Loopback-only evaluation: no mail ports, no Caddy, no certificates |
| `--dir` | `./PROJECT` | Deployment directory, new or empty |
| `--project` | `ihasmail-DOMAIN` | Compose project name |
| `--stalwart-image` | pinned | Server image; renamed for the fork |
| `--ihasmail-image` | newest release, written as its dated tag | Webmail image |
| `--caddy-image` | pinned | Caddy image |
| `--webmail-bind` | `127.0.0.1:8080` | Host address for ihasmail's port |
| `--stalwart-bind` | `127.0.0.1:8081` | Host address for the server's plain HTTP. Renamed; it no longer carries an admin UI |
| `--subnet` | `172.31.253.0/24` | Private network for the stack |
| `--acme-directory`, `--acme-ca-root` | Let's Encrypt | Private CA for ACME |
| `--yes` | off | Skip confirmation |

### 6.2 What first boot does

Oneshot's sequence, all over JMAP, with no web interface involved:

1. Start the server with an empty configuration, which puts it in bootstrap
   mode with a temporary admin pinned by environment variable.
2. Check it really is in bootstrap mode. A configured server refuses
   bootstrap credentials, and oneshot stops.
3. Complete bootstrap through `x:Bootstrap`, which returns the permanent
   administrator.
4. Look up the domain; turn on ACME explicitly (upstream's certificate flag
   alone creates no ACME provider); retry certificates.
5. Trust forwarded addresses from the reverse proxy, and allow its IP, so the
   auto-ban doesn't ban the proxy.
6. Create the first user; write the credentials file and the DNS zone file.

Found at the fork's first boot, and to fix:

- On first boot the server downloads Stalwart's web interface
  (`webui.zip` from GitHub) before anything is configured. §5.3 removes this.
- Whenever `STALWART_RECOVERY_ADMIN` is set, its password is a full admin
  login, outside bootstrap and recovery mode too. oneshot is safe, because
  it recreates the container without the variable once setup is done, but a
  plain restart keeps it. The fork honors the variable only in bootstrap and
  recovery mode, and logs a warning when it's set otherwise.
- Default listeners after setup: HTTP 8080, HTTPS 443, SMTP 25, submissions
  465, IMAPS 993, POP3S 995, ManageSieve 4190. There's no plain 587 or 143.
- The Enterprise upsell error (`crates/jmap/src/registry/mod.rs`) goes. With
  every feature built in, there's nothing to sell.

Additions for the fork:

- Register ihasmail as the first-party OAuth client (§5.2).
- Behavior fixes where upstream's first boot needs workarounds: an ACME order
  that fails isn't retried on restart, some network settings need a restart,
  and the default log path doesn't exist in the image. Each is a candidate for
  fixing in the fork, and oneshot's workaround drops out once it is.
- A setup screen in ihasmail for operators who install without the
  installer. It performs the same steps against a server in bootstrap mode.

### 6.3 Recovery without a web front end

When a settings change cuts ihasmail off from the server (a bad listener, a
bad certificate, a lockout), there has to be a way back in on the host:

- A CLI subcommand of the server binary that runs locally and edits the
  registry directly, or starts the server in upstream's recovery mode with
  only a loopback listener.
- Minimum it covers: list and edit listeners and certificates, reset an
  administrator's password, lift IP bans, and export or import the
  configuration.
- Upstream documents a CLI with `get`, `describe` and `snapshot` commands
  (public docs, `management/cli`). Check how much of the above it already
  covers before building anything.
- Open: whether this lives in the server binary or in the installer as
  `oneshot recover`.

## 7. INBUXA cutover

INBUXA moves to the fork **before** the fork is announced. Its Enterprise
subscription can be ended at 30 days' notice, and the server falls back to
the Community Edition 15 days later. So the fork must be carrying INBUXA
before anything that could prompt that notice happens.

1. Fork builds and passes upstream's test suite, minus the removed Enterprise
   tests, plus the fork's own.
2. INBUXA's data opens in the fork on a copy: tenants, masked addresses,
   archived items, every account.
3. Masked addresses already handed out still deliver; archived items still
   restore.
4. Cutover on the running host, with the Enterprise build kept for rollback.
5. Only then: public repository, announcement, and ihasmail accepting the
   fork.

## 8. Open decisions

- Product name: whether the shipped product is called inbuxa-server or
  something else inside the INBUXA brand.
- The namespace for the fork's own JMAP capabilities.
- Whether the recovery CLI lives in the server binary or in the installer.
- Whether the installer stays its own repository or joins the fork's.
- Governance: solo, or set up for outside contributors from the start
  (contributing guide, sign-off on contributions).
- Whether the fork follows upstream's version numbers or has its own.
