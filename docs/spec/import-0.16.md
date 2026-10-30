# Importing a Stalwart 0.16.27 store

Status: decided 2026-10-29 (John); checked against 27.1-rc.4 the same day.

From 27.1 the store's layout is inbuxa's own, marked with its own store
version (`INBUXA_STORE_VERSION`, beside the 0.16 schema version). Stalwart is
a migration source like any other server. What inbuxa keeps is the ability to
read one Stalwart format, frozen at **0.16.27**, the last release it imported.
That format is defined here and checked on every release candidate. Stalwart
1.0 changed its own layout and isn't read by this route. It needs a converter
of its own (inbuxa-migrate, planned).

This replaces "the store format is upstream's and unchanged" in `SPEC.md` §1
and `migration.md`. inbuxa still opens a 0.16.27 store in place today,
because store version 1 is the 0.16 layout plus inbuxa's own subspace. That
holds until the first layout change bumps the version. The supported route
is the one below: export, then import into a new store.

## The route

1. Stop Stalwart 0.16.27 and export its store with its own binary:
   `stalwart --config <its config> --export <dir>`.
2. Import into an empty inbuxa store: `inbuxa --config <config> --import <dir>`.
   The export holds the data, registry, blob, changelog, queue, report and
   task subspaces. The full-text index isn't in it, so the import queues a
   reindex.
3. Start inbuxa. The source isn't touched, so rolling back means starting
   Stalwart again.

An export goes from any backend to any other. A RocksDB 0.16 store can become
a PostgreSQL inbuxa one, or the other way round.

## What carries over unchanged

Checked by `tools/import-check` against the fixture in
`tests/resources/import-0.16.27/`:

- accounts with their passwords, descriptions, aliases, quotas, group
  membership and roles, including custom roles that inherit built-in ones;
- groups and their shared mailboxes;
- tenants, their domains and their accounts;
- domains and their DKIM keys (Ed25519 and RSA);
- every built-in role's permissions;
- mailboxes and their tree, mail with its keywords, threads, attachments,
  sizes and received dates;
- mailbox sharing between accounts;
- calendars and events, with recurrence and time zones;
- address books and cards;
- Sieve scripts (active and inactive) and the vacation response.

## What changes when inbuxa first starts

Each of these is done in place on first start, and each is listed in
`tests/resources/import-0.16.27/known-differences.txt` or tested on its own:

- **Store version:** written as 1 (`crates/migration`).
- **Roles:** inbuxa adds its Compliance Officer role. The built-in System
  Administrator and Tenant Administrator roles gain inbuxa's own permissions
  (account locks, audit, legal holds, journaling, DLP, mail rules,
  deliverability, scheduled reports, security acceptance, AI explanations).
  Nothing is taken away.
- **Spam filter blobs** move from their pre-rename keys (`crates/migration`,
  `rename_spam_blobs`).
- **The web interface's OAuth client** `stalwart-webui` is retired, and an
  application naming it moves to `inbuxa-webui` (`first_party.rs`, test
  `renamed_identifiers`).
- **Sieve:** scripts that `require "vnd.stalwart.expressions"` or
  `"vnd.stalwart.while"` keep running and can be edited and saved again. The
  old names are aliases (#212).
- **Search:** the index is rebuilt. Each account's reindex is spread over the
  first five minutes after start, so imported mail can be missing from
  search results until then. New mail is indexed as it arrives.

## What the operator has to change

- **Clients signing in to JMAP with a password.** inbuxa takes tokens on JMAP
  and the management API, never passwords (contract C-23). IMAP, POP3,
  SMTP, CalDAV and CardDAV keep passwords. `INBUXA_HTTP_BASIC_AUTH=all`
  restores passwords on JMAP for an operator who needs it while clients move
  to OAuth.
- **The 0.16 web interface.** Its application record carries over and points
  at upstream's `webui` release on GitHub. inbuxa keeps an imported
  application and fetches it (SPEC.md §5.3), so it serves that interface at
  `/admin` unless the operator removes it. Open: whether an import should
  disable it (see below).

## Not covered

- **Enterprise data.** The fixture is a Community store, and a Community
  server has no Enterprise objects to carry. inbuxa's own cutover from an
  Enterprise store is recorded in `compat-tests.md`.
- **Stalwart releases other than 0.16.27.** An older 0.16 upgrades to 0.16.27
  with Stalwart first (stalwart-migrator does this). 1.0 and later aren't
  read by this route.

## The check

`tools/import-check/check.sh <image>` runs on every release candidate. It
needs docker and about seven minutes, most of it waiting for the reindex.
It fails on any difference that isn't in `known-differences.txt`, and on
any of the after-import checks: delivery through the imported Sieve filter,
search over imported mail, and re-saving a pre-rename filter. A known
difference that stops happening is reported as `GONE`, so the list can't go
stale without anyone noticing.

The CI workflows compile the test suites but don't run them (by design), and
they don't run this check either.

`tools/import-check/make-fixture.sh` rebuilds the fixture from the official
0.16.27 image, pinned by digest. Run it only when the fixture needs more in
it. The server it builds has no internet access, so upstream's web
interface bundle and the data files it downloads at first start never reach
the fixture. The fixture holds only what `populate.py` creates, plus what
0.16.27 creates at setup.

## Open

- Whether importing a 0.16 store should disable the leftover web interface
  application (keeping the record, so the operator can switch it back on),
  rather than serving upstream's interface at `/admin`.
