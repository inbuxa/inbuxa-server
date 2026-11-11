# Changelog

All notable changes to inbuxa-server.

Versions follow the inbuxa suite: a series (`27.1`), its patches (`27.1.3`),
and release candidates before a series ships (`27.1-rc.1`). The tag is the
version with a `v`. Releases before 27.1 are dated (`2026.11.10`). The 2026
series is kept on the `release/2026` branch and gets security and data-loss
fixes until 27.1 ships. Its releases are listed here too, by date.

Each release's page has its container image and binaries:
https://git.coffeylabs.org/inbuxa/inbuxa-server/releases. Security advisories:
https://github.com/inbuxa/inbuxa-server/security/advisories.

Every version PR adds that version's entry here. CI refuses a version this
file has no entry for (`tools/release/version.py --changelog`).

## [27.1-rc.21] - 2026-11-11

DMARC and TLS reports reach the server on every domain without a postmaster
account for each, and the sign-in page can match the app that opens it.

### Security
One advisory (GHSA-c3c4-2c6m-ffrc), overall severity High: records under an
active legal hold could be destroyed on schedule (spoliation). 27.1-rc.1 to
27.1-rc.20 are affected.
- Legal hold: an account deleted while undelete still retained it now has its
  archived mail frozen by a covering hold, instead of being purged on
  schedule. (#377)
- Legal hold: the audit and journal records of such a deleted-but-held account
  are kept under the hold, instead of being purged once past their retention
  floor. (#381)

### Added
- The sign-in page takes `theme=light` or `theme=dark` from the app that opens
  it, so it matches the console or webmail instead of following the device.
  Without the parameter it follows the device as before. (#375, #376)

### Changed
- With no default folders configured, a new account also gets an Archive
  folder. A folder list an admin set is left as it is, and existing accounts
  aren't changed. (#378, fixes #374)
- Mail to a report address (`postmaster@*` by default) on one of the server's
  domains is taken even when no account has that address, as long as the
  sender hasn't signed in. A DMARC, TLS or feedback report in it is read as
  usual; anything else is refused at DATA with the same "Mailbox does not
  exist" as before. Extra domains no longer need a postmaster account for
  their reports. (#379, fixes #373)

## [27.1-rc.20] - 2026-11-11

The audit log, the journal, legal holds and undelete's notes move to tables
of their own.

### Changed
- Store layout version 3. The audit log, the journal, legal holds and
  undelete's notes move out of the settings table into tables of their own
  (column families on RocksDB): `ib_audit`, `ib_journal`, `ib_holds` and
  `ib_undelete`. The first node to start copies them, checks the copy row
  for row against the original, and only then removes the originals. A run
  that's cut short picks up where it stopped. See
  https://docs.inbuxa.org/install/updating/#store-layout (#368)
- Exports and backups have a `compliance` family for the same data, on by
  default. Before this release it travelled with `registry`, so
  `EXPORT_TYPES=registry` now copies the settings without it. See
  https://docs.inbuxa.org/run/backup/ (#368)
- Relayed inbound mail follows the settings in force now. A relay link judged
  its messages with the settings it had when it connected, so a change to a
  domain's directory, the RCPT and DATA rules, the spam filter or sender
  authentication didn't reach mail arriving through a relay until the link
  reconnected. (#366, #367)
- A recipient refused because a domain's LDAP or SQL directory had no answer
  for it is logged at info level, as `smtp.directory-no-answer`, with the
  reason and the filter or query that ran. (#364, #365)

### Before you upgrade
- This upgrade can't roll. Stop every node, start one on 27.1-rc.20 and wait
  for "Upgraded the store layout to version 3" in its log, then start the
  others. Mail is down for those few minutes.
- Back up the data store first. An older release refuses the store
  afterwards (on RocksDB it can't open it at all), so going back means
  restoring that backup.
- Run this with inbuxa-admin 27.1-rc.13 and inbuxa-webmail 27.1-rc.3.

## [27.1-rc.19] - 2026-11-10

Once a blob store change is settled, the server can clean up the old store.

### Added
- Clean up the old store after a blob store change. Once a change is copied,
  the old store still holds a copy of every blob it had. A cleanup deletes
  them from it, each one only after reading back its copy in the new store
  and checking it: message content against its id, anything else byte for
  byte against the old copy. A blob that doesn't check out stays where it is
  and is listed. A preview (`dryRun`) counts and deletes nothing. The cleanup
  needs `confirm` set to the change's id, because backups of the data store
  taken before the change read their blobs from the old store and won't
  restore in full afterwards. It's refused while a node still has its blob
  store in the old place, when the two stores overlap, and while a copy runs.
  Over the API it's `"action": "cleanUp"` on `inbuxa:BlobStoreChange`; in
  inbuxa Admin 27.1-rc.12 it's **Clean up the old store**, and in inbuxa-cli
  27.1-rc.2 it's `store clean-up`. (#342, #357, #358, #359)

### Before you upgrade
- Changes settled from this release on keep the old store's settings so it
  can be cleaned up. Changes settled before it can't be cleaned up from the
  server; remove their old store by hand, as before.
- No change to the store's layout; it stays at version 2. Upgrading from
  27.1-rc.16 or older still runs the upgrade in 27.1-rc.17, so read its notes
  first.
- Run with inbuxa-admin 27.1-rc.12 and inbuxa-webmail 27.1-rc.3.

## [27.1-rc.18] - 2026-11-10

A blob store change can be planned ahead and copied before the setting
moves, and snapshots stay listed while a change isn't settled.

### Added
- Plan a blob store change ahead. Give the new store's settings, and the
  server checks it can write there, then copies everything into it while the
  current store stays the blob store. Mail keeps going to the current store
  meanwhile, and a blob deleted there is deleted from the new store too. Once
  that copy ends, "apply" writes the planned settings to the blob store
  setting, credentials included. After the nodes restart on it, the last copy
  transfers only what arrived in between. One change can be planned at a
  time, and none while another isn't settled. Over the API it's
  `inbuxa:BlobStoreChange` with `target` on create and `"action": "apply"`;
  in inbuxa Admin 27.1-rc.11 it's **Plan a change**. (#341, #354, #355)
- Settings › Storage links to inbuxa Admin's pages for the store check,
  snapshots and blob store changes. (#350)

### Fixed
- While a blob store change wasn't settled, the snapshots already on disk
  went missing from the server's view: none were listed, deleting one
  answered `notFound`, and start-up didn't clean up a partial one. They're
  listed and can be deleted again; only a new snapshot is refused. (#351)

### Before you upgrade
- No change to the store's layout; it stays at version 2. Upgrading from
  27.1-rc.16 or older still runs the upgrade in 27.1-rc.17, so read its notes
  first.
- Run with inbuxa-admin 27.1-rc.11 and inbuxa-webmail 27.1-rc.3.

## [2026.11.10] - 2026-11-10

A bug fix for the 2026 series. No security fixes beyond 2026.11.9.

### Fixed
- Store snapshots: while a blob store change wasn't settled, the snapshots
  already on disk went missing from the server's view.
  `inbuxa:StoreSnapshot/get` listed none, deleting one answered `notFound`,
  and partial snapshots weren't cleaned up at start-up. A new snapshot is
  still refused until the change is settled, but the existing ones are listed,
  can be deleted, and are cleaned up. Nothing on disk was lost. (#352)

### Upgrading
- Nothing to do. Rolling back to 2026.11.9.2 is safe.

## [2026.11.9.2] - 2026-11-09

A bug fix for the 2026 series. No security fixes beyond 2026.11.9.

### Fixed
- CalDAV/CardDAV: copying or moving a whole calendar or address book into
  another account skipped every entry whose collection id in the old account
  matched the destination collection's id in the new one. A copy came out
  empty, and a move deleted the source while those entries stayed behind,
  listed nowhere. A copy onto a calendar or address book of the same name in
  another account was also refused with 502. (#347)

### Upgrading
- Nothing to do. Rolling back to 2026.11.9.1 is safe.

## [27.1-rc.17] - 2026-11-09

The first change to the store's layout, a fix for calendars and address
books that lost entries when copied between accounts, and the bundled
inbuxa-migrate 27.1-rc.12.

**This release upgrades the store when it first starts, and that can't be
undone.** Once it has run, 27.1-rc.16 and older refuse to start on the store.
The only way back is a backup taken right before the upgrade.

### Added
- Store layout upgrades. A release can now change how the store is laid out,
  in steps, at startup. The log says when a step starts and ends and what it
  changed, and warns before it starts that it can't be rolled back without a
  backup. Every start logs the store's layout version. In a cluster, one node
  runs the step and the others wait for it. A running node that finds the
  store upgraded by a newer release stops, so it can't keep writing the old
  layout. (#345)
- Layout version 2. On PostgreSQL, MySQL and SQLite, a rate-limit counter
  keeps its expiry in its own row instead of a second row beside it, so a
  counted request writes one row, not two, and expired counters are cleared
  with one statement. The counter table gets a new column at startup and the
  upgrade moves existing counters over. On RocksDB and FoundationDB only the
  version changes. (#345)

### Changed
- The container image bundles inbuxa-migrate 27.1-rc.12. (#339)

### Fixed
- CalDAV/CardDAV: copying or moving a whole calendar or address book into
  another account lost entries, as described under 2026.11.9.2. (#346)
- Rate-limit counters write their expiry marker once per time bucket, not on
  every request, on every backend. (#344)

### Before you upgrade
- Take a backup right before you start this release. A nightly backup isn't
  enough: restoring it loses the mail that arrived since. For PostgreSQL or
  MySQL, dump the database. For RocksDB or SQLite, copy the data directory
  with the server stopped. `inbuxa upgrade` archives a store on the host for
  you.
- The upgrade to layout version 2 is rolling-safe. In a cluster, upgrade the
  nodes one at a time; nodes still on 27.1-rc.16 keep working meanwhile.
- Run with inbuxa-admin 27.1-rc.10 and inbuxa-webmail 27.1-rc.3.

## [2026.11.9.1] - 2026-11-09

Three store tools from 27.1 for the 2026 series, the same as in 27.1-rc.16.
No security fixes beyond 2026.11.9.

### Added
- Store check (`inbuxa:StoreCheck`). Checks that every blob the server's data
  holds is in the blob store; a full check also reads each one back and
  checks its hash. Missing and damaged blobs are reported with the account,
  the object and the blob id. It runs inside the server, throttled, while
  mail flows.
- Store snapshot (`inbuxa:StoreSnapshot`). Takes a consistent RocksDB
  checkpoint, plus a filesystem blob store's files if you use one, into
  `snapshots/` in the store's directory, without stopping the server. The
  latest two are kept for a backup tool to pick up.
- Blob store changes (`inbuxa:BlobStoreChange`). Changing `x:BlobStore` used
  to strand every blob written under the old setting. Now the server notices
  the change when it starts and logs a warning naming both stores. A blob it
  can't find in the new store is read from the old one and kept in the new
  one, and an administrator can copy the rest over, checked by hash. Going
  back to an earlier store marks the change reverted. Nothing is deleted from
  the old store.

All three are JMAP objects under `urn:inbuxa:jmap`, for administrators only,
with the new permissions `sysStoreCheck`, `sysStoreSnapshot` and
`sysBlobStoreChange`. (#340)

### Upgrading
- Existing administrator roles are granted the three new permissions once, on
  the first start.
- A store snapshot is refused while a blob store change is unresolved,
  because it would miss blobs that are only in the old store.
- Rolling back to 2026.11.9 is safe: roles keep loading, without the new
  permissions.

## [27.1-rc.16] - 2026-11-09

27.1-rc.15 with 8 security fixes, 7 bug fixes and three new store tools.

### Security
The same 8 fixes as 2026.11.9, below, with the same behavior changes. All
versions up to 2026.10.29.1, and 27.1-rc.1 to 27.1-rc.15, are affected.

### Added
- Store check: `inbuxa:StoreCheck`, permission `sysStoreCheck`. A quick check
  confirms that every blob the data links to is in the blob store; a full
  check also reads each one back and compares its hash. Mail is checked from
  the message side too, so a message whose blob nothing links to any more is
  reported. It changes nothing, runs in the background, throttled, and keeps
  the first 1,000 problems. (#322, #324)
- Store snapshot: `inbuxa:StoreSnapshot`, permission `sysStoreSnapshot`. With
  a RocksDB data store, a consistent snapshot of the store while mail keeps
  flowing, so a backup tool can copy it instead of stopping the server. A
  filesystem blob store is copied with it. Snapshots go under `snapshots/` in
  the RocksDB directory, and the latest two are kept. Other stores are
  refused, with the reason. (#323, #328)
- Changing the blob store: `inbuxa:BlobStoreChange`, permission
  `sysBlobStoreChange`, event `store.blob-read-through`. A node that starts
  with `x:BlobStore` pointing somewhere new records the change and keeps the
  old store's settings. Until it's resolved, a blob the new store doesn't
  have is read from the old one and kept in the new one. An administrator
  has one node copy the rest, checked by hash, and what couldn't be copied is
  reported. Store snapshots are refused while a change is open. (#333, #335)

The new permissions are in the superuser and admin grants; tenant
administrators are refused.

### Fixed
- The four data-loss and DNS fixes of 2026.11.9 (Email/copy, file replace,
  automatic DNS, BDAT). Automatic DNS here also leaves MX records it didn't
  create alone.
- Deleted accounts: a kept user that never had a password can be restored;
  the new password becomes its password. (#326, #330)
- Domains: deleting a domain removes its queued DKIM, DNS and certificate
  tasks, and turning one of those to manual removes its task. Turning DKIM
  back to automatic no longer leaves two tasks. Stale tasks from before end
  quietly on their next run instead of as Failed. (#327, #332)
- Settings: lists stored by a newer release, such as a role with permissions
  this release doesn't know, load without those values instead of failing.
  (#329)

### Before you upgrade
- Read the behavior changes under 2026.11.9.
- Run with inbuxa-admin 27.1-rc.10 and inbuxa-webmail 27.1-rc.3.

## [2026.11.9] - 2026-11-09

8 security fixes from our own review of the server (6 medium, 2 low), and 4
bugs that could lose or damage data. All versions up to and including
2026.10.29.1, and 27.1-rc.1 to 27.1-rc.15, are affected. The same fixes are in
27.1-rc.16.

### Security
Medium
- IMAP: a mailbox name could inject responses into other users' IMAP sessions
  (GHSA-8fvp-37f9-h56q)
- Live delivery test: the target address could inject SMTP commands
  (GHSA-489p-848x-h3c9)
- JMAP: keyword rights on one mailbox changed messages held in others
  (GHSA-99x7-xgg9-p2w3)
- JMAP: a query with limit 0 returned the whole result set
  (GHSA-3qw8-p6hx-p3wj)
- OAuth: token introspection named the wrong owner and called other tokens
  active (GHSA-8wvx-v756-mv4h)
- CalDAV: sharees saw the details of private events and hidden attendees
  (GHSA-p9mf-rphv-j27j)

Low
- WebDAV: with directory queries on, a user could read another tenant's
  principals (GHSA-84jh-xghf-4m97)
- Queue: only the first recipient-domain quota was enforced
  (GHSA-52gf-846h-j5ch)

### Fixed
- JMAP: Email/copy with "destroy original" no longer destroys an original
  whose copy failed.
- Files: replacing an existing file replaces it only once the new write is
  accepted; a refused write used to destroy it.
- DNS: if the DNS provider can't list the records at a name, automatic DNS
  leaves that name alone instead of overwriting the TXT and CAA records it
  didn't create. Network errors, timeouts, 5xx answers and rate limits are
  retried instead of failing the task for good.
- SMTP: when a BDAT chunk is refused as too big, the rest of that transaction
  is refused too, instead of queuing a truncated message.
- Roles saved by a newer release, with permissions this release doesn't know,
  load without those permissions instead of failing, so administrators' roles
  keep working after a rollback from 27.1. (#331)

### Changed
- The store carries inbuxa's own store version. A store marked by a newer
  release is refused before anything writes to it, with a message pointing at
  that release or the pre-upgrade backup. (#247)

### Behavior changes
Mail
- Mailbox names can't contain control characters (tab included) over JMAP,
  IMAP CREATE/RENAME or Sieve `fileinto :create`. Existing names are left as
  they are; one with a line break is sent to IMAP clients as a literal.
- JMAP: on a shared account, changing a message's keywords needs the right to
  modify messages on every mailbox the message is in, and `$deleted` also
  needs the right to remove them. IMAP's `\Deleted` needs only the remove
  right, as before.
- JMAP: `limit: 0` on a query returns no ids, only the total when
  `calculateTotal` is set.

Calendars
- CalDAV shows people a calendar is shared with what JMAP shows them: only
  the time of private and confidential events, and among the attendees of
  events that hide them only the owners and themselves, unless they may
  change the event.
- People a calendar is shared with can't copy or move a private or
  confidential event, or a calendar holding one, into another account over
  CalDAV.
- People with write access to a shared calendar can no longer save changes
  over CalDAV to the owner's private or confidential events (403), since they
  only see the time of those events.

Administration
- The live delivery test accepts only a valid email address or domain name as
  its target; anything else gets 400. A bare domain needs a known public
  suffix, or a reserved one such as `.test`.
- OAuth introspection names the token's owner, and only access tokens are
  reported active.
- WebDAV: with directory queries on, a principal in another tenant answers
  403.

## [27.1-rc.15] - 2026-11-08

27.1-rc.14 with one relay addition.

### Added
- A relay can use one of the server's certificates. `certificateId` on
  `inbuxa:Relay` can point at one of the server's own certificates, a
  wildcard say. The server refuses one that doesn't name the relay, copies it
  and its key to the relay, and orders nothing for that relay. A renewal is
  stored as a new certificate, so the relay follows the newest one for the
  same names. If none will do, the relay keeps its last copy and
  `certificateError` says why. Setting `certificateId` back to null goes back
  to ordering. (#316, #318)

### Before you upgrade
- Nothing to do. Run with inbuxa-admin 27.1-rc.10, which has the picker for
  it, and inbuxa-webmail 27.1-rc.3.

## [27.1-rc.14] - 2026-11-08

27.1-rc.13 with two fixes for deleting domains and accounts.

### Fixed
- A domain with automatic DKIM can be deleted. If the DKIM keys it generated
  are the only things still referring to it, they're deleted with it. If
  anything else still uses it, such as an account, the delete is refused as
  before and nothing is removed. (#313, #314)
- An `objectIsLinked` error has a description, such as "It's still used by 1
  x:Account", for clients that show only the description. (#314)
- Cancelling a deleted account's destroy task no longer says account
  recovery isn't supported. With account retention set, a kept account is
  restored, or destroyed early, with `inbuxa:DeletedAccount/set`, and the
  message says so. (#313, #314)

### Changed
- Management › Directory links to the new Deleted Accounts page in
  inbuxa-admin 27.1-rc.9. (#315)

## [27.1-rc.13] - 2026-11-07

27.1-rc.12 with one fix.

### Fixed
- DNS-01 follows the challenge CNAME. If `_acme-challenge.<name>` is a
  CNAME, the server follows it (up to eight hops) and writes the TXT record
  where the chain ends, in that name's own zone. This lets you delegate
  challenges to a separate zone that is the only one taking dynamic updates.
  (#310, #311)
- A certificate name outside the domain's zone no longer crashes the renewal
  task. A domain's Origin is used only for names inside it, and other names
  go to their own registered domain. A record that still can't be placed in
  its zone fails the order with a reason. (#310, #311)
- A task that crashes counts as a failed attempt: it waits the usual retry
  delay and its error shows on the task. Before, it ran again straight away,
  which for a certificate renewal meant a new ACME order about once a second.
  (#311)

### Before you upgrade
- Nothing to do. If you set a domain's certificates to manual because of the
  crash, you can switch them back to automatic.

## [27.1-rc.12] - 2026-11-07

27.1-rc.11 with one fix.

### Fixed
- A renewal created through the API replaces the queued one. Creating a
  certificate renewal task with `x:Task/set`, or a DNS task that renews the
  certificate afterwards, clears the domain's queued renewals first, as
  saving the domain already did. A second renewal for the same domain in one
  request is refused. (#308)

## [27.1-rc.11] - 2026-11-06

27.1-rc.10 with two fixes.

### Fixed
- Calendars: a recurring event that starts in UTC keeps its zone. A series
  whose start is in UTC (a JMAP `timeZone` of `Etc/UTC`) came back in the
  zone of whoever asked, at a shifted time. Series stored before this are
  read correctly too, with no reindex. (#303, #305)
- Automatic DNS can publish nothing. A domain that only needs its DNS host to
  answer DNS-01 challenges can leave every record type off, and saving it no
  longer queues a DNS task that can only fail. (#304, #306)

### Before you upgrade
- Nothing to do. If you used the workaround for DNS-01 without records (only
  TLS-RPT ticked, no report address), you can untick it.

## [27.1-rc.10] - 2026-11-06

27.1-rc.9 with clearer wording for two settings. The server's behavior
doesn't change.

### Changed
- Additional Hostnames is now Certificate Hostnames, and its description
  says a list replaces the default names instead of adding to them, what an
  empty list gets, and how a name without a dot is read. The property and
  saved configs are unchanged. (#291, #299)
- Allow Directory Queries' description says it also decides who a regular
  user can look up and share with. (#301)
- SECURITY.md: vulnerabilities can also be reported privately through the
  GitHub copy's Security tab. (#300)

## [27.1-rc.9] - 2026-11-06

27.1-rc.8 with certificate and DNS fixes, paging fixes for two query
methods, and fuller milter traces.

### Changed
- CAA records are off by default. A domain with automatic certificates and
  automatic DNS used to publish a CAA record at its apex, tied to this
  server's ACME account, which made another ACME client under the domain
  fail at its next renewal. New domains leave CAA off. DNS-PERSIST-01
  providers publish their `_validation-persist` record whether or not CAA is
  on. (#294)
- Changing a domain's names orders a certificate right away. Editing
  Certificate Hostnames, the ACME provider or the domain name on a domain
  already on ACME used to wait for the next renewal. A domain keeps a single
  queued renewal. (#295)

### Fixed
- `x:MaskedEmail/query` and `x:ArchivedItem/query` honor `position`, `anchor`
  and `limit`; a `position` past the first page returned the first page
  again. Thanks to Stefan for the masked email fix and its test. (#296, #297)
- Milter replies show in delivery traces: when a milter rejects with its own
  reply, the trace records the SMTP code and text the client was sent. Thanks
  to Stefan. (#293)

### Before you upgrade
- Existing domains keep the records they publish today, CAA included. If
  another ACME client issues certificates for names under a domain that
  inbuxa publishes CAA for, untick CAA in that domain's DNS settings, then
  delete the record at your DNS provider: unticking it doesn't remove a
  published record.

## [27.1-rc.8] - 2026-11-04

27.1-rc.6 with one security fix and a new journal report format. 27.1-rc.7
was tagged with the security fix, but its build failed and it was never
published.

### Security
- Allow Directory Queries now does what it says. With the setting off, the
  default, regular users could still list and look up the other accounts on
  their server. Listing and searching are now refused over JMAP and WebDAV.
  A regular user can only look up the accounts they already have a
  connection to: their own, their groups, people who shared with them, and
  people on their own shares. Sharing follows the same rule on JMAP, WebDAV
  and IMAP. (#282, #283)

### Changed
- Journal reports follow a public specification, the journal report format
  (https://coffeylabs.org/specs/journal-report/): a `multipart/report` with a
  summary for people, an envelope part for programs with one line per
  recipient, and the message byte for byte. Reports already stored keep the
  layout they were written in.

### Before you upgrade
- On the default, regular users lose directory suggestions in compose,
  picking anyone they have no connection to in the share dialog, free/busy
  for people who haven't shared with them, and starting a share with someone
  new. People already on a share keep it. To keep all of that, turn on
  Settings › Sharing › Allow Directory Queries. An IMAP connection picks up a
  change to the setting when it reconnects.
- Journal report scripts should read the new envelope part, not the summary,
  whose wording isn't fixed. The `Bcc` line is now `Not in To or Cc`, and
  `addressed=not-in-headers` in the envelope part. Reports to an archive
  declare `BODY=8BITMIME` or `BODY=BINARYMIME`; a server that can't take the
  message unchanged doesn't get the report, which stays in the built-in
  journal and shows as an archive failure.
- Run with inbuxa-webmail 27.1-rc.3.

## [27.1-rc.7] - 2026-11-02

Tagged with the directory security fix that is in 27.1-rc.8, but its build
failed and nothing was published. Use 27.1-rc.8.

## [27.1-rc.6] - 2026-10-31

27.1-rc.5 with one fix.

### Fixed
- A new server where a role was made in recovery mode before its first
  normal start never got the built-in roles, the default Authentication
  settings or the new-install privacy defaults, so every account was refused
  with 403. The first normal start now seeds them when there are no roles, or
  when recovery mode left a note that it ran. A server that has started
  normally before is unchanged. (#265)

## [27.1-rc.5] - 2026-10-31

inbuxa Relay, and moving a domain in from inbuxa Admin. No security fixes.

### Added
- inbuxa Relay: a small relay for a public machine that takes mail in on
  port 25 for your server and can send its mail on, so the server itself
  never opens a mail port to the internet. The server dials out to it and
  manages it under Settings › Mail flow › Sending › Relays.
  - While the link is up, the server decides on each message during the
    sender's session: its spam filter, directory and rules answer at the
    door.
  - While the link is down, the relay holds mail for your addresses,
    encrypted to the server's key, and passes it on once the link is back.
  - Outgoing mail goes through it with DKIM signed by the server, DANE and
    MTA-STS, REQUIRETLS, and TLS-RPT reports from the relay's TLS results.
  - The server publishes the relays in its domains' MX and SPF records where
    it manages DNS, and orders each relay's certificate by DNS-01.
  - Signed upgrades from inbuxa Admin; a list of who may dial the link; a new
    link CA without a new join; relay keys wrapped under a key file
    (`INBUXA_RELAY_KEY_FILE`).
  - It ships from each server tag as
    `registry.coffeylabs.org/inbuxa/inbuxa-relay` (linux/amd64, linux/arm64)
    and as static musl binaries, each with a `.sig` by the inbuxa release
    key. Run it with the server release of the same version.
  (#242 to #245, #249, #253 to #274)
- Migrations: an administrator can move a domain in from another server, from
  IMAP, JMAP, Microsoft 365 or Google Workspace, under Management › Directory
  › Migrations in inbuxa Admin: preview, move, final pass, and the new
  accounts' passwords once. The server runs the bundled inbuxa-migrate. It
  needs the new Run migrations permission, which only the Administrator role
  has. (#275, #276, #278)

### Changed
- The store carries inbuxa's own store version. A store marked by a newer
  release is refused before anything writes to it, with a message pointing at
  that release or the pre-upgrade backup. (#246)
- A store brought over from Stalwart 0.16 has its old web interface switched
  off the first time inbuxa opens it, so it is no longer served at `/admin`.
  The log says how to switch it back on. (#251)

## [27.1-rc.4] - 2026-10-29

Fixes for Sieve filters, IMAP pipelining and file deletion. No security
fixes.

### Fixed
- Sieve: an out-of-office reply (vacation) and `notify` answered mail sent by
  programs: mail with an `Auto-Submitted` header other than `no`, other
  autoresponders included (RFC 3834). They now stay silent for it. (#235)
- Sieve: `string` depended on the order of its keys; a test is now true when
  any key matches. (#236)
- Sieve: `date :regex` and `currentdate :regex` compared the date as a
  wildcard pattern, so a regular expression never matched. (#236)
- IMAP: a `SELECT` pipelined with the `FETCH` or `STORE` after it got `BAD No
  mailbox is selected` for those commands. Each command is now checked when
  it runs. A `FETCH` pipelined after `UNSELECT`, `CLOSE` or `UNAUTHENTICATE`
  is refused with BAD; before, it closed the connection. (#237)
- Files: the task that keeps a deleted file for undelete could wait up to
  five minutes on a quiet server. Deleting a file now starts it at once.
  (#234)

## [2026.10.29.1] - 2026-10-29

7 security fixes from our own review of the server, all medium. All versions
up to and including 2026.10.29, and 27.1-rc.1 to 27.1-rc.2, are affected. The
same fixes are in 27.1-rc.3.

### Security
- OpenID Connect directories: tokens issued to other applications could sign
  in (GHSA-v3gv-4j87-3mg2)
- OpenID Connect directories: opaque tokens from any application could sign
  in (GHSA-2p7h-9hv3-4292)
- Calendars: one calendar object could cost tens of seconds of CPU to expand
  (GHSA-pw47-x75c-v45r)
- IMAP: one session could start an unbounded number of operations at once
  (GHSA-6x5j-v349-9v79)
- Sieve: a script's CPU limit did not count the message it scanned
  (GHSA-whf3-4g3x-w7r6)
- Sign-in: bearer tokens were offered and accepted on unencrypted connections
  (GHSA-5phc-xg42-vp24)
- OpenID Connect directories: provider responses were read without a size
  limit (GHSA-6hcw-cw8m-jcx7)

### Behavior changes
Sign-in and tokens
- OAuth bearer sign-in (OAUTHBEARER, XOAUTH2) always needs TLS in IMAP, POP3,
  ManageSieve and SMTP submission, even with plain-text sign-in allowed. A
  proxy that terminates TLS has to report it through the proxy protocol.
  Password sign-in is unchanged.
- New OpenID Connect directories must set a required audience (the client ID
  registered for this server). Existing directories without one keep
  working, log a warning each time they load, and appear on the Security
  to-do list; a later release will require it. An audience, once set, can't
  be removed.
- OpenID Connect directories have an opaque-token setting: reject, check by
  token introspection (RFC 7662, with a client ID and secret), or accept on
  the user info endpoint's word. New directories reject opaque tokens unless
  an introspection endpoint is set. Existing directories keep accepting them
  through user info; set the policy to close the hole.
- Responses from an OpenID Connect provider larger than 1 MiB are refused. A
  token without a key ID is checked against freshly fetched provider keys
  when the cached ones don't verify it.

Mail and calendars
- IMAP: a session runs at most four read operations at once, and commands
  that change mail or the session run one at a time in the order sent. A
  NOOP or LOGOUT sent during a long FETCH answers after it.
- Sieve: the CPU limit (`max_cpu_cycles`) also counts the message bytes that
  tests scan: every 64 KiB compared, times the number of keys, costs one
  instruction, so a script can scan about 300 MiB per message by default. A
  script that goes over stops with the usual CPU-limit error and the message
  is kept.
- Calendars: recurrence expansion has one work limit per calendar object
  (about 50 ms). Objects whose rules use it up are stored with the instances
  found so far, and the server logs a calendar rule expansion error.

## [27.1-rc.3] - 2026-10-29

### Security
The same 7 fixes as 2026.10.29.1, above, with the same behavior changes.

### Added
- `/.well-known/source`, as https://coffeylabs.org/specs/well-known-source/
  defines: the server's name, version and license, its public repository, and
  the commit the build was made from. A build without a full commit id
  answers 404. (#227)

## [27.1-rc.2] - 2026-10-29

### Security
The same 34 fixes as 2026.10.29, below, with the same behavior changes.

### Changed
- Spam filter: the rules stay on v3.0.2 and are maintained in this
  repository from now on, versioned `3.0.2-inbuxa.N`. Later upstream rule
  releases rename tags and settings this server doesn't use, and would score
  the AI classifier's verdicts at 0 on new installs. The first change adds
  scores for the DKIM2 result tags the server already emits. (#225)

## [2026.10.29] - 2026-10-29

34 security fixes from our own review of the server: 2 high, 31 medium and 1
low. All versions up to and including 2026.10.28, and 27.1-rc.1, are
affected. The same fixes are in 27.1-rc.2.

### Security
High
- SMTP: BDAT reserved the declared chunk size before any data arrived
  (GHSA-v35h-m53h-jxgx)
- IMAP and ManageSieve: unauthenticated clients could make the server hold
  about 100 MB per connection (GHSA-fvgm-5jfp-rpmm)

Medium
- OpenID Connect directory: an ID token from another application could sign
  in as its user (GHSA-mfq6-g7cj-pxp7)
- OAuth: a refresh token could be redeemed without its client's secret
  (GHSA-fw6c-mjh4-5mf5)
- JMAP: a property listed many times in /get or Email/parse was rendered once
  per mention (GHSA-rj6m-4hv5-r34v)
- Calendar: a deeply nested iCalendar component could crash the server
  (GHSA-w697-j727-2ffc)
- Sieve: regex tests could cost seconds of CPU per delivery and 10 MiB each
  (GHSA-7m5r-6wf6-c55c)
- Sign-in: password hash checks could stall every protocol
  (GHSA-h6mp-735j-h3c7)
- SMTP: TLS reports and MTA-STS policy fetches could be aimed at the server's
  own network (GHSA-pf39-vc2q-8r54)
- JMAP: an open WebSocket ignored token expiry, account locks, password
  changes and removed shares (GHSA-wf4x-2gmj-c46w)
- WebDAV: one lock token let a request through every other lock it touched
  (GHSA-65q8-w3r7-3v6q)
- WebDAV: file COPY and MOVE skipped the add and delete rights
  (GHSA-qpp4-998x-cg8w)
- WebDAV: a copied folder kept its own sharing inside someone else's folder
  (GHSA-6593-48rg-fhgq)
- POP3: OAuth bearer tokens were accepted over clear text with plain-text
  sign-in turned off (GHSA-vh5g-wvxj-x8gf)
- Sign-in: an address whose ban had ended was never banned again
  (GHSA-9pmc-86q4-q82f)
- Spam filter: one message could make the server issue hundreds of URL
  lookups (GHSA-j825-8cpr-r2w3)
- SMTP: a From header naming two domains skipped DMARC (GHSA-f5r6-c8px-rwmm)
- Mail: many messages with one subject made every later delivery slower
  (GHSA-v2cm-f2pc-x8rv)
- JMAP: web push could be aimed at the server's own network
  (GHSA-w27c-h3jv-85c9)
- HTTP: bearer tokens kept working after they expired (GHSA-hhcw-frq4-p343)
- SMTP: an on-path attacker could switch off MTA-STS for a domain
  (GHSA-w5xh-2264-rh54)
- Calendar: iTIP REFRESH and REPLY were accepted from people who weren't
  attendees (GHSA-wjcq-c7g4-q568)
- IMAP: a JMAP keyword could inject responses into other users' IMAP sessions
  (GHSA-xprp-24v8-28c8)
- IMAP: a user with flag rights on a shared mailbox could set `\Deleted`
  (GHSA-2qxg-g2qm-983v)
- WebDAV: dead properties and lock owners could inject XML into other users'
  responses (GHSA-rfcv-29qm-49qj)
- IMAP: a revoked mailbox share stayed readable for as long as the connection
  stayed open (GHSA-qq56-9g55-5gh2)
- Calendar: a local user could send iMIP invitations and replies in another
  person's name (GHSA-9m6q-mwc8-34c4)
- Sharing: sharing a calendar or address book exposed an unrelated event or
  contact (GHSA-8fv8-q3vx-c544)
- JMAP calendars: sharees saw the details of private and confidential events,
  and hidden attendees (GHSA-vw7g-hjcp-wcch)
- Calendar: invitations to an event that hides its attendees listed every
  attendee (GHSA-cr6x-q56w-r597)
- WebDAV: sync-collection showed a sharee what was deleted from the owner's
  other collections (GHSA-xjqh-p8qf-m4ff)
- WebDAV: nresults 0 lifted the cap on query results (GHSA-hgf7-8wq9-hff3)
- Quota: calendar, contact and file writes could go past the disk quota
  (GHSA-vmw3-q5hr-6p5f)

Low
- JMAP: a message with two Bcc headers, or a very long one, sent the Bcc
  addresses to every recipient (GHSA-gh3w-qwv3-57cj)

### Behavior changes
Sign-in and tokens
- External OpenID Connect directories: a JWT the provider marks as an ID,
  refresh, offline or logout token (Keycloak `typ`, Amazon Cognito
  `token_use`) is refused as a bearer token. Clients that were sending ID
  tokens instead of access tokens stop signing in.
- OAuth refresh tokens can be redeemed only by the client they were issued
  to, and a confidential client has to authenticate to do so. A request
  naming another client gets `invalid_grant`. Refresh tokens issued before
  tokens named their client go to the first client that authenticates with
  them.
- Bearer tokens over HTTP stop working when they expire. Before, a token
  could keep working for up to the access-token lifetime after its first use.
- A JMAP WebSocket is closed with an `unauthorized` error when its token
  expires, the account is locked or deleted, the password changes, or the app
  password or API key it used is removed. Requests on a WebSocket count
  toward the per-account request limits.
- POP3 with plain-text sign-in off: OAUTHBEARER and XOAUTH2 are refused on
  clear-text connections, and CAPA lists no SASL mechanism there.
- IMAP and ManageSieve accept at most 64 KiB per request before sign-in.
- Slow password hashes (bcrypt, crypt family, Argon2, PBKDF2, scrypt) are
  checked at most one per CPU at a time; under a sign-in flood the rest wait
  their turn.
- An address that fails sign-in again after its ban ended is banned again.

Mail
- DMARC: a From header with addresses in several domains is checked for each
  domain, and the strictest result applies. Some mail that was accepted
  before will now be rejected or quarantined.
- MTA-STS: a cached policy stays in force until it expires when a new one
  can't be fetched. A domain whose `mta-sts.` host resolves only to private
  addresses fails its policy fetch; in the default optional mode mail still
  goes out, but with MTA-STS set to "require" that domain is deferred.
- TLS reports over https connect only to public addresses and follow no
  redirects. A report address that is a local IP literal is skipped.
- Spam filter: at most ten URL-redirector lookups per message, over https
  with the certificate checked.
- Threading compares a new message with the newest 512 messages that share
  its subject. A reply whose thread has no message among those starts a new
  thread.
- iMIP: a scheduling message from a signed-in sender is credited to its
  envelope sender, not its From header. From counts only when it passed
  DMARC.
- JMAP: keywords must be valid names (1-255 printable ASCII characters, none
  of `( ) { ] % * " \`). Email/set and Email/copy refuse others with
  `invalidProperties`, and Email/import refuses the whole message. IMAP
  leaves stored keywords that aren't atoms out of FLAGS.
- IMAP: on a shared mailbox, setting or clearing `\Deleted` needs the remove
  right ("t"), and other flags the modify right ("w"), on every mailbox the
  message is in. Flags the user can't change are left alone.
- IMAP: once a share is removed, commands on that still-selected mailbox get
  `NO [NOPERM]`. CLOSE and UNSELECT still work.

Calendars, contacts and files
- JMAP calendar privacy applies to everyone but the calendar's owner:
  private, confidential and secret events show sharees only their time, and
  events that hide attendees list only their owners and the reader.
- Invitations, updates and cancellations for an event that hides its
  attendees go out as one message per recipient.
- iTIP REFRESH is answered only for attendees of the event. A REPLY for an
  instance the organizer didn't change is stored only from an attendee of the
  series and only for a date of the series.
- Components nested more than 32 levels deep are dropped when an event is
  converted for JMAP.
- Quotas: calendar events, contacts and files count against the quota of the
  account they are written into, not the writer's, and files written through
  JMAP now count. Accounts near their quota may start getting `overQuota`.
- WebDAV file COPY, and MOVE from another account, takes the destination
  folder's sharing, as an upload does (RFC 3744). COPY or MOVE into a folder
  needs the right to add to it; overwriting needs the right to delete every
  node replaced.
- WebDAV writes need a lock token for every locked resource they touch.
  Holders of a shared lock still need only their own token.
- WebDAV sync-collection reports only deletions inside the synced
  collection.
- WebDAV `<nresults>0</nresults>` is treated as 1.

Sieve and push
- A Sieve `:regex` pattern that compiles to more than 1 MiB is refused
  ("Invalid regular expression"). With Unicode `\w`, `\w{50}` is too large
  and `\w{20}` fits. Stored scripts with such a pattern stop matching that
  test.
- Web push goes only to public addresses and never through a configured
  proxy. Push to a host name on your LAN (a self-hosted ntfy or UnifiedPush
  server, say) no longer works.

## [27.1-rc.1] - 2026-10-28

The first release candidate of the 27.1 series: 2026.10.28 under the new
version scheme.

### Changed
- One version for the whole workspace, in Cargo.toml, shown as tags name it:
  `27.1`, `27.1.3`, `27.1-rc.1`. Release candidates are images `:27.1-rc.N`
  and `:27.1-rc`, never `:latest`, which stays on the 2026 series until 27.1
  ships. (#223, #224)

## [2026.10.28] - 2026-10-28

A security release: 21 fixes, among them several that let a sharee or a
limited administrator reach data or accounts they shouldn't, and several ways
one request or one inbound message could tie up or crash the server. (#222)

### Changed
- An unknown JMAP capability is answered as `unknownCapability`, not
  `notRequest` (RFC 8620 §3.6.1). (#210)
- IMAP: OBJECTID+ follows draft rev 08. LIST takes the OBJECTID return
  option, and SELECT/EXAMINE by identifier never matches a mailbox the user
  may not read; it falls back to the name instead. (#219)
- Sieve scripts that require the extension names from before the rename
  (`vnd.stalwart.expressions`, `vnd.stalwart.while`) can be saved again after
  an edit. Only the inbuxa names are advertised. (#212)

### Before you upgrade
- Behind a proxy? `X-Forwarded-For` and `Forwarded` are read only from
  trusted proxies: loopback and private addresses by default. If your proxy
  connects from a public address, list it in `INBUXA_HTTP_TRUSTED_PROXIES`.
- PKCE is S256 only (since 2026.10.19). The console signs in with S256 over
  HTTPS or on localhost; on plain `http://` from another machine the browser
  has no Web Crypto and sign-in fails, so serve the console over HTTPS.
- Device sign-ins (OAuth device grant) in progress during the upgrade have to
  start again.

## [2026.10.19] - 2026-10-19

### Security
- OAuth: only S256 PKCE challenges are accepted. The authorization endpoint
  took the plain method, and assumed it when a challenge came without one,
  though the metadata listed only S256. Codes issued with plain before the
  upgrade still verify. (#205)
- A registry write that sent back a stored secret as read (`****`) stored
  `****` as the secret: a webhook's password or signing key, a store's or
  directory's password, a DNS provider's key, an OAuth client's secret.
  Written straight at a secret it now keeps the stored one; anywhere else the
  write is refused with `invalidProperties`. (#206)

### Fixed
The last upstream import, 0.16.27 (#204):
- IMAP: `APPEND` and `COPY`/`MOVE` into another account's mailbox did not
  change the JMAP `EmailDelivery` state.
- IMAP: `SEARCH RETURN` with `MIN` or `MAX` alongside `ALL` returns only the
  minimum and maximum in `ALL`, and `SAVE` combined with `MIN` or `MAX` and
  `ALL` or `COUNT` saves only the minimum and maximum.
- iTIP: merging a received update didn't copy the `VTIMEZONE` definitions it
  carried, so an occurrence moved by an external organizer could reference a
  `TZID` the stored event no longer defined.
- OAuth: loopback redirect URIs without a path (`http://127.0.0.1:45678`)
  weren't matched against registered loopback URIs on any port, and were
  rejected by dynamic client registration.
- WebDAV: `PROPFIND` `allprop` returns `DAV:current-user-principal`, so
  Windows Explorer shows every file and folder under the account name.

## Earlier releases

The dated releases from 2026.9.20 to 2026.10.16 list their changes on their
release pages. Until 2026.10.19 this file carried the changelog of the
codebase inbuxa was forked from, up to 0.16.27, the last release imported.
It is in the history: `git show v2026.10.19:CHANGELOG.md`.
