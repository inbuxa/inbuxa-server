# Changelog

All notable changes to inbuxa-server's 2026 series, the dated releases
(`2026.11.10`) kept on this branch. It gets security and data-loss fixes until
the 27.1 series ships; `main` carries 27.1 and its changelog lists both.

Each release's page has its container image and binaries:
https://git.coffeylabs.org/inbuxa/inbuxa-server/releases. Security advisories:
https://github.com/inbuxa/inbuxa-server/security/advisories.

Every version PR adds that version's entry here. CI refuses a version this
file has no entry for (`tools/release/changelog-check.py`).

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

## [2026.11.9] - 2026-11-09

8 security fixes from our own review of the server (6 medium, 2 low), and 4
bugs that could lose or damage data. All versions up to and including
2026.10.29.1, and 27.1-rc.1 to 27.1-rc.15, are affected. The same fixes are in
27.1-rc.16 for the 27.1 series.

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
