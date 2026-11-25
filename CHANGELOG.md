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

## [27.1-rc.48] - 2026-11-25

27.1-rc.47 with filters for shared mailboxes, two fixes, and dependency
updates.

### Added
- Shared mailboxes: a shared mailbox's Full members can manage its filters
  (SieveScript/get, query, set and validate on the shared mailbox), sorting
  only. Forwarding and automatic replies (redirect, vacation, notify,
  reject) are added, changed and turned on by an administrator; a member
  may keep or remove them. Every change to a shared mailbox's filters is in
  the audit log, and the session offers filters only on accounts where they
  can be managed. Before this, a shared mailbox had no filters of its own.
  (#643, #646)

### Fixed
- Email/get: `header:List-Id:asText` (and asText on any header parsed as
  something other than text) answered null even when the message had the
  header. It now returns the header's text. (#642, #644)
- Recovery mode: a server imported from Stalwart served its old web
  interface in recovery mode. Recovery mode now switches that interface
  off. A server that already went through recovery mode kept serving it
  afterwards too; it is switched off on the first start of this release,
  with nothing to redo. Thanks to Moritz. (#638, #639)

### Changed
- Dependencies: url 2.5.9, libz-sys 1.1.33 and zstd 0.13.5, for dependency
  advisories. (#641)
- Images: the server and relay images carry OCI labels (title,
  description, license, source, version, revision). (#637)

## [27.1-rc.47] - 2026-11-25

27.1-rc.46 with security fixes (two high, four medium, two low, and two
smaller hardening fixes). 27.1-rc.1 to 27.1-rc.46 are affected, and so is
2026.x up to and including 2026.11.24.2. The same fixes are in 2026.11.25.

### Added
- Recovery mode: optional `INBUXA_RECOVERY_MODE_URL` (scheme, host and
  port) makes the URLs recovery and bootstrap mode hand out absolute:
  OAuth/OpenID metadata, token issuer, device verification_uri and JMAP
  session. Unset, they stay relative as before. (#560, #629)

### Security
High
- OAuth: a tenant administrator could register a client and use the real
  sign-in page to get full-access tokens for accounts in other tenants or
  for the server administrator. A client a tenant owns now signs in,
  approves devices for and refreshes tokens for that tenant's accounts
  only, and the server's own client ids can't be taken by a tenant.
  (GHSA-3xqc-x8f6-2242, #631)
- OAuth: an app password or API key could sign in on the OAuth and device
  pages without the second factor and get a token for the whole account.
  Those pages now take only the account's password or a passkey.
  (GHSA-v596-p29h-9jfq, #631)

Medium
- Multi-tenancy: a tenant administrator could see every recipient of a
  queued message with one recipient on its domains, Bcc included, and
  download, cancel or delete it. A tenant now has the whole message only
  when its own person sent it or every recipient is its own; otherwise it
  sees and manages its own recipients only. (GHSA-v6rf-rr22-4mfr, #631)
- Multi-tenancy: a tenant's domain could name the server's host or another
  tenant's domain in its certificate. A tenant domain's certificate names
  must now be the domain or names under the tenant's proven domains.
  (GHSA-5wcm-3mfx-xpfx, #631)
- IMAP and ManageSieve: a request of many tiny tokens held up to 34 times
  the request size limit in memory. Every token now counts its memory.
  (GHSA-9rvj-p5hr-wxh4, #631)
- Settings: config.json, which holds the data store password, was written
  readable by everyone on most installs. It is now written 0600 and
  replaced in one step. (GHSA-g9xf-p2pw-hpvp, #631)

Low
- Roles: removing a permission from a default role didn't reach signed-in
  accounts until their session cache expired. It now does at once, on
  every node. (GHSA-m3qr-2hvr-5v7m, #631)
- Milter: a header that wasn't valid UTF-8 reached the milter empty. It is
  now sent as the bytes it arrived as. (GHSA-r8wh-mrj5-rjch, #631)
- IMAP: CREATE and RENAME now refuse a mailbox name over the maximum
  length even when it has no "/". JMAP now accepts a name of exactly the
  maximum length. (#631)
- Accounts: destroying an account now also removes its spam training
  samples and the message bodies they held. (#631)

### Upgrading
- Tenant domains: certificate names must be the domain or names under a
  domain or alias the tenant has proven. A new tenant domain gets its
  certificate once it is verified: save its certificate settings again
  after verifying. A tenant domain already saved with another name in its
  certificate list must have that name removed before any other change to
  it saves.
- OAuth: if a tenant registered a client under one of the server's own
  client ids, the server leaves it alone and logs an error at start-up,
  and that front end stays unregistered until you delete the tenant's
  client.
- OAuth sign-in with an app password now fails like a wrong password; the
  reason is in the server log.
- Queue: a tenant that didn't send a message, and doesn't hold every
  recipient, can no longer change its priority or envelope id, and sees
  0.0.0.0 as the address it came from.
- Cluster: upgrade every node together. During a rolling upgrade an older
  node drops the new cache message, and signed-in accounts on it can keep
  a removed default-role permission until their session cache expires.

## [27.1-rc.46] - 2026-11-24

27.1-rc.45 with a build fix and a settings fix. 27.1-rc.45's binaries and
images could not be built, so 27.1-rc.46 is the first release that carries
its security fixes (see 27.1-rc.45 below).

### Fixed
- Build: the EventSource session check made the stream's body lose `Sync`
  with the SQL and Redis store backends, so the release build failed. The
  check now runs as its own task, and CI builds those backends. (#623)
- Settings: set fields (email, domain and trimmed lists) now validate each
  value added; values already stored are kept on edit. ACME providers
  store contacts as plain addresses, and ones saved as `mailto:` are
  rewritten at start. (#608, #621)

## [27.1-rc.45] - 2026-11-24

27.1-rc.44 with security fixes from security reviews (one high,
eleven medium, two low). 27.1-rc.1 to 27.1-rc.44 are affected, and so is 2026.x
up to and including 2026.11.24. The same fixes are in 2026.11.24.1.

### Security
High
- Mail protocols: a client that sent commands and then stopped reading
  kept its SMTP, IMAP, POP3 or ManageSieve session, and its place under the
  connection limit, open forever. A session whose answer makes no progress
  for the session's timeout is now closed. (GHSA-w5xx-gxq9-2vpv, #617)

Medium
- HTTP: any web page could get its visitors' addresses banned from every
  service with images whose URLs are too long to parse. Requests refused
  as too large (414, 431) no longer count toward the scan ban.
  (GHSA-5xw5-x276-jfqr, #617)
- HTTP: any web page could post wrong passwords to the sign-in API from
  its visitors' browsers and get them banned. `/api/auth` and
  `/api/passkey/register` now accept only `application/json` and answer
  anything else with 415. (GHSA-j4p4-p27c-rxqq, #617)
- JMAP: a signed-in user could make the server read far past its request
  limit. Request bodies stop at the request size limit, also for accounts
  with unlimited uploads; a WebSocket message over it is closed with code
  1009; only the first KiB of a push error body is read.
  (GHSA-4552-7cpj-q8xw, #617)
- Security: an IPv6 client could change address within its /64 to walk
  past bans and rate limits. IPv6 clients are now counted and banned by
  their /64, and a network ban added at runtime works at once.
  (GHSA-6wwx-hx9h-h77q, #617)
- Sign-in: failures on a login whose bytes spell an IP address counted
  toward that address, so anyone could make its owner's next typo ban
  them. Login and recipient counts now have keys of their own.
  (GHSA-7pg4-qvq9-wh3m, #617)
- IMAP: one command could keep a core busy for minutes, or one FETCH hold
  hundreds of copies of a message. Extreme FETCH, SEARCH, flag and
  sequence-set requests are refused with BAD, and a FETCH answer over four
  times the message size stops with NO [LIMIT]. (GHSA-95gr-gfhg-8vrx, #617)
- Sign-in: very long passwords could keep the CPU busy against SHA-crypt
  and MD5-crypt hashes. A password over 1,024 bytes fails before any hash
  runs, and can't be set. (GHSA-8hjh-58j2-27q6, #617)
- Sessions: open IMAP, POP3, ManageSieve, SMTP submission, EventSource and
  WebSocket sessions kept working after a password change, token
  revocation, lock or loss of access. They now end at the next command,
  and streams end at once on a password change. (GHSA-r7c2-rhj2-h98x, #617)
- Sieve: `reject` sent its notice to the return path, which anyone can
  forge. A notice now goes only to a verified sender (signed in, SPF pass,
  or mail this server generated); other rejected mail is discarded and
  the discard is logged. (GHSA-pr42-7c58-rf2c, #617)
- Calendar: one scheduling message could keep the server busy and grow
  stored events. An object holds at most 32 time zone definitions, time
  zones are merged in one pass, and at most four iMIP parts of a message
  are processed. (GHSA-rc52-h8j5-h3v4, #617)
- JMAP: any signed-in user could store uploads under another account and
  use up its upload limits. `/jmap/upload/{accountId}` now answers 403
  unless the user owns, belongs to or may impersonate that account.
  (GHSA-p623-3g53-v7mc, #617)

Low
- Logs: the log viewer read every file in the Log tracer's directory. It
  now reads only the tracer's own files. (GHSA-qqh8-qvfv-rxp9, #617)
- Sieve: `+` built strings past the maximum variable size, and `enclose`
  dropped Received headers, so enclose-and-redirect loops skipped the hop
  limit. Both fixed. (GHSA-6mcv-hhxv-jq24, #617)

### Changed
- SMTP: at most five different EHLO domains per session; the sixth gets
  421. (#617)
- SMTP: an unparseable line gets exactly one reply; the rest of the line
  is never run as a command. (#617)
- SMTP: mailing-list expansion is linear in the list size, and a repeated
  RCPT TO for a list already expanded isn't expanded again. (#617)
- Audit: OAuth and directory-token sign-ins are logged as auth.success.
  (#617)
- Accounts: destroying an account removes all of its search index
  entries. (#617)
- Recovery mode: the new `INBUXA_RECOVERY_MODE_BIND` sets the address
  recovery and bootstrap mode listen on. The default is still `[::]`.
  (#617)

### Upgrading
- IPv6 bans now cover the whole /64, and lifting one lifts the /64.
  Allowed IPs still win.
- Sieve `reject` on mail from a sender that isn't verified discards it
  without a notice. On listeners where SPF is off, such as LMTP, every
  reject becomes a silent discard.
- Scripts that post to `/api/auth` must send
  `Content-Type: application/json`.
- Passwords longer than 1,024 bytes can no longer be used or set.
- Per-login and per-recipient failure counts start over once.

## [27.1-rc.44] - 2026-11-24

27.1-rc.43 with 52 bug fixes from the 27.1 bug sweep (#572): mail
delivery, IMAP, JMAP, Sieve, the spam filter, calendars and contacts, and
the cluster. There are no new features and no store layout change.

### Fixed
Mail delivery:
- SMTP: mail to a mailing list with no members is refused at RCPT TO with
  the same 550 5.1.2 an unknown address gets, instead of failing at DATA.
  (#529, #587)
- SPF: records with an unknown modifier containing "/" (for example
  `foo=bar/baz`) no longer fail as permerror; the modifier is ignored.
  (#533, #587)
- DKIM: automatic key rotation keeps the replaced key's settings (signed
  headers, canonicalization, AUID, expiry, reporting, third-party signing,
  DKIM2 flags) instead of resetting them to defaults. (#534, #587)
- Delivery Test: no longer reports a STARTTLS error for hosts secured with
  DANE; it checks certificates the way delivery does. (#530, #599)
- SMTP: `RCPT TO:<>` is refused for every sender, including signed-in
  users. (#532, #599)
- SMTP: a bare `RCPT TO:<postmaster>` (any case) is accepted and delivered
  to postmaster at the default domain. (#531, #599)
- Mail delivery: mail a signed-in user sends (587/465 or JMAP) to a local
  mailbox is stored with a Return-Path, like mail received on port 25.
  (#537, #599)

IMAP:
- IMAP: clients get EXISTS for new messages in the reply to FETCH, STORE,
  SEARCH, THREAD and UIDBATCHES, and IDLE reports changes that were
  waiting when it started. (#538, #588)
- IMAP: when SELECT or EXAMINE fails, no mailbox is left selected, so a
  following CLOSE or EXPUNGE can no longer remove messages from the
  mailbox that was open before. (#540, #588)
- IMAP: a command the account isn't allowed to use now gets a tagged NO
  [NOPERM] and the session continues; before, the connection was dropped
  without a reply. (#590, #596)
- IMAP: SELECT or EXAMINE with QRESYNC, sent before ENABLE QRESYNC, now
  gets BAD instead of NO. (#591, #596)
- IMAP: saving drafts or sent copies, copying or moving messages, and
  appends by migration tools no longer trigger "new mail" pushes; mail
  that arrives by SMTP or LMTP still does. (#548, #596)
- IMAP: clients that enable CONDSTORE get HIGHESTMODSEQ in the STATUS sent
  during IDLE. (#539, #610)
- IMAP: SELECT or EXAMINE with CONDSTORE turns CONDSTORE on for the whole
  session (RFC 7162). (#605, #610)
- IMAP: with CONDSTORE on, flag changes sent during IDLE and NOOP include
  MODSEQ. (#607, #610)
- Mail: creating or renaming a folder to the same name from two clients at
  once no longer leaves two folders with that name. (#541, #610)

JMAP:
- JMAP: saving a draft, importing a message or copying one between
  accounts no longer sends a "new mail" push; only mail that actually
  arrives does. (#547, #592)
- JMAP: EmailSubmission sends to recipients on any well-formed domain
  (internal names, new gTLDs), and a To/Cc/Bcc address that isn't valid is
  reported as `invalidRecipients` instead of being silently dropped.
  (#549, #592)
- JMAP: destroying the active Sieve script is refused with sieveIsActive
  (RFC 9661) instead of scriptIsActive. (#553, #601)
- JMAP: changing the active Sieve script reports both scripts' isActive
  and moves the SieveScript state. (#554, #601)
- JMAP: activating a script that the same SieveScript/set call destroys is
  ignored, and the current script stays active. (#555, #601)
- JMAP: WebSocket RequestError frames carry the request's requestId.
  (#552, #602)
- JMAP push: a push subscription whose endpoint answers 410 Gone is
  removed; other failures are still retried. (#559, #602)
- JMAP: Sieve scripts that fail to compile are reported as invalidSieve
  (RFC 9661) instead of invalidScript. (#600, #602)
- JMAP: a request body that isn't JSON gets notJSON instead of notRequest.
  (#557, #602)
- JMAP: an empty createdIds in a request is echoed in the response, and
  WebSocket responses name it createdIds. (#558, #602)
- JMAP: Identity/set and EmailSubmission/set check ifInState
  (stateMismatch) and always return oldState and newState. (#556, #602)
- JMAP: one Mailbox/set request can no longer create or rename two
  mailboxes to the same name, or give two mailboxes the same role. (#606,
  #610)

Sieve:
- Sieve: a redirect to a local account keeps the message's spam verdict,
  so spam lands in the target's Junk. (#542, #593)
- Sieve: no vacation reply is sent to mail the spam filter puts in Junk.
  (#543, #593)
- Sieve: a script sends at most one vacation reply per message. (#546,
  #601)
- Sieve: notify mailto links can no longer set Auto-Submitted, Received,
  Date, Message-ID or From on the notification. (#581, #601)

Spam filter:
- Spam filter: uploading messages over IMAP (for example a mailbox
  migration) no longer trains the classifier unless they're flagged $Junk
  or $NotJunk or uploaded into Junk. (#544, #593)
- Spam filter: every cluster node starts scoring with a newly trained
  model, not only the node that trained it. (#545, #593)
- Spam filter: moving a message from another account (such as a shared
  mailbox) into your Junk folder, or out of Junk into another account,
  trains the classifier again. (#589, #597)
- Spam filter: creating messages in the Inbox with JMAP Email/set no
  longer trains the classifier as ham. (#594, #610)
- Spam filter: resetting the classifier stops every node scoring with the
  deleted model right away. (#595, #610)

Calendar and contacts:
- Contacts: ContactCard/parse returns every contact in a .vcf file, as an
  array per blob, not just the first one. (#550, #584)
- Contacts: contacts created over JMAP without a uid now get one
  (urn:uuid:…), returned in the response and written as the vCard UID.
  (#551, #584)
- Contacts: a contact's online service with only a user name is now kept,
  and CardDAV clients see it as a text SOCIALPROFILE. (#568, #584)
- CalDAV: clients see the same default calendar as the webmail. (#565,
  #585)
- Calendar: unknown time zone names are refused instead of being stored as
  floating time. (#563, #585)
- Calendar: ending a series early, or moving an event into the past, now
  updates the attendees. (#561, #585)
- Calendar: RSVP=FALSE attendees (rooms, people invited for information)
  now get invitations, updates and cancellations. To leave an attendee
  out, use SCHEDULE-AGENT=CLIENT or NONE. (#567, #585)
- Calendar: attendees who accepted a series are told when one occurrence
  is moved or edited. (#566, #585)
- Calendar: destroying an account removes its queued event alarms. (#562,
  #604)
- Calendar: invitation and alarm emails keep the line breaks in the event
  description. (#564, #604)
- Calendar: an attendee's delegation now reaches a delegate who already
  has the event; only the delegation itself is applied to the delegate's
  copy. (#586, #604)

Search, cluster and recovery:
- Search: when Elasticsearch rejects some documents in a bulk request, the
  server logs an error with the count and first reason and retries them,
  instead of treating them as indexed. (#536, #592)
- Undelete: a restore whose account has since been deleted ends at once
  instead of retrying until it fails. (#569, #609)
- Cluster: after a coordinator outage, a node reloads lookup lists and web
  apps along with its settings. (#570, #609)
- Recovery mode: an invalid INBUXA_RECOVERY_MODE_PORT stops the start
  instead of silently using 8080. (#571, #609)

### Upgrading
- JMAP clients see a few error and response changes: `sieveIsActive` and
  `invalidSieve` (RFC 9661) replace `scriptIsActive` and `invalidScript`,
  a body that isn't JSON gets `notJSON`, and ContactCard/parse returns
  every card in a file as an array per blob. The old Sieve error names are
  still accepted when reading.
- Calendar: attendees marked RSVP=FALSE (rooms, people invited for
  information) now get invitations, updates and cancellations. Use
  SCHEDULE-AGENT=CLIENT or NONE to leave one out. Unknown time zone names
  are refused instead of stored as floating time.
- SMTP: `RCPT TO:<>` is refused for signed-in users too, and mail to a
  mailing list with no members is refused at RCPT TO.
- Spam filter: messages uploaded over IMAP APPEND or created with JMAP
  Email/set train the classifier only when flagged $Junk or $NotJunk or
  put in Junk.
- Recovery and bootstrap mode refuse to start on an invalid
  INBUXA_RECOVERY_MODE_PORT instead of using 8080.
- 27.1-rc.43 to 27.1-rc.44 rolls like any update, with no store layout
  step.


## [27.1-rc.43] - 2026-11-23

27.1-rc.42 with security fixes from an internal security review (two high,
three medium). 27.1-rc.1 to 27.1-rc.42 are affected, and so is 2026.x up to
and including 2026.11.23. The same fixes are in 2026.11.23.1.

### Security
High
- DNS: a sender's SPF record could hide another domain's DMARC policy and
  DKIM keys. TXT lookups were cached by name only, so naming
  `_dmarc.<domain>` or a DKIM key name in an SPF `include:`, `redirect=` or
  `exp=` made that domain's policy or key look missing, and mail spoofing a
  `p=reject` domain was accepted. Failed lookups are no longer cached.
  (GHSA-2h94-5pr4-7q3w, #577)
- Roles: anyone allowed to create or change roles could make the
  administrator role a parent of a role they hold, and become an
  administrator. A role's parents now count toward the permissions needed
  to create or change it, and a parent from another tenant is refused.
  (GHSA-rv5j-gmx8-8mjx, #577)

Medium
- Sieve: an incoming Subject could add header lines to out-of-office
  replies, which the server signs and sends. Header values in vacation
  replies, notifications and enclosed messages no longer keep line breaks
  or control characters. (GHSA-9v39-p3px-g58p, #577)
- HTTP: any web page could get its visitors' addresses banned from every
  service by linking to a scan-ban path such as `/x.php`. Requests the
  browser marks as caused by another site no longer bring a ban.
  (GHSA-78p8-qv5v-wpjj, #577)
- Sign-in: anyone who knew a login name could make its owner's next typo
  ban the owner's address. When a login's failures go over the limit, only
  the address that took it over is banned, and only until the count starts
  over. (GHSA-vf25-5gq2-f3cp, #577)

### Changed
- OAuth: a self-registered client asking for a device code gets only the
  scopes it registered for, as with an authorization code. (#577)
- Sieve: a notify mailto link with an invalid header name or a line break
  in an address is refused. (#577)

### Upgrading
- A role manager can no longer change a role that inherits permissions
  they don't hold themselves.
- Sieve scripts with a literal notify mailto link that has an invalid
  header name no longer compile.

## [27.1-rc.42] - 2026-11-23

27.1-rc.41 with a security fix from a private security review (medium)
and two hardening changes. 27.1-rc.1 to 27.1-rc.41 are affected, and so is
2026.x up to and including 2026.11.20.2. The same fixes are in 2026.11.23.

### Security
Medium
- OAuth: the device grant didn't authenticate confidential clients. A
  device code could be requested and, once a user approved it, redeemed in
  a confidential client's name with its client id alone. Both device
  endpoints now ask for the client's secret, in the body or over HTTP
  Basic. (GHSA-fwvh-2466-qmjg, #573)

### Changed
- OAuth: an authorization code or device code sent several times at once
  grants tokens once. (#573)
- A tenant's OIDC directory checks the URLs the provider's discovery
  document names before it sends anything to them. (#573)

### Upgrading
- Device-flow clients registered with a secret must now send it to
  `/auth/device` and with the device-code token request.

## [27.1-rc.41] - 2026-11-22

27.1-rc.40 with one container change.

### Changed
- The container image also writes the log to standard output, at `info`,
  so `docker logs` and `kubectl logs` show it. Until now a new install in
  a container logged only to its log file and printed nothing. The image
  sets `INBUXA_LOG_STDOUT=info`; a console tracer in the settings takes
  its place. The log file is kept either way. Installs from the binaries
  or packages don't change. (#527)

### Before you upgrade
- 27.1-rc.40 to 27.1-rc.41 rolls like any update, with no store layout
  step.
- To keep only the log file in a container, set `INBUXA_LOG_STDOUT=off`.
- Docker's default `json-file` log driver doesn't rotate. If your host has
  no `max-size` for it, set one (for example `--log-opt max-size=50m`), or
  the container's log grows without limit.

## [27.1-rc.40] - 2026-11-22

27.1-rc.39 with one cluster change.

### Added
- In a cluster, the `taskScheduler` and `metricsCalculate` roles can be
  given to several nodes, and one node at a time does each role's work.
  Each role has a lease in the store. The node holding it renews it every
  minute, and if that node stops, another node with the role takes over
  within about 4 minutes. Until now each role had to be on exactly one
  node, and losing that node paused scheduled maintenance, alerts and
  their emails until it came back. A node taking over alerts carries on
  from the alerts already firing, so they aren't sent again. Taking and
  losing a lease log `cluster.singleton-lease-taken` and
  `cluster.singleton-lease-lost`. A server without a cluster coordinator
  works as before. (#437, #524)
- Gauge `cluster.singleton-metrics`: 1 on the node holding the
  `metricsCalculate` role, whose queue, account and domain gauges are the
  cluster's, and 0 elsewhere. (#525)

### Fixed
- In a cluster, `queue.count` on a node that doesn't calculate metrics
  went up with every report, DSN and autogenerated message it queued, and
  never came down. Only the node calculating metrics shows the queue
  gauges now; the others show 0. (#525)

### Upgrading
- 27.1-rc.39 to 27.1-rc.40 rolls like any update, with no store layout
  step. While the roll is under way, nodes still on rc.39 act on their
  roles as before.

## [27.1-rc.39] - 2026-11-21

27.1-rc.38 with one console addition.

### Added
- The console's Settings › Network › Web links to Front ends, inbuxa
  Admin's page for `inbuxa:FrontEnds`: where inbuxa Admin and the webmail
  are served, the webmail's client secret, and other origins allowed to
  call the server from a browser. Until now only `inbuxa join` or the
  server's environment could set these. The page needs inbuxa Admin
  27.1-rc.23; an older console hides the link. (#522)

### Upgrading
- 27.1-rc.38 to 27.1-rc.39 rolls like any update, with no store layout
  step.

## [27.1-rc.38] - 2026-11-20

27.1-rc.37 with one fix.

### Fixed
- Outbound DMARC and TLS reports wait up to 3 hours before their first
  delivery attempt, on purpose, so receivers don't get every report at
  the same moment. That wait was counted as delivery time, so the
  delivery-time graph and metrics showed hours for reports delivered on
  the first try. Delivery time now starts at the end of the planned
  wait. (#517)

### Upgrading
- Reports already in the queue when you update still count their wait
  until they go out, at most 3 hours.
- 27.1-rc.37 to 27.1-rc.38 rolls like any update, with no store layout
  step.

## [27.1-rc.37] - 2026-11-20

27.1-rc.36 with 2 security fixes from a private security review (1 high,
1 medium), two hardening changes and a fix for spam-training samples left
behind. 27.1-rc.1 to 27.1-rc.36 are affected, and so is 2026.x up to and
including 2026.11.20. The same security fixes are in 2026.11.20.1.

### Security
High
- WebDAV: an uploaded HTML or SVG file ran as a page of the server's
  origin when opened in a browser. Every WebDAV file answer now carries
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none';
  sandbox` and `nosniff`; only raster images, audio, video and plain text
  are shown inline, everything else downloads. (GHSA-v4c6-686h-h927, #511)

Medium
- Multi-tenancy: a tenant administrator could make the server send
  requests to internal addresses through an ACME or DNS provider. A
  tenant's providers now reach only public addresses (HTTPS for ACME and
  HTTP-based DNS providers), RFC 2136 servers must be public, and fields
  built into URLs must be plain names. ACME errors carry only the problem
  type and detail. (GHSA-qmc9-xcrm-w836, #511)

### Changed
- A tenant's OIDC directory reaches only public HTTPS addresses,
  discovered endpoints included. (#511)
- Passkeys: a sign-in challenge or registration ceremony sent several
  times at once is used once. (#511)

### Fixed
- Deleting a message whose spam-training sample was still held left the
  sample's record behind for good, also after the account was deleted.
  (#510)

### Upgrading
- WebDAV: HTML, SVG, XML, PDF and untyped files now download instead of
  opening in the browser.
- Tenant-owned ACME providers, DNS providers and OIDC directories at a
  private, loopback or plain-HTTP address stop working; move them to a
  public HTTPS address, or have a server administrator own them.
- 27.1-rc.36 to 27.1-rc.37 rolls like any update, with no store layout
  step.

## [27.1-rc.36] - 2026-11-20

A tenant's disk usage now matches what its accounts store: calendar,
contact and file writes are checked at the size they're charged, and
destroying an account no longer upsets any tenant's count.

### Fixed
- Destroying an account could reset the disk usage of an unrelated tenant
  that had the same number, so the tenant could store more than its
  quota until a recount. Destroying an account now takes its usage off its
  own tenant instead. (#507, fixes #499)
- Copying or moving a single event or contact into another account didn't
  check that account's quota or its tenant's. (#507, fixes #499)
- CalDAV, CardDAV and WebDAV writes were checked at the bare body length,
  not the size an item is charged, so each could go a few hundred bytes
  past a limit. Creating, updating, copying and moving items now check the
  charged size, and a refused file upload stores nothing. (#507, #508)
- When a sharee, a delegate or an administrator wrote into someone else's
  account, the change in usage could be counted against the writer's
  tenant instead of the account's. (#507)
- A tenant recount left out deleted members whose data is still kept.
  (#507)

### Upgrading
- Run a tenant quota recount after upgrading if tenants' accounts have been
  destroyed, to correct counters the old destroy reset.
- 27.1-rc.35 to 27.1-rc.36 rolls like any update, with no store layout
  step.

## [27.1-rc.35] - 2026-11-20

Tenant limits hold across many accounts and parallel writes, tenants
verify the domain names they add, and a read-only config.json is reported
clearly.

### Security
High
- Multi-tenancy: a tenant administrator could add any domain name, as a
  domain or as an alias, and the server then delivered mail that its other
  accounts sent to that name into the tenant. Names a tenant adds now have
  to be verified first, as described below. (GHSA-rvw7-gvh9-mx8g, #503)

### Changed
- Multi-tenancy: a domain name a tenant administrator adds, as a new
  domain, a rename or an alias, has to be verified before the server uses
  it. The tenant publishes a TXT record at `_inbuxa-verification.<name>`
  with `inbuxa-verification=<token>` (the domain's `verificationToken`),
  then takes the name off the domain's `unverifiedNames`. Until then the
  name takes no mail and gives no addresses to send as. Names a server
  administrator adds need no record. Every name, aliases included, counts
  toward the tenant's `maxDomains`. (#503)
- Items kept for undelete count toward their account's and tenant's disk
  usage until they're destroyed, expire or are restored; deleting still
  never fails. A held spam-training sample lets go of its message once the
  account's own copy is gone. (#502, fixes #500)

### Fixed
- The accounts in a tenant could together be given more disk quota than
  the tenant has; four 5 GB accounts fitted in a 5 GB tenant. The total is
  now checked (accounts with no quota of their own share what's left), on
  restores and on domain moves into a tenant too. Thanks to BulTester.
  (#497, inbuxa-admin#257)
- Parallel writes could each pass a tenant's count limits (accounts,
  domains and the rest) and together go over them. Count and disk limits
  are now checked under one lock per tenant. An object moved into a tenant
  by an update now counts against its limits, and DKIM keys a domain adds
  later count toward `maxDkimKeys`. (#501, fixes #498)
- Encrypted mail was checked against quota before encryption, invitations
  without the notification they store, and a bigger vacation reply not at
  all. (#502, fixes #500)
- Saving the data store settings when config.json is read-only (such as a
  Kubernetes mount) failed the whole request. That object is now refused
  with `forbidden`, saying the settings are managed outside the server and
  where. (#496)

### Upgrading
- Domain names saved before this version are kept as they are, verified.
  If tenant administrators can manage domains on your server, review the
  domains and aliases your tenants have added.
- Items deleted before this version aren't counted while they're kept;
  items deleted from now on are.
- In a cluster, have tenants leave their domains alone until every node
  runs 27.1-rc.35: a domain saved through an older node during the roll
  loses its pending verification.
- 27.1-rc.34 to 27.1-rc.35 rolls like any update, with no store layout
  step.

## [27.1-rc.34] - 2026-11-20

Tenants can no longer hand out more disk space than they have, listeners
that can't open are retried and reported, backups straight to S3, metrics
and alerts for Kubernetes, and signed images with SBOMs.

### Added
- Release images are signed with cosign, keyless, on the registry and on
  the GHCR copy, with an SPDX SBOM per architecture and build provenance
  attested on GitHub. The SBOMs list the Rust crates in the binaries, not
  only the image's system packages. (#492, #493)
- `--export s3://bucket/prefix` streams an export into S3 (or any
  S3-compatible store) without touching local disk, and
  `--import s3://bucket/prefix[/<name>]` restores one, the newest finished
  export when no name is given. The bucket and keys come from
  `INBUXA_EXPORT_S3_*` variables. `--store-check quick|full` runs a store
  check to its end and exits with its result. (#491)
- Metrics can be turned on from the environment: a password-protected
  `/metrics/prometheus` (`INBUXA_METRICS_PROMETHEUS_USERNAME` and
  `INBUXA_METRICS_PROMETHEUS_SECRET_FILE`), and OTLP from the standard
  `OTEL_` variables when the store sets none (`INBUXA_OTLP_HEADERS_FILE`
  reads the headers, such as a collector token, from a file). Three new
  gauges for alerts:
  `queue.oldest-message`, `cluster.lease-renewed` and
  `tls.earliest-expiry`. (#488)
- A listener whose port is in use is retried for 30 seconds. Until it
  opens, `/healthz/ready` answers 503 naming it, and the console's cluster
  view lists it. `INBUXA_LISTENER_FAILURE=exit` stops the server instead
  when a listener still can't open. (#487, fixes #485)

### Fixed
- A tenant administrator could give an account a bigger disk quota than
  the whole tenant has. The account's mail was refused as over quota while
  the webmail still showed most of its space free. Such a quota is now
  refused, whoever sets it, and JMAP and IMAP report the space the account
  can really use: its own quota or what's left in the tenant. Accounts
  already set too high keep their quota until it's edited. Thanks to
  BulTester. (#494, fixes inbuxa-admin#257)
- An import into a fresh store refused to run, from a directory too, since
  27.1-rc.16. (#491)
- An import put blobs into the data store even when the imported settings
  name S3, so the restored server couldn't find them. (#491)
- A live export could list blobs it didn't contain. (#491)
- An S3 export or import could hang for good on a machine or pod limited
  to one CPU. (#491)
- `/healthz/live` went through the anonymous request limit, so with the
  data store down the probe timed out and an orchestrator could restart
  every node at once. (#488)
- Metrics: counters still at zero were left out of the scrape, gauges
  could wrap below zero, and in a cluster `queue.count` could read low.
  (#488)

### Upgrading
- Nothing special: 27.1-rc.33 to 27.1-rc.34 rolls like any update, with no
  store layout step.

## [27.1-rc.33] - 2026-11-19

Passkeys that work on upgraded installs, a Passkeys link in the console's
own Account section, a data-layer check, and certificates read from
mounted directories.

### Added
- `inbuxa --config <path> --check` opens the data store the way a start
  does, writes, reads and deletes one small object in the blob store, and
  connects to the coordinator (NATS) once. It prints a line per part and
  exits, starting nothing. A part that can't be used is reported as
  `<part>: <case>: ...`, with the data-store exit codes from 27.1-rc.32.
  Before, a wrong S3 key or NATS password only showed after the start.
  (#473)
- `INBUXA_TLS_CERTIFICATE_DIRS` names directories that each hold `tls.crt`
  and `tls.key`, as a Kubernetes TLS Secret mounts them. Their certificates
  are used for the names in them and aren't stored. Every node checks those
  files, and the files of file-backed stored certificates, once a minute,
  and reloads its certificates when they change, so a renewal no longer
  waits for a restart. (#477)
- Console: the Account section gets a Passkeys link under Credentials, so
  people can manage their own passkeys without opening Directory ›
  Accounts. Needs a console that has the page; an older one hides the link.
  Thanks to Stefan. (#481)

### Fixed
- Passkeys: an install from before 27.1-rc.32 never got the passkey
  permissions added to its stored default roles, so nobody on it, not even
  the administrator, could list or add a passkey, and they couldn't be
  granted by hand either. Start-up now adds them once to the user, tenant
  administrator and administrator roles. A role that turns one off keeps it
  off. A test now fails if a later permission is missed the same way.
  Thanks to Faisal. (#483, fixes #478)
- Two nodes starting together on a fresh store could both add the
  defaults, and the second came up without its HTTP listener. Adding the
  defaults now takes a short store lease, one node at a time. (#482, fixes
  #436)

### Upgrading
- Nothing special: 27.1-rc.32 to 27.1-rc.33 rolls like any update, with no
  store layout step.
- Passkeys start working on an upgraded install at the first start of
  27.1-rc.33. Nothing needs changing by hand.

## [27.1-rc.32] - 2026-11-19

Passkey sign-in, a Logs page that can filter and follow, subjects in
delivery history, a dark-mode logo, QR-code links in the spam filter, and
the server-side pieces for running inbuxa on Kubernetes.

### Added
- Passkeys: accounts can sign in with a passkey on the server's sign-in
  page, by autofill or a "Sign in with a passkey" button, in both the
  authorization-code and device flows. A passkey is enough on its own, with
  no TOTP code after it. Passkeys are added on a new page the server hosts,
  `/passkey/register`, after the password (and TOTP code) or an existing
  passkey, and managed over JMAP as `inbuxa:Passkey`. Removing one signs the
  account out everywhere. Passkeys are allowed by default; `passkeysAllowed`
  turns them off for the server, a tenant or a domain, and the session tells
  clients whether this account may add one. Accounts on an external
  directory (LDAP, SQL, OIDC) can't use passkeys, and IMAP, SMTP and the
  other mail protocols still use passwords or app passwords. Spec:
  `docs/spec/features/passkeys.md`. Thanks to Stefan. (#466, #468, #469,
  #470, #471, #474, fixes #334)
- Delivery history: inbound and outbound lists show each message's subject.
  It comes from a debug-level event, `queue.message-subject`, capped at 255
  characters, so it stays out of info-level log files and OpenTelemetry
  exports. Only full administrators can read it, and it is kept as long as
  history is. History stored before this release has no subject. Thanks to
  Faisal. (#452, fixes #228)
- Logs: `x:Log/query` filters by level and above, component and time, and
  the Log tracer can write JSON lines (`format`: `text`, the default, or
  `json`). The Logs page reads text, JSON and a file holding both. Thanks to
  Stefan. (#455, #462, fixes #456)
- Branding: a separate logo for dark mode, `logoDark` on domains and
  tenants and `logoUrlDark` server-wide. `/logo?theme=dark` serves it, or
  the ordinary logo where none is set; the built-in sign-in and RSVP pages
  ask for it when they show dark. Emails keep the light logo. Thanks to
  Faisal. (#459, fixes #410)
- Spam filter: "Check links in QR codes" (`scanQrCodes`, off by default)
  reads QR codes in a message's images and sends the links through the same
  checks as its other links, adding the tag `QR_CODE_URL` (score 0.0 in the
  bundled rules, now 3.0.2-inbuxa.2). At most 4 images a message, 4 MB and
  16 megapixels each, and 1 s in all. Thanks to Stefan. (#463, fixes #401)
- OAuth token revocation (RFC 7009) at `POST /auth/revoke`, listed in both
  discovery documents. A revoked token is refused on every node until it
  would have expired. (#438)
- `inbuxa --upgrade-store` upgrades the store layout and exits, and
  `inbuxa --upgrade-plan` says, read only, what it would do and whether a
  step needs every other node stopped. Both are for orchestrators that
  upgrade the store as a job of its own. (#448, #457)
- `inbuxa --seed <PATH>` sets up a new store from a file of JMAP method
  calls, once, then exits. Spec: `docs/spec/features/store-seed.md`. (#451)
- Secrets from files: `INBUXA_RECOVERY_ADMIN_FILE`,
  `INBUXA_WEBMAIL_CLIENT_SECRET_FILE` and, for the relay,
  `INBUXA_RELAY_JOIN_TOKEN_FILE`. Setting both forms, or naming a file that
  is missing or empty, stops the start. (#461)
- `INBUXA_LISTENER_PORTS` moves or leaves out the default listeners a new
  store gets, for example `smtp=2525,submissions=4465,imaps=9993,pop3s=off,https=8443`.
  (#443)
- `INBUXA_HTTP_USE_FORWARDED=true|false` overrides "Use X-Forwarded-For"
  from the environment. (#467)

### Changed
- The container image runs with every capability dropped: the binary no
  longer carries `cap_net_bind_service` as a file capability. Docker is
  unaffected. Elsewhere, binding a port below 1024 needs
  `CAP_NET_BIND_SERVICE`, the `net.ipv4.ip_unprivileged_port_start` sysctl,
  or higher ports through `INBUXA_LISTENER_PORTS`, and a refused bind now
  says so. (#443)
- A start that can't open the data store exits with a code per case: 78
  bad configuration, 69 unreachable, 77 credentials refused, 76 TLS failed,
  1 anything else, with "data store: <case>" on its last line. Before, every
  case exited 1. (#472)

### Fixed
- TLS: with no default certificate set, a connection with no or an unknown
  name got whichever certificate came first, and every handshake logged a
  warning. The server now uses the certificate for its own hostname (or a
  wildcard on its domain), else the first by name, and logs the warning
  once per certificate load. Thanks to khashmeshab. (#450, fixes #418)
- Cluster: after a server was renamed, its old node stayed on the dashboard
  as "not responding" for a day. The old lease is now dropped once it has
  missed two renewals. (#460)

### Upgrading
- Nothing special: 27.1-rc.31 to 27.1-rc.32 rolls like any update, with no
  store layout step.
- Rolling back: an older server can't read delivery-history entries stored
  after this upgrade, drops a dark logo if it saves that branding record
  again, and ignores a Log tracer's `format` (it writes text).
- Scripts that read the exit code of a failed start: see the data store
  codes above.

## [27.1-rc.31] - 2026-11-18

27.1-rc.30 with 3 security fixes from our own review of the suite (1 high,
1 medium, 1 low) and one hardening change. 27.1-rc.1 to 27.1-rc.30 are
affected, and so is 2026.x up to and including 2026.11.18.2. The same fixes
are in 2026.11.18.3.

### Security
High
- SMTP: one unauthenticated message could stall the server through DKIM2
  verification, which took time quadratic in a signature's s= list. DKIM2
  is now checked only when each signature has at most 4 s= values, the
  chain has at most 20 links and no DKIM2 field is over 64 KiB; otherwise
  the message has no DKIM2 result. (GHSA-8wjf-95c6-c4q3, #444)

Medium
- Mail parsing: header fields had no limit, so a large header block could
  exhaust memory. A part keeps at most 10,000 header fields and a message
  262,144; over SMTP, more than 1,000 header fields in any part is refused
  with `552 5.3.4`. (GHSA-mvcp-vm37-f74j, #444)

Low
- Spam filter: an off-path host could forge Pyzor replies and mark mail as
  listed. Replies must now come from the Pyzor server queried and match the
  request, and request ids are random. (GHSA-4q7q-hg28-7666, #444)

### Changed
- Spam filter: the URL homograph check looks up at most 10 distinct names
  per message, each once. ARC chains of more than 20 sets, or with a field
  over 64 KiB, are treated as broken. (#444)

### Upgrading
- A message with more than 1,000 header fields in any part is refused over
  SMTP.

## [27.1-rc.30] - 2026-11-18

27.1-rc.29 with 4 security fixes from our own review of the suite (3 high,
1 medium). 27.1-rc.1 to 27.1-rc.29 are affected, and so is 2026.x up to and
including 2026.11.18.1. The same fixes are in 2026.11.18.2.

### Security
High
- SMTP: one unauthenticated message could stall the server through DKIM
  verification, which took time quadratic in a signature's header list.
  At most the first 10 signatures are now checked, a signature listing
  more than 128 header fields is ignored, and a message with more than
  1,000 header fields has none checked (dkim=none; refused with
  `550 5.7.20` under strict DKIM). (GHSA-v7ww-m523-wjfj, #439)
- Spam filter: one unauthenticated message could exhaust the server's
  memory, since every punctuation mark became a token. At most 25,000
  tokens per part and 100,000 per message are tokenized, and at most
  1 MiB of HTML is parsed. (GHSA-gg2c-9hwc-59cm, #439)
- Mail parsing: deeply nested message/rfc822 parts could overflow the
  stack and crash the server, again on every retry. Unencoded nested
  messages are parsed at most 20 levels deep; a deeper part is kept as an
  attachment. mail-parser 0.11.9 is now vendored for this.
  (GHSA-6245-jpv6-5pqm, #439)

Medium
- Mail store: a message with more than 65,535 MIME parts wrapped its
  stored part ids, and opening it exhausted memory. Such messages are now
  refused (`552 5.3.4` at DATA, NO on APPEND, an error from JMAP import),
  and ones already stored show only their well-formed parts.
  (GHSA-xm8r-p3w9-7cw8, #439)

### Upgrading
- Spam padded past the token limits hides later text from the classifier
  and the URL checks; rules that read the text itself still see all of it.
- A message with more than 65,535 MIME parts or nested messages is refused.

## [27.1-rc.29] - 2026-11-18

27.1-rc.28 with 6 security fixes from our own review of the suite (4 high,
2 medium), one of them also in inbuxa Relay. 27.1-rc.1 to 27.1-rc.28 are
affected, and so is 2026.x up to and including 2026.11.18. The same fixes
are in 2026.11.18.1.

### Security
High
- SMTP: one unauthenticated message could exhaust the server's memory
  through the DMARC check. A From header listing many addresses in
  different domains copied the whole message once per domain. Author
  domains are now deduplicated and checked without a copy; a From naming
  more than ten different domains fails DMARC with no lookups, and with
  strict DMARC verification is refused with `550 5.7.1`.
  (GHSA-jpf9-fq33-x6m6, #431)
- IMAP and ManageSieve: empty quoted strings (`""`) didn't count toward the
  request size limit, so a client could grow memory without bound before
  signing in. They now count like any other argument.
  (GHSA-5f9w-xjcx-j9h2, #431)
- Sieve: `replace` or `enclose` inside `foreverypart` crashed delivery on a
  message with nested parts, and enough such messages stopped local
  delivery for the whole node. `replace` now renumbers the remaining parts
  and the loop goes on over them; `enclose` ends the loop it runs in.
  (GHSA-jvv9-5xq7-64f5, #431)
- HTTP: a client that stopped sending its body or reading its answer held
  a listener slot forever. Such requests and connections are now dropped
  after 60 seconds without progress. (GHSA-p33r-wr8j-hmw3, #431)

Medium
- SMTP: a signed-in user could inject SMTP commands and DSN header fields
  through an encoded line break in ENVID or ORCPT. ENVID, ORCPT and MAIL
  FROM `AUTH=` values that decode to anything but printable ASCII are now
  refused with `501 5.5.4`, and ENVID and ORCPT go out as xtext. inbuxa
  Relay does the same, and passes ORCPT on with its `rfc822;` type, so
  relayed recipients with ORCPT are no longer refused.
  (GHSA-c332-jfj8-p9w6, #431)
- SMTP: on a listener offering AUTH without requiring it, AUTH after MAIL
  FROM made a transaction authenticated after its sender was checked
  anonymously. AUTH during a mail transaction is now refused with
  `503 5.5.1` (RFC 4954). (GHSA-7xrh-5v6g-hg45, #431)

### Upgrading
- A client that sends AUTH after MAIL FROM must RSET first.
- A From header naming more than ten different domains now fails DMARC.

## [27.1-rc.28] - 2026-11-18

27.1-rc.27 with 10 security fixes from our own review of the suite (6
medium, 4 low), three of them in inbuxa Relay, and two hardening changes.
27.1-rc.1 to 27.1-rc.27 are affected (inbuxa Relay from 27.1-rc.5), and so
is 2026.x up to and including 2026.11.17. The same fixes, except the three
for inbuxa Relay, are in 2026.11.18.

### Security
Medium
- SCIM: a deeply nested filter could stop the server. The filter parser had
  no nesting limit, so one request from a SCIM credential overflowed the
  stack and ended the server process. A filter longer than 8 KiB or nested
  more than 32 levels deep is now refused with `400 invalidFilter`
  (`invalidPath` for a PATCH path). (GHSA-6rvx-x4wr-558j, #419)
- Account lock: a limited administrator could lock a fuller account and
  take over its mail by naming itself as delegate. Creating, changing and
  ending a lock now need every permission the account has, the rule that
  changing an account already follows. (GHSA-f3q6-j22f-7cf8, #419)
- Mail flow: attachments in a few messages could stall the server. Each ZIP
  or Office attachment was unpacked up to 50 MiB, with no total per message,
  on the server's async workers. A message now gets one 10 MiB inspection
  budget across its bodies and attachments, unpacked data included, and at
  most 100 attachments are read; what's past either limit counts as "can't
  be inspected". Attachments are opened only when a rule checks content, the
  work runs off the async workers, and a failure while checking answers 451.
  (GHSA-qfcc-2hjm-7xjh, #419)
- Relay: unauthenticated clients could hold port 25 sessions until inbuxa
  Relay ran out of file descriptors. Port 25 now takes at most
  `maxSmtpSessions` sessions at once (new setting, default 1000) and answers
  `421 4.3.2` past it, a client that doesn't read its replies for 5 minutes
  is disconnected, and the per-address limits count an IPv6 sender by its
  /64. (GHSA-2993-jvgq-9qvp, #419)
- DLP: files inside Office packages, renamed text files and other archives
  went uninspected. Every file in an Office or OpenDocument package is now
  looked at, a file with no declared text type is read as text when it
  looks like text, and embedded objects, macro projects and non-ZIP archives
  (gzip, 7-Zip, RAR, tar and others) count as "can't be inspected".
  (GHSA-w2g2-f65h-wwhq, #419)
- HTTP: the sign-in and consent pages could be framed by another site. Every
  HTML answer (sign-in, device sign-in, RSVP, and the console and account
  pages the server serves) now sends `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'` and
  `Referrer-Policy: strict-origin-when-cross-origin`. Every answer sends
  `X-Content-Type-Options: nosniff`, and every answer on a TLS listener
  `Strict-Transport-Security: max-age=15552000`. Headers set in
  `http.response_headers` take precedence. (GHSA-vxfg-3rh4-wc94, #419)

Low
- Branding: `/logo` was an open redirect to a domain's or tenant's URL logo.
  It now redirects only when a browser loads it as an image
  (`Sec-Fetch-Dest: image`) and answers 404 otherwise; the redirect isn't
  cached, and a logo stored as an `http:` URL is no longer used.
  (GHSA-49j4-h9f5-6h3x, #419)
- Mail flow: an outside sender could keep a disclaimer, such as an
  external-sender warning, off their message by including its text.
  Incoming mail now always gets the disclaimer; outgoing mail still skips
  one that's already there. (GHSA-6p5j-4m95-c6qh, #419)
- Relay: with the link down and 10,000 events waiting, each new connection
  rewrote and synced inbuxa Relay's whole event file. The oldest thousand
  are now dropped at once. (GHSA-j2qx-wxvv-5x6h, #419)
- Relay: mail still being received wasn't counted toward `spoolMaxBytes`.
  It now is, and a message that would take the spool past it, or the
  spool's disk past 95%, is refused with `452 4.3.1` at the end of `DATA`.
  (GHSA-wcq3-6qc3-f5w2, #419)

Hardening
- DLP: detectors no longer crash on digits from other scripts (Arabic,
  Persian, Hindi, fullwidth). A message holding them ended the sender's
  session; it's now checked and sent normally. (#419)
- Autoconfig and autodiscover: answers carry
  `Content-Security-Policy: default-src 'none'; sandbox` and
  `X-Content-Type-Options: nosniff`, so they can't run as a page on the
  server. (#419)

Found by Coffey Labs.

### Changed
- The container image bundles inbuxa-migrate 27.1-rc.16: `import jmap` no
  longer sends the inbuxa profile's API key to the source server, and
  certificate checks no longer trust the distrusted emSign intermediates.
  Migrations the server runs itself were not affected. (#422)

### Upgrading
- After a browser has visited the server over HTTPS, it will also use HTTPS
  for `http://<server name>:8080`. Open the plain listener by IP address, or
  set your own `Strict-Transport-Security` in `http.response_headers` (e.g.
  `max-age=0`) if you rely on it by name.
- To show the server's pages in a frame (a portal, say), set your own
  `Content-Security-Policy` with `frame-ancestors` in
  `http.response_headers`.
- "Can't be inspected" now covers more attachments: gzip, 7-Zip, RAR, tar,
  xz, bzip2, zstd and CAB files, Office files with embedded objects or macros
  (`.docm`, `.xlsm`), and attachments past a message's 10 MiB inspection
  budget or its first 100. Rules on that condition act on them now.
- A URL logo shows only where a browser loads `/logo` as an image, as the
  sign-in page and the console do. Opening the link directly gives 404, and
  browsers that don't send `Sec-Fetch-Dest` (Safari before 16.4) show the
  built-in logo. Logos stored as `http:` URLs are no longer used; set an
  `https:` URL or an image.
- A role that can lock accounts can no longer lock, change the lock of, or
  unlock an account holding permissions it lacks, administrators included.
- SCIM filters longer than 8 KiB or nested more than 32 levels deep are
  refused. Identity providers send far less.
- inbuxa Relay: `maxSmtpSessions` (default 1000) caps port 25 sessions
  across all senders, and the per-address rate limits count an IPv6 sender
  by its /64, so a large sender using many addresses in one /64 shares one
  budget. The console doesn't show `maxSmtpSessions` yet; set it with
  `inbuxa:Relay/set` (`settings/maxSmtpSessions`). An older relay ignores
  it.

## [27.1-rc.27] - 2026-11-17

27.1-rc.26 with 2 security fixes from a private review of the server (1
medium, 1 low) and four hardening changes. All versions up to and including
2026.11.11, and 27.1-rc.1 to 27.1-rc.26, are affected. The same fixes are in
2026.11.17.

### Security
Medium
- HTTP: behind a reverse proxy, a client could choose its own address. With
  forwarding headers trusted, the server read RFC 7239 `Forwarded` before
  `X-Forwarded-For`, so a proxy that writes only `X-Forwarded-For` passed a
  client's own `Forwarded` header through. It now reads one header,
  `X-Forwarded-For` unless `INBUXA_HTTP_FORWARDED_HEADER=forwarded`, and a
  loopback address in it counts as this host only when every hop after it
  is loopback too. (GHSA-hxp3-8c95-4q5v, #413)

Low
- Multi-tenant: a tenant administrator could download any blob by its hash.
  Inside a tenant, `fetchAnyBlob` now reaches only blobs the tenant holds:
  linked by one of its accounts, or in a queued message the tenant sees.
  Tenant queue downloads keep working. (GHSA-x596-5p95-2rm3, #413)

Hardening
- TLS: rustls-webpki 0.103.17, webpki-roots 1.0.12 and webpki-root-certs
  1.0.12 stop trusting the distrusted emSign intermediates
  (RUSTSEC-2026-0381, RUSTSEC-2026-0382, RUSTSEC-2026-0383). (#413)
- Tenants: no tenant policy grants writing system Sieve scripts, which can
  run programs as the server's user. (#413)
- OAuth: with `requireClientRegistration` off (it's on by default), a client
  nobody registered must use PKCE (S256) and may only redirect to a loopback
  address or a private-use scheme (RFC 8252). (#413)
- Downloads: a requested type that isn't a valid header value falls back to
  `application/octet-stream`, and a response with a bad header value is a
  500 instead of a dropped connection. (#413)

These came from a private security review; thanks to its author.

### Upgrading
- If your reverse proxy sends only RFC 7239 `Forwarded`, set
  `INBUXA_HTTP_FORWARDED_HEADER=forwarded`; otherwise client addresses read
  as the proxy's. nginx, Caddy and Traefik send `X-Forwarded-For` and need
  nothing.
- With `requireClientRegistration` off, a web application signing in by
  OAuth has to be registered now.

## [27.1-rc.26] - 2026-11-17

The bundled inbuxa-migrate moves to 27.1-rc.15.

### Changed
- The container image bundles inbuxa-migrate 27.1-rc.15: upstream v1.1.0's
  dependency updates, and `export` no longer sends a message again on every
  run when the target keys it differently, as with a message carrying two
  `Message-ID` headers. (#411)

## [27.1-rc.25] - 2026-11-16

A TLS report counts once on the dashboard, however many policies it covers,
and Deliverability stops failing SPF for a container's own addresses.

### Fixed
- TLS reports: a report logged one incoming-report event per policy, so a
  report covering both an MTA-STS and a DANE policy counted as two reports
  on the dashboard, and as two with warnings when both had failures. It now
  logs one event per report, with the totals summed over its policies and
  each policy's figures kept in the event. Thanks to khashmeshab. (#406,
  fixes #402)
- Deliverability: with no source addresses set, the check tested what the
  server's name resolves to, and in a container /etc/hosts maps that name
  to the container's own addresses. On an installer's container install it
  failed SPF for 172.31.253.10 and fd69:6e62:7578::2, which no receiver ever
  sees. Private, shared, loopback, link-local and unique-local addresses
  are left out now, and when those are all the name gave, DNS itself is
  asked. Thanks to faisal. (fixes #408)

## [27.1-rc.24] - 2026-11-16

The sign-in page no longer stays behind in the browser history.

### Fixed
- Sign-in page: after a successful sign-in the page sent the browser on to
  the app with `location.assign`, which left it in the history. In the
  console and webmail installed as apps, Back then landed on a spent
  sign-in form, and signing in there failed. It now replaces itself.
  Thanks to khashmeshab. (#404, fixes #403)

## [27.1-rc.23] - 2026-11-15

Delivery history keeps inbound and outbound mail apart, automatic DKIM makes
a DKIM2 key as soon as it is ticked, and release downloads are signed.

### Added
- Delivery history: inbound and outbound lists can be scoped by kind.
  `x:Trace/query` takes a `kind` filter (received, submitted, remote, local,
  any), worked out from each trace's events, so older history is covered
  too. Inbound defaults to mail received from other servers and Outbound to
  remote deliveries, so mail your users send over 587/465 and local
  deliveries no longer mix in; a Show filter brings them back. Thanks to
  Faisal. (#398, fixes #397)
- A `spam.result` event (info level) records the spam verdict, score and the
  rules hit, highest points first, so they appear in an inbound trace. (#398)
- Release downloads come with `SHA256SUMS.minisig`, a minisign signature of
  `SHA256SUMS`. (#396)

### Fixed
- Automatic DKIM: ticking a new signing algorithm on a domain already set to
  Automatic, such as DKIM2 next to DKIM1, made no key until the next
  rotation. The save now makes it. Unticking one still takes effect at
  rotation. Thanks to Stefan. (#399)

## [27.1-rc.22] - 2026-11-13

Fixes from the community: Check now reads fresh DNS, Automatic DNS publishes
newly enabled record types, and the dashboard counts DMARC warnings the way
the reports page does.

### Changed
- The container image bundles inbuxa-migrate 27.1-rc.14: upstream v1.0.16's
  Exchange EWS and Graph fixes, and the POP3, Fastmail, Zoho and Zimbra
  sources. (#393)

### Fixed
- Deliverability: Check now used the same cached DNS answers as mail traffic,
  so a check right after fixing reverse DNS or adding a DMARC record could
  still show the old state. A manual check now skips the caches. The daily
  check and SMTP keep them. Thanks to Stefan. (#387, fixes #385)
- Automatic DNS: adding a record type to `publishRecords` on a domain already
  set to Automatic queued no DNS task, so the new records were never
  published until the domain was switched to Manual and back. The save now
  publishes them. Thanks to Stefan. (#389, fixes #372)
- DMARC reports: the dashboard marked a report "with warnings" when any row
  failed SPF or DKIM, so forwarded mail that passed DMARC on DKIM counted as a
  warning. A warning now means a row failed DMARC, as on the reports page.
  (#392, fixes #391)

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
