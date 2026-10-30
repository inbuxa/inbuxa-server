# Feature spec: inbuxa-relay, the edge appliance

Status: draft, 2026-10-29. Not a rebuild: inbuxa's own design (SPEC.md §4).
Its open questions were settled on 2026-10-29: see "Decisions".

## Provenance

inbuxa's own design. No upstream Enterprise file or snippet was used, and
there is no upstream equivalent to rebuild. Sources:

| Source | Used for |
|---|---|
| RFC 5321 (SMTP), RFC 3461–3464 (DSN), RFC 1870 (SIZE), RFC 3207 (STARTTLS) | The SMTP door and outbound delivery |
| RFC 8620 (JMAP core), RFC 8887 (JMAP over WebSocket) | The link |
| RFC 8621 §7 (`EmailSubmission`) | The `Envelope` and `DeliveryStatus` shapes the link reuses |
| RFC 7672 (DANE for SMTP), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT) | Outbound TLS |
| RFC 9180 (HPKE) | Sealing the inbound spool |
| RFC 2645 (ODMR/ATRN) | Considered for the link and not chosen (see "The link") |
| This repository's AGPL code: `crates/smtp` (inbound stages, outbound delivery, DANE and MTA-STS), `crates/jmap-proto` (`urn:inbuxa:jmap:*` capabilities), `crates/jmap/src/inbuxa` (`inbuxa:` objects) | What the relay reuses, and where the downstream hooks in |
| docs.inbuxa.org "An edge server in front" (`run/edge-server`), and the lab behind it, 2026-10-14 | What the settings-only edge does today, and what it costs |

## What it is

inbuxa-relay is a small, single-purpose appliance that sits on a machine the
internet can reach, such as a small cloud server or an edge box. It takes
mail in on port 25 for one inbuxa server or cluster, called the
**downstream**, and sends that downstream's outgoing mail on. The downstream
can sit on a protected network, or on one that can't expose mail ports at
all. It opens no port to the relay. Instead it dials **out** to the relay and
keeps that connection open.

The relay stores no one's mail. It keeps a spool of mail waiting to move in
either direction, and nothing else.

In copy it is **inbuxa Relay**. The binary and the container image are
`inbuxa-relay`.

The settings-only edge in the docs works, but leaves the operator to get a
lot right by hand. The relay removes each of those jobs:

| Settings-only edge (docs, `run/edge-server`) | inbuxa-relay |
|---|---|
| The edge must reach the internal server on port 25 | The downstream dials out; no inbound port on the protected network |
| No recipient check without LDAP or SQL, so unknown addresses are accepted and bounced later | Unknown addresses refused at RCPT, always (RL-1) |
| A full second inbuxa with its own console and administrators | No console; administered only from the downstream's inbuxa-admin (RL-2) |
| A relay account with a password, and a "Must match sender" exception | No SMTP AUTH anywhere; outbound only over the pinned link (RL-4) |
| SPF, DMARC and reverse IP turned off on the internal server for the edge's IP; two spam filters to reconcile | The downstream sees the real sender's session and runs its own checks: one spam brain |
| A 100 MB server binary and a data store | One small static binary and a spool directory (RL-3) |

## The four rules

These are invariants. No setting, on either side, turns any of them off.

- **RL-1. Real recipients only.** The relay accepts a recipient only if the
  downstream says it exists: an account, alias, list, masked address, or an
  address matched by a catch-all or sub-addressing rule the downstream
  pushed. Anything else is refused at RCPT with `550 5.1.1`. A recipient at a
  domain the relay doesn't serve is refused with `550 5.7.1`.
- **RL-2. Administered only from the assigned downstream.** The relay has no
  web interface, no local accounts, no API other than the link, and no
  configuration file beyond its state directory and listen address. All
  settings arrive over the link from the downstream it was joined to. The
  local command line can join, show status, and reset (see "Joining and
  reset"). Reset un-assigns the relay; it doesn't administer it.
- **RL-3. Smallest footprint.** A single static binary with no database, no
  web server, no spam filter, no directory and no message store. Budgets are
  in "Footprint" and are checked in CI.
- **RL-4. One downstream only.** The relay is pinned to exactly one
  downstream identity at join, and refuses every other link client until it
  is reset. It accepts inbound mail only for that downstream's domains, and
  outbound mail only over that downstream's link, only from envelope senders
  at that downstream's domains (or the null sender). Port 25 never relays:
  there is no AUTH, so no SMTP client can send through it.

## Roles and topology

```
 internet ──25──▶ inbuxa-relay ◀══ JMAP over mTLS, dialed OUT by the downstream ══ downstream
                   spool only                                                   directory, spam filter,
                                                                                DKIM keys, mail store
```

- One relay serves one downstream. One downstream may have several relays,
  for example two relays as MX 10 and MX 20. Each relay has its own
  settings, and inbuxa-admin can copy one relay's settings to another.
- A downstream cluster is one downstream. Every node that runs the link
  service holds its own link to each relay. The relay treats them as one
  client and hands each message to exactly one of them (RL-15).
- The relay is a JMAP **server**, and the downstream is a JMAP **client**.
  That is JMAP's own direction, and it is what lets the downstream dial out.

## The link

### Transport

- **RL-5.** The relay listens for the link on one TCP port: `443` by
  default, changed with `--link-listen`. The downstream is the side that
  dials out, and outbound 443 is the one port a locked-down network almost
  always allows. TLS 1.3 only. JMAP method calls and push go over a
  WebSocket (RFC 8887) on HTTP/1.1, at the session's `webSocketUrl`. A
  WebSocket takes over its HTTP/1.1 connection, so blobs go over separate
  kept-alive HTTP/1.1 connections to `uploadUrl` and `downloadUrl` on the
  same port, up to 4 per node.
- **RL-6.** The relay requires a client certificate during the handshake, and
  completes the handshake only if the certificate chains to the pinned
  downstream link CA. A client without one gets a TLS alert and no HTTP
  response, so the port says nothing about what is behind it.
- **RL-7.** The downstream pins the relay's link key: the SHA-256 of its
  SubjectPublicKeyInfo, learned at join. Names in the relay's link
  certificate are not checked; the pin is the identity.
- The downstream sends a WebSocket ping every 30 seconds, so NAT and
  firewalls between the two keep the connection open. After two missed pongs
  the downstream reconnects, with backoff from 1 s up to 60 s.

The link doesn't use WebSockets over HTTP/2 (RFC 8441): few WebSocket
libraries support them, and the relay would carry more code to save a few
TLS connections. It is not WireGuard (inbuxa VPN), because a tun device needs
privileges an unprivileged container doesn't have, and a control channel
would still be needed on top. It is not ATRN (RFC 2645), because ATRN only
reverses delivery: configuration, recipient sync, status and outbound
results would still need another channel. JMAP carries all of them, and is
the protocol the rest of the suite already speaks.

### Identities

| Key | Lives on | Pinned by | Purpose |
|---|---|---|---|
| Downstream link CA | Downstream registry (secret), shared by all cluster nodes | Relay, at join | Issues each node's link client certificate (30 days, renewed at 20) |
| Relay link key | Relay state directory | Downstream, at join | The relay's link server certificate (self-signed) |
| Downstream sealing key (X25519) | Downstream registry (secret); public half pushed to the relay | — | The relay seals held inbound mail to it (RL-21) |
| Relay SMTP certificate | Relay state directory | — | STARTTLS on port 25, under the relay's public hostname. Issued by the downstream (RL-27) |

### Joining and reset

1. In inbuxa-admin, an administrator adds a relay: a name and the address the
   downstream should dial (host and link port). The downstream creates the
   `inbuxa:Relay` object and returns a **join token** once, in the create
   response. It is never shown again.
2. The token is base64url of `{v: 1, relayId, caSpki, secret, expiresAt}`,
   where `secret` is 32 random bytes and the token expires after 24 hours.
3. On the relay host: `inbuxa-relay join <token>`. The relay generates its
   link key, stores the CA pin and the secret, and starts listening on the
   link port. Port 25 stays closed.
4. The downstream dials the relay. It can't check the relay's key yet, so on
   this one connection it makes only one call: `Relay/join` with a random
   `nonce`. The relay answers with
   `HMAC-SHA256(secret, nonce || relayLinkSpki)`.
5. If the proof checks out, the downstream pins the relay's link key, the
   relay deletes the secret, and the downstream pushes the first settings
   and recipient set. The relay opens port 25 only once it has both.

A relay that was reset joins again with a new token. In inbuxa-admin, an
update with `rejoin: true` returns one, once, and forgets the relay's
pinned link key and its recipient key.

- **RL-8.** A join token works once. A wrong proof, an expired token, or a
  second join attempt fails, and the relay stays unjoined.
- **RL-9.** `inbuxa-relay status` prints the link state, the number of
  linked clients, queue counts, the version and the last error. It prints no
  address, subject or message content.
- **RL-10.** `inbuxa-relay reset` deletes the state directory and returns
  the relay to unjoined. It refuses while held inbound mail is in the spool,
  printing the count, unless `--discard-held` is given. Held mail is sealed
  to the old downstream and is unreadable afterward, so discarding it is
  final.

## The relay's JMAP API

### Session

The session lists `urn:ietf:params:jmap:core` and
`urn:inbuxa:jmap:relay`. There is one account, the relay's own. The
`urn:inbuxa:jmap:relay` capability object:

| Field | Meaning |
|---|---|
| `protocolVersion` | `1`. The downstream refuses a relay with a higher major version than it knows |
| `relayVersion` | The relay's release, e.g. `27.1.0` |
| `maxBlobSize` | Largest upload the relay accepts, in bytes |
| `features` | Optional features, as strings. Empty in version 1 |

The relay does not claim `urn:ietf:params:jmap:mail` or
`urn:ietf:params:jmap:submission`. It has no mailboxes and no Email objects,
and a partial claim would mislead real JMAP clients. It reuses RFC 8621's
`Envelope` and `DeliveryStatus` shapes field for field.

The relay's type names sit in their own capability, so they don't collide
with the server's own `inbuxa:` objects. In particular, the relay's
`Inbound` is not the server's `inbuxa:HeldMessage` (the DLP review queue).

### Types

**`Relay`**: one object, id `singleton`.

| Property | Set by | Meaning |
|---|---|---|
| `hostname` | downstream | Public name: the EHLO name, the banner, and the SMTP certificate's name |
| `smtpListen` | downstream | Addresses for port 25. Default `[::]:25` |
| `domains` | downstream | The domains served (RL-1, RL-4) |
| `maxMessageSize` | downstream | SIZE limit. Default 50 MiB |
| `maxRecipients` | downstream | Per message. Default 100 |
| `rateLimits` | downstream | Connections and messages per minute per remote IP, and concurrent sessions per IP |
| `dnsbl` | downstream | DNSBL zones checked at connect in held mode. Default empty (RL-14) |
| `liveVerdictTimeout` | downstream | Seconds to wait for a live verdict. Default 30, maximum 120 (RL-13) |
| `heldMaxAge` | downstream | How long held inbound mail waits for the downstream. Default 30 days, maximum 90 |
| `spoolMaxBytes` | downstream | Spool size cap |
| `outboundRetry`, `outboundExpiry` | downstream | Retry schedule and give-up time. Defaults match the server's (three days) |
| `outboundTls` | downstream | Opportunistic TLS default; DANE and MTA-STS always enforced where published |
| `smtpCertificate` | downstream | PEM chain and private key. `/get` never returns the key |
| `sealingKey` | downstream | The downstream's public sealing key |
| `status` | relay | `{startedAt, linkClients, mode, spool: {inbound, outbound, bytes}, recipientState, certificateNotAfter, lastError}` |

Settings are cached in the state directory as the downstream last set them,
so a reboot without the link comes back with the same settings (RL-22).

**`RecipientDomain`** and **`Recipient`**

| Type | Properties | Meaning |
|---|---|---|
| `RecipientDomain` | `domain`, `catchAll` (bool), `subaddressSeparator` (string or null) | Domain-wide rules |
| `Recipient` | `hash` | One accepted address |

- **RL-11.** `hash` is `HMAC-SHA256(recipientKey, address)` over the address
  lowercased and with any sub-address removed. `recipientKey` is made by the
  downstream per relay and pushed with the settings. This keeps the
  directory from being read off a seized relay as a list. It does **not**
  stop someone holding the relay's key from testing guessed addresses
  offline; nothing on the relay could, since the relay has to check real
  ones.
- Deltas use `Recipient/set` (create and destroy by hash). A full refresh
  uses the custom `Recipient/replace {blobId}`: a sorted file of 32-byte
  hashes, swapped in atomically. The relay's `Recipient` state string lets
  the downstream tell whether the relay is current.

**`Inbound`**: a message the relay accepted on port 25.

| Property | Meaning |
|---|---|
| `id` | Stable for the message's whole life. The downstream deduplicates on it (RL-16) |
| `receivedAt` | When the relay accepted it (or got the final dot, if pending) |
| `state` | `pending` (live, awaiting a verdict), `held`, or `claimed` |
| `claimedUntil` | End of the current lease, when claimed |
| `envelope` | RFC 8621 `Envelope`: `mailFrom` and `rcptTo`, with parameters |
| `session` | `{remoteIp, remotePort, localIp, helo, tls: {version, cipher} or null, ptr}` |
| `size` | Bytes |
| `blobId` | The sealed message (RL-21) |
| `doorChecks` | What the relay checked at the door, e.g. DNSBL results in held mode |

**`Outbound`**: a message the downstream handed to the relay to send.

| Property | Meaning |
|---|---|
| `id`, `createdAt` | |
| `blobId` | The message as the downstream signed it |
| `envelope` | RFC 8621 `Envelope` |
| `deliveryStatus` | RFC 8621 `DeliveryStatus` per recipient: `smtpReply`, `delivered` (`queued`, `yes`, `no`, `unknown`) |
| `nextAttemptAt`, `attempts`, `expiresAt` | Retry state |

**`RelayEvent`**: read-only, `{id, at, type, data}`. The relay's sessions,
deliveries, rejections and errors, for the downstream's history and tracer.

### Methods

Standard RFC 8620 methods, plus five of its own:

| Method | What it does |
|---|---|
| `Relay/get`, `Relay/set` | Read status; push settings |
| `Relay/join` | Join proof (see "Joining and reset"). Answers only on an unjoined relay |
| `Relay/upgrade` | `{blobId, signature}`: install a signed release (RL-29) |
| `RecipientDomain/get`, `/set`; `Recipient/set`, `/changes` | Recipient sync |
| `Recipient/replace` | Full recipient refresh from a blob |
| `Inbound/changes`, `/get`, `/query` | See what is waiting |
| `Inbound/claim` | `{limit, leaseSeconds}` → ids leased to this connection (RL-15) |
| `Inbound/set` | `update` sets a live verdict; `destroy` acknowledges a message as taken |
| `Outbound/set` | `create` hands a message over; `destroy` cancels one still queued, or clears a finished one |
| `Outbound/get`, `/changes` | Delivery status |
| `RelayEvent/changes`, `/get`, `/set` (destroy only) | Read and acknowledge events |

Push: the relay sends a `StateChange` for `Relay`, `Inbound`, `Outbound` and
`RelayEvent` to every linked client with push enabled.

## Inbound

### At the door, always

In this order, whatever the mode:

1. Connection rate limits per IP.
2. EHLO, and protocol hygiene: early talkers are dropped, and the session
   ends after the error limit.
3. MAIL FROM: syntax and SIZE.
4. RCPT TO: RL-1, then `maxRecipients`.
5. DATA: the size limit.

The relay advertises no AUTH, and refuses ETRN and ATRN.

### Live mode

The relay is in live mode while at least one link client has push enabled
for `Inbound`.

- **RL-12.** After the final dot, the relay seals the message to the spool
  (RL-21) as `Inbound` state `pending`, and pushes. It holds the SMTP reply.
- The downstream claims the message, downloads it, and runs its own inbound
  pipeline on it, with the session context (RL-23). It answers with
  `Inbound/set` update `verdict`:
  - `{accept}`: the relay replies `250`, and deletes the message once the
    downstream destroys it.
  - `{reject: {code, enhanced, text}}`: the relay replies with that `5xx`,
    and deletes the message.
  - `{tempfail: {code, enhanced, text}}`: the relay replies with that `4xx`,
    and deletes the message.
- **RL-13.** If no verdict arrives within `liveVerdictTimeout`, the relay
  replies `250` and the message becomes `held`. It is then handled as in
  held mode, and the downstream deduplicates it if it had already taken it
  (RL-16). `liveVerdictTimeout` must be at least the downstream's
  `spamCallCeiling` (20 s by default, see the AI spam classification spec)
  plus 5 s, so a slow model still answers in time. inbuxa-admin warns when
  it isn't. Senders wait up to 10 minutes after DATA (RFC 5321
  §4.5.3.2.6), so the wait costs nothing.
- The verdict is for the whole message. If the downstream accepts it for
  some recipients and not others, it handles the rest as it does today for a
  failure after DATA, under RL-18's limit on DSNs.

So in live mode the downstream's directory, spam filter, AI classifier and
Sieve decide before the sender is told yes, and a refused message is refused
by the sender's own server: no bounce from inbuxa.

### Held mode

When no link is up, or after RL-13:

- The door checks above, plus any `dnsbl` zones at connect.
- The relay seals the message to the spool with fsync, then replies `250`.
- **RL-14.** Spam is never refused in held mode. The relay has no spam
  filter, and it doesn't guess. There is no greylisting and no reverse DNS
  requirement either: both add state or turn away real mail, and the
  downstream judges held mail later anyway.
- `dnsbl` is empty by default. Most lists refuse queries that come through
  public resolvers, which small servers often use, so a default list would
  either do nothing or refuse everything. The add-a-relay wizard offers
  zones, with that warning.

### Handing held mail down

- **RL-15.** `Inbound/claim` leases messages to the calling connection for
  `leaseSeconds` (default 300). A leased message is offered to no other
  connection until the lease runs out. This is how a cluster takes each
  message on exactly one node.
- The downstream downloads the blob, unseals it, ingests it with the session
  context (RL-23), and then sends `Inbound/set destroy`. The relay deletes
  the message only on destroy.
- **RL-16.** If anything fails between ingest and destroy (a crash, a link
  drop, a node loss), the lease expires and the message is offered again.
  The downstream records every `Inbound` id it has ingested for at least
  `heldMaxAge` plus one day, and destroys a repeat without delivering it
  again.
- **RL-17.** Held mail is never bounced for a spam verdict. Under the
  reject threshold, the downstream files it by its usual rules. Over it, the
  message goes to Junk, never dropped, with the header
  `X-Inbuxa-Relay: held, over reject threshold`. The sender was already told
  `250`, so dropping it would lose mail without anyone knowing. Junk expires
  on the downstream's own schedule. There is no setting for this.
- **RL-18.** The downstream sends a DSN for held mail only when the sender
  passed SPF or DMARC in its own checks. A forged sender gets no bounce,
  so the relay can't become a backscatter source.
- Held mail older than `heldMaxAge` is deleted, with an
  `inbound.expired` event and no DSN.
- The downstream raises an alert when one of its nodes has had no link to
  an enabled relay for an hour, so held mail doesn't sit unnoticed. It can't
  alert while it is down itself. An outside monitor on the relay's port 25
  covers that.

## Outbound

- **RL-19.** The relay accepts outbound mail only through `Outbound/set`
  create over the link, never on port 25. It refuses a create whose
  `mailFrom` is neither empty nor at one of `domains` (`forbiddenFrom`).
- The downstream DKIM-signs every message before handing it over. Signing
  keys never leave the downstream.
- The relay delivers by MX, with DANE (RFC 7672) where the destination has
  DNSSEC-signed TLSA records, MTA-STS (RFC 8461) where it publishes a policy,
  and otherwise opportunistic TLS per `outboundTls`. That logic is taken from
  the server's own outbound delivery code, not re-invented.
- After each attempt the relay updates `deliveryStatus` and pushes. The
  downstream writes any DSN itself, and its history shows the remote
  server's real reply. The relay never writes a message of its own.
- TLS results for each destination are sent as `RelayEvent`s. The downstream
  builds TLS-RPT reports from them, as it does from its own deliveries.
- **RL-20.** If no relay can be reached, the downstream keeps the message in
  its own queue and retries. With several relays, it hands messages to the
  linked ones in turn, skipping any marked `inboundOnly`.

## The spool

- One file per message, in `spool/in/` and `spool/out/`. Each is written to a
  temporary name, fsynced, renamed into place, and the directory fsynced,
  before the relay acknowledges it in any way. A small header in each file
  holds the object's properties, so the index is rebuilt by reading the
  directory at start. There is no database.
- **RL-21.** Inbound mail is sealed with HPKE (RFC 9180, base mode,
  X25519-HKDF-SHA256, ChaCha20-Poly1305) to the downstream's sealing key,
  in streaming chunks as the message arrives. Plaintext never reaches the
  relay's disk, and the relay can't read held mail afterward. Outbound mail
  is stored as handed over, since the relay has to read it to send it.
- When the spool passes 90% of `spoolMaxBytes`, or 90% of its disk, the
  relay answers new inbound mail with `452 4.3.1`, and `Outbound/set` create
  with `overQuota`. Senders retry, and nothing already accepted is dropped.
- **RL-22.** The state directory holds the link key, the pins, the cached
  settings, the recipient set, the SMTP certificate, the spool and the
  unacknowledged events. Everything else is rebuilt at start.

## The downstream

### Registry objects

| Object | What it holds |
|---|---|
| `inbuxa:Relay` | One per relay: `name`, `address`, `linkPort`, `enabled`, the settings pushed to the relay, `sendThrough` (route outbound mail through relays), `inboundOnly` (takes mail in but sends none, e.g. while its IP isn't warmed up or isn't in SPF yet), and read-only status mirrored from the relay: link state per node, version, queue counts, `lastSeen`. Create, or an update with `rejoin: true`, returns `joinToken` once |
| `inbuxa:RelayMessage` | Read-only view of a relay's `Inbound` and `Outbound` queues, fetched over the link when asked. Never message content |

Permissions: `sysRelayGet`, `sysRelayUpdate`, `sysRelayQueueGet`,
`sysRelayQueueUpdate` (cancel an outbound message, discard held mail). The
admin role gets all four. Nobody in a tenant gets any. A relay serves the
whole downstream, not a tenant.

Relay settings live in the downstream's registry, so on a cluster they are
in the shared store, backed up and audited like any other setting.
inbuxa-admin changes them through `urn:inbuxa:jmap:registry`, and the link
service applies them to the relay. inbuxa-admin never talks to a relay.

### The link service

Runs on every node. On a cluster, every node keeps a link to every enabled
relay. It:

- keeps the WebSocket open and pushes settings and recipient deltas when
  they change. A directory change reaches every relay within seconds;
- claims, unseals and ingests inbound mail;
- hands outbound mail to a relay, and follows its status;
- maps `RelayEvent`s into the downstream's own trace events, with the relay
  named, so they show in history and the tracer;
- renews node link certificates.

### Ingest with session context

- **RL-23.** Mail from a relay is judged as if the downstream had taken the
  SMTP session itself. Its inbound pipeline runs with the relay's `session`
  and `envelope`: `remote_ip` is the original sender's address, and SPF,
  reverse IP, DMARC, DNSBL, the spam filter, the AI classifier, and Sieve all
  see the real facts. In expressions, `relay` is the relay's name, or empty
  for mail that didn't come through one.
- The downstream accepts session context only over a pinned relay link. Mail
  arriving at its own port 25 (if it has one) is never treated as relayed,
  whatever its headers say.
- DKIM is checked on the downstream as usual. A relay can't fake a
  signature.

This is the main server change. It replaces the docs edge recipe's steps of
allowing the edge's IP and disabling SPF, DMARC and reverse IP for it.

### Outbound routing

- **RL-24.** A new route type, `inbuxaRelay`, alongside the existing route
  types, names one or more `inbuxa:Relay`s. With `sendThrough` on, it is the
  route for every non-local recipient.
- The downstream's queue keeps the message until a relay reports a final
  status. The item shows "handed to relay ‹name›", and then the remote
  server's reply.

### DNS and certificates

- **RL-25.** When a domain's DNS management is Automatic and relays are
  enabled, the published MX set is the relays, each with its own preference,
  and SPF covers the sending addresses of every relay not marked
  `inboundOnly`. Publishing must keep every
  relay in the set: never replace a multi-host MX set with one host.
- **RL-26.** A relay's public hostname needs an A or AAAA record and a
  reverse DNS name that matches it. The deliverability check runs against
  each relay's address, not the downstream's.
- **RL-27.** The downstream gets each relay's SMTP certificate by ACME DNS-01
  through its DNS server settings, pushes it with `Relay/set`, and renews it
  30 days before it expires. Without DNS automation, an administrator
  uploads one. The relay never runs ACME, and opens no port 80.

### Updates

- **RL-28.** The downstream shows when a relay is older than itself, and
  refuses to link a relay whose link `protocolVersion` it doesn't know.
- **RL-29.** `Relay/upgrade` takes a release binary as a blob and a
  signature by the inbuxa release key, which is compiled into the relay. The
  relay checks the signature, refuses a downgrade, replaces its binary, and
  exits for its supervisor to restart it. In a container image the relay
  reports `selfUpgrade: false`, and inbuxa-admin says to update the image
  instead.

## inbuxa-admin

A **Relays** page under Settings › Mail flow:

- **Add a relay** is guided or manual, like every job with a wizard. The
  join token shows once, with a copy button and the one command to run on
  the relay host.
- The list shows a status line only when something needs attention: link
  down on a node, spool filling, an old version, a certificate near expiry,
  a stale recipient set. No line at all when everything is fine.
- Each relay has its settings, its queues (from `inbuxa:RelayMessage`), and
  its events in the existing history view.
- Every option gets a tooltip, keyed `inbuxa:Relay.<field>`.
- Security checks: a relay with `sendThrough` on but not linked from every
  node; MX records that don't match the enabled relays; a relay whose
  version is older than the downstream's.

## Footprint

- **RL-30.** A separate binary, `inbuxa-relay`, in this workspace, so the
  link protocol and the server's ingest change land in the same PR and ship
  in the same release. It is built
  without the `smtp`, `common`, `jmap`, `store`, `directory` or `spam-filter`
  crates. It uses smtp-proto, rustls, hickory (with DNSSEC, for DANE), tokio,
  hyper, a WebSocket library, serde_json, an HPKE implementation, and the
  outbound DANE and MTA-STS logic moved from `crates/smtp` into a small
  shared crate.
- It has a small JMAP core of its own: the session, the request, response
  and error envelope, `/get`, `/set`, `/changes`, `/query`, push, upload and
  download. It doesn't use `jmap-proto`, which depends on `registry`: about
  88,000 lines, most of it generated schema (measured 2026-10-29), for five
  types. If the envelope is worth sharing later, it moves into a small crate
  both use.
- Budgets, checked in CI on the release build:

  | Measure | Budget |
  |---|---|
  | Static musl binary, stripped, x86_64 and aarch64 | ≤ 15 MB |
  | Resident memory, joined and idle | ≤ 32 MB |
  | Resident memory, 50 concurrent SMTP sessions | ≤ 128 MB |
  | Container image | `FROM scratch`: the binary and CA roots only |

- **RL-31.** It ships as its own artifacts, from the same release tag as
  the server: a multi-arch image (linux/amd64, linux/arm64) named
  `inbuxa-relay`, tagged like the server's, and static `inbuxa-relay`
  binaries for x86_64 and aarch64 attached to the same Release. Running a
  relay never needs the server image or binary. `publish.yml` builds both
  products, so a relay and a server with the same version always speak the
  same link protocol.
- It runs as a non-root user, with `CAP_NET_BIND_SERVICE` only.
- It logs to stderr only: start, stop, link up and down, and errors. It logs
  no address and no content. Everything else goes up the link as
  `RelayEvent`s.

## Failure behavior

| What fails | What happens |
|---|---|
| The link | Held mode. Outbound mail already handed over keeps being delivered. The downstream keeps new outbound in its own queue, or uses another relay |
| The downstream, for days | Held mail waits up to `heldMaxAge`. When the spool is full, senders get `452` and retry |
| The relay | Senders try the next MX, or retry. The downstream holds outbound or uses another relay |
| A relay reboot | It resumes from the spool and cached settings, with port 25 open, before the link returns |
| A cluster node mid-ingest | The lease expires and another node takes the message (RL-15, RL-16) |
| A stale recipient set | An address removed since the last sync is accepted and refused downstream, with RL-18's limit on DSNs. A new address is refused until the next delta, normally seconds |
| The relay's clock | TLS on the link and on port 25 depends on it. The relay reports clock skew larger than 60 s against the downstream as `lastError` |

## Security considerations

- **No path in.** The protected network accepts no connection from the
  relay. The link is dialed out, and speaks only the methods above.
- **The link port.** Pinned mTLS before any HTTP. TLS handshakes are rate
  limited per IP.
- **Port 25 can't relay.** There is no AUTH and no outbound path from port
  25 (RL-4, RL-19).
- **A compromised relay** gives an attacker mail in flight, the outbound
  queue, the hashed recipient set with its key, and the relay's SMTP
  certificate key. It doesn't give them held inbound mail (sealed), DKIM
  keys, the directory as a list, or any way into the downstream. It *can*
  forge session facts for mail it injects. The downstream's DKIM check still
  holds, and a relay can be disabled from inbuxa-admin at once, which drops
  its link.
- **Secrets on the downstream:** the link CA key, the sealing key and the
  recipient key, as registry secrets. inbuxa-admin never shows them.

## Acceptance tests

- **RL-T1.** A RCPT for a foreign domain, unauthenticated, is refused with
  `550 5.7.1`. AUTH is not advertised.
- **RL-T2.** A RCPT for an unknown address at a served domain is refused
  with `550 5.1.1`, in live mode and in held mode.
- **RL-T3.** Live: a message the downstream scores over its reject threshold
  is refused at DATA with the downstream's reply, and leaves nothing in the
  spool.
- **RL-T4.** Live: the downstream withholds its verdict. The sender gets
  `250` after `liveVerdictTimeout`, and the message is delivered once.
- **RL-T5.** The downstream is killed between ingest and destroy. After the
  lease expires the message is offered again, and is delivered exactly once.
- **RL-T6.** The downstream is offline for an hour, with ham and spam
  arriving. On reconnect everything is ingested, spam goes to Junk, and no
  DSN is sent.
- **RL-T7.** A held message containing a known marker string: the spool on
  disk doesn't contain the marker.
- **RL-T8.** A link client with a certificate from another CA fails the TLS
  handshake and gets no HTTP response.
- **RL-T9.** A join token used twice, used after expiry, or presented with a
  wrong proof fails, and the relay stays unjoined.
- **RL-T10.** `Outbound/set` create with a `mailFrom` outside `domains` is
  refused with `forbiddenFrom`.
- **RL-T11.** Outbound to a destination answering `550` shows `delivered:
  no` and the reply in `deliveryStatus`, and the downstream sends one DSN.
- **RL-T12.** Outbound to a DANE destination with a wrong TLSA record is not
  delivered. To an MTA-STS `enforce` destination with a bad certificate,
  not delivered either.
- **RL-T13.** `reset` with held mail refuses without `--discard-held`.
- **RL-T14.** A relay rebooted with no link comes back with its settings
  and accepts mail for known recipients.
- **RL-T15.** Two cluster nodes linked: 1,000 messages are each ingested
  once. A node killed mid-lease: its messages are taken by the other after
  the lease.
- **RL-T16.** `Relay/upgrade` with a bad signature, or with an older
  version, is refused.
- **RL-T17.** A held message from a sender that fails both SPF and DMARC, to
  a recipient removed since the last sync: no DSN is sent.
- **RL-T18.** The footprint budgets in RL-30 hold.
- **RL-T24.** A release tag publishes the `inbuxa-relay` image for both
  architectures and both binaries, and the relay image contains no server
  binary.
- **RL-T19.** The downstream's DNS publish with two relays keeps both MX
  records, at their preferences.
- **RL-T20.** Held mail over the downstream's reject threshold lands in
  Junk with the `X-Inbuxa-Relay` header, and no DSN is sent.
- **RL-T21.** inbuxa-admin warns when `liveVerdictTimeout` is under the
  downstream's `spamCallCeiling` plus 5 s.
- **RL-T22.** With two relays, one marked `inboundOnly`, every outbound
  message goes through the other, and SPF lists only the other's address.
- **RL-T23.** A node with no link to an enabled relay for an hour raises an
  alert.

## Decisions

Settled by John on 2026-10-29:

1. **Name.** "inbuxa Relay" in copy; `inbuxa-relay` for the binary and
   image. It lives in this workspace, not its own repository (RL-30), and
   ships as its own image and binaries at release time (RL-31).
2. **Held-mode door checks.** Domain, recipients, size and rate limits;
   DNSBL only when an administrator lists zones. No greylisting, no reverse
   DNS requirement (RL-14).
3. **Several relays per downstream.** Yes, each with its own settings, each
   serving one downstream. Outbound takes turns among linked relays;
   `inboundOnly` keeps one out of the rotation (RL-20).
4. **Live mode is in the first release.** Held mode is built first, but
   doesn't ship alone (see "Implementation status").
5. **`liveVerdictTimeout`.** 30 s by default, at most 120 s, and at least
   `spamCallCeiling` plus 5 s (RL-13).
6. **Link port.** 443, changed with `--link-listen` (RL-5).
7. **JMAP core.** The relay's own, not `jmap-proto` ("Footprint").
8. **`heldMaxAge`.** 30 days by default, at most 90, with a link-down alert
   after an hour.
9. **Held mail over the reject threshold.** Junk, with a header; never
   dropped, and no setting (RL-17).
10. **WebSocket transport.** HTTP/1.1, with blobs on separate connections
    (RL-5).

No questions are open.

## Implementation status

In progress. Done so far:

- `crates/relay-proto`: the link's shared types, joining, recipient
  hashing and sealing (PR #244).
- `crates/relay`: the relay binary, inbound in held and live mode (PR #245).
- On the downstream: `inbuxa:Relay` and its permissions, the link CA and
  sealing key, and join tokens. Status, `inbuxa:RelayMessage` and the link
  service are not done yet.

Order:

1. This spec (settled 2026-10-29).
2. The relay: the link (join, pins, settings, recipients) and held-mode
   inbound with the sealed spool. On the downstream: the link service,
   `inbuxa:Relay`, ingest with session context (RL-23).
3. Live mode (RL-12, RL-13). Steps 2 and 3 ship together: held mode alone
   can't refuse spam at the door, which the settings-only edge already can.
4. Outbound: `Outbound`, the `inbuxaRelay` route, status and DSNs, TLS-RPT
   events.
5. inbuxa-admin's Relays page, certificates (RL-27), DNS (RL-25), and
   upgrades (RL-29).
6. Packaging (RL-31, and an installer path) and a docs page. The edge-server page
   points to it.
