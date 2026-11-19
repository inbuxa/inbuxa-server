# Feature spec: client access through inbuxa-relay

Status: design note, 2026-11-19. Not approved, not scheduled. inbuxa-server
#484 (After 27.1), discussed on the forum (t/340). It builds on
`features/relay.md` and doesn't change any of that spec's rules.

## Provenance

inbuxa's own design. No upstream file or snippet was used. Sources:

| Source | Used for |
|---|---|
| `features/relay.md` (RL-1 to RL-35), and the relay code in `crates/relay`, `crates/relay-proto`, `crates/services/src/inbuxa_relay_link.rs` | The link, its identities and hardening, which this reuses |
| RFC 8446 §4.1.2 and RFC 6066 §3 (TLS ClientHello, server_name) | Reading the requested name without decrypting anything |
| HAProxy PROXY protocol, version 2 | Carrying the client's real address to the downstream |
| RFC 8659 (CAA), RFC 8657 (CAA `accounturi`, `validationmethods`) | Keeping a compromised relay from getting a certificate for the client names |
| This repository: listener `proxyTrustedNetworks`, `BlockedIps` (`crates/common/src/network/security.rs`), CAA records (`crates/common/src/network/dns/records.rs`) | What the downstream already has |

## The question

inbuxa-relay lets a server take mail without opening port 25: the server
dials out to a small relay on a public machine and keeps that link open. A
reader asked for the same for client access (webmail, JMAP, IMAP, CalDAV,
submission), so a server at home or in an office is reachable from outside
with no open port and no VPN.

#484 framed it as JMAP and webmail only, with passkey or token sign-in "so
the gateway never handles a reusable password". This note argues for a
different line: **the relay never decrypts client traffic at all**, and
then the protocol list stops being the hard part.

## Where TLS ends

There are two ways to build it, and they differ in what a compromised relay
gets.

**The relay ends TLS** (it holds the certificate for the client names, reads
requests, and sends them down the link). Even with passkeys:

- every session token and every OAuth access and refresh token passes
  through it in the clear. A passkey keeps the password safe, not the
  session. Whoever holds the relay holds every session signed in through it,
  for as long as the tokens last;
- every message, contact and calendar entry read through it is in the clear
  on the relay;
- passwords for IMAP, POP3 and submission are in the clear on it too, so
  those protocols would have to be left out.

That is a different class of box from today's relay. A compromised relay
today gets mail in flight, and nothing that lets anyone sign in as anyone
(relay.md, "Security considerations"). A terminating gateway would give
whoever takes it every account that signs in through it.

**The relay passes TLS through** (it reads only the unencrypted start of the
handshake to see which name is asked for, and copies the encrypted bytes to
the downstream, which ends TLS with its own certificate, as it does now).
The relay then sees client addresses, the names asked for, timing and
volume. It sees no password, token or content, for any protocol. IMAP and
submission become as safe to carry as JMAP.

The objection in #484 to passing through was that it's "a plain tunnel, and
generic tunnels already do that", and that commands sent before sign-in
still reach the server's parsers. Both are true, and neither is a reason
against it:

- **Parsers.** Behind a pass-through relay the server's IMAP, HTTP and SMTP
  parsers face the internet exactly as they would with the ports open. That
  is the bar every mail server meets today. The gateway doesn't raise or
  lower it. What it removes is the need for the protected network to accept
  connections at all. A gateway that parses and rebuilds each protocol to
  filter it would be a second IMAP, HTTP and SMTP implementation on a box
  that has to stay small (RL-3), and it would have to end TLS to do it.
- **Generic tunnels.** A hosted tunnel service either ends TLS itself (and
  sees everything) or carries only HTTPS. A tunnel built by hand (a small
  VPS, WireGuard, a TCP proxy) works, but leaves the operator to wire up the
  client's real address, ban lists, certificates and DNS. That is the same
  gap the relay closed for port 25 against the settings-only edge, and the
  case for building it is the same: one box the operator already runs, set
  up from inbuxa-admin, with each of those jobs done for them.

**Recommendation: pass-through only.** The relay never holds a certificate
for a client name and never ends a client's TLS. This becomes rule CG-1.

## Rules

These hold alongside RL-1 to RL-4. No setting turns them off.

- **CG-1. The relay never ends client TLS.** It reads the ClientHello's
  `server_name` to route and filter, and forwards the rest unread. It holds
  no certificate for a client name.
- **CG-2. Implicit TLS only.** The relay carries only ports whose
  connections start with TLS: HTTPS 443, IMAPS 993, submissions 465, and
  POP3S 995 only where the downstream has legacy protocols on. Never 143,
  110 or 587. Their STARTTLS start is in the clear, and passwords sent
  there by a misconfigured client would cross the relay readable.
- **CG-3. The downstream picks the target.** A forwarded connection names a
  target by id. The node maps the id to an address from its own settings,
  never from anything the relay sends. A compromised relay can reach only
  what an internet client could reach through it.
- **CG-4. The client's address reaches the downstream.** Each forwarded
  connection carries a PROXY protocol v2 header with the client's address.
  Without it every client would look like the node itself, and the
  server's per-address sign-in limits would ban the node.
- **CG-5. Off by default.** Client access is turned on per relay, per port,
  from inbuxa-admin.

## How a connection goes

```
 client ──TLS──▶ relay :443/:993/:465 ──bytes──▶ pooled stream (mTLS, dialed OUT by a node) ──▶ node ──PROXY v2 + bytes──▶ target listener
                 checks: blocked list, rate,                                                        (server listener, or the
                 name allowed (443)                                                                 install's front proxy)
```

1. A client connects to the relay on a client port. Before reading
   anything, the relay checks the source address against the blocked list
   the downstream pushed, and the per-address connection rate and count.
   Failing either closes the connection.
2. On 443 the relay reads the ClientHello (one TLS record, at most 16 KB,
   within 5 s) and takes `server_name`. A name not in the relay's list of
   client names closes the connection. On 993, 465 and 995 there is one
   target per port, and the name isn't checked.
3. The relay takes an idle **stream** from its pool. A stream is an mTLS
   connection a downstream node dialed to the link port (`GET /stream`,
   upgraded), authenticated by the node's link certificate like any link
   connection (RL-6), waiting to be used. The relay writes a short header
   (target id, client address and port, the relay's address) and then the
   bytes it has read so far, and from then on copies both ways.
4. The node reads the header, connects to the target's address from its own
   settings, writes a PROXY v2 header with the client's address, and copies
   both ways. The target ends TLS as it does now.
5. The node dials a new stream to keep its pool full.

If the pool is empty, the relay asks for more streams over the link's
WebSocket, and holds the client up to 5 s for one before closing.

**Why a pool of connections, not streams inside the WebSocket.** Carrying
many client connections inside the link's one WebSocket needs flow control
per stream, and a large download would hold up the link's own JMAP calls. A
connection per client stream, dialed ahead of time, needs no new framing,
adds no wait on connect, and matches how the link already carries blobs on
separate HTTP/1.1 connections (Decision 10). Each node keeps a few idle
streams (4 by default) and the relay spreads clients across nodes. Idle
streams are pinged like the link (RL-5).

**Long-lived connections.** IMAP IDLE and webmail push hold a connection
for hours. The relay sets no idle timeout of its own on a client stream.
TCP keepalive on both legs finds dead peers.

**HTTP/3.** QUIC is UDP and isn't carried. Clients fall back to TCP. The
target shouldn't advertise HTTP/3 (`Alt-Svc`) for the relayed names, or
clients will try it first and lose a few seconds.

## Targets

The downstream decides where each client port goes:

| Relay port | Default target | Alternative |
|---|---|---|
| 443 | The node's own HTTPS listener | The install's front proxy (webmail, console, server behind one name or several), by address |
| 993 | The node's IMAPS listener | — |
| 465 | The node's submissions listener | — |
| 995 | The node's POP3S listener, only with legacy protocols on | — |

For the node's own listeners, the node's addresses are added to the
listener's PROXY trusted networks automatically. For a front proxy, the
administrator confirms in inbuxa-admin that it takes PROXY v2 from the
nodes. Without that confirmation 443 doesn't turn on (CG-4).

## The names on 443

The relay forwards only the names it's given, for example `mail.example.com`
and `webmail.example.com`. The console's name is left off the list unless an
administrator adds it, so the console isn't put on the internet just because
webmail is.

A client can ask for one name in the TLS handshake and another in the HTTP
`Host` header. If the target serves the console and webmail on the same TLS
listener, it must refuse a `Host` that doesn't match the TLS name (answer
421), or a client could reach the console through an allowed name. The
server's own HTTPS listener would gain that check for relayed connections,
as part of this work. For a front proxy it's on the checklist inbuxa-admin
shows before 443 turns on.

## Certificates and CAA

The client names point at the relay's address, so whoever controls the relay
can answer an HTTP or TLS-ALPN challenge for them and get a valid
certificate from a public CA. With that, a compromised relay could end TLS
after all and read everything (CG-1 broken from outside).

The server already publishes, for domains whose certificates it manages, a
CAA record naming its CA and its ACME account (`accounturi`, RFC 8657). A CA
that honours it issues only to that account, so the relay can't get one.
Client access therefore needs:

- the domain's certificates and DNS both managed by the server, as the
  relay's own certificate already needs (RL-27);
- the CAA record in place before 443 turns on. The downstream checks it
  in public DNS and refuses to turn 443 on while it's missing;
- the downstream's certificates for the client names issued by DNS
  challenge, since an HTTP challenge would have to go through the relay. The
  CAA record then adds `validationmethods=dns-01` for those names.

A domain whose DNS isn't managed by the server can still use 993 and 465,
with a warning in inbuxa-admin that an unrestricted CAA leaves the names
open to a certificate from whoever runs the relay's address.

## DNS

The client names need A and AAAA records at the relay's address. For domains
whose DNS the server manages, the downstream publishes them when client
access turns on, and puts them back when it turns off, the way it publishes
MX and SPF for relays (RL-25). It also publishes SRV records for IMAP and
submission (RFC 6186) at the relay's name, so mail apps that look for them
find it.

**Clients on the protected network.** Once the names point at the relay,
clients inside the network also go out to the relay and back, unless local
DNS answers with the server's own address. inbuxa-admin says so when client
access turns on, with the records to add locally.

## What the relay learns from the downstream

Pushed over the link with the other settings:

- `clientAccess`: per port, on or off, and the target id; the list of names
  for 443;
- `clientLimits`: connections per address per minute (60), open connections
  per address (50), open client connections in all (2000);
- `blockedAddresses`: the downstream's blocked list (`BlockedIps`),
  changes pushed as they happen. An address the server blocks after failed
  sign-ins through the relay is then dropped at the relay, before it reaches
  the network.

The relay reports, as `RelayEvent`s: a connection refused for a blocked
address or a limit (counted, not each one), and a stream pool that ran dry.

## Footprint

No new dependency. In the relay: reading a ClientHello's `server_name`
(a small parser, without rustls), the stream pool, the copy loop
(`tokio::io::copy_bidirectional`), the client listeners, and the limits and
blocked list. In the server: the stream dialer and forwarder in the link
service, the PROXY v2 writer, settings on `inbuxa:Relay`, and a Client
access section on the console's Relays page. Rough size: 1,000 to 1,500
lines in all. RL-3's budgets for binary size and idle memory are unchanged.
Memory per open client connection is two socket buffers, so the 50-session
budget gains a client-connection one: 500 open client connections within
64 MB more.

## Bandwidth

Every byte a client reads crosses the protected network's uplink and then
the relay's. A mailbox opened from outside costs the downstream's upload
bandwidth, which on a home connection is often a tenth of the download.
inbuxa-admin shows client traffic per relay, so it's visible before it's a
surprise.

## Security considerations

- **A compromised relay** gets, in addition to what relay.md lists: client
  addresses, the names they ask for, and the timing and size of their
  traffic. It doesn't get passwords, tokens, or content (CG-1), and can't
  get a certificate for the names while the CAA record holds. It can drop or
  delay connections, and it can write a false client address into the
  header, which could get an innocent address blocked or let one address
  get round per-address limits. A relay that can do that can already stop
  client access outright, so this adds no new reach.
- **No path in.** Still none. Streams are dialed out by the nodes, and they
  reach only the targets the downstream names (CG-3).
- **Exposure.** The targets' parsers face the internet as they would with
  the ports open. Turning client access on is the same decision as opening
  those ports, and inbuxa-admin says so.
- **Port 25 and 465.** Port 25 is unchanged. 465 at the relay is the
  downstream's own submission listener: sign-in happens there, end to end.
  The relay still offers no AUTH of its own (RL-4).
- **The console.** It isn't forwarded unless its name is added (see "The
  names on 443").
- **Sign-in limits.** They work per client address, through CG-4. A target
  that ignores the PROXY header would rate-limit the node itself. The
  automatic trusted-network setting covers the server's own listeners.

## A first step without code

Everything above can be done by hand today, with a small VPS, WireGuard
(relay.md RL-32) and any TCP proxy that sends the PROXY protocol and routes
by TLS name. A docs page with that recipe would answer the forum question
now, show whether people use it, and give the built version a test to
match. Recommended before any code.

## Acceptance tests (if built)

- **CG-T1.** A client on 993 signs in to IMAP through the relay. The
  server sees the client's address, not the node's, and the bytes the relay
  forwards after the ClientHello are the client's TLS records, unchanged.
- **CG-T2.** On 443, a ClientHello for a name not on the list is closed
  without a reply. One for an allowed name reaches the target and completes
  TLS with the downstream's certificate.
- **CG-T3.** An address the server blocks after failed sign-ins is refused
  at the relay within one push.
- **CG-T4.** A connection asking for the webmail name with `Host:` set to
  the console's name gets 421 from the server's HTTPS listener.
- **CG-T5.** 443 refuses to turn on while the domain has no CAA record with
  `accounturi`.
- **CG-T6.** With the stream pool empty and no node linked, a client is
  closed after 5 s. With a node linked, it's served within the link's
  round trip.
- **CG-T7.** An IMAP IDLE connection through the relay stays open for 2
  hours.
- **CG-T8.** The relay is asked for a target id the node doesn't have. The
  node closes the stream, and connects nowhere.
- **CG-T9.** Ports 143, 110 and 587 can't be turned on for client access
  (refused by the server and by the relay).

## Open questions

For John. A recommended answer is given for each.

1. **Pass-through only, never ending TLS (CG-1)?** This replaces #484's
   "JMAP and webmail with passkey sign-in". Recommended: yes.
2. **Which ports?** Recommended: 443, 993 and 465; 995 only with legacy
   protocols on; never the STARTTLS ports (CG-2).
3. **Sharing 443 with the link.** Both default to 443. Recommended: one
   listener, split by TLS name, the link on a name of its own, when they
   share an address. When the link runs over WireGuard (RL-32) they're
   apart anyway.
4. **The CAA check as a hard stop for 443 (CG-T5)?** Recommended: yes.
5. **Managing the client names' A and AAAA records.** Recommended: yes for
   domains whose DNS the server manages, with the inside-network note.
6. **The docs recipe first?** Recommended: yes, and decide on building it
   after seeing who uses it.
7. **Milestone.** Recommended: stays in After 27.1, unscheduled until 6 has
   an answer.
