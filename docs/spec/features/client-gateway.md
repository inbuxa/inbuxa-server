# Feature spec: client access through inbuxa-relay

Status: design note, 2026-11-19, revised 2026-11-21 to cover both modes,
2026-11-24 for sign-in choices through a terminating relay (t/340 post
11), and 2026-11-25 after a review of the note (t/340 post 13): quarantine
and rejoin are separate permissions, client tokens never trigger a
quarantine, the ClientHello is reassembled, worker isolation is tested,
strict CAA on every port is an option, and outside blocklists feed the
blocked-address list. Questions 1 to 13 answered 2026-11-21 (all as
recommended, 6 refined 2026-11-25 for the split keys); 14 and 15 are open.
Still a suggestion: not approved, not planned, not scheduled.
inbuxa-server #484 (milestone 27.7), discussed on the forum (t/340). It
builds on
`features/relay.md` and doesn't change any of that spec's rules.

## Provenance

inbuxa's own design. No upstream file or snippet was used. Sources:

| Source | Used for |
|---|---|
| `features/relay.md` (RL-1 to RL-36), and the relay code in `crates/relay`, `crates/relay-proto`, `crates/services/src/inbuxa_relay_link.rs` | The link, its identities and hardening, which this reuses |
| RFC 8446 §4.1.2 and RFC 6066 §3 (TLS ClientHello, server_name) | Reading the requested name without decrypting anything |
| HAProxy PROXY protocol, version 2 | Carrying the client's real address to the downstream |
| RFC 8659 (CAA), RFC 8657 (CAA `accounturi`, `validationmethods`) | Keeping a compromised relay from getting a certificate for the client names |
| RFC 9112 §6.3 and §11.2 (message body length, request smuggling) | What a terminating relay refuses before rebuilding a request |
| RFC 7009 (token revocation), as built in #427 | Why sessions in terminating mode are bound to a relay instead of revoked one by one |
| This repository: listener `proxyTrustedNetworks`, `BlockedIps` (`crates/common/src/network/security.rs`), CAA records (`crates/common/src/network/dns/records.rs`), OAuth revocation (`crates/common/src/auth/oauth/revoke.rs`) | What the downstream already has |
| Forum t/340, posts 6 and 8 | The case for terminating mode, stateless relays, and detection and response |
| Forum t/340, post 13 | Separate quarantine and rejoin permissions, client tokens kept out of the quarantine triggers, fragmented ClientHello tests, strict CAA on every port, worker isolation tests, outside blocklists |
| RFC 8446 §5.1 (record layer: a handshake message may span records) | Why the ClientHello is reassembled before `server_name` is read |

## The question

inbuxa-relay lets a server take mail without opening port 25: the server
dials out to a small relay on a public machine and keeps that link open. A
reader asked for the same for client access (webmail, JMAP, IMAP, CalDAV,
submission), so a server at home or in an office is reachable from outside
with no open port and no VPN.

#484 framed it as JMAP and webmail only, with passkey or token sign-in "so
the gateway never handles a reusable password". The first version of this
note argued for the opposite line, a relay that never decrypts client
traffic. The forum discussion made the case for the other side too, and
both are worth having. This version covers both, chosen per port.

## Two modes

The difference is where client TLS ends, and that decides what a
compromised relay gets and what an attacker on the internet can reach.

**Pass-through.** The relay reads only the unencrypted start of the
handshake to see which name is asked for, and copies the encrypted bytes to
the downstream, which ends TLS with its own certificate, as it does now. The
relay sees client addresses, the names asked for, timing and volume. It
sees no password, token or content, for any protocol. IMAP and submission
are as safe to carry as JMAP.

The cost: the server's IMAP, HTTP and SMTP parsers face the internet
exactly as they would with the ports open. An exploit for one of them
reaches the server, just through a tunnel. What pass-through removes is
the need for the protected network to accept connections at all.

**Terminating.** The relay holds a certificate for the client names, ends
TLS, parses each request completely, and sends the downstream a request it
has rebuilt itself, never the client's bytes. This is what the relay
already does for port 25: it speaks SMTP to the world and hands mail over
the link, so an exploit aimed at its SMTP parser lands on the relay, not
the server. Here the same holds for HTTP. To reach the server an attacker
needs a second exploit, one that works through a well-formed request.

The cost: everything that passes through the relay is in the clear on it.
Whoever takes the relay sees every message read through it, and every
session token, for as long as they hold it. Passwords sent through it are
exposed too, which is why terminating mode refuses them (CG-7).

| | Pass-through | Terminating |
|---|---|---|
| A compromised relay sees | Addresses, names, timing | All of that, plus content and session tokens while it's held |
| A parser exploit lands on | The server | The relay |
| Protocols | 443, 993, 465 (995 with legacy on) | 443 (JMAP, webmail, DAV) at first |
| Sign-in | Anything the server allows, end to end | Chosen per relay; no password crosses it in the clear (CG-7, CG-13, CG-14) |
| Certificates for client names | Only on the downstream | A short-lived one on the relay, key made there (CG-9) |
| Fits | Few users, or content that matters more than the server | Many users, or a server that matters more than one session |

Pass-through is also the answer where rules require two-factor sign-in.
The relay never sees the sign-in, so OAuth with a second factor,
OAUTHBEARER on IMAP and submission, passkeys, and the server's own token
lifetimes all work exactly as they would on a direct connection.

Neither is wrong. Which one is worth more depends on what is being
protected. For one person on their own server, a taken relay and a taken
server are close to the same loss, and pass-through costs less. For an
office with many accounts, keeping the server out of reach of a single
exploit is worth a box that sees traffic while it's compromised, provided
that box is small, holds nothing, can be cut off at once, and comes back
clean (see "Detection and response").

**Recommendation: both, chosen per port, pass-through by default.**
Pass-through is built first. Terminating comes second, for 443 only at
first, as its own build of the relay (see "Footprint"). The one mix within
a port: a terminating 443 can pass the sign-in name through (CG-13).

## Rules

These hold alongside RL-1 to RL-4. No setting turns them off.

For both modes:

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
  connection carries the client's address: a PROXY protocol v2 header in
  pass-through, a field in the stream header in terminating mode. Without
  it every client would look like the node itself, and the server's
  per-address sign-in limits would ban the node.
- **CG-5. Off by default.** Client access is turned on per relay, per port,
  from inbuxa-admin, and each port says which mode it uses.

Pass-through:

- **CG-1. A pass-through port never ends client TLS.** The relay reads the
  ClientHello's `server_name` to route and filter, and forwards the rest
  unread. It holds no certificate for a name it passes through.

Terminating:

- **CG-6. Rebuilt, never forwarded.** The relay sends the downstream only
  requests it has parsed in full and written out again in one canonical
  form. No byte from the client reaches the downstream unparsed. Anything
  it can't parse, or that is ambiguous, is refused at the relay.
- **CG-7. No reusable secret.** A terminating name refuses password
  sign-in: HTTP Basic, the OAuth password form, and any other form that
  sends a password. Sign-in is by passkey, by the server's normal sign-in
  done on a name the relay doesn't terminate (CG-13), or with a token
  already bound to this relay (CG-8). Which of these a relay accepts is
  chosen per relay (see "Sign-in through a terminating relay"). A passkey
  assertion is bound to its challenge and can't be replayed, so a relay
  that sees one gains nothing lasting.
- **CG-8. Sessions belong to a relay generation.** Every token issued
  through a terminating relay carries the relay's id and generation, and
  the server accepts it only through that relay and generation. A new
  generation (rebuild, rejoin, quarantine) makes all of them useless at
  once, with no list of tokens to revoke. A token issued anywhere else is
  refused on a terminating port, so tokens from inside the network never
  cross the relay.
- **CG-9. The relay's certificate key never leaves it.** The relay makes a
  key for the client names on start, keeps it in memory, and sends the
  downstream a certificate request over the link. The downstream orders the
  certificate by DNS challenge with its own ACME account (so the CAA record
  is unchanged, see "Certificates and CAA"), at the shortest lifetime the CA
  offers, and pushes back the certificate only. This differs from RL-27,
  where the downstream pushes the SMTP certificate's key; that one stays as
  it is.
- **CG-10. Nothing kept.** A terminating relay writes nothing about client
  traffic to disk: no cache, no log of content or tokens, no session state.
  Its image runs with a read-only root. A restart or rebuild loses nothing
  that matters, and a compromise doesn't survive one.
- **CG-11. One worker per client connection.** Each client connection is
  parsed in its own sandboxed worker process, with no access to other
  connections, the link credentials, or the certificate key. The worker
  hands rebuilt requests to the relay's main process over a pipe. Breaking
  a worker gives an attacker their own connection and nothing else. "No
  access" is checked, not assumed: a worker inherits no file descriptor
  but its client socket and its pipe (everything else is close-on-exec),
  and runs with limits on memory, open files, CPU time and processes, so
  one connection that hits a limit ends that worker and nothing else.
- **CG-12. Can be cut off at once.** The downstream can quarantine a relay
  in one step, from inbuxa-admin or with an API key that holds only that
  permission (see "Detection and response").
- **CG-13. The sign-in page is never terminated.** When a relay offers the
  server's normal sign-in, the server's authorization pages are served on
  a name of their own that the relay passes through (CG-1), even on a
  relay whose other 443 names terminate. The password and second factor go
  end to end to the server, as in pass-through. Only the token that comes
  out of it is used on the terminating name, bound to the relay (CG-8).
- **CG-14. Tokens through a terminating relay are short.** Each relay has
  its own cap on how long a session issued through it lasts, refreshes
  included, set in inbuxa-admin. Default 12 hours. After that the client
  signs in again. The server's normal token lifetimes are unchanged for
  everything else.

## How a connection goes

### Pass-through

```
 client ──TLS──▶ relay :443/:993/:465 ──bytes──▶ pooled stream (mTLS, dialed OUT by a node) ──▶ node ──PROXY v2 + bytes──▶ target listener
                 checks: blocked list, rate,                                                        (server listener, or the
                 name allowed (443)                                                                 install's front proxy)
```

1. A client connects to the relay on a client port. Before reading
   anything, the relay checks the source address against the blocked list
   the downstream pushed, and the per-address connection rate and count.
   Failing either closes the connection.
2. On 443 the relay reads the ClientHello (at most 16 KB in all, within
   5 s), reassembling it when it arrives split over several TLS records or
   TCP segments, which RFC 8446 §5.1 allows, and takes `server_name`. A
   ClientHello that isn't complete in that size and time closes the
   connection. A name not in the relay's list of
   client names closes the connection. On 993, 465 and 995 there is one
   target per port, and the name isn't checked.
3. The relay takes an idle **stream** from its pool. A stream is an mTLS
   connection a downstream node dialed to the link port (`GET /stream`,
   upgraded), authenticated by the node's link certificate like any link
   connection (RL-6), waiting to be used. The relay writes a short header
   (mode, target id, client address and port, the relay's address) and
   then the bytes it has read so far, and from then on copies both ways.
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

### Terminating

```
 client ──TLS──▶ relay :443 ──▶ worker (one per connection, sandboxed) ──rebuilt requests──▶ relay main ──▶ pooled stream ──▶ node ──▶ server HTTP service
                 ends TLS        parses, refuses, rebuilds (CG-6)                                                  re-checks canonical form,
                 (CG-9 cert)                                                                                       relay id + generation (CG-8)
```

1. Steps 1 and 2 above, then the relay ends TLS with its own short-lived
   certificate (CG-9) and hands the connection to a fresh worker (CG-11).
2. The worker parses HTTP/1.1 or HTTP/2 from the client and refuses, with
   no request sent on: a request with both `Content-Length` and
   `Transfer-Encoding`, repeated or malformed length headers, obsolete line
   folding, bare CR or LF, a path outside the allowed set (JMAP, its
   WebSocket, `.well-known`, webmail, and DAV if turned on), a header
   section or body over the limits, and a JMAP body that isn't valid JSON
   or is nested deeper than the server accepts. Compressed request bodies
   are refused.
3. The worker writes the request out again: method, normalized path,
   headers from an allow list with values re-encoded, JSON bodies
   re-serialized. The relay sends it on a stream with a header saying it
   was terminated, the client's address, and the relay's id and generation.
   Responses come back from the downstream and are passed to the client
   as they are; they come from the trusted side.
4. The node checks that each request is already in canonical form, so
   rebuilding it again would change nothing. A relay sending anything else
   has been tampered with, and the node quarantines it (see "Detection and
   response"). The node hands the request to its own HTTP service, marked
   as coming through that relay and generation, and the service applies
   CG-7 and CG-8.

JMAP over WebSocket (RFC 8887) is parsed and rebuilt one message at a time
the same way. Event streams and blob downloads are responses and pass
straight back.

**What the protocol break does and doesn't stop.** It stops anything that
lives in framing and encoding: request smuggling, header tricks, malformed
TLS, HTTP/2 frame floods, oversized or broken JSON. These end at a worker.
It doesn't stop a bug the server has with a well-formed request, since the
relay rebuilds that faithfully. That's the "second exploit" an attacker
still needs.

**IMAP and submission.** Not terminated at first. Doing it means an IMAP
and SMTP submission parser in the relay (the workspace's own `imap-proto`
and `smtp-proto` would do; a bug in the shared parser then fires on the
relay, and the server only sees the rebuilt command). The harder part is
sign-in: most IMAP and submission clients send passwords, which CG-7
forbids. Clients that can do OAuth (OAUTHBEARER) would use the sign-in name
(CG-13). For the rest, app passwords bound to the relay like tokens (CG-8)
could stand in. Listed as an open question.

## Sign-in through a terminating relay

Raised on t/340: rules that require two-factor sign-in mostly mean OAuth,
nobody keeps a second password just for the relay, and a static app
password is weaker than a short-lived token. So a terminating relay offers
a choice rather than one fixed method, and the admin picks what each relay
accepts:

- **Passkeys.** On by default. Nothing reusable crosses the relay.
- **The server's normal sign-in.** Off by default. The client is sent to
  the sign-in name (CG-13), where the user signs in as they would anywhere
  else, second factor included. The token issued is bound to the relay
  (CG-8) and capped by CG-14. This is the one to use where policy requires
  two-factor sign-in.
- **App passwords bound to the relay.** Only once IMAP and submission are
  terminated (question 3), for clients that can't do OAuth. Each one is
  shown once, works only through that relay and generation, and is capped
  by CG-14 like a token.

Users can narrow this for their own account (passkeys only, or no access
through the relay at all) but can't widen it past what the admin allows.

The limit is the clients. Many desktop and phone mail apps only do OAuth
for a handful of large providers they know by name, so for IMAP the app
password may stay the fallback in practice. Webmail and JMAP clients that
use the browser for sign-in don't have that problem.

## Detection and response

A terminating relay is only as good as how fast a compromised one is cut
off and replaced. Pass-through relays get the same tools, since a taken one
can still drop traffic and forge client addresses.

**Quarantine.** One update on `inbuxa:Relay` (`quarantine: true`), from
inbuxa-admin or through the API with a key holding only
`sysRelayQuarantine`. It:

- drops the relay's link and every stream, and the nodes stop dialing it;
- starts a new generation, so every token bound to the old one is refused
  (CG-8);
- asks the CA to revoke the client-name certificates issued for it;
- withdraws its A, AAAA and MX records where the server manages DNS, if
  another relay is still serving;
- forgets its link identity, so it can only come back by joining again with
  a new token, as a fresh install.

**What can trigger it.**

- An administrator.
- The downstream itself, on things a healthy relay never does: a
  terminating stream that isn't in canonical form, a request on a port
  that is off, a link message outside the protocol. Only what the relay
  itself produces counts. Anything a client controls never triggers a
  quarantine, or a client could take the relay down at will: a token for
  another relay or an older generation is what every phone holds after a
  rebuild, so it's refused (CG-8) and counted, and a burst of them raises a
  `RelayEvent` for the admin, nothing more.
- A monitor watching the relay's host. The quarantine key is meant for
  this. The Cairn OBS agent is the first one to wire up: on a relay host it
  can watch for processes that shouldn't run, files changed on a read-only
  root, outbound connections other than the link and port 25 delivery, and
  the relay binary's hash, and a Cairn OBS alert can call the quarantine.
  inbuxa doesn't depend on it; any monitor that can make an HTTP call can
  do the same.

**Coming back clean.** Since the relay keeps nothing (CG-10), recovery is a
rebuild from the signed image and a new join. Whatever runs the relay does
the rebuild: Kubernetes, a systemd unit with a fresh image, a VPS restored
from a snapshot. A second scoped key, holding only `sysRelayRejoin`, can
ask for a join token (the `rejoin: true` update on `inbuxa:Relay` from
`features/relay.md`, which otherwise needs `sysRelayUpdate`), so an
orchestrator can rebuild and rejoin with no one at a keyboard. The two
permissions are never on one key: the quarantine key sits on a monitoring
system, and if that system is taken it must not be able to cut a relay off
and then join one of its own in its place. The rejoin key belongs to
whatever rebuilds the relay, and every join token it asks for is logged and
shown in inbuxa-admin. A relay can also be rebuilt on a schedule, so a
compromise nobody noticed still has a shelf life. CA rate limits cap how
often the same names can be issued (Let's Encrypt allows 5 a week for an
identical set), so a scheduled rebuild defaults to weekly where it's turned
on.

**Outside blocklists.** Tools such as CrowdSec judge client addresses, not
the relay. Their decisions belong in the blocked-address list this design
has the downstream push to the relay (`blockedAddresses`, checked in step 1
of "How a connection goes"), not in a quarantine. That list is the
server's `BlockedIps`, so an outside tool adds to it the way the server's
own bans after failed sign-ins do: a `BlockedIp` entry with an expiry,
made through the API with a key holding only `sysBlockedIpCreate`.
Quarantine stays for credible evidence that the relay itself is
compromised.

**Further out.** Several relays already serve one downstream (RL-25). With
the Kubernetes recipe, terminating relays could run as short-lived pods,
replaced every few hours, with clients spread across them. One relay per
user or per client address goes further still: a compromised one holds
only the attacker's own traffic. That's a lot of machinery for most
installs, and it isn't part of this design, but nothing here rules it out:
CG-11 is the same idea inside one box.

## Targets

The downstream decides where each client port goes:

| Relay port | Mode | Default target | Alternative |
|---|---|---|---|
| 443 | Pass-through | The node's own HTTPS listener | The install's front proxy (webmail, console, server behind one name or several), by address |
| 443 | Terminating | The node's own HTTP service, in process | inbuxa-webmail, once it accepts relay-bound sessions |
| 993 | Pass-through | The node's IMAPS listener | — |
| 465 | Pass-through | The node's submissions listener | — |
| 995 | Pass-through | The node's POP3S listener, only with legacy protocols on | — |

For the node's own listeners, the node's addresses are added to the
listener's PROXY trusted networks automatically. For a front proxy, the
administrator confirms in inbuxa-admin that it takes PROXY v2 from the
nodes. Without that confirmation 443 doesn't turn on (CG-4). A front proxy
can't be the target of a terminating port, since the server must see the
relay's id and generation to apply CG-8.

## The names on 443

The relay forwards only the names it's given, for example `mail.example.com`
and `webmail.example.com`. The console's name is left off the list unless an
administrator adds it, so the console isn't put on the internet just because
webmail is. In terminating mode the console can't be added at all.

A client can ask for one name in the TLS handshake and another in the HTTP
`Host` header. In terminating mode the worker refuses a mismatch itself.
In pass-through, if the target serves the console and webmail on the same
TLS listener, it must refuse a `Host` that doesn't match the TLS name
(answer 421), or a client could reach the console through an allowed name.
The server's own HTTPS listener would gain that check for relayed
connections, as part of this work. For a front proxy it's on the checklist
inbuxa-admin shows before 443 turns on.

## Certificates and CAA

The client names point at the relay's address, so whoever controls the relay
can answer an HTTP or TLS-ALPN challenge for them and get a valid
certificate from a public CA. With that, a compromised pass-through relay
could end TLS after all and read everything (CG-1 broken from outside), and
a compromised terminating relay could keep a certificate past its
quarantine.

The server already publishes, for domains whose certificates it manages, a
CAA record naming its CA and its ACME account (`accounturi`, RFC 8657). A CA
that honors it issues only to that account, so the relay can't get one.
Client access in either mode therefore needs:

- the domain's certificates and DNS both managed by the server, as the
  relay's own certificate already needs (RL-27);
- the CAA record in place before 443 turns on. The downstream checks it
  in public DNS and refuses to turn 443 on while it's missing;
- the certificates for the client names issued by DNS challenge, since an
  HTTP challenge would have to go through the relay. The CAA record then
  adds `validationmethods=dns-01` for those names.

In terminating mode the relay's certificate comes from that same account,
on the relay's own key (CG-9). A taken relay holds its current certificate
until it expires or is revoked at quarantine, and can't get another.

A domain whose DNS isn't managed by the server can still use pass-through on
993 and 465, with a warning in inbuxa-admin that an unrestricted CAA leaves
the names open to a certificate from whoever runs the relay's address.

**Strict CAA.** An admin can make the CAA check a hard stop on every client
port, not just 443. Then 993, 465 and 995 also refuse to turn on until
public DNS shows a CAA record naming the server's ACME account. That works
for a domain whose DNS is managed elsewhere too: inbuxa-admin shows the
record to add by hand, and the downstream checks it the same way. Off by
default, so the existing warning-only behavior is unchanged (question 15).

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
access turns on, with the records to add locally. With a terminating 443
this matters more: a token issued inside the network is refused through the
relay (CG-8), so a laptop that moves between the two signs in again.

## What the relay learns from the downstream

Pushed over the link with the other settings:

- `clientAccess`: per port, on or off, the mode, and the target id; the
  list of names for 443; in terminating mode, the sign-in methods accepted,
  the sign-in name if the normal sign-in is on, and the session cap
  (CG-14);
- `clientLimits`: connections per address per minute (60), open connections
  per address (50), open client connections in all (2000), and in
  terminating mode the request limits (header section 16 KB, body 10 MB
  outside uploads, JSON depth);
- `blockedAddresses`: the downstream's blocked list (`BlockedIps`),
  changes pushed as they happen. An address the server blocks after failed
  sign-ins through the relay is then dropped at the relay, before it reaches
  the network;
- in terminating mode, the relay's generation and its certificate.

The relay reports, as `RelayEvent`s: a connection refused for a blocked
address or a limit (counted, not each one), a stream pool that ran dry, and
in terminating mode requests refused by a worker (counted by reason) and
workers that crashed. A run of crashing workers is worth an alert of its
own; it's what probing for a parser bug looks like.

## Footprint

**Pass-through.** No new dependency. In the relay: reading a ClientHello's
`server_name` (a small parser, without rustls), the stream pool, the copy
loop (`tokio::io::copy_bidirectional`), the client listeners, and the limits
and blocked list. In the server: the stream dialer and forwarder in the link
service, the PROXY v2 writer, settings on `inbuxa:Relay`, and a Client
access section on the console's Relays page. Rough size: 1,000 to 1,500
lines in all. RL-3's budgets for binary size and idle memory are unchanged.
Memory per open client connection is two socket buffers, so the 50-session
budget gains a client-connection one: 500 open client connections within
64 MB more.

**Terminating.** An HTTP server, which RL-3 rules out for the relay. So
it's a build feature, `client-gateway`, shipped as its own image and
binaries (`inbuxa-relay-gateway`) from the same tag (RL-31), and the
default relay keeps RL-3's budgets. It adds hyper's HTTP/2 server, the
request rebuilder, the worker sandbox (seccomp and a process per
connection), and certificate requests over the link. In the server: the
canonical-form check, relay-bound tokens, quarantine, and the two scoped
permissions. Rough size: another 3,000 to 4,000 lines. A worker per
connection costs a process each; at 500 connections that's measured before
it's promised.

## Bandwidth

Every byte a client reads crosses the protected network's uplink and then
the relay's. A mailbox opened from outside costs the downstream's upload
bandwidth, which on a home connection is often a tenth of the download.
inbuxa-admin shows client traffic per relay, so it's visible before it's a
surprise.

## Security considerations

- **A compromised pass-through relay** gets, in addition to what relay.md
  lists: client addresses, the names they ask for, and the timing and size
  of their traffic. It doesn't get passwords, tokens, or content (CG-1), and
  can't get a certificate for the names while the CAA record holds.
- **A compromised terminating relay** gets, while it's held, the content of
  every request and response through it, and the relay-bound tokens of
  everyone signed in through it. It doesn't get passwords (CG-7, CG-13),
  tokens that work anywhere else (CG-8) or for longer than the relay's cap
  (CG-14), anything from before its last rebuild (CG-10), or a way to keep
  its access past quarantine. Breaking one worker
  gives only that connection (CG-11). This is the price of the mode, and
  inbuxa-admin says so when it's turned on.
- **Either kind** can drop or delay connections, and write a false client
  address, which could get an innocent address blocked or let one address
  get round per-address limits. A relay that can do that can already stop
  client access outright, so this adds no new reach.
- **No path in.** Still none. Streams are dialed out by the nodes, and they
  reach only the targets the downstream names (CG-3).
- **Exposure.** In pass-through the targets' parsers face the internet as
  they would with the ports open; turning it on is the same decision as
  opening those ports, and inbuxa-admin says so. In terminating mode the
  server's HTTP parser faces only the relay's rebuilt requests.
- **Port 25 and 465.** Port 25 is unchanged. 465 at the relay is the
  downstream's own submission listener: sign-in happens there, end to end.
  The relay still offers no AUTH of its own (RL-4).
- **The console.** It isn't forwarded unless its name is added (see "The
  names on 443"), and never in terminating mode.
- **Sign-in limits.** They work per client address, through CG-4. A target
  that ignores the PROXY header would rate-limit the node itself. The
  automatic trusted-network setting covers the server's own listeners.
- **A fake sign-in form.** A taken terminating relay controls what it
  serves on the names it terminates, so it could show its own password
  form there instead of sending the client to the sign-in name. CG-13
  keeps passwords off the relay in normal running; it can't stop a
  compromised relay from asking for one. That's part of why passkeys stay
  the default, and why the normal sign-in is something the admin turns on.
- **The quarantine key.** Whoever holds it can take client access down, but
  can't read or change anything else, and can't bring a relay back: joining
  needs the separate rejoin key. That's the right trade for a key that sits
  on a monitoring system.
- **The rejoin key.** Whoever holds it can ask for join tokens, so it's as
  sensitive as the machine that rebuilds relays, and kept there. Each token
  it asks for is logged and shown in inbuxa-admin.
- **Clients trying to trip a quarantine.** Nothing a client sends counts as
  evidence against the relay (see "What can trigger it"), so a client can't
  turn a quarantine into a denial of service.

## A first step without code

Pass-through can be done by hand today, with a small VPS, WireGuard
(relay.md RL-32) and any TCP proxy that sends the PROXY protocol and routes
by TLS name. A docs page with that recipe would answer the forum question
now, show whether people use it, and give the built version a test to
match. Recommended before any code.

Terminating mode has no by-hand equivalent with the same guarantees. A
reverse proxy on a VPS ends TLS, but sessions aren't bound to it and there
is nothing to cut it off with, so it's the worst case of both modes. The
docs page shouldn't suggest it.

## Acceptance tests (if built)

Pass-through:

- **CG-T1.** A client on 993 signs in to IMAP through the relay. The
  server sees the client's address, not the node's, and the bytes the relay
  forwards after the ClientHello are the client's TLS records, unchanged.
- **CG-T2.** On 443, a ClientHello for a name not on the list is closed
  without a reply. One for an allowed name reaches the target and completes
  TLS with the downstream's certificate.
- **CG-T3.** An address the server blocks after failed sign-ins, and one an
  outside tool adds as a `BlockedIp` through the API, are each refused at
  the relay within one push.
- **CG-T4.** A connection asking for the webmail name with `Host:` set to
  the console's name gets 421 from the server's HTTPS listener.
- **CG-T5.** 443 refuses to turn on, in either mode, while the domain has no
  CAA record with `accounturi`.
- **CG-T6.** With the stream pool empty and no node linked, a client is
  closed after 5 s. With a node linked, it's served within the link's
  round trip.
- **CG-T7.** An IMAP IDLE connection through the relay stays open for 2
  hours.
- **CG-T8.** The relay is asked for a target id the node doesn't have. The
  node closes the stream, and connects nowhere.
- **CG-T9.** Ports 143, 110 and 587 can't be turned on for client access
  (refused by the server and by the relay).
- **CG-T21.** A ClientHello split over two or more TLS records, one sent a
  byte per TCP segment, and one with a post-quantum key share large enough
  to need more than one segment are each routed exactly like the same
  ClientHello sent whole. One that isn't complete within 16 KB or 5 s is
  closed. The ClientHello reader is a fuzzing target, with these cases in
  its seed corpus.
- **CG-T22.** With strict CAA on, 993 and 465 (and 995 with legacy
  protocols on) refuse to turn on while public
  DNS has no CAA record naming the server's account, including for a domain
  whose DNS is managed elsewhere, and turn on once the record is there.
  With it off, they turn on with the warning.

Terminating:

- **CG-T10.** Requests with both `Content-Length` and `Transfer-Encoding`,
  with two `Content-Length`s, with a bare LF, and with broken JSON are each
  refused at the relay, and the server's HTTP service receives nothing.
- **CG-T11.** A JMAP session through the relay works end to end, and every
  request the server receives is byte-identical to rebuilding it again.
- **CG-T12.** A stream from the relay carrying a request that isn't in
  canonical form quarantines the relay.
- **CG-T13.** Password sign-in through a terminating port is refused in
  every form. Passkey sign-in works and returns a token bound to the relay.
- **CG-T14.** A token bound to relay R generation G is refused through
  relay R2, through R after a new generation, and on the server directly. A
  token issued inside the network is refused through R.
- **CG-T15.** A quarantine through the quarantine key drops the link and
  every stream within 5 s, refuses the old tokens, requests revocation of
  the certificate, and the relay can't link again until it rejoins. The
  same key is refused when it asks for a join token; only a key holding
  `sysRelayRejoin` gets one, and the request shows in inbuxa-admin.
- **CG-T23.** Clients sending tokens from an older generation, from
  another relay, and from inside the network, a thousand a minute, are
  each refused, and the relay is not quarantined; a `RelayEvent` reports
  the burst.
- **CG-T24.** A worker's open file descriptors are its client socket, its
  pipe and nothing else. A worker that allocates past its memory limit,
  opens files past its limit, spins past its CPU limit or tries to fork
  ends alone, and the other connections on the relay carry on.
- **CG-T16.** The relay's state directory and logs never hold the
  certificate key, a token, or request content, after a session that used
  all three.
- **CG-T17.** A worker that crashes mid-request takes down only its own
  connection, and is reported in a `RelayEvent`.
- **CG-T18.** With the normal sign-in on, a client on a terminating name is
  sent to the sign-in name, completes TLS there with the downstream's
  certificate, signs in with a password and second factor, and gets a
  token that works on the terminating name and is refused through any
  other relay or generation.
- **CG-T19.** A token issued through a relay with a 1-hour cap stops
  working after an hour, and can't be refreshed past it.
- **CG-T20.** With the normal sign-in off, the sign-in name isn't served
  and the relay accepts passkeys only. A user who set their account to
  passkeys only can't use the normal sign-in through a relay that allows
  it.

## Questions

Answered by John on 2026-11-21: all as recommended below. That settles the
shape of the proposal; it doesn't schedule the work, which stays a
suggestion open for discussion on the forum (t/340).

1. **Both modes, chosen per port, pass-through by default?** Recommended:
   yes, pass-through built first, terminating second.
2. **Which ports in each mode?** Recommended: pass-through on 443, 993 and
   465, 995 only with legacy protocols on, never the STARTTLS ports
   (CG-2); terminating on 443 only to start.
3. **IMAP and submission in terminating mode later?** Only with app
   passwords bound to the relay, since CG-7 rules out real passwords.
   Recommended: decide after terminating 443 has been used for a while.
4. **Passkeys only for sign-in through a terminating port (CG-7)?**
   Recommended: yes. Allowing passwords there would hand a compromised
   relay credentials that work everywhere.
5. **Terminating mode as its own build and image, so the default relay
   keeps RL-3?** Recommended: yes.
6. **A quarantine permission for outside monitors, with Cairn OBS as the
   first integration?** Recommended: yes, and kept generic so any monitor
   can call it. Refined 2026-11-25 (t/340 post 13): `sysRelayQuarantine`
   only quarantines. Asking for a join token is a separate permission,
   `sysRelayRejoin`, held by whatever rebuilds the relay and never on the
   same key, so a taken monitor can't cut a relay off and join its own.
7. **Scheduled rebuilds.** Recommended: off by default, weekly when on,
   because of CA rate limits.
8. **A worker per connection (CG-11)?** Recommended: yes as the design,
   with the cost measured before it's promised.
9. **Sharing 443 with the link.** Both default to 443. Recommended: one
   listener, split by TLS name, the link on a name of its own, when they
   share an address. When the link runs over WireGuard (RL-32) they're
   apart anyway.
10. **The CAA check as a hard stop for 443 (CG-T5)?** Recommended: yes, in
    both modes.
11. **Managing the client names' A and AAAA records.** Recommended: yes for
    domains whose DNS the server manages, with the inside-network note.
12. **The docs recipe first?** Recommended: yes, for pass-through only, and
    decide on building after seeing who uses it.
13. **Milestone.** Recommended: stays in 27.7, unscheduled until 12
    has an answer.

Open (added 2026-11-24 and 2026-11-25, from t/340):

14. **Sign-in choices through a terminating relay.** Recommended: passkeys
    on by default; the server's normal sign-in on a pass-through sign-in
    name (CG-13) as an option the admin turns on; app passwords only with
    terminated IMAP and submission; a per-relay session cap, 12 hours by
    default (CG-14); users can narrow but not widen. This refines answer 4:
    still no password through a terminating name, but passkeys are no
    longer the only way in.
15. **Strict CAA on every client port.** Recommended: an option, off by
    default. When it's on, 993, 465 and 995 refuse to turn on, like 443
    (answer 10), until public DNS has a CAA record naming the server's ACME
    account, including for a domain whose DNS is managed elsewhere, where
    inbuxa-admin shows the record to add by hand (CG-T22). When it's off,
    those ports keep the warning they have now.
