# Contract: inbuxa-server and its front ends

Status: draft, 2026-09-18. Expands SPEC.md §5.2.

## Parties

| Party | What it is | How it reaches the server |
|---|---|---|
| **inbuxa-server** | The mail server | — |
| **ihasmail-inbuxa** | The INBUXA fork of ihasmail: a Node server and a web app. Public ihasmail stays Stalwart-facing and isn't party to this (SPEC.md §5) | Its **Node server** calls inbuxa-server, server to server. The browser only ever talks to ihasmail-inbuxa |
| **INBUXA Admin** (`inbuxa-admin`) | A static web app, a fork of Stalwart WebUI | The **browser** calls inbuxa-server directly, cross-origin |

That split decides most of what follows. Cross-origin rules matter only for
INBUXA Admin. Token custody matters most for ihasmail-inbuxa, which holds
tokens on its server for people who aren't there.

## What upstream does today

Observed in the source at `v0.16.22` and against a running inbuxa-server on
2026-09-18. It's shared AGPL code, not Enterprise.

- **OAuth endpoints:** discovery at `/.well-known/oauth-authorization-server`
  and `/.well-known/openid-configuration`; the sign-in page at `/login`, which
  posts to `/api/auth`; `/auth/token` (authorization code with PKCE, device
  code, refresh token); `/auth/device`, `/auth/introspect`, `/auth/userinfo`;
  dynamic client registration at `/auth/register`, which issues "stateless"
  sealed client ids that carry their own redirect URIs; `/api/discover/{user}`,
  which INBUXA Admin uses to find the endpoints.
- **There's no revocation endpoint.** Tokens are stateless and sealed, so a
  token can only be invalidated by changing the account's password.
- **Clients aren't required to be registered, by default.**
  `x:OidcProvider.requireClientRegistration` defaults to `false`. With it off,
  any `client_id` with any redirect URI is accepted (HTTP ones only with PKCE).
  With it on, a registered `x:OAuthClient` must use one of its `redirectUris`,
  and an unregistered id is refused unless the person signing in holds
  `oAuthClientOverride`.
- **Cross-origin:** `x:Http.usePermissiveCors` (all origins, `*`) defaults to
  off, and is forced on in recovery mode, which includes first-boot bootstrap.
  The OAuth metadata, token and OpenID endpoints answer `*` regardless. So on a
  configured server running normally, INBUXA Admin's JMAP calls from another
  origin are **blocked**, unless an operator allows every origin.
- **A server with no public URL** returns relative OAuth endpoints (`/login`)
  and an empty issuer. INBUXA Admin now resolves them against the server's
  address (fixed 2026-09-18).
- **Endpoint gating:** `x:Http.allowedEndpoints` is an expression that can
  refuse endpoints by path and client IP. JMAP administration shares `/jmap`
  with everything else, so it can't separate admin calls on its own.
- **ihasmail today** (public, and so the starting point for ihasmail-inbuxa)
  signs in with HTTP Basic auth and keeps the password sealed in its session
  store (`sealedCredentials: {username, password}`), sending it on every
  upstream call. It registers JMAP push subscriptions to its own URL, and reads
  permissions and edition from `/api/account`.

## Requirements

Each has an ID, and tests name the IDs they check.

### Discovery and versions

- **C-1.** The JMAP session carries a capability `urn:inbuxa:jmap` (the fork's
  own namespace, SPEC.md §2.4) with:
  - `version`: INBUXA's version (`2026.9.18`);
  - `base`: the Stalwart release it's built on (`0.16.22`), absent once the
    fork no longer tracks upstream;
  - `contract`: this contract's version, an integer, starting at `1`;
  - `webmailUrl` and `adminUrl`: where the front ends are, if configured.
- **C-2.** Each front end states the contract versions it supports and checks
  `contract` after signing in. Outside its range it stops, with a message
  naming both versions. For ihasmail-inbuxa this replaces public ihasmail's
  "Stalwart 0.16 or later" check.
- **C-3.** A breaking change to anything in this document bumps `contract`.
  Adding optional fields doesn't.

### The front ends, configured once

- **C-4.** A server-level singleton, `x:FrontEnds`, in the fork's namespace,
  records `webmailUrl`, `adminUrl`, and `extraOrigins` (a list of further
  allowed origins). It's the single source for discovery (C-1), the OAuth
  client registrations (C-6), the cross-origin allowlist (C-14) and the admin
  lane (C-18). The installer sets it, and so does INBUXA Admin's setup wizard.

### Sign-in

- **C-5.** INBUXA requires client registration: `requireClientRegistration`
  defaults to **true**, and `anonymousClientRegistration` to **false**, since
  anonymous dynamic registration would otherwise let anyone register a client
  with their own redirect URI and sidestep the requirement. Both are
  deliberate differences from upstream (see "Security note"). An operator who
  wants open dynamic registration for third-party apps can turn it back on;
  C-9's consent page still names every non-first-party client.
- **C-6.** Two first-party clients are registered as `x:OAuthClient` whenever
  `x:FrontEnds` is set or changed:
  - **`inbuxa-admin`**: a public client (no secret), authorization code with
    PKCE S256, redirect URI `{adminUrl}/oauth/callback`.
  - **`ihasmail-inbuxa`**: a confidential client with a secret held by the
    ihasmail-inbuxa server, authorization code with PKCE S256, redirect URI
    `{webmailUrl}/api/auth/callback`.
  INBUXA Admin's `<meta name="oauth-client-id">` is set to `inbuxa-admin`.
  Until then it keeps upstream's `stalwart-webui`, which only works while
  registration isn't required.

  **Built (interim), 2026-09-18.** C-5's defaults are in the server, and
  `crates/common/src/manager/first_party.rs` registers the clients on every
  start. Until `x:FrontEnds` exists, three environment variables stand in for
  it: `INBUXA_ADMIN_URL`, `INBUXA_WEBMAIL_URL` and
  `INBUXA_WEBMAIL_CLIENT_SECRET` (the webmail client is registered only when
  both of its variables are set). A web interface the server serves itself
  (none on a new install since SPEC.md §5.3; possible on one upgraded from
  Stalwart) is registered too, as its application's OAuth client id or `stalwart-webui`, at the
  server's public URL. A missing client is created. An existing one gains any
  redirect URI it lacks, and the webmail client gets the configured secret.
  Nothing an operator added is removed. Bootstrap and recovery mode skip this:
  their recovery admin holds `oAuthClientOverride`.

  Checked on a local first boot of the debug build: setup still signed in;
  after a restart with the three variables set, the server reported
  registration required and anonymous registration off, and held the three
  clients with the expected redirect URIs. A user signed in through each
  public client. A foreign redirect, an unregistered client and anonymous
  registration were refused, and so was the webmail client's code exchange
  with a wrong or missing secret. A second restart left three clients.

  An existing server that saved its OAuth settings keeps them (INBUXA's
  production server did). One upgraded from Stalwart that never saved them
  moves to the new defaults, with its web interface registered first.
- **C-7.** Third-party apps that want OAuth (Thunderbird, mobile apps) get a
  client in one of two ways: an administrator registers it (`x:OAuthClient`,
  in INBUXA Admin), or the operator turns anonymous dynamic registration back
  on (`/auth/register`, whose stateless client ids carry their own redirect
  URIs), accepting that anyone can then register. Either way, C-9's consent
  page names the app and its redirect host. Mail apps that sign in with a
  password or app password are unaffected, and that's everything INBUXA's
  users were observed doing (see "Security note").
- **C-8.** People sign in on **the server's own sign-in page** (`/login`,
  already INBUXA-branded), never on a front end's form. Two-factor happens
  there, on the page's existing one-time-code step. Front ends never see a
  password. ihasmail-inbuxa's own sign-in form is retired in favor of a
  redirect.
- **C-9.** **Consent for anything that isn't first-party.** When a client other
  than the two first-party ones asks to sign someone in, the sign-in page names
  the client and the host its redirect URI goes to ("*Thunderbird* wants access
  to your mail, and will return to *localhost*"). First-party clients skip it.
  **Decision**: this is what makes an authorization-code phishing link visible
  even where registration isn't required.

### Tokens

- **C-10.** ihasmail-inbuxa holds tokens, never passwords. It keeps the access
  and refresh token for each session sealed in its session store, where it now
  keeps sealed credentials, and refreshes the access token before it expires.
  The browser still holds only ihasmail-inbuxa's own session cookie. Public
  ihasmail's "the browser never holds a credential" property is kept.
- **C-11.** INBUXA Admin holds its tokens in the browser, as upstream WebUI
  does, since it has no server of its own. So admin tokens are short-lived
  (C-13).
- **C-12.** **Revocation**, which upstream can't do per token. Each refresh
  token belongs to a *grant*: one sign-in by one client on one device, with its
  own id. The server keeps a list of revoked grant ids until their tokens would
  have expired anyway, and checks it on every token use and refresh. Revoking
  is available:
  - per grant, through `POST /auth/revoke` (RFC 7009, for a token the client
    holds);
  - for the signed-in account: every grant, or every grant except this one
    ("sign out other sessions");
  - for an administrator: any account's grants;
  - automatically, on password change (as upstream does today) and on account
    deletion or suspension.
  A revoked token stops working on its next use, and never later than one
  access-token lifetime.
- **C-13.** Grants are listed per account (client, device description, created,
  last used, IP), so ihasmail-inbuxa's "your sessions" screen shows server-side
  truth. Lifetimes, all configurable: access tokens 1 hour and refresh 30 days
  for ihasmail-inbuxa; access tokens 15 minutes and refresh 8 hours for
  `inbuxa-admin`.

### Cross-origin

- **C-14.** Cross-origin requests are allowed only from the origins in
  `x:FrontEnds`: `adminUrl`'s origin, `webmailUrl`'s origin, and
  `extraOrigins`. The server echoes the matching origin in
  `Access-Control-Allow-Origin` with `Vary: Origin`, never `*`, and sends
  nothing for any other origin.
- **C-15.** OAuth discovery metadata may stay `*`, since it's public and
  read-only. The token, revocation, introspection and userinfo endpoints follow
  C-14, so a random web page can't exchange or probe tokens.
- **C-16.** Bootstrap and recovery mode keep upstream's permissive CORS, since
  no front ends are configured yet and the admin needs to reach the server.
  They're also when the recovery administrator applies (SPEC.md §6.2).
- **C-17.** `x:Http.usePermissiveCors` stays available for operators, but
  turning it on logs a warning at startup saying which endpoints it opens.

### The admin lane

- **C-18.** Server-level administration (registry objects outside a tenant,
  `x:Bootstrap`, `x:Action`, `x:Task`, the telemetry and troubleshooting
  endpoints) requires a token issued to `inbuxa-admin`. That's the new OAuth
  scope `inbuxa:admin`, which only that client is ever granted. An admin
  account signing in through a mail client can't administer the server with
  that token, even though the account could.
- **C-19.** ihasmail-inbuxa's own administration (accounts, domains, groups,
  lists, roles, tenants, the dashboard) uses the scope `inbuxa:account-admin`,
  granted only to `ihasmail-inbuxa`, and limited to those object types.
- **C-20.** Optionally, `x:FrontEnds.adminNetworks` (a list of CIDRs) limits
  where `inbuxa:admin` requests may come from. Empty means anywhere.
- **C-21.** Basic auth never reaches the admin lane outside recovery mode. An
  administrator who needs a script uses an API key or an app password with an
  explicit admin scope, which is a separate, auditable credential.

### Push

- **C-22.** Unchanged from public ihasmail: ihasmail-inbuxa registers JMAP push
  subscriptions to its own URL, with VAPID for browser notifications. The only
  difference is that it authenticates with its token rather than the password.

## First boot

1. The installer, or INBUXA Admin's setup wizard, completes bootstrap
   (SPEC.md §6.2). In bootstrap mode, CORS is permissive (C-16) and the
   recovery administrator applies.
2. It sets `x:FrontEnds` (webmail and admin URLs, the public URL), which
   registers both first-party clients (C-6). For ihasmail-inbuxa it returns the
   client secret once, for the installer to write into ihasmail-inbuxa's
   environment.
3. After the restart out of bootstrap, CORS follows C-14, registration is
   required (C-5), and the recovery administrator is ignored (SPEC.md §6.2).

## Security note: upstream accepts any client by default

With `requireClientRegistration` off, which is upstream's default, the server
issues authorization codes to any `client_id` and any redirect URI, provided
PKCE is used for HTTP redirects. That allows authorization-code phishing:

1. An attacker sends someone a link to the **genuine** sign-in page, with the
   attacker's site as the redirect URI and a PKCE challenge the attacker made.
2. The person signs in on the real page, correctly, since nothing about it is
   fake.
3. The code goes to the attacker's site, and the attacker, holding the PKCE
   verifier, exchanges it for a working token to the person's mailbox.

INBUXA closes this with C-5 (registration required), C-9 (consent naming the
redirect host), C-15 (token endpoint not callable from arbitrary pages) and
C-18 (no admin scope for anything but `inbuxa-admin`).

**Checked on INBUXA's production server (upstream Stalwart Enterprise
0.16.22), 2026-09-18, read-only:**

- `requireClientRegistration: false` and `anonymousClientRegistration: true`.
  So the gap is open, and turning registration on **alone wouldn't close it**:
  anyone can dynamically register a client with their own redirect URI without
  signing in, then run the same phishing flow with a "registered" client. C-5
  therefore also needs anonymous registration **off** by default, and C-9's
  consent page covers dynamically registered clients too.
- No `x:OAuthClient` is registered, and no dynamic registrations appear in the
  server log for September 6–18.
- The same log shows no sign of OAuth sign-ins by mail clients (no
  `OAUTHBEARER` or `XOAUTH2`). Sign-ins over those 12 days: IMAP 606, HTTPS
  208, submission 102. Of the HTTPS ones, 102 came from ihasmail's host (Basic
  auth), 26 were test probes, and 80 were two accounts' own devices. The log
  doesn't record the sign-in method, so this is strong circumstantial evidence,
  not proof.
- The one client that very likely depends on the open setting is Stalwart's
  own web interface (`/admin`, `/account`), which signs in as the unregistered
  client `stalwart-webui`.

**Fixed on production, 2026-09-18,** in the order that keeps the web
interface working throughout:

1. Registered `stalwart-webui` as an `x:OAuthClient` with exactly two redirect
   URIs, the `/admin` and `/account` OAuth callbacks.
2. Turned `anonymousClientRegistration` off and `requireClientRegistration` on,
   then reloaded settings.

Verified over the API with a test account: `stalwart-webui` signs in to both
callbacks and exchanges its code for a token; the same client with a foreign
redirect URI, an unregistered `client_id`, and anonymous dynamic registration
are all refused (401). Signing in to `/admin` and `/account` in a browser
was confirmed working the same day. To roll back, set the two settings back, destroy the
client and reload settings. This is the state C-5 and C-6 make the default.

## Acceptance tests

1. The session shows `urn:inbuxa:jmap` with `version`, `base`, `contract: 1`
   and the front-end URLs (C-1).
2. A front end supporting only contract 2 refuses a contract-1 server with
   both numbers in its message (C-2).
3. Setting `x:FrontEnds` registers both clients with the right redirect URIs.
   Changing `adminUrl` updates `inbuxa-admin`'s (C-4, C-6).
4. An unregistered `client_id` is refused at sign-in. A registered one with a
   foreign redirect URI is refused (C-5).
5. The phishing flow in the security note fails at step 1, and a registered
   third-party client with a non-first-party redirect shows the consent page
   (C-9).
6. ihasmail-inbuxa signs in without ever handling a password. Its session
   store holds tokens only (C-8, C-10).
7. Revoking one grant stops that session within one access-token lifetime,
   leaves others working, and "sign out other sessions" keeps the current one
   (C-12).
8. A password change revokes every grant (C-12).
9. A cross-origin request from the admin origin gets that origin echoed. From
   any other origin it gets no CORS headers, on `/jmap` and on `/auth/token`
   alike (C-14, C-15).
10. In bootstrap mode, INBUXA Admin reaches the server from any origin (C-16).
11. An admin account's token from a third-party mail client can't read
    `x:NetworkListener`. The same account through `inbuxa-admin` can (C-18).
12. ihasmail-inbuxa's token can manage accounts and tenants but not listeners
    or certificates (C-19).
13. With `adminNetworks` set, an `inbuxa:admin` request from outside is refused
    (C-20).
14. Basic auth to an admin method is refused on a configured server (C-21).

## Open questions

1. Whether `x:FrontEnds` is a new registry object (a schema addition in the
   fork's namespace) or kept in the fork's own store. A registry object is
   editable in INBUXA Admin for free, since the admin is schema-driven.
2. The consent page's wording and whether it remembers a decision per client.
3. API keys and app passwords with explicit scopes (C-21): what upstream's
   `x:ApiKey` already supports, to observe before specifying.
4. Whether ihasmail-inbuxa's secret should rotate, and how.
