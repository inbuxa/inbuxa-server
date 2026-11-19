# Feature spec: passkeys

Status: draft, 2026-11-18. inbuxa-server #334, asked for on the forum (t/242).
Planned for the series after 27.1. The decisions at the end are open until
approved; nothing is built yet.

## Provenance

This is inbuxa's own design, not a rebuild. Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| W3C Web Authentication Level 3 (`https://www.w3.org/TR/webauthn-3/`) | W3C document license | The ceremonies, relying-party id rules, flags, conditional mediation |
| `webauthn-rs` documentation (`https://docs.rs/webauthn-rs`) | MPL-2.0 | What the protocol crate checks for us, and what it leaves to the caller |
| This repository: the OAuth sign-in path (`crates/http/src/auth/oauth/auth.rs`, `crates/http/src/api/mod.rs`), the built-in login page (`resources/html-templates/login.html`), the in-memory store keys for OAuth codes (`KV_OAUTH`, `KV_OAUTH_DEVICE`), the app-password view over account credentials (`crates/jmap/src/registry/mapping/account.rs`), token revocation by credential version (`crates/common/src/auth/access_token.rs`) and the audit layer (`crates/jmap/src/inbuxa/audit.rs`) | AGPL-3.0-only | Where passkeys plug in, and what they reuse |

Upstream's passkey code (Stalwart 1.1 and later) was not read and must not be:
the last upstream import was 0.16.27.

## What it is

A user signs in to the browser apps (inbuxa Webmail, inbuxa Admin, any OAuth
client) with a passkey instead of a password: one kept in a password manager
or on the phone for daily use, and a hardware key as a backup. No external
identity provider is needed.

Passkeys sign in on the server's own login page only. IMAP, SMTP, POP3,
ManageSieve, CalDAV and CardDAV keep using the password or app passwords:
those protocols have no passkey mechanism. The docs say so on the page that
explains passkeys.

## Data model

### The passkey, `inbuxa:Passkey`

One record per registered passkey, in the fork's own data (`_` subspace),
keyed by account. **Decision:** not a new variant of the account's
`credentials` list. A server that doesn't know passkeys then still reads every
account, and a passkey can be found by its credential id without loading
accounts.

| Field | Mutability | Meaning |
|---|---|---|
| `id` | server-set | The record id |
| `accountId` | create-only | The owning account |
| `name` | mutable | The user's label, ≤ 64 chars, e.g. "Phone" or "YubiKey" |
| `state` | server-set | `pending` until the browser part of registration completes, then `active` |
| `registrationUrl` | server-set, `pending` only | Where the browser part of registration runs (PK-6) |
| `rpId` | server-set | The relying-party id it was registered for (PK-3) |
| `usable` | server-set | `rpId` equals the server's current one |
| `backedUp` | server-set | The authenticator said the key is synced (the BS flag) |
| `transports` | server-set | As reported at registration (`usb`, `nfc`, `ble`, `internal`, `hybrid`) |
| `createdAt` | server-set | When registration completed |
| `lastUsedAt` | server-set | When it last signed in, or null |

Kept with it, never returned over JMAP: the credential id, the public key
(COSE), the signature counter, and the authenticator's AAGUID.

Per account, also in `_`: the **user handle**, 32 random bytes made at the
first registration and kept until the account is deleted. It's what the
authenticator stores as the user id. It is neither the account id nor the
address, so a passkey says nothing about the account to anyone who reads it.

Two indexes: credential id → passkey, and user handle → account.

### Settings, on `x:Authentication`

| Field | Default | Meaning |
|---|---|---|
| `passkeys` | `allowed` | `allowed` or `disabled` server-wide (PK-12) |
| `passkeyRpId` | null | The relying-party id. Null means the host of the server's public HTTPS URL (PK-3) |
| `maxPasskeys` | 10 | Per account |

Per domain and per tenant, `passkeys` can be set to `allowed` or `disabled`,
overriding the server's value; the most specific setting applies.

### Permissions

`sysPasskeyGet`, `sysPasskeyQuery`, `sysPasskeyCreate`, `sysPasskeyUpdate`,
`sysPasskeyDestroy`, in the default user role for the user's own account,
like the app-password permissions. Reaching another account's passkeys takes
the same permissions plus the rights to manage that account, as for app
passwords.

## Required behavior

### Relying party

- **PK-1.** Registration and sign-in use discoverable credentials
  (`residentKey: required`) with user verification required. Attestation is
  `none`. Algorithms: ES256, EdDSA, RS256, in that order.
- **PK-2.** The origin of every ceremony must be `https://` with a host that
  equals the relying-party id or ends with `.` plus it, and is one of the
  server's own HTTP hostnames. Anything else is refused.
- **PK-3.** The relying-party id is `passkeyRpId`, or the host of the
  server's public HTTPS URL when that's unset. `passkeyRpId` may be that host
  or a registrable parent of it (`mail.example.com` → `example.com`), never a
  public suffix; a write that breaks this is refused with `invalidProperties`.
- **PK-4.** A passkey is bound to the relying-party id it was registered for.
  When the id changes (the server renamed onto another domain, or
  `passkeyRpId` changed), passkeys for the old id read `usable: false`, are
  not offered at sign-in, and the webmail and console show them as "Registered
  for the old name: add a new passkey". Nothing is deleted. The docs advise
  setting `passkeyRpId` to the parent domain before people register, so a
  later rename inside that domain keeps every passkey, and the installer's
  rename steps warn when the change will make passkeys unusable.

### Registration

- **PK-5.** `inbuxa:Passkey/set` create takes `accountId` and `name` and makes
  a `pending` record with a `registrationUrl`. Creating fails with
  `overQuota` at `maxPasskeys` (pending ones count), and with `forbidden`
  when passkeys are disabled for the account or the account signs in through
  an external directory (PK-13).
- **PK-6.** `registrationUrl` is a page the server serves itself, like the
  login page, carrying a single-use ticket valid for 10 minutes. The browser
  apps open it in a new window. The page asks for the passkey (the browser's
  own dialog), sends the result back, and says "Passkey added. You can close
  this window." The browser apps can't run the ceremony themselves: they're on
  other hostnames than the relying-party id (see decision 1).
- **PK-7.** Completing registration turns the record `active`, fills the
  server-set fields, and refuses a credential id already registered to any
  account. A pending record whose ticket expired is removed.
- **PK-8.** Registering needs a fresh sign-in: the session behind the create
  must have signed in within the last 10 minutes, or the create fails with
  `forbidden` and the app asks the user to sign in again. Access tokens carry
  the time of the sign-in behind them, kept across refreshes; a token without
  it counts as old. A stolen session token alone can't add a passkey.

### Sign-in

- **PK-9.** The login page offers passkeys when they're allowed server-wide:
  through autofill on the username field (conditional mediation) where the
  browser supports it, and a "Sign in with a passkey" button. Both the OAuth
  authorization-code flow and the device flow (`/device`) accept them.
- **PK-10.** The page asks the server for a challenge, `POST
  /api/auth/passkey`, anonymous and limited like the other sign-in requests.
  The challenge lives in the in-memory store, beside the OAuth codes, for two
  minutes, and is deleted when used. Any node can answer the next step, as for
  OAuth codes today; nothing is kept in a node's memory.
- **PK-11.** The login request then carries the assertion instead of a name
  and password. The server finds the account by user handle and the passkey by
  credential id, checks the signature, the origin (PK-2), the user-verified
  flag, and the counter: when both the stored and the new counter are above
  zero and the new one isn't higher, sign-in fails and the passkey is marked
  as possibly cloned in its log event. Then the same checks run as for a
  password: account disabled or locked, client registration, redirect URI,
  PKCE, scope. On success, the code or device grant is issued exactly as after
  a password, and `lastUsedAt` is set.
- **PK-12.** A passkey signs in on its own: it already proves possession and
  user verification, so an account with TOTP isn't asked for the code after a
  passkey (see decision 2). Failures count toward the same sign-in limits and
  blocking as wrong passwords.
- **PK-13.** Passkeys work only for accounts in the server's own directory. A
  domain that signs in against LDAP, SQL or OIDC (per-domain directories)
  doesn't offer them: its directory owns sign-in.

### Managing

- **PK-14.** `inbuxa:Passkey/get`, `/query` (filter `accountId`) and `/set`
  update (`name` only) and destroy, with the permissions above.
- **PK-15.** Destroying a passkey ends every session of the account, the way
  a password change does today (tokens carry a credential version). Until the
  grant registry (#435) can end one session, this is the only way to cut off a
  lost device. The account's password still works.
- **PK-16.** An administrator can destroy any account's passkeys, which is the
  recovery path for a user who lost them all. Deleting an account deletes its
  passkeys, its user handle and both index entries.

### Recording

- **PK-17.** Creates, renames and removals are recorded in the audit log by
  the existing set-method layer, as for app passwords; an administrator
  reaching another account's passkeys is recorded as such.
- **PK-18.** Sign-in with a passkey raises the same `auth.success` and
  `auth.failed` events as a password, with `type = passkey` and the passkey
  id, so the Logs page and alerts treat both alike. A refused counter raises
  `auth.passkey-counter` (warn).

## Interfaces

- **JMAP:** `inbuxa:Passkey` as above. The schema carries it, so inbuxa Admin
  lists passkeys on the account page with no special form.
- **HTTP:** `POST /api/auth/passkey` (challenge for sign-in), the login
  request's `passkey` field, and the registration page with its two requests
  (fetch options, send the result), all on the server's own hostname.
- **inbuxa Webmail:** Settings › Security gets a Passkeys list: name, added,
  last used, "synced" when backed up, "needs re-adding" when not usable;
  add (opens the registration page), rename, remove. Shown only when the
  server signs people in on its own page (`signIn: oauth`): with the
  webmail's password form there's nowhere to use a passkey.
- **inbuxa Admin:** the account page lists the account's passkeys with a
  remove action and a "Remove all" for recovery. An administrator's own
  account gets the same add, rename and remove as in the webmail. The
  authentication settings get the three settings above, and domains and
  tenants their `passkeys` override.

## Acceptance tests

1. Register a passkey with a virtual authenticator from the registration
   page: the record goes `pending` → `active` with `rpId`, `transports`,
   `backedUp` set (PK-5 to PK-7).
2. A create from a session that signed in more than 10 minutes ago fails
   `forbidden` (PK-8). At `maxPasskeys`, `overQuota` (PK-5).
3. Sign in with the passkey through the authorization-code flow and through
   `/device`: both issue tokens; `lastUsedAt` is set; an account with TOTP
   isn't asked for a code (PK-9 to PK-12).
4. An assertion from another origin, without the UV flag, with a counter that
   went backwards, or for an unknown credential id fails, and counts toward
   the sign-in limit (PK-2, PK-11, PK-12).
5. A challenge issued on one node is completed on another; a used challenge
   can't be used again; an expired one fails (PK-10).
6. Destroying a passkey ends the account's existing sessions; the password
   still signs in (PK-15).
7. Changing `passkeyRpId` makes older passkeys `usable: false` and keeps them
   (PK-4). Setting it to a public suffix or an unrelated domain is refused
   (PK-3).
8. A domain on an external directory: create fails `forbidden`, the login page
   offers no passkey for it (PK-13). `passkeys: disabled` on a domain does the
   same for its accounts.
9. Deleting an account removes its passkeys and user handle; another
   account can't use a passkey whose user handle belonged to it (PK-16).
10. The audit log shows create, rename and destroy; the Logs page shows the
    sign-in with `type = passkey` (PK-17, PK-18).
11. A server built before this feature starts on a store holding passkeys and
    signs everyone in with passwords (rollback).

## Open decisions (for John)

1. **The registration page lives on the mail host.** The browser apps are on
   other hostnames than the relying-party id, so they can't call the browser's
   passkey API for it. PK-6 has the server serve one small page for it, next
   to the login page it already serves. §5.3 says the mail host serves no web
   interface; the login page is the existing exception, and this would be the
   second. The alternative is Related Origin Requests (the server lists the
   webmail and console origins at `/.well-known/webauthn`), which spares the
   page but isn't in every browser yet. Recommended: the page now, related
   origins later as an option.
2. **A passkey replaces the password and the TOTP code** (PK-12), as on most
   services, because user verification is a second factor already.
   Recommended. The alternative asks for the TOTP code after a passkey too.
3. **On by default** (`passkeys: allowed`). Nobody gets a passkey without
   adding one, and an administrator can turn them off per server, tenant or
   domain. Recommended. The alternative is off until an administrator turns
   them on.

Decided in this spec, unless John says otherwise: passkeys stored apart from
account credentials; bound to the relying-party id with no automatic move on a
rename (PK-4); removing a passkey ends the account's sessions (PK-15); the
password stays (no passkey-only accounts); no passkeys for accounts on an
external directory (PK-13); "require a passkey" for browser sign-in is later,
after this ships.

## Implementation status

Not started. Planned order, one PR each: storage and `inbuxa:Passkey`
management; registration page; sign-in in the authorization-code flow; the
device flow, settings and policy; then the webmail and console pages.
