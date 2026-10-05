# Feature spec: per-domain directories and the OIDC directory

Status: draft, 2026-09-18. Feature 9, proposed for SPEC.md §4. It isn't in
§4's table yet. Proposed row:

| # | Feature | What an operator gets | Notes |
|---|---|---|---|
| 9 | Per-domain directories | Each domain can sign its users in against its own LDAP, SQL or OIDC directory, instead of the server's one default | The OIDC directory itself is already AGPL and isn't a gap (see below). Tenants bring their own directories. |

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| This repository: `crates/directory`, `crates/common/src/auth`, `crates/common/src/cache`, `crates/common/src/network/mta.rs`, `crates/http/src/auth`, `crates/jmap/src/registry/mapping`, `tests/src/directory`, `tests/src/utils` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL (Enterprise-only code was stripped before commit) | How directories are opened, chosen, queried and cached today; what the OIDC directory validates; what survives the strip |
| Registry schema: `crates/registry/src/schema/*.rs` and `resources/schema/schema.json.gz` | As above | Field shapes, defaults, descriptions, and which fields upstream flags `"enterprise": true` |
| Strip report `docs/fork/strip-reports/v0.16.22.json` (and `.md`) | Ours | Which files and how many snippets were removed, per file. Only names and counts were read |
| Stalwart documentation (`website` repo): `auth/backend/oidc.md`, `auth/backend/index.md`, `install/directory.md`, `auth/scim/provisioning.md`, `auth/authorization/tenants.md`, `server/enterprise.md`, `ref/object/domain.md`, `ref/object/directory.md`, 0.15 `auth/backend/oidc.md` and `auth/principals/domain.md`, and the edition comparison `pages/compare.yml` | Unlicensed public documentation: facts used, prose not copied | What upstream says is Enterprise, just-in-time provisioning rules, OIDC limits |
| OpenID Connect Core 1.0 and Discovery 1.0; RFC 7662; RFC 9068; RFC 7628; RFC 4511; RFC 8620 | IETF / OpenID Foundation | Token validation, introspection, `OAUTHBEARER`, LDAP, JMAP errors |

No Enterprise-only file or snippet was used. The author is a fresh session
that has never seen Enterprise code, and read the stripped tree only. No
server, live or local, was probed for this spec. Where the sources above
don't settle a behavior, this spec makes a **Decision** of its own, or lists
it under "Open questions / to observe". Nothing is filled in by guessing what
upstream code does.

## What it is

A directory is where the server checks who someone is: the internal
directory (accounts in the server's own store), or an external one (an LDAP
server, an SQL database, or an OpenID Connect provider). Today one setting,
`x:Authentication.directoryId`, picks a single external directory for the
whole server, or none for the internal one.

Per-domain directories let each domain pick its own. One server can sign in
`corp.example` users against the company's Active Directory, `school.example`
users against a Keycloak realm, and `example.net` users against the internal
directory. This matters most with tenants (Feature 1): each organization
brings its own identity system.

Upstream ships per-domain directories only in its Enterprise Edition. The
edition comparison lists "Per-domain directory backends" as Enterprise-only.
inbuxa-server ships it to everybody.

### Where the fork stands today

`x:Domain.directoryId` is stored, writable over JMAP, validated as a
reference to an `x:Directory`, and copied into the domain cache
(`DomainCache.id_directory`, `crates/common/src/cache/principals.rs`). The
cache is already invalidated when it changes (`cache/invalidate.rs`). But
nothing reads it. The two lookups every caller goes through,
`get_directory_for_domain` and `get_directory_for_cached_domain`
(`crates/common/src/auth/authentication.rs`, marked `inbuxa:`), return the
server default for every domain.

So a domain carried over from an Enterprise install with `directoryId` set
currently signs in against the wrong source: the server default, or the
internal directory. **Decision:** INBUXA's cutover (SPEC.md §7) checks the
copied data for any domain with `directoryId` set. If there is one, this
feature is a cutover blocker.

Everything else the feature needs is already in the AGPL tree, and already
routes through those two lookups: sign-in, bearer-token routing, recipient
lookup, account discovery, the PACC DNS record, and the refusal to change
passwords on external accounts. Rebuilding the feature mostly means making
the two lookups honor the domain, then adding the rules below.

## Is the OIDC directory a gap?

**No.** Signing in against an OIDC provider is AGPL in upstream, and works in
the stripped tree as the server's default directory. Only two things around
it are Enterprise: pointing a single domain at it (this feature), and giving
it a tenant (`OidcDirectory.memberTenantId`, Feature 1). The integration test
is gated only because the test file itself was Enterprise-only and was
removed.

Evidence:

1. **Headers.** `crates/directory/src/backend/oidc/mod.rs`, `config.rs` and
   `lookup.rs` all carry `AGPL-3.0-only OR LicenseRef-SEL`. So do
   `core/dispatch.rs`, `core/config.rs`, `core/sasl.rs` and `lib.rs`.
2. **Nothing stripped from the directory crate.** The strip report lists no
   removed file and no removed snippet anywhere under `crates/directory`. Its
   `enterprise` Cargo feature is declared in `Cargo.toml` and gates no code.
3. **Schema flags.** The `x:Directory` object and its `Oidc` variant aren't
   flagged. Of `x:OidcDirectory`'s nine fields only `memberTenantId` is
   flagged, the same as on the LDAP and SQL variants.
   `x:Authentication.directoryId`, which picks the default directory, isn't
   flagged. `x:Domain.directoryId` is.
4. **It compiles and is wired in.** The stripped build (SPEC.md §2.2b) opens
   OIDC directories in `Directories::build` and uses one as the default when
   `Authentication.directoryId` names it. The bearer path in
   `authentication.rs` (routing, then the external directory, then the
   server's own tokens) sits outside any removed snippet. So do
   `/api/discover` and the PACC record.
5. **Ungated AGPL tests use it.** `tests/src/directory/discovery.rs` runs a
   Keycloak container and asserts that the default directory is the OIDC
   provider. `tests/src/directory/unavailable.rs` checks an unreachable OIDC
   directory. Neither is behind `pending-rebuild`.
6. **What's gated, and why.** `tests/src/directory/oidc.rs` was a whole file
   licensed `LicenseRef-SEL` alone. It was removed, which left
   `pub mod oidc;` dangling (strip report, "dangling mods") and the
   `oidc::test()` call gated. What it tested can't be known without reading
   it, and it wasn't read. Nothing shows OIDC sign-in itself to be
   Enterprise.
7. **Public docs.** The OIDC backend page has no Enterprise marker. The
   comparison page lists "Third-party OIDC providers" and "OpenID Connect" in
   both editions, and "Per-domain directory backends" as Enterprise-only. The
   reference page for `Domain.directoryId` marks it Enterprise.

What follows from this: the OIDC directory needs no rebuild. It does need a
new integration test, written from this spec (tests 12 to 17 below), to
replace the lost one. The `oidc::test()` gate comes off when that lands.

## Data model

Unchanged from upstream, so existing data opens as it is (SPEC.md §7).

### On `x:Domain`

| Field | Type | Meaning |
|---|---|---|
| `directoryId` | `Id<x:Directory>`, nullable, mutable | The directory this domain's accounts sign in against. Flagged Enterprise upstream; ordinary here |

The schema describes null as "use the internal directory". This spec reads
null as "use the server default" instead (DIR-1), because that's what every
domain does today, in both editions, whenever a default is set.

### On `x:Authentication` (singleton)

| Field | Type | Meaning |
|---|---|---|
| `directoryId` | `Id<x:Directory>`, nullable | The server default directory. Null: the internal directory |

### `x:Directory`, three variants

Permission prefix `sysDirectory`. The variants are `Ldap`
(`x:LdapDirectory`), `Sql` (`x:SqlDirectory`) and `Oidc` (`x:OidcDirectory`).
Each variant carries `memberTenantId`, a nullable `Id<x:Tenant>` flagged
Enterprise upstream. Feature 1 covers that field. `TenantStorageQuota` has
`maxDirectories`.

### `x:OidcDirectory`

| Field | Type, default | Meaning |
|---|---|---|
| `description` | string | Label |
| `issuerUrl` | URI | The provider's issuer. Discovery is fetched from `<issuerUrl>/.well-known/openid-configuration` |
| `requireAudience` | string, nullable | If set, a token's `aud` must include it |
| `requireScopes` | set of strings, default `openid`, `email` | Every listed scope must be in the token |
| `claimUsername` | string, default `preferred_username` | Claim that names the account |
| `usernameDomain` | string, nullable | Appended as `@domain` when the username claim has no `@`. Also appended to bare group names |
| `claimName` | string, nullable, default `name` | Claim for the display name |
| `claimGroups` | string, nullable | Claim for group memberships |
| `memberTenantId` | `Id<x:Tenant>`, nullable | Tenant (Feature 1) |

The LDAP and SQL variants are unchanged, and this feature adds nothing to
them.

## Required behavior

Each requirement has an ID, and tests name the IDs they check. "Effective
directory" means the directory DIR-1 picks for a domain.

### Choosing the directory

- **DIR-1.** A domain's effective directory is the one its `directoryId`
  names. If that is null, it's the server default
  (`Authentication.directoryId`). If that is null too, it's the internal
  directory. **Decision:** null means the server default, not the internal
  directory as the schema text says. Every existing install with a default
  external directory relies on this reading, since that is how every domain
  behaves before this feature exists.
- **DIR-2.** Which domain decides:
  - **Password sign-in:** the domain of the address signing in. With
    impersonation (`target%master`), it's the master user's domain. A bare
    name gets the default domain, as now.
  - **Bearer token:** the domain of the user the client names (the SASL
    `a=` authorization identity, or the HTTP username). If there is none, the
    domain of the first address found in the token's claims (`email`,
    `preferred_username`, `upn`, as the code reads them now). If there is
    none of those either, the server default. The claims are read unverified,
    and only to choose the directory. The chosen directory then verifies the
    token (DIR-26), and DIR-6 checks the result.
  - **Recipient:** the recipient's domain.
- **DIR-3.** Local credentials are checked before any directory, as now:
  the recovery admin, app passwords and API keys. They belong to the server,
  not the directory, and they're how users of clients without `OAUTHBEARER`
  reach an OIDC domain (public OIDC docs). See open question 3.
- **DIR-4.** No fallback. A domain whose effective directory is external
  signs in against that directory and nothing else. When it says no, is
  unreachable, or failed to start, sign-in fails. It never falls back to the
  server default, another directory, or a password held in the internal
  directory. **Decision** (settled for this spec). The AGPL test
  `unavailable.rs` already requires this for password sign-in against an
  unavailable directory.
- **DIR-5.** A `directoryId` that names no directory the server could build
  (deleted, or never opened) makes the domain's directory unavailable: DIR-4
  applies. It is never read as "no directory". Today the cached-domain lookup
  returns nothing in that case, which would mean internal sign-in. It must
  not.
- **DIR-6.** A directory speaks only for its own domains. The account a
  directory returns must be on a domain whose effective directory is that same
  directory. Otherwise sign-in fails, and no account is created or updated.
  **Decision.** Without it, a tenant's identity provider could sign someone in
  as, or create, an account on another tenant's domain. The same rule filters
  what synchronization accepts. An alias or group address on a domain served
  by a different directory is dropped, and a warning event is emitted.
  Upstream's code already drops aliases on other tenants' domains. This goes
  further.
- **DIR-7.** The token must match the named user. When a bearer client
  names a user (DIR-2) and the token resolves to a different account, sign-in
  fails, unless the named address is one of the account's aliases and the
  account holds `authenticateWithAlias`, the same rule as password sign-in.
  **Decision.** Today the bearer path doesn't compare them.
- **DIR-8.** Tokens the server issued itself (its own OAuth provider) are
  still accepted after the external directory rejects a bearer token, as now.
  They aren't another directory. For a domain with its own directory, the
  server's sign-in page authenticates through that directory (DIR-4), so the
  server only issues such tokens on its say-so.

### Recipients

- **DIR-9.** Recipient lookup asks the domain's effective directory when it
  can look recipients up (LDAP, SQL). A positive answer synchronizes the
  account or group (DIR-14) before the message is accepted. The directory is
  the authority for accounts on that domain: an account in the internal store
  that the directory doesn't know isn't a valid recipient. Mailing lists and
  the catch-all still resolve from the internal store. That is what the AGPL
  code does today for the server default, applied per domain.
- **DIR-10.** An OIDC domain has no recipient lookup, because OIDC offers
  none. The internal store decides. An account that has never signed in
  doesn't exist unless an administrator created it first (public docs).
  Administrators may create accounts on an OIDC domain, without a password
  (DIR-13).
- **DIR-11.** If the directory can't be reached during a recipient lookup, the
  answer is a temporary failure (`4xx`). The message is never accepted, and
  the lookup never falls back to the internal store. **Decision**, to be
  checked by test 9.

### Discovery

- **DIR-12.** `GET /api/discover/{address}` returns the discovery document
  of the address's domain's provider when its effective directory is OIDC.
  Otherwise it returns the server's own OAuth metadata. The recovery admin
  always gets the server's own. The PACC DNS record for a domain carries the
  domain's provider issuer when its effective directory is OIDC, and the
  server's own URL otherwise. Both work this way today, but only for the
  server default.

### External accounts

- **DIR-13.** On an account whose domain's effective directory is external,
  setting or changing the password or its OTP secret is refused with
  `forbidden`, and `/api/account` leaves out `sysAccountPasswordGet` and
  `sysAccountPasswordUpdate`. That's today's behavior, decided per domain.
  App passwords and API keys stay allowed.

### Creating and updating accounts (just-in-time)

- **DIR-14.** After a successful sign-in, or a positive recipient answer, the
  server synchronizes the directory's record into a local account, matched by
  address (local part and domain):
  - **Missing account:** created with the local part as name, the domain,
    the domain's tenant (MT-7), the `User` roles, the description, and the
    aliases and groups (as filtered by DIR-6). It also gets a password
    credential when the directory supplies a secret (LDAP, SQL; never OIDC).
    Missing groups are created on the same terms.
  - **Existing account:** the description is overwritten when the directory
    supplies a different one. Aliases are added and never removed. Groups are
    replaced when the directory reports them: a missing claim leaves them
    alone, while an empty list clears them. The secret is updated. Quotas,
    roles, permissions and settings are local and never touched.
  - The domain must already exist and be enabled. A directory never creates a
    domain.
- **DIR-15.** Creating an account or group this way counts against the
  tenant's `maxAccounts` and `maxGroups` (MT-17). Over the limit, sign-in or
  delivery fails, and `limit.tenant-quota` is emitted. **Decision**: a
  directory is not a way around a tenant's limits.
- **DIR-16.** Synchronization never deletes or suspends an account (public
  docs). On a domain with `allowScimProvisioning` set, Feature 7's spec
  governs instead: there, synchronization only reads, and never creates an
  account.

### Changing a domain's directory

- **DIR-17.** A change to `Domain.directoryId`, `Authentication.directoryId`
  or any `x:Directory` takes effect on the next request, without a restart.
  Sessions already signed in keep running until they end. Tokens the server
  has already issued aren't revoked (see open question 5).
- **DIR-18.** Changing a domain's directory never deletes, moves or changes
  any account, message, alias, group, app password or API key. When the new
  directory first vouches for an address, it updates the account already
  there (DIR-14) rather than making a second one.
- **DIR-19.** Accounts the new source doesn't know can't sign in through it
  (app passwords and API keys still work, DIR-3). On an LDAP or SQL domain
  they also stop receiving mail (DIR-9). The admin front ends say how many
  accounts that is before the change is saved.
- **DIR-20.** When a domain moves from an external directory to the internal
  one, password credentials synchronized from the directory stay and keep
  working. **Decision**: it lets an operator migrate a domain off LDAP or SQL
  without resetting every password. The front ends warn that each password is
  whatever the directory last supplied, and that accounts disabled in the
  directory can sign in again. Accounts that came from OIDC have no password.
  They need one set, or an app password.
- **DIR-21.** Writes are checked:
  - `directoryId` must name an existing `x:Directory` (the registry's
    foreign-key check, as today).
  - A directory still named by a domain or by `Authentication` can't be
    deleted: `objectIsLinked`, listing what refers to it.
  - A directory that fails to open is logged against its id and becomes
    unavailable. Every other directory, and the rest of the reload, carries
    on (open question 6).

### Tenancy

- **DIR-22.** Directories follow Feature 1:
  - A directory with `memberTenantId` belongs to that tenant. It is visible
    only to the tenant (MT-1), created by its administrator, and counted
    against `maxDirectories`.
  - A domain can name only a directory in its own tenant, and a server-level
    domain only a server-level directory. Otherwise the write is refused with
    `invalidForeignKey`, naming `directoryId` (MT-3).
  - `Authentication.directoryId` must name a server-level directory.
    **Decision**: the server default is server infrastructure.
- **DIR-23.** A tenant domain whose `directoryId` is null uses the server
  default, like any other domain (DIR-1). **Decision**, for compatibility, and
  open question 7. MT-3 is still met: the domain links to nothing, and DIR-6
  means the server default can't create accounts in any tenant whose domains
  point elsewhere.
- **DIR-24.** A tenant administrator can set `directoryId` on its own
  tenant's domains, to its own tenant's directories. It can't change
  `Authentication`.

### The OIDC directory

The AGPL code does all of this today. It's stated here so the new tests
check it and the fork keeps it.

- **DIR-25. Opening.**
  - The server fetches the discovery document. Its `issuer` must equal
    `issuerUrl`, ignoring a trailing slash. A mismatch is a configuration
    error.
  - It then fetches the JWKS from `jwks_uri`.
  - Network and provider errors are retried every 3 seconds for up to 30.
    Configuration errors aren't retried.
  - A directory that doesn't open is unavailable (DIR-4, DIR-5).
  - A required scope or configured claim that the provider doesn't advertise
    gives a warning, not an error.
- **DIR-26. JWT access tokens.**
  - `HS*` algorithms are refused, and HMAC keys in the JWKS are skipped. RSA
    (RS and PS), EC P-256 and P-384, and EdDSA are accepted.
  - The key is found by `kid`. An unknown `kid` refetches the JWKS, at most
    once every 300 seconds. With no `kid`, every key is tried.
  - `iss` must equal the discovery document's issuer.
  - `exp` is checked, with 60 seconds of leeway.
  - If `requireAudience` is set, `aud` must be present and include it.
  - Every `requireScopes` entry must appear in `scope`, which may be a
    space-separated string or an array.
- **DIR-27. Opaque tokens.** A token that isn't a JWT is sent to the
  provider's userinfo endpoint (OIDC Core §5.3). `401` or `403` means sign-in
  fails. Token introspection (RFC 7662) isn't used (public docs), and no
  audience or scope check is possible on this path (open question 2).
- **DIR-28. Identity.**
  - The account address is the `claimUsername` claim if it contains `@`.
    Otherwise it is that claim plus `@usernameDomain`, or failing that the
    `email` claim. With none of these, sign-in fails.
  - When the JWT lacks the address, or a configured name or groups claim,
    the userinfo response fills the gaps. The JWT's own claims win.
  - Group names without `@` get `@usernameDomain`.
- **DIR-29.** An OIDC directory refuses password sign-in. Under DIR-4, a
  password is never tried anywhere else for that domain. App passwords
  (DIR-3) remain.
- **DIR-30. Failure classes.** An invalid or rejected token is an
  authentication failure: it counts toward the sign-in ban. A network,
  provider or configuration fault is an error: it doesn't count, and the
  client gets a temporary failure where the protocol has one. The same split
  applies to LDAP and SQL (an unreachable server is an error, not a wrong
  password).

### Caching

- **DIR-31.** Only these are cached:
  - the domain cache, including its directory id, which is invalidated when
    `directoryId` changes;
  - the built directories (connection pools, OIDC discovery and keys),
    rebuilt when any `x:Directory` or `Authentication` changes;
  - each OIDC directory's JWKS, refreshed under DIR-26.
- **DIR-32.** Directory answers aren't cached. Every password sign-in and
  every bearer token without a server-issued match asks the directory.
  **Decision**: no positive cache, which would keep a disabled user in, and no
  negative cache, which would keep a fixed user out. Recipient answers
  materialize local accounts (DIR-14). Those accounts are what later lookups
  find.

## Interfaces

- **Existing, unchanged:** `x:Domain/get` and `/set` with `directoryId`;
  `x:Directory/*`; `x:Authentication`; `GET /api/discover/{address}`;
  `/api/account`; SASL `PLAIN`, `LOGIN`, `OAUTHBEARER` and `XOAUTH2`; HTTP
  Basic and Bearer. What changes is behavior: which directory answers.
- **Errors:** RFC 8620 `SetError` types: `invalidForeignKey` (DIR-22),
  `objectIsLinked` (DIR-21), `forbidden` (DIR-13), `overQuota` (DIR-15,
  surfaced as a sign-in or delivery failure). Protocols keep their own
  failure codes, temporary for DIR-11 and DIR-30.
- **Events:** existing `auth.*` events. DIR-6 drops and DIR-5 dangling ids
  emit `auth.warning` with the domain and directory id.
- **New:** none. The DIR-19 count comes from querying accounts on the domain,
  which the front ends can already do.

## ihasmail changes

These go in inbuxa-webmail, the INBUXA fork of ihasmail, never in public
ihasmail, which stays Stalwart-facing (SPEC.md §5).

- **Domain editor:** a directory picker offering "server default" and the
  directories the admin can see (its tenant's, for a tenant admin, DIR-22).
  The directory objects themselves are edited in INBUXA Admin, which
  ihasmail links to (SPEC.md §5.4).
- **Before saving a directory change:** warn with the DIR-19 count, and, when
  moving to the internal directory, the DIR-20 warning.
- **Settings:** hide password and two-factor changes when `/api/account`
  lacks `sysAccountPasswordUpdate` (DIR-13), and point users to app
  passwords. On an OIDC domain, say that the password is managed by the
  organization's sign-in provider.
- **Sign-in:** when the address's domain has its own OIDC provider
  (`/api/discover`, DIR-12), send the user there, not to a password form.
  How this fits the OAuth contract belongs in `contract.md`.
- **Errors:** show DIR-15 quota refusals and DIR-30 outages in plain words
  ("your organization's sign-in service is unreachable"), not as a wrong
  password.

INBUXA Admin builds its forms from the schema, so it shows `directoryId`
with no work beyond the edition gating it already removes.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code. Tests
needing a directory use the containers the AGPL suite already has
(`tests/src/utils/containers.rs`): OpenLDAP (`osixia/openldap`, fixtures in
`tests/docker/ldap`) and Keycloak (realm in `tests/docker/keycloak`). The
per-domain tests need a second Keycloak realm, or a Dex container, as a
second provider. The OIDC tests go in a new module that replaces the gated
`oidc::test()` call. Marked **(compat)**: also run against a copy of INBUXA's
data.

1. Domain A on LDAP, domain B on SQL, domain C on none, and no server
   default: A and B sign in against their own directories, C against the
   internal one. With SQL made the server default, C signs in against SQL,
   and A is unchanged (DIR-1). *LDAP, SQL (SQLite).*
2. A has LDAP and the LDAP server is stopped: A's password sign-in fails,
   even for a user with an internal password on A. B is unaffected (DIR-4).
   *LDAP.*
3. `directoryId` naming a directory that failed to open: sign-in fails and
   never reaches the internal store (DIR-5). *None.*
4. A's LDAP returns an account on domain B: refused, and nothing is created
   (DIR-6). Aliases and groups on B are dropped with a warning. *LDAP.*
5. OAUTHBEARER naming `alice@a` with a valid token for `bob@a`: refused
   (DIR-7). *Keycloak.*
6. App password on an LDAP-backed domain works while LDAP is stopped (DIR-3).
   *LDAP.*
7. Mail to an LDAP user who has never signed in is accepted and creates the
   account (DIR-9, DIR-14). Mail to an internal-only account on that domain
   is rejected. *LDAP.*
8. Mail to an OIDC domain address that never signed in is rejected. After a
   pre-created account exists, it's accepted (DIR-10). *Keycloak.*
9. Mail to an LDAP domain with LDAP stopped gets a `4xx` (DIR-11). *LDAP.*
10. `/api/discover` for a user on A (provider 1) and a user on B (provider 2)
    returns each provider's document. The PACC record differs likewise
    (DIR-12). *Two Keycloak realms.*
11. A password change on an external-directory account: `forbidden`. It's
    allowed again after the domain moves to the internal directory (DIR-13,
    DIR-20). *LDAP.*
12. OIDC first sign-in creates the account with name, groups and tenant.
    Second sign-in with an empty groups claim clears the groups. With no
    groups claim, they stay (DIR-14). *Keycloak.*
13. Tenant at `maxAccounts`: OIDC first sign-in fails with
    `limit.tenant-quota` (DIR-15). *Keycloak.*
14. Moving a domain from LDAP to OIDC keeps every account and message, and
    the first OIDC sign-in reuses the existing account (DIR-18). *LDAP,
    Keycloak.*
15. Deleting a directory a domain uses: `objectIsLinked` (DIR-21). A tenant
    domain naming a server-level directory: `invalidForeignKey` (DIR-22).
    *None.*
16. JWT validation: wrong issuer, wrong audience, a missing required scope,
    expired beyond 60 seconds, `HS256`, and an unknown `kid` are each
    refused. A rotated key is picked up (DIR-26). *Keycloak.*
17. Opaque token accepted through userinfo, and one revoked at the provider
    is refused (DIR-27). Username without `@` plus `usernameDomain` resolves
    (DIR-28). Password sign-in to an OIDC domain is refused (DIR-29).
    *Keycloak.*
18. Provider stopped: sign-in fails as a temporary error, and 20 attempts
    from one IP don't trigger the sign-in ban. 20 bad tokens do (DIR-30).
    *Keycloak.*
19. Changing `directoryId` takes effect on the next sign-in with no restart
    (DIR-17, DIR-31). *LDAP.*
20. **(compat)** Every domain in INBUXA's data signs in against the same
    source as before cutover. Any domain with `directoryId` set is listed
    first (see "Where the fork stands today").

## Open questions / to observe

1. **Explicit internal directory.** Under DIR-1, a domain can't opt out of a
   server default and use the internal directory. The data model has no way
   to say so. Needed? If it is, it's a fork-namespace field, not a change to
   upstream's.
2. **Opaque tokens and audience.** On the userinfo path (DIR-27),
   `requireAudience` and `requireScopes` can't be enforced. Should a
   directory with either set refuse opaque tokens, or offer RFC 7662
   introspection (which needs client credentials the schema has no field
   for)? The docs name `requireAudience`'s default as `stalwart`, and the
   schema has no default. Observe which one a new directory gets.
3. **Local credentials outlive the directory.** App passwords and API keys
   keep working for a user disabled in the directory (DIR-3). Should
   synchronization, or a failed directory sign-in, suspend them?
4. **ID tokens as access tokens.** DIR-26 doesn't check `typ` (RFC 9068
   `at+jwt`). An ID token whose `aud` equals `requireAudience` would pass.
   Check `typ` when present, or advise a distinct audience?
5. **Revocation on a directory change.** DIR-17 leaves server-issued tokens
   valid. That ties to the contract's token revocation (SPEC.md §5.2).
6. **One broken directory.** When one directory fails to open, the build
   error is recorded, and the non-certificate reload path applies only when
   there were no errors (`cache/reload.rs`). Observe on a local build whether
   one bad directory blocks unrelated setting changes. DIR-21 requires it
   doesn't.
7. **Tenant domains and the server default.** DIR-23 lets a tenant's domain
   with no directory use the server default. Alternative: tenant domains
   default to the internal directory. Settle once INBUXA's data shows whether
   any tenant domain relies on a default.
8. **Which snippets in `cache/directory.rs` matter.** The strip report shows
   6 snippets removed from that file, 2 from `authentication.rs`, 2 from
   `auth/mod.rs` and 2 from `cache/principals.rs`. This spec doesn't say what
   they did and doesn't need to. The rules they may have enforced (quota,
   SCIM authority, tenant checks) are specified here from other sources.

## Implementation status

Built 2026-09-19 from this spec, clean-room, under the multi-tenancy
hand-off brief's rules. The two lookups every caller goes through now
honor the domain (`crates/common/src/auth/authentication.rs`), with the
rules around them in `cache/directory.rs` (synchronization),
`network/mta.rs` (recipients), `crates/directory/src/core/config.rs`
(building) and `crates/jmap/src/registry/set.rs` (reloading); each change is
marked `inbuxa:`.

- **DIR-1 to DIR-32:** built, with the limits below. DIR-2, DIR-8, DIR-12,
  DIR-13 and DIR-25 to DIR-30 were already in the AGPL code and now follow
  the domain.
- **Tests.** `directory::per_domain::per_domain_directory_tests` covers
  tests 1, 3, 4, 6, 7, 9, 11, 15 and 19, and DIR-20 and DIR-21, over SQL
  directories on SQLite files, with no container. `directory_tests` runs a
  new `oidc` module in place of the removed one, against Keycloak, whose
  container now imports a second realm: tests 5, 8, 10, 12, 13, 14, 16, 17
  and 18, the last two in part (below). SCIM's acceptance test 5
  (`scim_oidc_tests`) now runs and passes.
- **Test 20 (compat)** is `per_domain_directory_compat`, ignored, and unrun
  until a copy of INBUXA's data is provided. It checks observed 1.
- **Not exercised, or only in part:**
  - Test 2 and test 9 use an SQL directory that can't open instead of a
    stopped LDAP server.
  - Test 12's later sign-ins (an empty groups claim clearing groups, a
    missing one keeping them) need changes to Keycloak users, and aren't
    run.
  - Test 13 is checked through synchronization itself, since the realm's
    users aren't on the tenant's domain. Test 14 reuses an account an
    administrator made, not one from an earlier LDAP directory.
  - Test 16 checks `HS256`, an unknown `kid`, another issuer and an expired
    token. Keycloak grants every required scope whatever is asked, so the
    missing-scope refusal isn't reached; audience and key rotation aren't
    run. Test 17 checks password sign-in and a malformed token; an opaque
    token that the provider accepts, and `usernameDomain`, aren't run.
    Test 18 stops the provider and checks an outage doesn't ban the
    client, and that bad tokens do; it doesn't measure the failure's
    latency.
  - DIR-22's rule that `Authentication.directoryId` names a server-level
    directory, and DIR-24 (a tenant administrator setting its own domains'
    directory), aren't tested.
- **Settled from the code, not a change of intent:**
  - A write to `x:Directory` or `Authentication` reloads the directories
    at once, on every node (DIR-17). Settings otherwise apply on an
    explicit reload.
  - A directory that fails to open is a build warning, not an error
    (DIR-21, open question 6): before, one error stopped every later
    reload from applying.
  - A server default naming no directory is unavailable, like a domain's
    (DIR-5); it used to mean the internal directory.
  - A token the OIDC directory refuses is an authentication failure, so it
    counts toward the sign-in ban (DIR-30); it used to be an error, which
    counts toward nothing.
- **Known limits, not requirements of this spec:**
  - An SQL directory on a SQLite path that can't be opened holds the reload,
    and the request that caused it, for the pool's 30-second connection
    timeout before it's marked unavailable.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), read-only, as a server-level administrator and the throwaway test
account. No upstream code was read.

1. **The cutover check passes.** INBUXA has no external directory
   (`x:Directory` is empty), `x:Authentication.directoryId` is null, and all
   nine domains have `directoryId` null. The fork ignoring `directoryId` today
   changes nothing for INBUXA.
2. **Tenant domains** (open question 7). INBUXA has no tenants, so no tenant
   domain relies on a default. DIR-23 stands as written.

Open question 2 (the `requireAudience` default) needs a directory to be
created, so it stays open.
