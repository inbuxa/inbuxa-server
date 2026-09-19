# Feature spec: SCIM 2.0 provisioning

Status: draft, 2026-09-18. Feature 7 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| This repository's surviving SCIM code: `crates/scim` and `crates/scim-proto` (manifests and stub `lib.rs` files) | AGPL-3.0-only | What exists, dependencies, where the crates are wired in |
| Surviving SCIM tests: `tests/src/scim/conformance.rs`, `oidc.rs`, `tenant.rs` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Observable behavior the tests assert: status codes, error types, tenancy, the OIDC interplay, advertised limits |
| Third-party client driver: `tests/docker/scim/driver.py` and `Dockerfile`, and `tests/src/utils/containers.rs` | Part of this AGPL repository | The lifecycle and IdP payload shapes the server must accept, and what it must return |
| Stalwart's registry schema: `crates/registry/src/schema/*.rs` and `resources/schema/schema.json.gz` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Field shapes and meanings, indexes, validation, the `scimAccess` permission, what upstream flags as Enterprise |
| AGPL code around the feature: `crates/common/src/auth/{credential,authentication}.rs`, `crates/common/src/cache/{directory,principals}.rs`, `crates/jmap/src/registry/mapping/principal.rs` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | API-key bearer authentication, just-in-time directory sync, account destruction, what is not there |
| Strip report `docs/fork/strip-reports/v0.16.22.{json,md}` | Ours | Which SCIM files, tests and snippets were removed (names and counts only) |
| Stalwart documentation (`website` repo): `docs/auth/scim/{index,configuration,endpoints,mapping,provisioning}.md`, `docs/auth/scim/providers/{index,entra-id,okta,keycloak}.md`, `docs/auth/authentication/api-key.md` | Unlicensed public documentation: facts used, prose not copied | Endpoints, limits, attribute mapping, authority rules, deprovisioning, provider behavior |
| RFC 7643, RFC 7644, RFC 9865 | IETF | The wire contract: schemas, operations, errors, cursor pagination |
| Spec `features/multi-tenancy.md`, `features/undelete.md` | Ours | Tenancy rules (MT-) and deleted-account handling (UD-) this spec relies on |

No Enterprise-only file or snippet was used. This spec was written by a fresh
session that never saw Enterprise code. The removed files are known here only
by the names the strip report lists. No running server was observed and no
production server was contacted. Where no allowed source settles a behavior,
this spec makes a **Decision** or lists it under "Open questions / to
observe". It never fills a gap from memory of upstream code.

Identity-provider behavior (what Entra ID, Okta and the Keycloak extensions
send) comes from Stalwart's public provider pages and from the payloads in
`driver.py`. The vendors' own SCIM documentation wasn't read for this draft
(see open questions).

## What it is

An identity provider (Entra ID, Okta, a Keycloak extension, a script) is the
system of record for people. SCIM lets it push their accounts into
inbuxa-server: create the mailbox the day a person is hired, keep the name,
aliases and group membership current, suspend the account when they leave,
and delete it when policy says so.

inbuxa-server is the SCIM **service provider** only. It receives requests at
`/scim/v2` on its existing HTTP listeners and applies them to its own
accounts. It never sends SCIM anywhere. SCIM doesn't authenticate mail users.
It's meant to be deployed beside an OIDC (or LDAP or SQL) directory that
does.

Upstream ships this only in its Enterprise Edition, and answers `/scim/v2`
with `403 Forbidden` in its Community Edition. inbuxa-server ships it to
everybody. There is no edition check. It's inert until an operator opens a
domain to it and issues a credential.

## What already exists in the fork

Surveyed 2026-09-18 at the v0.16.22 import.

### Present

| What | State |
|---|---|
| `crates/scim` | `Cargo.toml` (deps: `scim-proto`, `common`, `jmap`, `store`, `registry`, `directory`, `http_proto`, `jmap_proto`, `types`, `utils`, `trc`, `hyper`, `serde`, `serde_json`, `xxhash-rust` with `xxh3`, `icu_locale`; features `test_mode`, `dev_mode`, `enterprise`) and a `src/lib.rs` that is a 5-line AGPL-3.0-only header with no code |
| `crates/scim-proto` | `Cargo.toml` (deps: `serde`, `serde_json`, `hashify`) and the same empty `src/lib.rs` |
| Wiring | `crates/http` and `crates/main` depend on `scim`, and both map their `enterprise` feature onto `scim/enterprise`. Nothing calls into it. The HTTP router (`crates/http/src/request.rs`) has no `scim` path |
| `tests/src/scim/conformance.rs` (177 lines) | Runs `driver.py` in a container: an RFC conformance checker (`scim2-tester` 0.2.8), a full lifecycle with `scim2-client` 0.7.5, and replayed Okta, Keycloak and Entra payloads |
| `tests/src/scim/oidc.rs` (332 lines) | `allowScimProvisioning` against a Keycloak OIDC directory: no just-in-time creation, SCIM attributes survive a login, clearing the flag restores just-in-time sync |
| `tests/src/scim/tenant.rs` (362 lines) | A tenant-scoped client sees and reaches only its tenant, can't provision outside its domains, and can inside them |
| `tests/docker/scim/` | `Dockerfile` (Python 3.12, `scim2-tester`, `scim2-client`, `scim2-models` 0.6.12, `httpx`) and `driver.py` (457 lines) |
| `tests/src/utils/containers.rs` | `ensure_scim_tester`, `scim_tester_exec`, `ensure_keycloak` (with `tests/docker/keycloak/stalwart-realm.json`) |
| Registry schema | `x:Domain.allowScimProvisioning` (bool, default `false`, property 932), `x:UserAccount.externalId` and `x:GroupAccount.externalId` (nullable string, property 933, search-indexed, an empty string fails validation), `Permission::ScimAccess` (`scimAccess`, 660). Stored and serialized. Nothing reads them |
| API keys | `x:ApiKey` credentials on accounts; the `API_…` bearer token format and its validation (`crates/common/src/auth/credential.rs`, `authentication.rs`) are shared AGPL code and work today |
| Account destruction | `schedule_account_destruction` and the `DestroyAccount` task (`crates/jmap/src/registry/mapping/principal.rs`) |
| Just-in-time sync | `synchronize_account` and `synchronize_group` (`crates/common/src/cache/directory.rs`). They have no SCIM authority check, and the domain cache (`DomainCache`) doesn't carry the flag |

### Removed by the strip, to be rebuilt

- **All SCIM code, 33 files.** `crates/scim-proto/src/`: `attributes.rs`,
  `etag.rs`, `filter.rs`, `json.rs`, `lib.rs`, `path.rs`,
  `message/{bulk,error,list,mod,patch,search}.rs`,
  `schema/{group,mod,spc,user}.rs` (16). `crates/scim/src/`: `auth.rs`,
  `bulk.rs`, `context.rs`, `discovery.rs`, `error.rs`, `lib.rs`,
  `request.rs`, `groups/{get,mod,patch,set}.rs`, `query/{cursor,mod}.rs`,
  `users/{get,mod,patch,set}.rs` (17). The file names are the only thing
  known about them.
- **Eight test files:** `tests/src/scim/{auth,bulk,discovery,groups,limits,mod,query,users}.rs`.
  `mod.rs` held the shared helpers the three surviving files import
  (`ScimTest`, `ScimClient`, `SCIM_DOMAIN`, `HTTP_PORT`, `api_key`,
  `user_body`, `group_body`, `patch_body`, `query`, `jmap_session_status`)
  and `scim_proto` exported `SCHEMA_USER` and `MESSAGE_BULK_REQUEST`. The
  strip also removed `pub mod scim;` from `tests/src/lib.rs`, so the
  surviving tests aren't compiled.
- **Snippets in shared files.** The report gives counts, not contents. Six
  were cut from `crates/common/src/cache/directory.rs`, the just-in-time sync
  that SCIM-58 changes, and four each from `crates/http/src/request.rs` and
  `crates/http/src/api/mod.rs`. What they held isn't known and doesn't
  matter: this spec says what the behavior must be.
- **A dependency not in any spec yet.** Per-domain directories
  (`x:Domain.directoryId`, also flagged Enterprise) aren't rebuilt:
  `get_directory_for_domain` returns the default directory. `oidc.rs` binds
  an OIDC directory to one domain, so it needs that first (see open
  questions).

## Data model

Unchanged from upstream, so existing data opens as it is (SPEC.md §7).
Upstream flags three fields as Enterprise. In inbuxa-server they're
ordinary fields, readable and writable over JMAP by anyone with the matching
`sysDomain*` or `sysAccount*` permission.

| Field | Type | Meaning |
|---|---|---|
| `x:Domain.allowScimProvisioning` | boolean, default `false` | SCIM may write accounts on this domain, and SCIM is authoritative for them: just-in-time directory sync stops creating or changing them |
| `x:UserAccount.externalId` | string or null | The identity provider's own identifier for the user. Search-indexed. Not unique in the index |
| `x:GroupAccount.externalId` | string or null | The same, for a group |

Everything else SCIM touches already exists: `x:UserAccount` (`name`,
`domainId`, `emailAddress`, `aliases`, `description`, `locale`, `timeZone`,
`memberGroupIds`, `memberTenantId`, `permissions`, `roles`, `createdAt`),
`x:GroupAccount` (`name`, `domainId`, `description`, `memberTenantId`,
`createdAt`), `x:ApiKey` (`description`, `secret`, `permissions`,
`allowedIps`, `expiresAt`, `createdAt`), and the permissions `authenticate`,
`scimAccess`, `sysAccountGet`, `sysAccountCreate`, `sysAccountUpdate`,
`sysAccountDestroy` and `unlimitedRequests`.

There is no "provisioned by SCIM" marker and no modification timestamp on
accounts. Nothing new is stored. The ETag (SCIM-44) is computed, and cursors
(SCIM-49) carry their own state.

### How SCIM resources map

**User** (`urn:ietf:params:scim:schemas:core:2.0:User`) is an
`x:UserAccount`:

| SCIM attribute | Account field | Mutability | Notes |
|---|---|---|---|
| `id` | the account's id | readOnly | The same id JMAP uses |
| `externalId` | `externalId` | readWrite | case-exact |
| `userName` | `name` + `domainId` | readWrite, required | A full email address |
| `displayName` | `description` | readWrite | |
| `name.formatted` | `description` | readWrite | The same stored value as `displayName` |
| `active` | the effective `authenticate` permission | readWrite | SCIM-27 |
| `emails` | primary address, then `aliases` | primary readOnly, others readWrite | SCIM-25 |
| `locale`, `preferredLanguage` | `locale` | readWrite | One stored value |
| `timezone` | `timeZone` | readWrite | IANA name |
| `groups` | `memberGroupIds` | readOnly | `value`, `display`, `$ref` |
| `meta` | `createdAt`, computed version | readOnly | `resourceType`, `created`, `location`, `version` |

**Group** (`urn:ietf:params:scim:schemas:core:2.0:Group`) is an
`x:GroupAccount`:

| SCIM attribute | Account field | Mutability | Notes |
|---|---|---|---|
| `id` | the group's id | readOnly | |
| `externalId` | `externalId` | readWrite | case-exact |
| `displayName` | `description` | readWrite, required | Unique among groups in scope |
| `members` | the members' `memberGroupIds` | readWrite | Users only |
| `meta` | `createdAt`, computed version | readOnly | Version covers membership |

## Required behavior

Each requirement has an ID, and tests name the IDs they check.

### The endpoint

- **SCIM-1.** SCIM is served under `/scim/v2` on every HTTP listener, beside
  JMAP. Every response, errors included, has content type
  `application/scim+json`. Requests with `application/scim+json` or
  `application/json` bodies are accepted (RFC 7644 §3.1).
- **SCIM-2.** Paths and methods are those in "Interfaces". An unknown path
  under `/scim/v2` answers `404`. A known path with the wrong method answers
  `405` with an `Allow` header. `OPTIONS` on any path answers `204`. `/Me`
  answers `501` for every method, which RFC 7644 §3.11 allows: the caller is
  a service account, not a provisionable user.
- **SCIM-3.** The discovery endpoints (`/ServiceProviderConfig`,
  `/ResourceTypes`, `/Schemas`, and their single-item forms) need no
  authentication and return no account data. They're subject to the anonymous
  HTTP rate limit. A `filter` parameter on them answers `403` (RFC 7644 §4).
- **SCIM-4.** `/ServiceProviderConfig` is fixed: `patch` supported, `bulk`
  supported with `maxOperations` 1000 and `maxPayloadSize` 1048576,
  `filter` supported with `maxResults` 200, `changePassword` not supported,
  `sort` supported, `etag` supported, and one authentication scheme of type
  `oauthbearertoken`, marked primary. It also carries the RFC 9865
  `pagination` object: `cursor` true, `index` true,
  `defaultPaginationMethod` `index`, `defaultPageSize` 100, `maxPageSize`
  200, `cursorTimeout` 3600 (SCIM-49), and `interopProfileConformant`
  `false` (SCIM-33). **Decision:** any `documentationUri` points at INBUXA's
  own documentation, never upstream's.
- **SCIM-5.** `/ResourceTypes` lists `User` (endpoint `/Users`) and `Group`
  (endpoint `/Groups`). **Decision:** no `schemaExtensions` are listed. The
  enterprise User extension is accepted in requests (SCIM-33) but not
  published, since nothing in it is stored.
- **SCIM-6.** `/Schemas` publishes only the attributes in the mapping tables
  above, with RFC 7643 characteristics (`mutability`, `returned`,
  `uniqueness`, `caseExact`, `required`). `password` isn't published.
  `members.type` publishes `User` as its only canonical value.
  `userName` has `uniqueness: server` and `caseExact: false`. `externalId`
  has `caseExact: true`.

### Authentication and the credential

- **SCIM-7.** Every non-discovery request authenticates with an API key of
  the service principal's, sent as `Authorization: Bearer API_…`. Missing,
  malformed, unknown, expired or revoked keys answer `401`. HTTP Basic
  answers `401` with a `detail` telling the caller to use a bearer token.
  **Decision:** other bearer tokens (the server's own OAuth access tokens, or
  an external OIDC provider's) are refused on `/scim/v2` with `401`, so that a
  person's sign-in token can't drive provisioning. A `401` carries
  `WWW-Authenticate: Bearer` (RFC 6750).
- **SCIM-8.** The key is issued the way every API key is today: as an
  `x:ApiKey` credential on the service principal's account, created over
  JMAP (INBUXA Admin, or ihasmail's administration). The server generates the
  secret, returns it once at creation and stores it hashed. The account's
  `maxApiKeys` quota applies. Nothing SCIM-specific is added to issuing.
- **SCIM-9.** The key's own controls apply to SCIM like any other use:
  `allowedIps` (a request from elsewhere is `401`), `expiresAt`, and its
  permission mode (`Inherit`, `Disable`, `Replace`). **Revocation** is
  deleting the credential, or disabling or deleting the service principal. It
  takes effect on the next request, with no cache delay. **Rotation** is a
  second key, the identity provider updated, and the first key deleted.
- **SCIM-10.** **Decision:** OAuth client credentials (RFC 6749 §4.4) aren't
  part of this feature. Every client this spec targets can send a static
  bearer token: Entra ID's "Secret Token", Okta's "HTTP Header" mode, and the
  Keycloak extensions. Adding the grant belongs with the OAuth work in
  `contract.md`, and would reuse the same permission checks.

### Authorization

- **SCIM-11.** Two gates, both on the effective permissions of the key (the
  account's, cut down by the key's mode, and by the tenant's ceiling, MT-13):
  - `authenticate` and `scimAccess` for every non-discovery request. Without
    either the answer is `403`, and the `detail` names the missing one.
  - Per operation: `sysAccountGet` for every read and query, `.search`
    included; `sysAccountCreate` for `POST`; `sysAccountUpdate` for `PUT`,
    `PATCH`, and any membership change, including a group created with
    members; `sysAccountDestroy` for `DELETE`. Missing: `403`, naming the
    permission, with nothing changed.
- **SCIM-12.** A service principal in a tenant needs its tenant to allow
  `scimAccess` (MT-13, MT-14). A tenant whose ceiling lacks it can't
  provision, whatever its principal is granted.
- **SCIM-13.** A request that would deactivate, delete or rename the service
  principal the request authenticated as answers `403`, and changes nothing.
  **Decision:** there is no other protected class. Administrators on a
  SCIM-enabled domain can be deactivated or deleted by SCIM like anyone, since
  a departed administrator is exactly who must be cut off. Operators who want
  admins out of the identity provider's reach keep them on a domain that
  isn't SCIM-enabled.
- **SCIM-14.** Authenticated HTTP rate limits apply per principal. Over the
  limit the answer is `429` with `Retry-After`. `unlimitedRequests` exempts
  the principal, as elsewhere. A `/Bulk` request counts as one request.

### Scope: domains and tenants

- **SCIM-15.** **Domain authority.** Every address a write touches (the
  `userName`, every alias in `emails`, and a new group's derived address)
  must be on a domain with `allowScimProvisioning` true, in the caller's
  scope. Otherwise the whole request is refused with `400 invalidValue` and
  a `detail` naming the domain. Domains are created by administrators, never
  by SCIM. A `userName` that isn't an email address at all is `400
  invalidValue`, and its `detail` contains "is not a valid email address".
- **SCIM-16.** **Visibility.** A principal's SCIM scope is every account of
  the resource's type that it could reach over JMAP (MT-1, MT-2): all of them
  for a server-level principal, its own tenant's for a tenant principal.
  **Decision:** SCIM further limits reads, queries and writes to accounts
  whose domain has `allowScimProvisioning` true. An identity provider has no
  business listing mailboxes it may not manage. Accounts in scope include
  ones created by hand (SCIM-36): the service principal and any other account
  on the domain appear in `/Users`.
- **SCIM-17.** **Tenant boundaries don't leak.** A resource outside the
  caller's tenant answers `404` to `GET`, `PUT`, `PATCH` and `DELETE`, the
  same as a resource that doesn't exist, and the same inside `/Bulk`
  operations. Filters never match it. An address on a domain in another
  tenant (or, for a tenant principal, on a server-level domain) answers
  `404`, with a `detail` naming the domain. A domain in the caller's tenant
  that isn't SCIM-enabled answers `400 invalidValue` (SCIM-15). Error
  `detail` never contains another tenant's data.
- **SCIM-18.** **Where new accounts land.** A new user is in its domain's
  tenant (MT-7). A new group is on the service principal's own domain,
  because a SCIM Group has no address to take a domain from. So a principal
  whose own domain isn't SCIM-enabled can manage users but can't create
  groups: `400 invalidValue`, naming its domain.
- **SCIM-19.** **Membership stays inside a tenant.** Adding a member in a
  different tenant from the group (no tenant counts as different) is `400
  invalidValue` (MT-3).
- **SCIM-20.** **Tenant quotas.** A create that would pass a tenant's
  `maxAccounts` or `maxGroups` is refused and emits `limit.tenant-quota`, as
  MT-17 requires. **Decision:** SCIM reports it as `403` with a `detail`
  naming the limit. RFC 7644 has no quota error type, and `403` is its code
  for an operation the caller may not perform.

### User resources

- **SCIM-21.** `id` is the account's registry id as a string, the same value
  JMAP uses. It never changes. An identity provider connected to an upstream
  Enterprise server keeps working after cutover without matching accounts
  again.
- **SCIM-22.** `userName` is the account's full address, `name@domain`. The
  server splits it into `name` and `domainId`. It's compared
  case-insensitively. **Decision:** it's stored and returned lowercased. A
  `userName` already used by any account, alias or list is `409 uniqueness`,
  naming the address.
- **SCIM-23.** Changing `userName` (by `PUT` or `PATCH`) moves the account to
  the new address. The new domain must pass SCIM-15 and be in the account's
  tenant (MT-7), or the change is refused. **Decision:** the old address is
  released, not kept as an alias. An identity provider that wants it kept
  sends it in `emails`.
- **SCIM-24.** The display name is stored in `description`. Precedence on
  write: `displayName`, then `name.formatted`, then `name.givenName` and
  `name.familyName` joined by one space (either may be missing). It's
  returned under both `displayName` and `name.formatted`, never as
  structured parts. With none of them sent, there is no display name, and
  neither attribute is returned.
- **SCIM-25.** **Emails.** The primary address always comes first in
  `emails`, with `primary: true` and `type: "work"`. It's derived from
  `userName`, and its sub-attributes are read-only: trying to remove it,
  retype it or make it non-primary through `emails` is `400 mutability`, with
  a `detail` pointing at `userName`. Every other entry is an alias,
  returned after the primary in stored order with `primary: false`.
  **Decision:** aliases are returned without a `type`, and any `type` sent
  for them is dropped. Entries that repeat the primary, or each other, are
  skipped. Each alias must pass SCIM-15 and be in the account's tenant. An
  alias another account already holds is `409 uniqueness`. `PUT` replaces the
  alias set. `PATCH` adds or removes aliases one by one, so an address
  dropped upstream is dropped here.
- **SCIM-26.** **Locale and time zone.** `locale` and `preferredLanguage`
  are one stored value. If both are sent, `locale` wins. Both are returned,
  with the same value. SCIM's hyphen form (`en-US`) maps to the stored
  underscore form (`en_US`) both ways, case-insensitively, and variants such
  as `ca-ES@valencia` are accepted. A locale the server has no translation
  for is `400 invalidValue`. `timezone` is an IANA name. An unknown one is
  `400 invalidValue`.
- **SCIM-27.** **`active`.** It isn't stored. Reading it gives the account's
  effective `authenticate` permission, from the account, its roles and its
  tenant.
  - Setting `false` adds `authenticate` to the account's disabled
    permissions, overriding its roles. If the account's `permissions` was
    `Inherit`, it becomes `Merge` with only that entry.
  - Setting `true` removes only that entry. An account that was `Inherit`
    before goes back to exactly `Inherit`. Every other permission an
    administrator set is left as it was.
  - If `authenticate` still isn't effective after `true` (a role or the
    tenant withholds it), the request succeeds and the response shows
    `active: false`. SCIM grants nothing beyond undoing its own suspension.
  - `PATCH` accepts JSON booleans and the strings `"true"` and `"false"` in
    any case (Entra ID sends `"False"`).
- **SCIM-28.** `groups` on a user is read-only. Each entry has `value` (the
  group's id), `display` (the group's display name) and `$ref`. A write to it
  is `400 mutability`. Membership is changed through the Group.
  **Decision** (2026-09-19): in a `POST` or `PUT` body, a `groups` value that
  equals the current membership (so `[]` on create, as Okta sends) isn't a
  write: it's accepted and ignored. A value that would change membership is
  `400 mutability`, and `PATCH` on `groups` always is.
- **SCIM-29.** `externalId` is stored exactly as sent and never interpreted.
  It's matched case-exactly. An empty string is `400 invalidValue`, as the
  schema already requires. **Decision:** within one tenant (or the
  server-level scope), two users, or two groups, may not share an
  `externalId`. A write that would cause it is `409 uniqueness`. Duplicates
  already in stored data are left alone, and a filter on that value returns
  them all.
- **SCIM-30.** `meta` has `resourceType`, `created` (the account's
  `createdAt`), `location` and `version`. `lastModified` isn't returned,
  because accounts don't record one. `location`, `$ref` values and the
  `Location` header are absolute URLs built from the server's public URL
  (`INBUXA_PUBLIC_URL`).
- **SCIM-31.** **Defaults on create.** A new user gets the `User` role,
  `Inherit` permissions (so the server's and tenant's defaults), the server's
  default locale, no time zone, and no credentials of any kind. It can sign in
  only through the directory that serves its domain, until someone gives it a
  password another way.
- **SCIM-32.** **Local settings stay local.** SCIM never reads or writes
  quotas, roles, permissions other than the `authenticate` entry of SCIM-27,
  credentials, encryption settings, Sieve scripts, mailboxes or any other
  field. An administrator's changes to them survive every sync.
- **SCIM-33.** **What is accepted and ignored.** Attributes of the core
  RFC 7643 User and Group schemas that aren't in the mapping tables, and
  everything under `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`,
  are accepted in `POST`, `PUT` and `PATCH` and discarded: never stored, never
  returned. That covers `password` (never written to the credential store,
  and never echoed in any response), `phoneNumbers`, `addresses`, `photos`,
  `ims`, `title`, `userType`, `nickName`, `profileUrl`, `entitlements`,
  `roles`, `x509Certificates`, the other `name` parts, and a Group's
  `description`. An attribute in no schema the server knows, an unknown
  schema URI, a duplicated attribute, or a missing `schemas` value is `400
  invalidSyntax`, with a `detail` naming it. This follows RFC 7644 §3.1, not
  the interoperability profile's rule that unknown attributes must be
  rejected, which is why `interopProfileConformant` is `false`. Attribute
  names are case-insensitive (RFC 7643 §2.1).

### Group resources

- **SCIM-34.** `displayName` is required and stored in the group's
  `description`. It must be unique among groups in the caller's scope,
  compared case-insensitively (**Decision** on case). A clash is `409
  uniqueness`.
- **SCIM-35.** **The group's address.** Derived once, at creation, from
  `displayName`: lowercased, every run of characters other than ASCII
  letters and digits replaced by one hyphen, leading and trailing hyphens
  trimmed, and cut to 64 characters, so `Sales EMEA` gives `sales-emea` on the
  service principal's domain (SCIM-18). If the address is taken, a numeric
  suffix is added until one is free. **Decision** on the details: the
  suffix is `-2`, `-3` and so on, the cut to 64 leaves room for it, and an
  empty result becomes `group`. If no free address can be found, `409
  uniqueness`. Renaming the group later doesn't change its address.
- **SCIM-36.** **Members.** Only users. A member that is a group is `400
  invalidValue`. Nested groups aren't supported either way. **Decision:** a
  member id that doesn't exist in scope is `400 invalidValue`, naming it.
  Membership is stored on each user (`memberGroupIds`), so a membership
  change writes each affected user, and needs `sysAccountUpdate`. Each entry
  returned has `value`, `display` (the user's display name), `type: "User"`
  and `$ref`. Entries are added or removed, never edited in place.
- **SCIM-37.** Reading a group with more than 200 members, without
  `excludedAttributes=members`, is `400 tooMany`, and the `detail` says to
  exclude `members` and read membership from the users' `groups`.
- **SCIM-38.** A group's `externalId` and `meta` behave as a user's
  (SCIM-29, SCIM-30). Its `version` covers its membership, so adding or
  removing a member changes it.

### Operations

- **SCIM-39.** **Create** (`POST /Users`, `POST /Groups`): `201`, the full
  resource, `Location` and `ETag` headers. The response has the `id` the
  identity provider must keep.
- **SCIM-40.** **Read** (`GET /{type}/{id}`): `200` and the resource, with
  `ETag`. `attributes` and `excludedAttributes` (RFC 7644 §3.9) work here and
  on every query. A resource that doesn't exist or is out of scope is `404`.
- **SCIM-41.** **Replace** (`PUT`): the body is the whole resource. Every
  readWrite attribute left out goes back to its default: no display name,
  no aliases, the default locale, no time zone, `active` true (undoing only
  SCIM's own suspension, SCIM-27), no `externalId`, and for a group no
  members. `id` in the body is ignored if it matches, and `400 mutability`
  if it doesn't. `200` and the resource.
- **SCIM-42.** **Modify** (`PATCH`, RFC 7644 §3.5.2): a `PatchOp` with
  `add`, `remove` and `replace`, op names in any case (Entra ID sends
  `Replace`).
  - With no `path`, `add` and `replace` take an object of attributes, as
    Keycloak's extensions send `{"active": "false"}`.
  - Paths may be simple (`displayName`), sub-attributes (`name.givenName`),
    fully qualified with a schema URN (enterprise-extension paths are
    accepted and discarded, SCIM-33), or value-filtered on a multi-valued
    attribute (`emails[value eq "a@b"]`, `members[value eq "id"]`).
  - `remove` needs a `path`. `remove` on `members` with no filter removes
    every member. **Decision:** removing a member or alias that isn't there
    succeeds with no change, because identity providers retry.
  - A path the server doesn't support is `400 invalidPath`. A write to a
    readOnly attribute is `400 mutability`.
  - All the operations in one request apply together or not at all. The
    answer is `200` with the full resource, never `204`.
- **SCIM-43.** **Delete** (`DELETE`): `204`. The resource is gone at once:
  `GET` answers `404`. What deletion does to mail is SCIM-52.
- **SCIM-44.** **Versions and conditional requests.** Every resource has
  `meta.version`, also sent as the `ETag` header. It's computed from the
  resource's content, so it changes when the resource does and only then.
  **Decision:** it's a weak ETag, `W/"…"`. `If-None-Match` on `GET` answers
  `304` when unchanged. `If-Match` on `PUT`, `PATCH` or `DELETE` answers `412`
  when the resource has changed. Without the header, writes are
  unconditional, and the last one wins. **Decision:** versions may differ
  from the ones an upstream server returned, so the first conditional request
  after cutover may get `412` and read again. None of the identity providers
  covered here send conditional requests.

### Queries

- **SCIM-45.** **Filters** work on `GET /Users`, `GET /Groups` and every
  `.search`. The operators are `eq` and `and` only, in any case. Every other
  operator (`ne`, `co`, `sw`, `ew`, `gt`, `ge`, `lt`, `le`, `pr`, `or`,
  `not`) is `400 invalidFilter`, and the whole filter is parsed first so the
  `detail` names the construct. Filterable attributes:
  - User: `id`, `externalId`, `userName`, `emails`, `emails.value`,
    `active`, `displayName`, `name.formatted`, `groups`, `groups.value`;
  - Group: `id`, `externalId`, `displayName`, `members`, `members.value`.

  Any other attribute is `400 invalidFilter`. `emails`, `groups` and
  `members` without a sub-attribute mean their `value`. A value filter
  (`attr[sub eq "x"]`) inside `filter` is `400 invalidFilter`. Comparison
  follows each attribute's `caseExact` (SCIM-6). A filter that matches
  nothing is `200` with an empty `ListResponse`: that's Entra ID's
  connection test.
- **SCIM-46.** `active`, `displayName` and `name.formatted` can't be
  answered from an index. They're checked after the indexed part of the
  filter has narrowed the candidates. If more than 200 candidates remain, the
  request is `400 tooMany`, and the `detail` asks for a narrower filter.
  `active eq false` on its own is allowed when it fits under that limit, since
  operators use it to find suspended accounts.
- **SCIM-47.** **Sorting.** `sortBy` accepts `id`, and `userName` for users.
  `sortOrder` accepts `ascending` and `descending`. Anything else is `400
  invalidValue`. **Decision:** with no `sortBy`, results are in ascending
  `id` order, so pages are stable.
- **SCIM-48.** **Index pagination** (RFC 7644 §3.4.2.4), the default:
  `startIndex` is 1-based, and a value below 1 is treated as 1. `count`
  defaults to 100 and is capped at 200. `count=0` returns only
  `totalResults`. Responses carry `totalResults`, `startIndex` and
  `itemsPerPage`.
- **SCIM-49.** **Cursor pagination** (RFC 9865): `cursor` empty for the first
  page, then each response's `nextCursor`. The last page has no
  `nextCursor`. `previousCursor` isn't offered. A cursor is opaque and
  tamper-evident, and bound to the principal, the filter, the sort and the
  `count` that produced it. A cursor presented with any of those changed, or
  a forged one, is `400 invalidCursor` (a changed `count` is `400
  invalidCount`). **Decision:** a cursor is good for at least 3600 seconds
  (advertised as `cursorTimeout`), then `400 expiredCursor`. It needs no
  server-side state. Each page is computed with the principal's permissions
  at the time, so a permission change can't leak anything through an old
  cursor. `startIndex` and `cursor` together are `400 invalidValue`.
- **SCIM-50.** **Query by POST.** `POST /Users/.search` and
  `POST /Groups/.search` take a `SearchRequest` with the same parameters.
  `POST /.search` searches both types and returns one `ListResponse`.
  **Decision:** in the combined result, users come before groups, each in
  the requested order, and each resource carries its `schemas` so the client
  can tell them apart.

### Bulk

- **SCIM-51.** `POST /Bulk` (RFC 7644 §3.7) takes up to 1000 operations and
  1 MiB. More operations, or a larger body, is `413`. It supports
  `failOnErrors` and `bulkId`: a later operation may refer to a resource
  created earlier in the same request, as `bulkId:<id>` in a `path` or in a
  member `value`. Operations run in the order sent. A reference that can't be
  resolved, or a circular one, fails that operation with `409 invalidValue`.
  Each operation is authorized and scoped exactly as it would be on its own
  (SCIM-11, SCIM-17), and reports its own `status` (a string, as RFC 7644
  requires), `location` and `version`. Bulk isn't atomic: a failure doesn't
  undo earlier successes. The response is `200` unless the request as a
  whole is malformed.

### Deprovisioning and mail

- **SCIM-52.** **Suspend and delete are different.**
  - **`active: false` (suspend).** The account can't authenticate on any
    protocol with any credential: password, app password, API key, OAuth
    tokens already issued, and external OIDC tokens. It takes effect on the
    next request, without waiting for a permission cache to expire, the way
    MT-16 requires for tenant changes. **Decision:** long-lived sessions the
    account already has open (IMAP IDLE, JMAP push and event streams,
    WebSockets, ManageSieve) are ended. Mail keeps arriving and is kept,
    and the account's Sieve rules, forwarding and vacation reply keep
    running (**Decision**; mail flow is unchanged by suspension). Its shares
    with others stay. It still counts against quotas.
  - **`DELETE`.** The account is destroyed through the same path as an
    administrator's `x:Account` destroy: the `DestroyAccount` task, shares
    other accounts held on it revoked, and its data destroyed. Mail to its
    addresses is refused as for an unknown recipient. If undelete's
    `archiveDeletedAccountsFor` is set, the account is kept for that period
    and its addresses stay reserved (UD-15, UD-16), so the identity provider
    re-creating the same `userName` meanwhile gets `409 uniqueness`.
  - Without `sysAccountDestroy`, `DELETE` is `403` and the account is left
    as it was, typically already suspended. Operators who want suspension
    only leave that permission off the key.
- **SCIM-53.** Deleting a group destroys the group account the same way. Its
  members lose the membership, and mail to its address is refused as for an
  unknown recipient.
- **SCIM-54.** **Decision:** every SCIM write emits an event naming the
  service principal, the resource, its `externalId` and the change
  (created, updated, suspended, reactivated, deleted), so operators can audit
  what the identity provider did. Filter values from query strings aren't
  added to any new log field, since RFC 7644 §7.5.2 warns they can carry
  personal data.

### Conflict with accounts made another way

- **SCIM-55.** Nothing marks an account as SCIM-owned. Every account in scope
  (SCIM-16) can be managed by SCIM, whether SCIM created it, an
  administrator did, or just-in-time sync did before the flag was set. An
  `externalId` is the only trace SCIM leaves.
- **SCIM-56.** `POST` never adopts an existing account. If the `userName` or
  an alias is taken, the answer is `409 uniqueness` naming the address.
  Identity providers look for a match first (`filter=userName eq …` or
  `externalId eq …`) and then update what they find with `PATCH` or `PUT`,
  which is how an account made by hand comes under the identity provider.
- **SCIM-57.** Administrators may still change SCIM-mapped fields over JMAP,
  `externalId` included. The next sync may overwrite them. That's expected,
  and not an error.

### Just-in-time sync and authority

- **SCIM-58.** When a domain's `allowScimProvisioning` is **true**, SCIM is
  authoritative there. Just-in-time directory sync (on sign-in, and on
  recipient lookup for LDAP and SQL directories) becomes read-only for that
  domain:
  - it creates no account. A person who authenticates at the directory before
    being provisioned gets an ordinary authentication failure (`401` over
    HTTP), not a half-made account;
  - it changes nothing on an existing account: not the display name, aliases,
    group membership or stored secret. The account's SCIM `version` doesn't
    change on sign-in;
  - it creates no group from a groups claim;
  - the directory still authenticates the person. A provisioned, active
    account signs in normally.
- **SCIM-59.** When the flag is **false** (the default), just-in-time sync
  works exactly as it does today, and SCIM writes to the domain are refused
  (SCIM-15).
- **SCIM-60.** Changing the flag moves nothing. Turning it on leaves existing
  accounts where they are; they stop being updated by sync, and the identity
  provider takes them over only when it matches them (SCIM-56). Turning it
  off leaves SCIM-made accounts in place; sync resumes and may overwrite their
  display name and replace their groups on the next sign-in, and SCIM can no
  longer see them (SCIM-16). The change takes effect without a restart.
- **SCIM-61.** The rule follows whichever directory serves the domain. Until
  per-domain directories (`Domain.directoryId`) are rebuilt, that's the
  default directory.
  **Decision** (2026-09-19): SCIM is built before per-domain directories
  (feature 9). Acceptance test 5 (`oidc.rs`) binds an OIDC directory to one
  domain, so it stays ignored until feature 9 is built, and runs unchanged
  then. Until then SCIM-58 to SCIM-60 are tested against the default
  directory.

## Interfaces

### Endpoints

All under `/scim/v2`.

| Path | Methods | Authentication |
|---|---|---|
| `/Users` | `GET`, `POST` | API key |
| `/Users/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` | API key |
| `/Users/.search` | `POST` | API key |
| `/Groups` | `GET`, `POST` | API key |
| `/Groups/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` | API key |
| `/Groups/.search` | `POST` | API key |
| `/.search` | `POST` | API key |
| `/Bulk` | `POST` | API key |
| `/ServiceProviderConfig` | `GET` | none |
| `/ResourceTypes`, `/ResourceTypes/{id}` | `GET` | none |
| `/Schemas`, `/Schemas/{urn}` | `GET` | none |
| `/Me` | any | answers `501` |
| any path | `OPTIONS` | none, answers `204` |

### Setting it up

What an operator does, all with existing objects:

1. Set `allowScimProvisioning` on each domain the identity provider may manage.
2. Create a dedicated service-principal account on one of those domains (its
   domain is where SCIM groups go, SCIM-18). In a tenant, create it in that
   tenant, and make sure the tenant allows `scimAccess` (SCIM-12).
3. Give it an API key. The narrowest is `Replace` mode with `authenticate`,
   `scimAccess`, `sysAccountGet`, `sysAccountCreate`, `sysAccountUpdate`, and
   `sysAccountDestroy` only if deletion should be honored. Add `allowedIps`
   if the identity provider's addresses are known.
4. Give the identity provider the base URL `https://<public host>/scim/v2` and
   the key.

The endpoint can be confined further with the existing
`x:Http.allowedEndpoints` expression (for example by remote address or
listener). SCIM adds no setting of its own.

### Errors

SCIM error documents (RFC 7644 §3.12): `schemas`
`["urn:ietf:params:scim:api:messages:2.0:Error"]`, `status` as a string,
`detail`, and `scimType` where one applies.

| Status | `scimType` | When |
|---|---|---|
| `400` | `invalidSyntax` | Malformed JSON; an attribute or schema URI in no known schema; a duplicated attribute; `schemas` missing |
| `400` | `invalidFilter` | Unsupported operator or attribute, or a value filter, in `filter` |
| `400` | `invalidPath` | Unsupported `PATCH` path |
| `400` | `invalidValue` | A value the server can't accept: a domain not open to SCIM, a non-address `userName`, an unknown locale or time zone, a group as a member, a cross-tenant member, an unknown member id, a bad sort, `startIndex` with `cursor` |
| `400` | `mutability` | A write to a readOnly attribute or to the primary email; a mismatched `id` on `PUT` |
| `400` | `tooMany` | Over 200 candidates for an unindexed filter; a group over 200 members read with its members |
| `400` | `invalidCursor`, `expiredCursor`, `invalidCount` | Cursor pagination (RFC 9865) |
| `401` | | No, bad, expired or revoked API key; Basic auth; a bearer token that isn't an API key; a disallowed IP |
| `403` | | A missing permission (named in `detail`); the service principal deactivating, deleting or renaming itself; a tenant limit reached; `filter` on a discovery endpoint |
| `404` | | Unknown resource or path; anything outside the caller's tenant |
| `405` | | Wrong method; `Allow` lists the right ones |
| `409` | `uniqueness` | An address, group name or `externalId` already in use; no free group address |
| `409` | `invalidValue` | An unresolvable or circular `bulkId` (inside a `/Bulk` result) |
| `412` | | `If-Match` no longer holds |
| `413` | | `/Bulk` over 1000 operations or 1 MiB |
| `429` | | Rate limited; `Retry-After` says when to retry |
| `501` | | `/Me` |

### JMAP

- **Existing, unchanged:** `x:Domain.allowScimProvisioning`,
  `x:UserAccount.externalId` and `x:GroupAccount.externalId` through
  `x:Domain` and `x:Account` `/get`, `/set` and `/query`, as ordinary fields;
  the `scimAccess` permission; `x:ApiKey` credentials.
- **New, Decision:** `x:Account/query` accepts an `externalId` filter (the
  index already exists), so administration screens can find the account an
  identity provider means.

## ihasmail changes

These go in ihasmail-inbuxa, not public ihasmail, which stays
Stalwart-facing (SPEC.md §5).

- **Domains:** an "Allow SCIM provisioning" switch on the domain form. Turning
  it on warns that sign-in sync stops creating and updating accounts on the
  domain (SCIM-58), and turning it off warns that sync resumes (SCIM-60).
- **Accounts and groups:** show `externalId` when set, as "Managed by the
  identity provider", and say that edits to the name, display name, aliases,
  groups or sign-in status may be overwritten at the next sync (SCIM-57).
  Allow clearing it.
- **Suspended accounts:** show an account whose `authenticate` permission is
  disabled as suspended, with a filter for them, so operators can review
  what Okta leaves behind (it never deletes). Reactivating from ihasmail
  undoes the suspension the same way SCIM-27 does.
- **Service principal and key:** creating an API key with the SCIM
  permissions stays in INBUXA Admin. ihasmail links there from the domain
  switch rather than growing its own screen (SPEC.md §5.4).
- Every string this adds is new translation work for ihasmail's nine
  languages.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code. The three
surviving suites come back first: rebuild `tests/src/scim/mod.rs` with the
helpers they import (from this spec, not from the removed file), put
`pub mod scim;` back in `tests/src/lib.rs`, and re-export the constants they
use from `scim-proto`. `oidc.rs` also needs per-domain directories (see open
questions). The rest are new, written from this spec to cover what the
removed suites (`auth`, `bulk`, `discovery`, `groups`, `limits`, `query`,
`users`) covered.

1. **Third-party lifecycle** (`conformance.rs`, `lifecycle`): discovery
   values, create user with an alias, read by id and by filter, `.search`,
   `PATCH` display name and `active`, `PUT` that resets `active` and the
   display name, group created with a member, membership shown on the user,
   members removed, group and user deleted, user `404` (SCIM-4, SCIM-22,
   SCIM-24, SCIM-25, SCIM-27, SCIM-28, SCIM-30, SCIM-36, SCIM-39 to SCIM-44,
   SCIM-50).
2. **Real client payloads** (`conformance.rs`, `clients`): Okta create with
   `password` and extra attributes, Keycloak create with only structured
   names, Entra create with the enterprise extension, Okta `PUT`, Keycloak
   no-path `PATCH` with `"false"`, Entra `Replace` with extension path,
   lookup by `userName`, and `dispalyName` refused `invalidSyntax`. No
   response contains `password` (SCIM-24, SCIM-27, SCIM-33, SCIM-42).
3. **Conformance checker** (`conformance.rs`): `scim2-tester` reports no
   error, critical or deviation beyond the generated non-address `userName`
   (SCIM-1 to SCIM-6, SCIM-15).
4. **Tenant isolation** (`tenant.rs`): a tenant client lists only its two
   accounts, filters and `.search` never find an outsider, every operation
   on an outsider is `404` (in `/Bulk` too), adding an outsider to a group is
   `400 invalidValue`, an address on a server-level domain is `404` naming
   it, and provisioning inside its own domain works end to end (SCIM-16,
   SCIM-17, SCIM-19, SCIM-51).
5. **OIDC authority** (`oidc.rs`): with the flag on, an unprovisioned
   Keycloak user's sign-in is `401` and creates nothing; a SCIM user signs in,
   and its display name, groups and `version` are unchanged after two
   sign-ins; no group is created from the claim. With the flag off, sign-in
   creates the account and its claimed group, and replaces the SCIM name and
   groups (SCIM-58 to SCIM-60).
6. Basic auth, a missing token, an OAuth access token, an expired key, a
   deleted key and a key from a disallowed IP: all `401`. A `Replace` key
   without `scimAccess`: `403` naming it. Deleting the key: the next request
   is `401` (SCIM-7, SCIM-9, SCIM-11).
7. A key without `sysAccountDestroy`: `DELETE` is `403`, `PATCH active=false`
   works (SCIM-11, SCIM-52).
8. The service principal deactivating, deleting or renaming itself: `403`,
   unchanged (SCIM-13).
9. A tenant whose ceiling lacks `scimAccess`: its principal is refused even
   with the permission on its account and key (SCIM-12).
10. Discovery without auth: `200`. `filter` on `/Schemas`: `403`. Unknown
    path `404`, wrong method `405` with `Allow`, `OPTIONS` `204`, `/Me` `501`
    (SCIM-2, SCIM-3).
11. `userName` on a domain with the flag off: `400 invalidValue` naming it.
    An alias on such a domain in an otherwise valid create: the whole create
    refused (SCIM-15).
12. Accounts on a domain without the flag don't appear in `/Users` (SCIM-16).
13. Group created by a principal whose domain isn't SCIM-enabled: `400
    invalidValue` (SCIM-18).
14. `maxAccounts` reached in a tenant: `403` naming the limit, and
    `limit.tenant-quota` emitted (SCIM-20).
15. Rename by `userName`: the account moves, the old address is refused as
    unknown, the id is unchanged (SCIM-21, SCIM-23).
16. Duplicate address on create: `409 uniqueness`, and the existing account
    is untouched (SCIM-22, SCIM-56).
17. Emails: the primary first and read-only, a duplicate alias skipped, an
    alias dropped by `PATCH remove` gone, an alias another account holds `409`
    (SCIM-25).
18. `EN-us`, `ca-ES@valencia` and `preferredLanguage` alone all store and
    read back; `xx-YY` and `Mars/Olympus` are `400 invalidValue` (SCIM-26).
19. `active` round trip on an `Inherit` account leaves `permissions` exactly
    `Inherit`; on an account with custom permissions, leaves them as they
    were. An account whose role lacks `authenticate` reads `active: false`
    (SCIM-27).
20. Same `externalId` on two users in one tenant: `409`. In two tenants:
    allowed. Filter on it: case-exact (SCIM-29).
21. Groups: `displayName` clash in any case `409`; `Sales EMEA` gives
    `sales-emea`, a second gives `sales-emea-2`; a rename keeps the address; a
    group as member `400`; 201 members read without exclusion `400 tooMany`;
    the version changes when a member is added (SCIM-34 to SCIM-38).
22. `PATCH` atomicity: one bad operation among good ones changes nothing.
    Removing a non-member succeeds (SCIM-42).
23. `If-None-Match` gives `304`; a stale `If-Match` gives `412` on `PUT`,
    `PATCH` and `DELETE` (SCIM-44).
24. Filters: each supported attribute answers; `co`, `or`, `pr` are `400
    invalidFilter`; an unfiltered `active eq false` over 200 candidates is
    `400 tooMany` (SCIM-45, SCIM-46).
25. Sorting and index pages: `count` 500 gives 200; `count=0` gives totals
    only; pages in stable `id` order (SCIM-47, SCIM-48).
26. Cursors: walk 450 users in pages of 200 to the end; a cursor with a
    changed filter `invalidCursor`, changed count `invalidCount`, a
    tampered cursor `invalidCursor` (SCIM-49).
27. Bulk: create a user and a group that references it by `bulkId`;
    `failOnErrors: 1` stops after the first failure; 1001 operations `413`
    (SCIM-51).
28. Suspend: IMAP login, JMAP with an existing OAuth token, and an app
    password all fail on the next attempt; an open IMAP IDLE is closed; mail
    to the account is still delivered (SCIM-52).
29. Delete: mail to the address is refused as unknown; with
    `archiveDeletedAccountsFor` set, re-creating the same `userName` is `409`
    until the hold ends (SCIM-52).
30. An account created by an administrator is found by `userName` filter,
    adopted by `PATCH` setting `externalId`, and its quota and roles are
    unchanged (SCIM-32, SCIM-55, SCIM-56).
31. **(compat)** On a copy of INBUXA's data: every `externalId` and flag
    reads back unchanged, and the SCIM ids equal the account ids JMAP
    returns (SCIM-21).

## Open questions / to observe

1. **Per-domain directories.** `x:Domain.directoryId` is flagged Enterprise,
   isn't rebuilt (`get_directory_for_domain` returns the default), and no
   feature in SPEC.md §4 claims it. `oidc.rs` needs it. It needs a home: its
   own small spec, or a section of this one.
2. **Does INBUXA use SCIM today?** If any identity provider provisions into
   the live server, cutover must keep it working (SCIM-21, SCIM-44), and
   that should be checked on a copy before cutover, not assumed.
3. **Visibility of accounts on domains without the flag** (SCIM-16). The
   public docs don't say whether upstream lists them. Observe, and decide
   whether matching upstream matters to any client.
4. **`externalId` uniqueness** (SCIM-29) is our Decision. The index isn't
   unique and the docs are silent.
5. **`userName` case** (SCIM-22). Whether upstream returns the case sent or
   a lowercased form. Strict clients compare it.
6. **Old address on rename** (SCIM-23), **alias `type`** (SCIM-25),
   **suffix format and empty slugs** (SCIM-35), **unknown member ids**
   (SCIM-36), **removing a non-member** (SCIM-42), **combined `.search`
   order** (SCIM-50): details the docs don't settle, decided here.
7. **`active: true` when a role withholds `authenticate`** (SCIM-27). Our
   answer is to succeed and report `false`. Some identity providers may loop
   on that. Check Entra ID's and Okta's handling.
8. **Suspended accounts' Sieve, forwarding and vacation** (SCIM-52), and
   **ending open sessions**: whether upstream does either.
9. **Other bearer tokens on `/scim/v2`** (SCIM-7). Upstream's docs name only
   API keys. Whether it also accepts OAuth access tokens is unknown; we
   refuse them.
10. **OAuth client credentials** (SCIM-10). Entra ID gallery apps and Okta's
    OAuth mode would want it. Decide with `contract.md`'s OAuth work.
11. **Tenant quota status** (SCIM-20) and the rate-limit accounting of
    `/Bulk` (SCIM-14) are our Decisions.
**Decision** (2026-09-19) on 12 and 13: SCIM is built to this spec without
reading the profile drafts or the vendors' documentation, since each point
they'd inform already has a Decision here. Both stay open, to check after
the build; the replayed Okta, Keycloak and Entra payloads in `driver.py`
cover the clients meanwhile.

12. **The interop and IPSIE profiles.** Upstream's docs say it follows
    draft-zollner-scim-interop-profile (except unknown-attribute rejection)
    and the IPSIE profile's lifecycle rules. Neither draft was read for this
    spec. Read both and add any requirement they impose that isn't here.
13. **Vendor documentation.** Microsoft's, Okta's and the Keycloak
    extensions' own SCIM documentation wasn't read. Check them against
    SCIM-7, SCIM-27, SCIM-42 and SCIM-45 before implementation.
14. **`SCIM_DOMAIN` and `HTTP_PORT` in the test helpers.** The surviving
    tests imply `scim.example.com` and port 8899 (from addresses and URLs in
    them). Confirm when rebuilding `mod.rs`.

## Implementation status

Built 2026-09-19 from this spec, clean-room, under the multi-tenancy hand-off
brief's rules. The wire contract is in `crates/scim-proto`, the service in
`crates/scim`, the endpoint and its authentication in
`crates/http/src/scim.rs`; upstream files carry hooks marked `inbuxa:`
(the domain flag in the domain cache, just-in-time sync in
`crates/common/src/cache/directory.rs`, session revocation in the push
router). Every SCIM operation is the same `x:Account` get, query or set
JMAP makes, as the service principal.

`scim::scim_tests` runs the rebuilt helpers (`tests/src/scim/mod.rs`), the
new `acceptance.rs` (tests 6 to 30, SCIM-14, and SCIM-58 to SCIM-60 through
`synchronize_account` itself) and the surviving `tenant.rs` (test 4); all
pass. With `SCIM_CONFORMANCE=1` it also runs the surviving
`conformance.rs` (tests 1 to 3), which passes: scim2-client's 12 lifecycle
steps, the 8 replayed Okta, Keycloak and Entra payloads, and scim2-tester
with errors only for its generated non-address `userName`.

- **SCIM-1 to SCIM-61:** built, with the limits below.
- **Test 5** (`oidc.rs`) is `scim_oidc_tests`, ignored until per-domain
  directories (feature 9) are built (Decision, SCIM-61).
- **Test 31 (compat)** is `scim_compat`, ignored, and unrun until a copy of
  INBUXA's data is provided. It checks observed 1.
- **Settled from the code, not a change of intent:**
  - Locales are stored hyphenated (`en-US`, `ca-ES-valencia`), not with an
    underscore as SCIM-26 assumed, so SCIM's form needs no conversion;
    `ca-ES@valencia` is read as `ca-ES-valencia`. "A locale the server has
    no translation for" is one outside the registry's locale list.
  - `/Schemas` describes `meta` (as the mapping tables give it, without
    `lastModified`): scim2-client builds its models from it.
  - The five `scim.*` events (SCIM-54) have ids 637 to 641, the fork's own,
    and are in the packaged schema's event list.
- **Known limits, not requirements of this spec:**
  - Ending open sessions on suspension (SCIM-52) covers subscriptions to
    changes (IMAP IDLE, JMAP event streams and WebSockets), and only on the
    node that took the SCIM request. An IMAP, POP3 or ManageSieve session
    already signed in and not idling isn't ended; by the code it keeps
    working until it disconnects (not tested), and can't sign in again.
  - A suspended account's cached HTTP credentials are refused with `403`
    rather than `401`.
  - Changing a group's membership writes each member in turn. Everything
    is validated first, but a store failure midway leaves the change
    partly made.
  - `externalId` and group `displayName` uniqueness (SCIM-29, SCIM-34) are
    checked before the write, without a lock, so two simultaneous writes
    can both pass.
  - With a `displayName` stored, a PATCH of only `name.givenName` or
    `name.familyName` changes nothing, by SCIM-24's precedence.
  - An email entry marked primary whose value isn't the `userName` is kept
    as an alias.
  - The conformance container runs on the host's network (a test-only
    change), since a host firewall can drop the Docker bridge.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), read-only, as a server-level administrator and the throwaway test
account. No upstream code was read.

1. **SCIM isn't used** (open question 2). No domain has
   `allowScimProvisioning` on, and none of the 8 accounts has an
   `externalId`. Cutover has nothing to carry.
2. **Discovery is anonymous.** `/scim/v2/ServiceProviderConfig`, `/Schemas`
   and `/ResourceTypes` answer `200` with no credentials, as
   `application/scim+json`. `/scim/v2/Users` without credentials answers
   `401` with `WWW-Authenticate: Bearer realm="Stalwart SCIM"`.
3. **What upstream advertises:** PATCH, Bulk (1,000 operations, 1 MiB),
   filtering (`maxResults` 200), sorting and ETags supported; password change
   not supported; pagination by index and by cursor, index by default, page
   size 100, at most 200. One authentication scheme, `oauthbearertoken`,
   described as an API key presented as a bearer token. `interopProfileConformant`
   is `false`. `/ResourceTypes` lists `User` and `Group` with no schema
   extensions, which matches this spec's decision. `documentationUri` points at
   upstream's documentation. The fork points it at its own.

The per-account behaviors (open questions 3 and 5 to 9) need an API key and
a SCIM-enabled domain, so they stay open.
