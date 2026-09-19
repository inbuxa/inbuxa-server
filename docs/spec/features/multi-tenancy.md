# Feature spec: multi-tenancy

Status: draft, 2026-09-18. Feature 1 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Everything here comes from these
sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `crates/registry/src/schema/*.rs` and `resources/schema/schema.json.gz`, upstream `d9dee0a` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Object shapes, field meanings, enum values, permission names, what upstream flags as Enterprise |
| Stalwart documentation, "Tenants" (`website` repo, `docs/auth/authorization/tenants.md`) | Unlicensed public documentation: facts used, prose not copied | Isolation, the permission ceiling, quota semantics, branding |
| ihasmail FEATURES.md, "Tenants", and its admin code | AGPL-3.0-or-later, ours | Behavior observed against a live Enterprise server |
| RFC 8620 | IETF | JMAP semantics for errors and `/set` |
| Probes of INBUXA's live Enterprise server, 2026-09-18 (Stalwart 0.16.22) | Observation | Everything under "Observed" |

No Enterprise-only file or snippet was used. The session that drafted this
had seen short Enterprise snippets while surveying the license split, so it
writes specs only. Where this spec needs a behavior no public source settles,
it settles it by observation (see "Observed") or makes a decision of its own, marked
**Decision**. It never fills a gap from memory of upstream code.

## What it is

A tenant is a separate organization on one server: its own accounts, groups,
mailing lists, domains and settings, and an administrator who manages only
what is in it. One tenant can't see or reach another's resources. The server
operator decides how much of the server each tenant may use: which
permissions its people can hold, how many of each thing it can create, and
how much storage it can consume.

Upstream ships this only in its Enterprise Edition. inbuxa-server ships it to
everybody, always on. There is no edition check.

## Data model

Unchanged from upstream, so existing data opens as it is (SPEC.md §7).

### The tenant object, `x:Tenant`

| Field | Type | Set by | Meaning |
|---|---|---|---|
| `name` | string | admin | The tenant's name. There is no separate description |
| `createdAt` | UTC date-time | server | When it was created |
| `logo` | string, nullable | admin | An image URL or a data URL, shown to the tenant's people |
| `roles` | `Roles`: `Default`, or `Custom` with a list of roles | admin | The roles the tenant holds, which are the most its people can be given |
| `permissions` | `Permissions`: `Inherit`, `Merge` or `Replace`, with enabled and disabled lists | admin | The permissions the tenant may grant |
| `quotas` | map from `TenantStorageQuota` to an unsigned number | admin | Limits; a missing key is no limit |
| `usedDiskQuota` | size in bytes | server | Storage used by all members together |

Permission prefix: `sysTenant`. Permissions: `sysTenantGet`,
`sysTenantCreate`, `sysTenantUpdate`, `sysTenantDestroy`, `sysTenantQuery`,
and `taskTenantMaintenance`.

### Quota keys, `TenantStorageQuota`

`maxAccounts`, `maxGroups`, `maxDomains`, `maxMailingLists`, `maxRoles`,
`maxOauthClients`, `maxDkimKeys`, `maxDnsServers`, `maxDirectories`,
`maxAcmeProviders`, and `maxDiskQuota` (bytes).

### Membership, `memberTenantId`

A nullable reference to an `x:Tenant`. Null means the object belongs to no
tenant and is managed at server level. It appears on:

- principals: `UserAccount`, `GroupAccount`, `MailingList`, `Role`;
- `Domain`;
- signing and DNS: `Dkim1Signature`, `Dkim2Signature`, every `DnsServer*`
  provider, `AcmeProvider`;
- directories: `LdapDirectory`, `SqlDirectory`, `OidcDirectory`;
- `OAuthClient`;
- incoming reports: `ArfExternalReport`, `DmarcExternalReport`,
  `TlsExternalReport`.

### Elsewhere

- `x:Authentication.defaultTenantRoleIds`: the roles a tenant gets when its
  `roles` is `Default`.
- Task `TenantMaintenance`, with `tenantId` and `maintenanceType`. The only
  type is `recalculateQuota`.
- Store maintenance type `resetTenantQuotas`: reset every tenant's usage
  figure.
- Event and metric `limit.tenant-quota`: a tenant limit was reached and the
  operation was refused.
- `x:Cache.tenants`: cache size for tenants.

Upstream flags these fields as Enterprise, and in inbuxa-server they're
ordinary: every `memberTenantId` listed above,
`Authentication.defaultTenantRoleIds` and `Domain.logo`. The other flagged
fields belong to other features' specs.

## Required behavior

Each requirement has an ID, and tests name the IDs they check.

### Isolation

- **MT-1.** A principal in a tenant can reach only objects with the same
  `memberTenantId`. Reach covers JMAP `/get`, `/query`, `/changes` and `/set`
  on every object type that carries the field, directory lookups, sharing and
  access rights, and any list an admin screen shows.
- **MT-2.** Objects in no tenant (`memberTenantId` null) are server-level. A
  principal in a tenant can't read or change them, except what every account
  already reads about itself: its own account, its own settings, and the
  server's public capabilities.
- **MT-3.** Any write that would link an object to one in a different
  tenant is refused with `invalidForeignKey`, naming the object it can't
  link to: a group member, a list member or owner, a role, a sharing grant, a
  domain's ACME or DNS provider. "Different" includes no tenant. A tenant's
  domain can't use a server-level provider, even when a server-level admin
  makes the change (observed 1). Shared infrastructure is therefore
  per-tenant: each tenant brings its own providers.
  **Decision** (2026-09-18) for sharing grants: a grantee that doesn't exist
  is refused with the same `invalidForeignKey`, naming the account id, so the
  error never confirms that another tenant's account exists (as acceptance
  test 2). This replaces upstream's `invalidProperties` for a nonexistent
  grantee, for everyone. Mailing-list recipients are addresses, not links,
  and lists have no owner field, so MT-3 has no list link to govern: mail to
  a list's recipients is mail flow (MT-4).
- **MT-4.** Mail flow isn't isolation. Mail between addresses in different
  tenants is delivered like any other mail, through the normal delivery path.
  Tenants separate administration and resources, not the network.
- **MT-5.** Queued and outgoing mail are resources. A tenant administrator sees
  and acts on queued messages whose recipients are on the tenant's own
  domains, whoever sent them, and never sees anything else in the queue
  (observed 4). **Decision** for the sender side, not yet observed: it also
  sees messages its own principals sent, until they leave the queue.

### Membership

- **MT-6.** Only an administrator in no tenant, with the matching `sys*`
  permission, can create a tenant, delete one, or change any object's
  `memberTenantId`. A tenant administrator can't move anything into or out of
  a tenant, their own included.
- **MT-7.** A principal's tenant always matches its domain's tenant. A
  principal on a domain in tenant T is in T. A principal on a domain in no
  tenant is in no tenant. On create, `memberTenantId` defaults to the domain's
  tenant. A write that sets any other value is refused with
  `invalidForeignKey` naming the domain, which is upstream's own refusal
  (observed 7).
  **Decision**, a deliberate difference: upstream doesn't default the tenant.
  An account created on a tenant's domain without one lands in no tenant, a
  server-level account on a tenant's domain. inbuxa-server never creates that
  state. Existing accounts found in it (none at INBUXA, possible elsewhere)
  are left working and listed in the admin dashboard for an operator to
  resolve.
  **Decision** (2026-09-18): the server exposes nothing new for that list.
  ihasmail finds such accounts itself by comparing each account's
  `memberTenantId` with its domain's.
- **MT-8.** A domain can move into a tenant only from no tenant, and out of one
  only back to no tenant. It moves only when no principal on it belongs to
  anything other than the destination. **Decision**, a deliberate improvement
  on upstream (observed 8): upstream lets a domain leave a tenant while the
  tenant's accounts are still on it. They stay in the tenant, on a domain
  that isn't, and can still sign in.
  **Decision** (2026-09-18) on what moves with it. Into tenant T from no
  tenant, the domain's principals (accounts, groups, mailing lists) and its
  DKIM keys move into T with it, after MT-17's limit check. Out of T, back to
  no tenant, it's refused while any principal on it is in T; a domain with
  none moves with its DKIM keys. It never moves straight from one tenant to
  another. A principal on it that's in a third tenant blocks either move.
- **MT-9.** Creating a domain inside a tenant also puts its DKIM keys in that
  tenant. Upstream generates two per domain (observed 9).
- **MT-10.** A tenant can be deleted only when nothing references it. Otherwise
  deletion is refused with `objectIsLinked`, listing what still refers to it.
  **Decision**: ihasmail already enforces this in its interface, and the server
  should too.

### Administering a tenant

- **MT-11.** A tenant's administrator is an account inside the tenant that
  holds administrative permissions (upstream: the `Admin` role, which inside a
  tenant carries 290 permissions against 641 at server level; observed 3). Within the tenant it can do what those
  permissions allow, on every object type that carries `memberTenantId`.
  Everything it creates lands in its own tenant (observed 1). It never needs
  to, and may not, set `memberTenantId` itself. `memberTenantId` isn't
  returned to it at all (observed 3).
- **MT-12.** A tenant administrator can read its own tenant's `x:Tenant` object
  (name, logo, quotas, usage) but can't change it. Changing the tenant object
  itself is server-level. **Decision**, a deliberate difference: upstream
  refuses the read with `forbidden` (observed 3), so a tenant admin can't see
  its own limits or usage. ihasmail needs them to warn before a limit is hit.
  **Decision** (2026-09-18) on how: the read needs `sysTenantGet` (and
  `sysTenantQuery` to list), which the default Tenant Administrator role now
  holds. Inside a tenant they reach only its own `x:Tenant`; any other comes
  back `notFound`. `x:Tenant/set` is refused inside a tenant whatever the
  permissions (MT-6). Only the defaults change: roles already stored on an
  existing server are left as they are (SPEC.md §7), and an operator adds the
  two permissions to an existing tenant-admin role by hand.

### The permission ceiling

- **MT-13.** A principal's effective permissions are its own, cut down to
  what its tenant allows. A permission the tenant doesn't hold has no effect
  on anyone in the tenant, whoever granted it. Granting it isn't an error. It
  just does nothing.
- **MT-14.** What a tenant allows is computed from its `roles` and its
  `permissions`:
  1. **Roles.** `Default` means the roles in
     `Authentication.defaultTenantRoleIds`; `Custom` means the listed roles.
     The permissions of all those roles, taken together, are the base.
  2. **Permissions.** `Inherit` uses the base unchanged. `Merge` adds the
     enabled list to the base. `Replace` uses only the enabled list and
     ignores the base.
  3. **Disabled wins.** In `Merge` and `Replace`, the disabled list is removed
     last. A disabled permission is never allowed, however it was reached.
- **MT-15.** The ceiling can never exceed what the server grants. No setting
  on a tenant can give its people a permission the server has disabled for
  them.
  **Decision** (2026-09-18): `impersonate` never takes effect inside a
  tenant, whatever the tenant allows. Impersonation reaches any account, so
  in a tenant it would break MT-1. A tenant administrator manages its own
  people's accounts and masks through its administrative permissions
  instead.
- **MT-16.** Changing a tenant's roles, permissions or quotas takes effect for
  its people without a restart and without them signing in again. The next
  request is judged by the new rules. **Decision**, a deliberate improvement:
  upstream caches each principal's permissions, and a change to the tenant
  hadn't reached an already-authenticated admin after seven minutes
  (observed 6). A change must invalidate the cached permissions of everyone it
  affects.

### Quotas

- **MT-17.** Count quotas. Creating an object that would take a tenant past
  its count limit for that kind is refused with `overQuota`, and the server
  emits `limit.tenant-quota`. Moving a domain into a tenant counts its
  principals and keys against the tenant's limits first, and is refused the
  same way if any limit would be crossed.
  **Decision** (2026-09-18): creating a domain with automatic DKIM in a
  tenant counts the keys the server will generate for it (MT-9) against
  `maxDkimKeys`, and the domain is refused with `overQuota` if they wouldn't
  fit. Nothing is ever generated past the limit.
- **MT-18.** Existing objects over a lowered limit stay. Only new ones are
  refused.
- **MT-19.** Disk quota. `maxDiskQuota` bounds the total storage of every
  member together. A message that would take the total past it isn't
  delivered, even if usage is still under the limit (observed 2). Per-account
  quotas still apply as well, whichever is reached first.
- **MT-19a.** The refusal matches upstream: local delivery answers
  `451 4.3.0 Organization over quota.`, a temporary failure, so the message
  waits in the queue and retries until the queue gives up. Submission itself
  still succeeds, so the sender learns nothing until the delay notice.
  **Decision** on top: when a sender inside the server submits to a
  recipient whose tenant is over quota, say so at submission time too (a
  JMAP `EmailSubmission` warning, not a refusal). **Deferred** (2026-09-18):
  RFC 8621 has no warnings field, so the submission-time warning waits until
  the contract defines one. The `451` refusal is built.
- **MT-20.** `usedDiskQuota` is kept current as members' usage changes: it
  moved on the delivery itself (observed 2). It is never written by a client.
- **MT-21.** The `recalculateQuota` task recomputes one tenant's
  `usedDiskQuota` from its members' actual usage. `resetTenantQuotas`
  recomputes every tenant. Both can run while the server is live.

### Branding

- **MT-22.** A signed-in principal can read the logo that applies to it: its
  domain's `logo` if set, else its tenant's `logo` if set, else none.
  **Decision** on the order: a domain is more specific than a tenant. Exposed
  over JMAP so ihasmail can draw it (see "Interfaces"). Branding BT-1 and BT-2
  (`branding-and-templates.md`) extend the chain past the tenant, to the
  server-wide logo and then the built-in one, and are the full rule.
  **Decision** (2026-09-18) on the shape: in the JMAP session, the
  principal's own account's `accountCapabilities` carry `urn:inbuxa:jmap`
  (contract C-1) with `logo`: a string (the URL or data URL as stored) or
  `null`. With branding built (2026-09-18) it follows BT-1 steps 1 to 3,
  skipping unusable values (BT-4); `null` means the built-in logo, step 4.
- **MT-23.** The server never fetches a logo URL itself. ihasmail draws URL
  logos through its image proxy, as it does today.

## Interfaces

- **Existing, unchanged:** `x:Tenant/get`, `/set`, `/query`, `/changes`; the
  `memberTenantId` field on the types listed above; the permission names; the
  task and maintenance types; the event.
- **New:** the signed-in principal's applicable logo (MT-22), as `logo` in
  the `urn:inbuxa:jmap` account capability of its own account in the JMAP
  session (contract C-1).
- **Errors:** RFC 8620 `SetError` types, as named above. Each refusal names
  the property or limit involved, so ihasmail can say which one.

## ihasmail changes

These go in the INBUXA fork of ihasmail, not public ihasmail, which stays
Stalwart-facing (SPEC.md §5).

- Drop the "Tenants are a Stalwart Enterprise feature" notice and the edition
  check in front of the Tenants page. Keep `SHOW_ENTERPRISE_NOTICES` for
  talking to upstream Stalwart.
- Show the applicable logo (MT-22) in the app for the signed-in user.
- Show `overQuota` and `limit.tenant-quota` refusals in plain words, naming the
  limit.
- The domain-leaves-tenant guard it enforces today (MT-8) stays, and becomes a
  second line of defense rather than the only one.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code. The ones
marked **(compat)** also run against a copy of INBUXA's data.

1. Tenant admin in T lists accounts: sees only T's (MT-1).
2. Tenant admin in T gets a U account by id: `notFound`, not `forbidden`.
   **Decision**: don't confirm that another tenant's object exists.
3. Tenant admin adds a U account to a T group: `invalidForeignKey` (MT-3).
   **Decision** (2026-09-18): MT-3's error, not `forbidden` as this test
   first said.
4. Mail from a T address to a U address is delivered (MT-4).
5. Tenant admin sets `memberTenantId` on anything: refused (MT-6, MT-11).
6. Account created on a T domain is in T with no `memberTenantId` sent (MT-7).
7. Domain with T accounts moved out of T: refused (MT-8).
8. Tenant with one account deleted: `objectIsLinked` (MT-10).
9. User in T granted a permission T lacks: the permission has no effect
   (MT-13).
10. `Replace` with an enabled permission that's also disabled: not allowed
    (MT-14).
11. Lowering T's roles takes effect on the user's next request with no new
    sign-in (MT-16).
12. `maxAccounts` 2: the third account is refused `overQuota` and the event is
    emitted (MT-17). Lowering it to 1 keeps both existing accounts (MT-18).
13. `maxDiskQuota` reached across two accounts: delivery to a third member is
    refused (MT-19).
14. `recalculateQuota` after hand-corrupting `usedDiskQuota`: restored
    (MT-21).
15. **(compat)** INBUXA's existing tenants, their members and quotas read back
    unchanged, and each tenant admin sees exactly what it saw before.

## Implementation status

Built 2026-09-18 from this spec, clean-room (hand-off brief
`handoff/multi-tenancy.md`). The rules live in `crates/features`
(`inbuxa-features`, module `tenancy`); upstream files carry only hooks marked
`inbuxa: MT-n`. Acceptance tests 1 to 14 pass as `tests/src/system/tenant.rs`,
called from `system_tests` with no gate.

- **MT-1 to MT-18, MT-20 to MT-23:** built.
- **MT-19, MT-19a:** built, except the submission-time warning, **deferred**
  (see MT-19a) until the contract defines a warnings shape.
- **ihasmail changes** (the section above) belong to ihasmail-inbuxa and
  aren't part of this repository. Its branding and quota warnings wait for
  ihasmail-inbuxa.
- **Test 15 (compat)** is written as `tenant_compat`, ignored, and unrun until
  a copy of INBUXA's data is provided. Its doc comment says how to run it.
- **Known limits, not requirements of this spec:**
  - Changing `Authentication.defaultTenantRoleIds` reaches tenants whose roles
    are `Default` after a settings reload and a cache invalidation
    (`x:Action` `ReloadSettings`, then `InvalidateCaches`), as upstream's other
    default role lists do. MT-16 covers changes to the tenant itself, and to
    any role a tenant holds, without either.
  - `recalculateQuota` corrects the stored figure by the difference, so it's
    safe while mail arrives, but a delivery that lands between its two reads
    leaves the figure off by that message until the next run (MT-21).
  - A domain's move (MT-8) saves the domain and then each object that follows
    it, not as one transaction. An object changed by someone else in between
    is skipped rather than overwritten.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), over JMAP and SMTP submission. The probes ran as a temporary
server-level admin, and created two tenants, two domains under `ttlhost.com`
with manual certificates, four accounts, three ACME providers pointed at
Let's Encrypt staging, and two probe messages. Everything was deleted
afterwards, and a sweep of every affected object type found nothing left.
No upstream code was read.

1. **References across tenants.** A tenant's domain can't use an ACME
   provider in no tenant, or one in another tenant. Both are refused with
   `invalidForeignKey`, even when a server-level admin makes the change. A
   provider the tenant admin creates lands in its tenant and works. The tenant
   admin can't see server-level providers at all.
2. **Full tenant disk quota.** With usage at 1,191 bytes and a 1,200-byte
   limit, the next message wasn't delivered: the check is on what delivery
   would bring the total to. Local delivery answered `451 4.3.0 Organization
   over quota.` at `RCPT TO` (temporary). Submission was accepted, and the
   message stayed queued with a retry due in 2 minutes, a delay notice due
   after 1 day, and expiry after 3 days. Usage rose on the delivery itself.
3. **What a tenant admin can read.** Its tenant's accounts, domain, DKIM keys
   and its own ACME providers, roles, DNS providers and queue. It gets
   `forbidden` for listeners, certificates, system settings and every tenant
   object, its own included. Objects in no tenant or another tenant, fetched by
   id, come back in `notFound`. `memberTenantId` isn't returned to it. Its
   `Admin` role carried 290 permissions (server-level admin: 641).
4. **The queue.** Tenant 1's admin saw exactly the two queued messages
   addressed to its domain, both sent from tenant 2. It saw none of the other
   23 entries in the server's queue. The sender side (a tenant admin seeing its
   own people's outgoing mail) wasn't tested: there was no admin in tenant 2.
5. **Directory search.** A tenant user's JMAP `Principal/query`, with and
   without a text filter, returned only its own tenant's two principals: not
   the other tenant's, and not the server-level accounts.
6. **Changes to a tenant's roles and permissions.** Setting tenant 1's
   `permissions` to `Replace` with nothing enabled, then its `roles` to an
   empty custom set, left its already-signed-in admin with all 290
   permissions for 2.5 minutes. A new admin created during the change was
   refused everything, including its JMAP session (HTTP 403): the ceiling
   works, but permissions are cached per principal. After the roles were
   restored, the new admin was still refused 6.7 minutes later, when polling
   stopped. The cache lifetime wasn't measured. The `permissions` field on its
   own wasn't isolated from the `roles` field, because only cached principals
   saw that change.
7. **An account's tenant.** Creating accounts on a tenant's domain without
   `memberTenantId` put them in no tenant. Giving one a tenant other than its
   domain's was refused with `invalidForeignKey` naming the domain. The same
   happened for a no-tenant domain with a tenant set.
8. **A domain leaving its tenant.** Allowed while one of the tenant's accounts
   was on it. The account kept its tenant and could still sign in.
9. **DKIM.** Each new domain got two DKIM keys, each in the domain's tenant.

Not yet settled: whether deleting a tenant that still holds objects is
refused (the probe accounts were deleted first), and the sender side of 4.
Both are low-risk to leave for implementation-time tests.
