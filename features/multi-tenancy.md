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

No Enterprise-only file or snippet was used. The session that drafted this
had seen short Enterprise snippets while surveying the license split, so it
writes specs only. Where this spec needs a behavior no public source settles,
it says so under "To observe" or makes a decision of its own, marked
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
- **MT-3.** Any operation that would link objects across tenants is refused
  with `forbidden`: a group member, a list member or owner, a role, a sharing
  grant, an alias domain. This includes linking a tenant object to a
  server-level one, unless the server-level object is shared infrastructure the
  operator made available (see "To observe" 1).
- **MT-4.** Mail flow isn't isolation. Mail between addresses in different
  tenants is delivered like any other mail, through the normal delivery path.
  Tenants separate administration and resources, not the network.
- **MT-5.** Queued and outgoing mail are resources. A tenant administrator sees
  and acts on queued messages only for senders or recipients on the tenant's
  own domains, and never sees another tenant's. **Decision**, derived from
  MT-1. Upstream's behavior here isn't publicly documented. Confirm it doesn't
  contradict "To observe" 4.

### Membership

- **MT-6.** Only an administrator in no tenant, with the matching `sys*`
  permission, can create a tenant, delete one, or change any object's
  `memberTenantId`. A tenant administrator can't move anything into or out of
  a tenant, their own included.
- **MT-7.** A principal's tenant always matches its domain's tenant. A
  principal on a domain in tenant T is in T. A principal on a domain in no
  tenant is in no tenant. On create, `memberTenantId` defaults to the domain's
  tenant. A write that sets any other value is refused with `invalidProperties`
  naming `memberTenantId`.
- **MT-8.** A domain can move into a tenant only from no tenant, and out of one
  only back to no tenant. It moves only when no principal on it belongs to
  anything other than the destination. **Decision**, a deliberate improvement
  on the observed upstream behavior: upstream lets a domain leave a tenant
  while the tenant's accounts are still on it, stranding them.
- **MT-9.** Creating a domain inside a tenant also puts its DKIM keys in that
  tenant (observed).
- **MT-10.** A tenant can be deleted only when nothing references it. Otherwise
  deletion is refused with `objectIsLinked`, listing what still refers to it.
  **Decision**: ihasmail already enforces this in its interface, and the server
  should too.

### Administering a tenant

- **MT-11.** A tenant's administrator is an account inside the tenant that
  holds administrative permissions. Within the tenant it can do what those
  permissions allow, on every object type that carries `memberTenantId`.
  Everything it creates lands in its own tenant. It never needs to, and may
  not, set `memberTenantId` itself.
- **MT-12.** A tenant administrator can read its own tenant's `x:Tenant` object
  (name, logo, quotas, usage) but can't change it. Changing the tenant object
  itself is server-level.

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
- **MT-16.** Changing a tenant's roles, permissions or quotas takes effect for
  its people without a restart and without them signing in again. The next
  request is judged by the new rules.

### Quotas

- **MT-17.** Count quotas. Creating an object that would take a tenant past
  its count limit for that kind is refused with `overQuota`, and the server
  emits `limit.tenant-quota`. Moving a domain into a tenant counts its
  principals and keys against the tenant's limits first, and is refused the
  same way if any limit would be crossed.
- **MT-18.** Existing objects over a lowered limit stay. Only new ones are
  refused.
- **MT-19.** Disk quota. `maxDiskQuota` bounds the total storage of every
  member together. Once the total reaches it, no more mail is accepted for
  any account in the tenant until usage falls. Per-account quotas still apply
  as well, whichever is reached first.
- **MT-20.** `usedDiskQuota` is kept current as members' usage changes, and is
  never written by a client.
- **MT-21.** The `recalculateQuota` task recomputes one tenant's
  `usedDiskQuota` from its members' actual usage. `resetTenantQuotas`
  recomputes every tenant. Both can run while the server is live.

### Branding

- **MT-22.** A signed-in principal can read the logo that applies to it: its
  domain's `logo` if set, else its tenant's `logo` if set, else none.
  **Decision** on the order: a domain is more specific than a tenant. Exposed
  over JMAP so ihasmail can draw it (see "Interfaces").
- **MT-23.** The server never fetches a logo URL itself. ihasmail draws URL
  logos through its image proxy, as it does today.

## Interfaces

- **Existing, unchanged:** `x:Tenant/get`, `/set`, `/query`, `/changes`; the
  `memberTenantId` field on the types listed above; the permission names; the
  task and maintenance types; the event.
- **New:** the signed-in principal's applicable logo (MT-22). Proposed as a
  read-only property on the principal's own account object in the fork's
  namespace, with the exact shape settled in the contract spec (SPEC.md §5.2).
- **Errors:** RFC 8620 `SetError` types, as named above. Each refusal names
  the property or limit involved, so ihasmail can say which one.

## ihasmail changes

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
3. Tenant admin adds a U account to a T group: `forbidden` (MT-3).
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

## To observe

Behavior no public source settles. Settled by watching INBUXA's live
Enterprise server with throwaway objects, never by reading upstream code:

1. Which server-level objects a tenant's things may reference: a shared DNS
   provider, ACME provider or directory in no tenant, used by a domain in a
   tenant.
2. The SMTP reply when delivery is refused for a full tenant disk quota: the
   code, whether temporary or permanent, and the text.
3. Whether a tenant administrator can read server-level settings at all, even
   read-only.
4. What a tenant administrator sees in the mail queue.
5. Whether a principal's directory search (JMAP principals) crosses tenants.
6. What happens to active sessions when a principal's tenant is changed by a
   server-level admin.

Record each answer here with its date and how it was observed, before
implementation starts.
