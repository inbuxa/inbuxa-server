# Feature spec: masked email

Status: draft, 2026-09-18. Feature 2 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema, `x:MaskedEmail` and `x:Email.maxMaskedAddresses`, upstream `d9dee0a` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | The stored record, field meanings, permissions |
| Stalwart documentation: "Masked email" (`email/management/masked-email.md`) and the MaskedEmail object reference | Unlicensed public documentation: facts used, prose not copied | Lifecycle, domain choice, quota, permissions, API |
| Fastmail's Masked Email API (`https://www.fastmail.com/for-developers/masked-email/`) | Published vendor API: facts used, prose not copied | The second API, its states and rules |
| RFC 8620 | IETF | `/get` and `/set` semantics, `SetError` types |
| Probes of INBUXA's live Enterprise server, 2026-09-18 (Stalwart 0.16.22), as an ordinary account | Observation | Everything under "Observed" |

No Enterprise-only file or snippet was used. As with multi-tenancy, the
drafting session writes specs only, and gaps are settled by observation or
marked **Decision**. None is filled from memory of upstream code.

## What it is

A masked address is a disposable address that delivers to one account
without revealing the account's real address. A user hands a different one
to each service, and can cut any of them off without touching the others.
Password managers can create them automatically when a new login is saved.

Upstream ships this only in its Enterprise Edition. inbuxa-server ships it to
everybody, and serves it through two APIs at once: upstream's, so existing
clients keep working, and Fastmail's published one, so password managers that
already speak it work without changes.

## The key fact for compatibility

Every stored mask carries its full address in `email`. Delivery therefore
finds a mask by looking the recipient address up among stored masks, and
never by working out who owns an address from its shape. That is how every
address INBUXA users already hold keeps delivering: inbuxa-server doesn't need
to know how upstream built them.

## Data model

### Upstream's record, `x:MaskedEmail`, unchanged

| Field | Upstream mutability | Meaning |
|---|---|---|
| `accountId` | immutable | The owning account |
| `email` | server-set | The address |
| `enabled` | mutable, default true | Upstream: whether mail is accepted |
| `description` | mutable | A short note from the user |
| `forDomain` | mutable | The origin of the site it was made for, e.g. `https://example.com` |
| `url` | mutable | A deep link back into the integrator's own record |
| `createdAt` | server-set | When it was made |
| `createdBy` | mutable | The creating client's name |
| `expiresAt` | immutable (create-only) | When it stops working. Upstream's docs say its generated addresses carry the expiry in the address itself |
| `emailPrefix` | create-only | Requested start of the local part: ≤ 64 chars, `a-z`, `0-9`, `_` |
| `emailDomain` | create-only | Requested domain |

Permissions: `sysMaskedEmailGet`, `sysMaskedEmailQuery`,
`sysMaskedEmailCreate`, `sysMaskedEmailUpdate`, `sysMaskedEmailDestroy`.
Limit: `maxMaskedAddresses`, as the server default on `x:Email` and per
account in `quotas`. Unset means unlimited, and 0 turns the feature off for
that account.

### Added by inbuxa-server, in its own store

Kept beside the upstream record, keyed by mask id, so the upstream record
stays byte-for-byte what upstream wrote:

- `state`: `pending`, `enabled`, `disabled` or `deleted` (see the next
  section). Missing for masks created before the fork: derived from
  `enabled`.
- `lastMessageAt`: when mail last arrived through it, or null.
- `pendingUntil`: for `pending` masks, when they're removed if no mail
  arrives.
- **Tombstones**: every address ever issued, including destroyed ones, so an
  address is never issued twice.

## One state, two APIs

Fastmail and upstream disagree about what "disabled" means. inbuxa-server
keeps one state per mask, and each API shows it in its own terms.

| inbuxa-server state | Mail to it | Fastmail `state` | Upstream `enabled` |
|---|---|---|---|
| `pending` | Delivered, and the mask becomes `enabled` | `pending` | `true` |
| `enabled` | Delivered normally | `enabled` | `true` |
| `disabled` | Accepted, filed straight to Trash | `disabled` | `true` |
| `deleted` | Refused | `deleted` | `false` |
| (destroyed) | Refused, as an unknown address | not returned | not returned |
| (expired) | Refused | `deleted` | `false`, see ME-6a |

Writes map back:

- **ME-1.** Fastmail `state` sets the state directly. `pending` can't be
  set once the mask has left it, per Fastmail's rules.
- **ME-2.** Upstream `enabled: false` sets `deleted`. Upstream
  `enabled: true` sets `enabled`, from any state.
- **ME-3.** Upstream `destroy`, and Fastmail `destroy`, remove the mask. The
  address is kept as a tombstone and mail to it is refused like mail to any
  unknown address.

**Decision:** upstream's `enabled: false` means "reject" in its docs, which is
Fastmail's `deleted`, not its `disabled`. So `disabled` (to Trash) has no
upstream equivalent, and a mask in it reads as `enabled: true` there: mail is
accepted, which is the fact `enabled` reports.

## Required behavior

### Delivery

- **ME-4.** A message to a masked address in `pending`, `enabled` or
  `disabled` is delivered to the owning account, found by stored address.
  Spam filtering, the account's Sieve scripts, quotas and tenant limits all
  apply exactly as they would to mail for the account's own address.
- **ME-5.** `disabled` delivers into the account's Trash mailbox, skipping
  the user's filing rules but not spam checks.
- **ME-6.** `deleted`, expired and destroyed masks refuse the message at
  `RCPT TO` with `550 5.1.2 Mailbox does not exist.`, upstream's own reply for
  disabled and expired masks (observed 1). It's permanent, and identical to
  the reply for an address that never existed, so a sender learns nothing
  about the mask.
- **ME-6a.** **Decision**, a deliberate difference: an expired mask reads
  `enabled: false` in the `x:` API. Upstream keeps reporting `enabled: true`
  after expiry and keeps listing it (observed 1), which tells the user it
  still works when it doesn't. Expired masks aren't removed automatically.
- **ME-7.** Arriving mail sets `lastMessageAt`, and moves a `pending` mask to
  `enabled`.
- **ME-8.** A `pending` mask with no mail within 24 hours of creation is
  removed, per Fastmail's rule, and tombstoned. It's hidden from ihasmail's
  list while pending, as Fastmail's own interface hides it.
- **ME-9.** Delivered mail keeps the masked address visible to the user.
  `To` and `Cc` are never rewritten (as upstream, observed 3). **Decision**,
  an addition: an `X-Masked-Email` header names the mask it came through,
  so filters and ihasmail can tell even when the mask was only BCC'd.
  Upstream's `Delivered-To` names the account's real address, not the mask
  (observed 3), and that stays as it is.
- **ME-10.** Sub-addressing (`mask+tag@domain`) on a mask works exactly as it
  does on the account's own addresses, as it does upstream (observed 4).

### Sending

- **ME-11.** **Decision**, an addition: a user may send from any of their
  masks in `pending`, `enabled` or `disabled` state, as they can from their
  own aliases. A mask can be a JMAP `Identity`, and SMTP submission accepts it
  as `MAIL FROM` and `From` for its owner. Upstream allows neither (observed
  5), so a masked address today can receive but never reply. Replying to mail
  that came through a mask defaults to sending from that mask: ihasmail's
  job, made possible by ME-9.

### Creating

- **ME-12.** The server generates the address. The domain is `emailDomain` if
  given, else the owning account's primary domain. `emailDomain` may be any
  domain or alias domain the account is linked to. Anything else fails with
  `forbidden` naming `emailDomain`, as upstream (observed 2). A default create
  lands on the account's own domain (observed 2). In a tenant, only the tenant's
  domains qualify (multi-tenancy MT-3).
- **ME-13.** Address format, **Decision**: the local part is
  `{emailPrefix}_{random}` when a prefix is given, else `{random}`, where
  `{random}` is 12 characters from `a-z0-9`, about 62 bits. It's checked
  against every address the server knows (accounts, aliases, lists, masks and
  tombstones) and redrawn on collision. inbuxa-server doesn't copy upstream's
  shape and doesn't need to. The expiry isn't encoded in the address, since
  it's stored in `expiresAt`. Upstream's addresses always contain a `.` (see
  observed 2). This format never does, so a fork-issued address can't be
  mistaken for an upstream one.
- **ME-14.** `maxMaskedAddresses` counts live masks: `pending`, `enabled`,
  `disabled`. A create past it fails with `overQuota`. 0 turns creation off.
- **ME-15.** Create-rate limit per account, as Fastmail's API allows: past it,
  create fails with `rateLimit`. **Decision**: 50 an hour per account,
  configurable.
- **ME-16.** `createdBy` is set by the server from the authenticated client's
  name (the OAuth client's name once SPEC.md §5.2 is in place). Fastmail's API
  treats it as server-set. Upstream's API accepts and stores a client-supplied
  value (observed 2), so the `x:` API still accepts it when the server has no
  client name of its own.
- **ME-17.** `forDomain` is stored as given. The Fastmail API asks integrators
  for an origin only, but inbuxa-server doesn't reject paths: upstream stores
  them as given (observed 2), so existing records may hold them.

### Who can do what

- **ME-18.** A user manages its own masks: get, query, create, update,
  destroy. Its role needs the `sysMaskedEmail*` permissions, which the default
  user role carries: an ordinary account holds all five (observed 7).
- **ME-19.** An administrator with the same permissions can manage another
  account's masks, for support. A tenant administrator can manage only masks
  owned by accounts in its tenant (multi-tenancy MT-1).

## The two APIs

### Upstream's, unchanged

`x:MaskedEmail/get`, `/query`, `/set` under `urn:stalwart:jmap`, standard RFC
8620 shapes, the record above. Upstream's `/query` accepts only an
`accountId` filter, and it has no `/changes` (observed 6).

**Decision**, additions: `/changes`, so ihasmail can keep its list current
without refetching; `/query` filters on `enabled`, `forDomain` and text
(address and description); and a `state` in every `/get` response, as RFC 8620
expects and upstream omits.

### Fastmail's

Capability `https://www.fastmail.com/dev/maskedemail`, advertised in the
session and in the account capabilities of every account that may hold
masks.

- `MaskedEmail/get` (with `ids: null` fetching all of an account's masks) and
  `MaskedEmail/set`, standard RFC 8620 shapes, in the user's own JMAP account.
- Properties: `id`, `email`, `state`, `forDomain`, `description`,
  `lastMessageAt`, `createdAt`, `createdBy`, `url`, and `emailPrefix`
  (create-only). The same ids as the `x:` API, so an id is one mask whichever
  API reads it.
- `description` defaults to the empty string.

## ihasmail

- A **Masked addresses** section in Settings: the list (address, description,
  site, created, last mail, state), create with an optional description and
  site, copy, switch between enabled, disabled (to Trash) and deleted, and
  destroy with a warning that the address is gone for good. Pending masks are
  hidden.
- **Compose:** a masked address can be chosen as the sender. Replying to mail
  that came through a mask selects that mask by default (ME-11).
- **Reading:** a small marker on mail that arrived through a mask, naming it.
- **Administration:** an account's masks on its panel, for admins with the
  permissions.
- Every string this adds is new translation work for ihasmail's nine
  languages.

## Acceptance tests

1. Create with no arguments: gets a unique address on the account's primary
   domain, state `pending` in the Fastmail API and `enabled: true` in `x:`.
2. Mail to a pending mask: delivered, state becomes `enabled`,
   `lastMessageAt` set (ME-7).
3. Pending mask with no mail for 24 hours: removed and tombstoned (ME-8).
4. Fastmail `disabled`: mail is accepted and lands in Trash (ME-5).
5. Fastmail `deleted`, and upstream `enabled: false`: mail refused at
   `RCPT TO` with the observed reply (ME-6). Both APIs read it back
   consistently (ME-2).
6. Destroyed mask: refused as unknown, and its address is never issued again
   (ME-3, ME-13).
7. `emailPrefix: "shop"` gives `shop_…`. `emailPrefix: "Shop!"` fails
   `invalidProperties`.
8. `emailDomain` the account isn't linked to fails `invalidProperties`
   (ME-12).
9. `maxMaskedAddresses` 2: the third fails `overQuota`. 0 blocks creation
   (ME-14).
10. The 51st create in an hour fails `rateLimit` (ME-15).
11. A user can't read another user's masks. An admin can. A tenant admin can
    only for its tenant (ME-18, ME-19).
12. **(compat)** INBUXA's existing masks all resolve by stored address and
    deliver after cutover, and read back identically through `x:`.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), as the ordinary throwaway account on `ttlhost.com`, over JMAP and
SMTP submission. The probes created four masks and six small messages, all to
the account itself: nothing was sent off the server. Two recipients were
refused, which triggered no IP ban. Afterwards the masks and messages were
deleted, and nothing was left. No upstream code was read.

1. **Refused delivery.** A disabled mask and an expired mask were each refused
   at `RCPT TO` on the submission connection with `550 5.1.2 Mailbox does not
   exist.`: permanent, and worded as for a nonexistent address. The expired
   mask kept `enabled: true` in its record and stayed in the list.
2. **Upstream's addresses and creation.** A default mask is
   `{16 chars}.{24 chars}@{account's domain}`. With `emailPrefix` the prefix
   replaces the first part (`probe_shop.{24 chars}@…`). Every character is
   `a-z0-9`. The 24-character part began with the same 9 characters for every
   mask created in the same second, so it carries data. It wasn't decoded, and
   doesn't need to be (ME-13). A prefix with a capital and `!` was refused
   `invalidProperties`. A domain the account isn't linked to was refused
   `forbidden` with `properties: ["emailDomain"]`. A client-supplied
   `createdBy`, and a `forDomain` with a path, were both stored as given.
3. **What arrives.** `To` shows the mask, unchanged. `Delivered-To` shows the
   account's real address.
4. **Sub-addressing.** `mask+news@domain` was delivered to the account.
5. **Sending as a mask.** Refused both ways. JMAP `Identity/set` gave
   `invalidProperties` ("E-mail address not configured for this account"), and
   SMTP `MAIL FROM` the mask gave `501 5.5.4 You are not allowed to send from
   this address.`
6. **API.** `x:MaskedEmail/changes` is an unknown method. `/query` accepts
   only `accountId` as a filter: `enabled`, `text`, `email` and `forDomain`
   are all `unsupportedFilter`. `/get` returns no `state`.
7. **Permissions.** The ordinary account holds all five `sysMaskedEmail*`
   permissions.

Not settled: 8, how many masks INBUXA holds across all accounts. It needs
admin rights or the operator's count, and only sizes the compatibility test.
