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
| Observation of INBUXA's live server | Observation | Everything under "To observe" once settled |

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
| (expired) | Refused | `deleted` | `false` |

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
  `RCPT TO`. The reply code matches upstream's reply for a disabled mask (to
  observe, 1), so senders see the same result whichever server they meet.
- **ME-7.** Arriving mail sets `lastMessageAt`, and moves a `pending` mask to
  `enabled`.
- **ME-8.** A `pending` mask with no mail within 24 hours of creation is
  removed, per Fastmail's rule, and tombstoned. It's hidden from ihasmail's
  list while pending, as Fastmail's own interface hides it.
- **ME-9.** Delivered mail keeps the masked address visible to the user: in
  the `To` or `Cc` header as sent, and in a `Delivered-To` header naming the
  mask, so filters and the reader can tell which mask it came through (to
  observe, 3: match upstream if it already does this).
- **ME-10.** Sub-addressing (`mask+tag@domain`) on a mask works exactly as it
  does on the account's own addresses (to observe, 4).

### Sending

- **ME-11.** A user may send from any of their masks in `pending`, `enabled`
  or `disabled` state, as they can from their own aliases. Replying to mail
  that came through a mask should default to sending from that mask:
  ihasmail's job (see "ihasmail"), made possible by ME-9. Whether upstream
  allows sending as a mask at all is to observe, 5.

### Creating

- **ME-12.** The server generates the address. The domain is `emailDomain` if
  given, else the owning account's primary domain. `emailDomain` may be any
  domain or alias domain the account is linked to. Anything else fails with
  `invalidProperties` naming `emailDomain`. In a tenant, only the tenant's
  domains qualify (multi-tenancy MT-3).
- **ME-13.** Address format, **Decision**: the local part is
  `{emailPrefix}_{random}` when a prefix is given, else `{random}`, where
  `{random}` is 12 characters from `a-z0-9`, about 62 bits. It's checked
  against every address the server knows (accounts, aliases, lists, masks and
  tombstones) and redrawn on collision. inbuxa-server doesn't copy upstream's
  shape and doesn't need to. The expiry isn't encoded in the address, since
  it's stored in `expiresAt`.
- **ME-14.** `maxMaskedAddresses` counts live masks: `pending`, `enabled`,
  `disabled`. A create past it fails with `overQuota`. 0 turns creation off.
- **ME-15.** Create-rate limit per account, as Fastmail's API allows: past it,
  create fails with `rateLimit`. **Decision**: 50 an hour per account,
  configurable.
- **ME-16.** `createdBy` is set by the server from the authenticated client's
  name (the OAuth client's name once SPEC.md §5.2 is in place). Fastmail's API
  treats it as server-set. Upstream's API accepts a client-supplied value
  (its docs show one in a create), so the `x:` API still accepts it when the
  server has no client name of its own.
- **ME-17.** `forDomain` is stored as given. The Fastmail API asks integrators
  for an origin only, but inbuxa-server doesn't reject paths, since existing
  upstream records may hold them.

### Who can do what

- **ME-18.** A user manages its own masks: get, query, create, update,
  destroy. Its role needs the `sysMaskedEmail*` permissions, which the default
  user role carries.
- **ME-19.** An administrator with the same permissions can manage another
  account's masks, for support. A tenant administrator can manage only masks
  owned by accounts in its tenant (multi-tenancy MT-1).

## The two APIs

### Upstream's, unchanged

`x:MaskedEmail/get`, `/query`, `/set` under `urn:stalwart:jmap`, standard RFC
8620 shapes, the record above, filtered by `accountId` in `/query`. Plus
`/changes`, if upstream offers it (to observe, 6).

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

## To observe

Settle against INBUXA before implementation, with a throwaway ordinary
account, never by reading upstream code:

1. The SMTP reply for mail to a disabled mask, and to an expired one: code,
   temporary or permanent, and text.
2. What an upstream address looks like: length, characters, where a prefix
   goes, which domain is chosen by default. Needed only so ME-13 can't mint a
   look-alike, and to confirm existing addresses fit in the tombstone and
   lookup design.
3. What a delivered message shows: headers naming the mask, whether `To` is
   rewritten.
4. Whether `mask+tag@domain` delivers.
5. Whether a user can send as a mask (as an identity, or through a
   submission `MAIL FROM`), and what the recipient sees.
6. Whether `x:MaskedEmail/changes` exists, and whether masks can be queried
   by fields other than `accountId`.
7. Whether an ordinary user holds the `sysMaskedEmail*` permissions by
   default.
8. How many masks INBUXA already holds, over all accounts (count only), to
   size the compatibility test. This needs an admin, or the operator can
   report it.
