# Feature spec: branding and templates

Status: draft, 2026-09-18. Feature 4 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `crates/registry/src/schema/*.rs` and `resources/schema/schema.json.gz`, as imported into this repository (v0.16.22) | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | The five flagged fields, their types, descriptions and defaults, the related settings, permission prefixes |
| This repository's shared code: the template syntax (`crates/utils/src/template.rs`), the variable names (`crates/common/src/config/groupware.rs`), the alarm and iMIP senders (`crates/services/src/task_manager/alarm.rs`, `imip.rs`), the RSVP API types (`crates/groupware/src/calendar/itip.rs`), the HTTP routes (`crates/http/src/request.rs`), the logo cache and its invalidation (`crates/common/src/lib.rs`, `cache/invalidate.rs`), and the default pages and templates (`resources/html-templates/`, `resources/branding/`) | AGPL-3.0-only OR LicenseRef-SEL, with Enterprise-only parts already stripped; the pages and logo are the fork's own | What the built-in templates receive, how they're rendered and escaped, what the pages call, where hooks go |
| Stalwart documentation: "Branding" (`docs/management/webui/branding.md` and the 0.15 `webadmin/branding.md`), "Scheduling" (`docs/collaboration/scheduling.md`, sections HTTP RSVP and Branding and templating), the Enterprise and CalendarAlarm object references | Unlicensed public documentation: facts used, prose not copied | The logo order, hostname-based selection, the RSVP page contract, which templates exist |
| RFC 2397 (`data:` URLs), RFC 2392 (`cid:` URLs), RFC 5546 (iTIP), RFC 6047 (iMIP), RFC 8620 | IETF | Logo value forms, how the email logo is referenced, the messages the templates dress, `/set` errors |

No Enterprise-only file or snippet was used. The author is a fresh session
that has never seen Enterprise code. No server was probed for this spec. Where
no public source settles a behavior, this spec makes a decision of its own,
marked **Decision**, or lists it under "Open questions / to observe". It never
fills a gap from memory of upstream code.

## What it is

An operator can put its own logo, and its own layout, on what the server
shows and sends to people:

- **Logos.** One server-wide logo, one per tenant, one per domain. The most
  specific one that applies is used on the server's sign-in page, the RSVP
  page, calendar alarm and invitation emails, and in ihasmail.
- **Templates.** The HTML of calendar alarm emails, of iMIP invitation emails
  (invitations, updates, cancellations and replies), and the whole HTTP RSVP
  page.

Upstream ships this only in its Enterprise Edition. inbuxa-server ships it to
everybody. INBUXA's own branding is the default: the fork already ships
rebranded built-in templates, an INBUXA email logo
(`resources/branding/email-logo.png`), and `INBUXA Calendar` as the alarm
sender name.

Today, in the stripped tree, the five fields read and write normally but do
nothing: the built-in templates are always used, `logo_resource` always
answers none, and there's no `/logo` route. The login and RSVP pages already
ask `/logo` and fall back to their built-in logo when it fails.

Tenant logos (`x:Tenant.logo`) and the per-principal logo over JMAP are in
multi-tenancy MT-22 and MT-23. This spec uses them and doesn't repeat them.

## Data model

Unchanged from upstream, so existing data opens as it is (SPEC.md §7). All
five flagged fields are nullable strings. Null means "use the built-in".

| Object | Field | Schema type | Meaning |
|---|---|---|---|
| `x:Enterprise` (singleton) | `logoUrl` | `Uri?` | The server-wide default logo |
| `x:Domain` | `logo` | `String?` | The domain's logo: "URL or base64-encoded image" |
| `x:CalendarAlarm` (singleton) | `template` | `Html?` | Replaces the built-in alarm email |
| `x:CalendarScheduling` (singleton) | `emailTemplate` | `Html?` | Replaces the built-in iMIP email |
| `x:CalendarScheduling` (singleton) | `httpRsvpTemplate` | `Html?` | Replaces the built-in RSVP page. "Served verbatim", and responsible for calling `/api/calendar/rsvp` itself |

Related, not flagged, and unchanged:

- `x:Tenant.logo` (multi-tenancy spec).
- `x:CalendarAlarm`: `enable`, `fromName` (default `INBUXA Calendar` in the
  fork), `fromEmail`, `allowExternalRcpts`, `minTriggerInterval`.
- `x:CalendarScheduling`: `enable`, `httpRsvpEnable` (default true),
  `httpRsvpUrl`, `httpRsvpLinkExpiry` (default 90 days), `autoAddInvitations`,
  `itipMaxSize`, `maxRecipients`.
- `x:Enterprise.licenseKey` and `apiKey`. There's no license (SPEC.md §4).
  **Decision**: they stay readable and writable so existing data round-trips,
  and are ignored.
- `x:OAuthClient.logo`, shown on the consent page (contract C-9). Not part of
  this feature, but it follows BT-3 and BT-7 too.

Permissions, all existing: `sysEnterpriseGet` and `sysEnterpriseUpdate`,
`sysCalendarAlarmGet` and `sysCalendarAlarmUpdate`,
`sysCalendarSchedulingGet` and `sysCalendarSchedulingUpdate`, and
`sysDomainUpdate` for a domain's logo. The names stay as they are, "Enterprise"
included: they're protocol identifiers (SPEC.md §2.4).

## Required behavior

Each requirement has an ID, and tests name the IDs they check.

### Logos: which one applies

- **BT-1.** Logos are resolved for a domain name. For a name D:
  1. the `logo` of the `x:Domain` whose `name` or `aliases` match D;
  2. else the `logo` of that domain's tenant (`memberTenantId`);
  3. else `x:Enterprise.logoUrl`;
  4. else the built-in INBUXA logo.
  This is the order upstream documents. **Decision** on matching: exact match
  first, then D with its leftmost label removed, repeated while at least two
  labels remain, so `mail.example.com` finds `example.com`. Matching is
  case-insensitive.
- **BT-2.** Where each surface gets its domain:
  - the sign-in page and the RSVP page: the `domain` query parameter of
    `/logo` (BT-5), else the request's `Host` without its port, as upstream
    documents;
  - alarm emails: the domain of the account's primary address;
  - iMIP emails: the domain of the message's `From` address;
  - ihasmail: the signed-in principal's domain (multi-tenancy MT-22).
  **Decision**: MT-22's chain ends at "none". This spec extends it with steps
  3 and 4, so ihasmail and the server show the same logo. The multi-tenancy
  spec should be updated to point here.
- **BT-3.** A logo value is one of:
  - an `https:` URL;
  - a `data:` URL (RFC 2397), base64, with type `image/png`, `image/jpeg`,
    `image/gif`, `image/webp` or `image/svg+xml`.
  **Decision** on writes: anything else is refused with `invalidProperties`
  naming the field, and so is a data URL whose decoded image is over 256 KiB
  or whose bytes don't match its declared type. `logoUrl` takes the same two
  forms: a data URL is a valid URI.
- **BT-4.** Stored values that predate the fork are read as they are, never
  rewritten, and never refused on read. **Decision** on odd ones: a bare
  base64 string (the schema says "base64-encoded image") is treated as a data
  URL whose type is sniffed from its first bytes, and an `http:` URL is used
  like an `https:` one. A value that is none of these is skipped as if unset,
  with a `registry.build-warning` event naming the object.

### Logos: serving and embedding

- **BT-5.** `GET /logo`, anonymous, rate-limited like the other anonymous
  endpoints. It resolves a logo per BT-1 and BT-2 and answers:
  - a data-URL logo: `200` with the decoded bytes and their type;
  - a URL logo: `302` to that URL;
  - no custom logo at any level: `404`, and the page draws its own.
  Every answer carries `Cache-Control: public, max-age=300`,
  `X-Content-Type-Options: nosniff`, and `Access-Control-Allow-Origin: *`.
  **Decision** on the shape (see open question 3).
- **BT-6.** An unknown domain answers exactly as a known domain with no logo
  of its own would: the server-wide logo or `404`. **Decision**: `/logo` isn't
  a way to test which domains are hosted, beyond what a domain's own logo
  shows.
- **BT-7.** The server never fetches a logo URL, for any purpose: not to serve
  it, not to check it, not to embed it. Only browsers and mail clients fetch
  URL logos, and ihasmail through its image proxy (MT-23).
- **BT-8.** An SVG served by `/logo` is sent with
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`.
  **Decision**, a security requirement: a tenant administrator can set its
  domain's logo, and `/logo` is on the server's origin, so a scripted SVG must
  never run there.
- **BT-9.** Emails embed the logo as an inline MIME part inside the
  `multipart/related` part, and the template reaches it through `{{logo_cid}}`,
  a `cid:` URL (RFC 2392). This is what the shared code already does. Only a
  PNG, JPEG or GIF data-URL logo is embedded. **Decision**: a URL logo is never
  embedded (BT-7), and SVG and WebP are skipped because many mail clients
  can't show them. Resolution then goes on down BT-1's chain for the first logo
  that can be embedded, ending at the built-in PNG.
- **BT-10.** A logo change takes effect without a restart, on every node of a
  cluster, through the existing `DomainLogo` and `TenantLogo` cache
  invalidations. A change to `logoUrl` clears the whole logo cache.

### Email templates

- **BT-11.** A template set in `x:CalendarAlarm.template` replaces the
  built-in alarm email, and one set in `x:CalendarScheduling.emailTemplate`
  replaces the built-in iMIP email. Null restores the built-in. Both are
  server-wide: there's no per-tenant or per-domain template. The logo is what
  varies (BT-9).
- **BT-12.** The template language is the one the built-in templates already
  use (`crates/utils/src/template.rs`):
  - `{{name}}` inserts a value, HTML-escaped (`& < > " '`);
  - `{{#if name}}…{{/if name}}` keeps its content only when `name` is set;
  - `{{#each name}}…{{/each name}}` repeats its content once per entry of a
    list, and inside it `{{name}}` and `{{#if name}}` refer to the entry.
  A token can't span lines. `#each` can't be nested.
- **BT-13.** The variables. What the server sets for each template:

  | Variable | Kind | Alarm | iMIP |
  |---|---|---|---|
  | `page_title` | value | the subject | the subject |
  | `lang`, `dir` | value | recipient's locale and direction | same |
  | `logo_cid` | value | `cid:` of the logo part | same |
  | `header` | value | the alarm heading | on update, cancel and reply: what happened |
  | `color` | value | — | `info`, `warning` or `danger`, with `header` |
  | `event_title`, `event_description` | value | if the event has them | same |
  | `event_details` | list of `key`, `value`, `link`?; iMIP also `changed`?, `old_value`? | start, end, location, conference, organizer | summary, description, when, location, conference; the old value when it changed |
  | `attendees_title` | value | always | when there are attendees |
  | `attendees` | list of `key` (name), `value` (address) | when there are guests | when there are attendees |
  | `action_name`, `action_url` | value | "open" label and the event's webcal link | — |
  | `rsvp` | value | — | "reply as …", when RSVP links are on |
  | `actions` | list of `action_name`, `action_url`, `color` | — | yes, no and maybe, when RSVP links are on |
  | `footer` | alarm: value; iMIP: list of `key` | the footer line | two footer lines |

  `link` is set only for `https`, `http`, `tel`, `sip`, `sips` and `xmpp`
  values, so a template can't be made to link `javascript:`. The labels are the
  server's own translations for the recipient's locale. A template can't add
  translated text of its own.
- **BT-14.** **Decision**, a security requirement: values are always escaped
  in operator templates. The shared syntax also has `{{!name}}` for raw output.
  A write that uses it is refused (BT-15). A stored template that uses it
  (from before the fork) is rendered with those values escaped too. Event titles,
  descriptions and attendee names come from whoever sent the invitation, often
  from outside the server, so raw output would let a stranger put HTML into
  mail the server sends under its own name.
- **BT-15.** A write of `template` or `emailTemplate` is checked, and refused
  with `invalidProperties` naming the field and the first problem, when:
  - it doesn't parse (unbalanced block, block end that doesn't match, token
    across lines, nested `#each`);
  - it names a variable not in BT-13;
  - it uses `{{!…}}`;
  - it's over 256 KiB.
  **Decision** on all four. A variable used outside the scope where it's set
  (e.g. `{{key}}` outside a list) renders empty. That's allowed, not refused.
- **BT-16.** The server fetches nothing a template references, and doesn't
  rewrite it. A remote image in an operator's template is the recipient's mail
  client's business. The plain-text part of each email is still generated from
  the rendered HTML, as today.
- **BT-17.** Subjects, sender names and addresses aren't templated. They stay
  as the shared code builds them, with `fromName` and `fromEmail` for alarms.
- **BT-18.** A template change takes effect for the next email rendered, with
  no restart and no settings reload. **Decision**, matching undelete UD-6a:
  whether upstream needs a reload is open question 4.
- **BT-19.** A stored template that fails BT-15's parse on load (data written
  before the fork) never stops the server. The built-in is used instead, and a
  `registry.build-warning` event names the field and the error. It's reported
  again whenever settings are reloaded until it's fixed.

### The RSVP page

- **BT-20.** When `httpRsvpEnable` is true, `GET /calendar/rsvp` serves
  `httpRsvpTemplate` if set, else the built-in page. A custom page is served
  byte for byte: no variables, no substitution. `{{` in it is plain text.
  Setting `httpRsvpEnable` to false turns off both the page and the API, as
  upstream documents.
- **BT-21.** Whichever page is served, the answer carries:
  - `Content-Type: text/html; charset=utf-8` and `Cache-Control: no-store`;
  - `Referrer-Policy: no-referrer`, because the token is in the query string;
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
  **Decision**, a security requirement: the page holds a live RSVP token. It
  may show remote images (URL logos, BT-5), but it can't send the token
  anywhere but the server.
- **BT-22.** A write of `httpRsvpTemplate` is refused with `invalidProperties`
  when it's over 1 MiB or isn't valid UTF-8. **Decision**. Its content isn't
  otherwise checked: it's the operator's own page, and only a server-level
  administrator can set it (BT-24).
- **BT-23.** The API a page calls is unchanged: `POST /api/calendar/rsvp` with
  `{token}` to load the invitation, and `{token, partstat, comment}` to reply.
  The answer is `invitation`, `recorded` or `error`, with localized `labels`, a
  `language` and a `dir`, as the scheduling documentation describes. This
  spec adds nothing to it.

### Who can change what

- **BT-24.** The three templates and `logoUrl` live on server-wide singletons.
  Only a principal in no tenant, holding the matching `sys*Update`
  permission, can change them. A principal in a tenant can't, whatever its
  permissions (multi-tenancy MT-2).
- **BT-25.** A domain's `logo` is changed with `sysDomainUpdate`. Inside a
  tenant, the tenant's administrator can set the logo of its own domains
  (multi-tenancy MT-11). A tenant's `logo` is server-level (MT-12).

### Built-in pages

- **BT-26.** The built-in sign-in and RSVP pages load the logo with an image
  element pointing at `/logo` (with `?domain=` as they do now), not with
  `fetch`. On an error they keep their built-in logo. **Decision**: `fetch`
  can't follow BT-5's redirect to another origin without that origin's CORS
  headers, and an image element can.

## Interfaces

- **Existing, unchanged:** `x:Enterprise/get` and `/set`,
  `x:CalendarAlarm/get` and `/set`, `x:CalendarScheduling/get` and `/set`,
  `x:Domain/get` and `/set`, their permissions; `GET /calendar/rsvp`;
  `POST /api/calendar/rsvp`.
- **New:** `GET /logo` (BT-5), with an optional `domain` parameter. The fork's
  own pages already call it.
- **Per principal:** the applicable logo over JMAP, as proposed in
  multi-tenancy MT-22, following BT-1's full chain (BT-2).
- **Errors:** RFC 8620 `invalidProperties`, naming the field, with the parse
  error or limit in `description`, so ihasmail and INBUXA Admin can show it.
- **Events:** `registry.build-warning` for BT-4 and BT-19.

## ihasmail changes

These go in the INBUXA fork of ihasmail, inbuxa-webmail, never in public
ihasmail, which stays Stalwart-facing (SPEC.md §5).

- **Administration, Domains:** a logo field on each domain. Upload a PNG, JPEG
  or GIF, stored as a data URL, with a preview and the 256 KiB limit checked
  before sending. A note says that SVG, WebP and URL logos show on the web but
  aren't used in email (BT-9). Tenant logos stay where multi-tenancy puts them.
- **Show the applicable logo** for the signed-in user (MT-22, BT-2). URL logos
  go through the image proxy (MT-23).
- **Not in ihasmail:** the server-wide logo and the three templates are
  server-level settings. INBUXA Admin's schema-driven forms already cover them
  (SPEC.md §5.4). ihasmail links there, and doesn't grow a template editor.
- New strings: the logo field's label, its help text, the email note, and the
  size and type errors. That's about six strings, new translation work for
  each of ihasmail's nine languages.

INBUXA Admin needs no new screen. It shows the `invalidProperties`
descriptions from BT-15 and BT-22 as it shows any validation error.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code. The one
marked **(compat)** also runs against a copy of INBUXA's data.

1. Nothing set: `/logo` answers `404`, and alarm and invite emails carry the
   built-in INBUXA PNG, referenced by `cid:` (BT-1, BT-5, BT-9).
2. `logoUrl` set to a PNG data URL: `/logo` answers `200` `image/png` with the
   bytes, and emails embed it (BT-1, BT-5, BT-9).
3. Tenant T with a logo, its domain without one: `/logo?domain=` for the
   domain gives T's logo. With the domain's own logo set, the domain's wins
   (BT-1).
4. `/logo?domain=mail.example.com` finds `example.com`'s logo. No parameter,
   `Host: mail.example.com`: the same (BT-1, BT-2).
5. A domain logo that's an `https:` URL: `/logo` answers `302` to it, the
   server makes no outbound request (watched at the network), and emails fall
   back to the next logo that can be embedded (BT-5, BT-7, BT-9).
6. An unknown domain and a known domain with no logo give identical answers
   (BT-6).
7. An SVG logo with a `<script>`: `/logo` sends the sandboxing CSP, and the
   script doesn't run when the URL is opened directly (BT-8).
8. Logo writes: `javascript:alert(1)`, `data:text/html,…`, a 300 KiB PNG, and
   `data:image/png` holding JPEG bytes are each refused `invalidProperties`
   (BT-3).
9. Changing a domain's logo shows on the next `/logo` request on another
   cluster node, without a restart (BT-10).
10. A custom alarm template renders with every BT-13 alarm variable filled.
    An event titled `<b>x</b>` shows as text, not bold (BT-12, BT-13, BT-14).
11. A custom iMIP template for an invitation, an update (with `changed` and
    `old_value`), a cancellation and a reply each render, with RSVP actions
    only when RSVP is on (BT-13).
12. Template writes: unbalanced `{{#if header}}`, `{{unknown}}`, `{{!header}}`,
    nested `#each`, and 300 KiB are each refused `invalidProperties`, naming
    the field (BT-15).
13. A template stored directly in the registry with `{{!event_title}}` renders
    the title escaped. One that doesn't parse leaves the server running, uses
    the built-in, and emits `registry.build-warning` (BT-14, BT-19).
14. A template change is used for the next alarm, with no reload (BT-18).
15. A custom RSVP page containing `{{page_title}}` is served byte for byte, with
    BT-21's headers. With `httpRsvpEnable` false, the page and the API are
    both gone (BT-20, BT-21).
16. A tenant administrator can set its domain's logo, but can't change
    `logoUrl`, any template, or its tenant's logo (BT-24, BT-25).
17. The built-in sign-in and RSVP pages show a URL logo through `/logo`'s
    redirect, and their built-in logo when `/logo` is `404` (BT-26).
18. **(compat)** Every logo and template INBUXA holds reads back unchanged, and
    each renders or is served as it did before cutover (BT-4, BT-19).

## Open questions / to observe

To check read-only against INBUXA's live Enterprise server before
implementation. None blocks the spec. Items 2 and 5 need a write, so they need
the operator's approval first, as with the other features' probes.

1. **What INBUXA holds.** Read `x:Enterprise.logoUrl`, every `x:Domain.logo`
   and `x:Tenant.logo`, and the three template fields. If all are null, test 18
   has nothing to carry over. Note the forms any logos take (URL, data URL,
   bare base64), which BT-4 depends on.
2. **URL logos in email.** Does upstream embed a URL logo in alarm and invite
   emails (which would mean it fetches it), reference it remotely, or skip it?
   Look at the MIME structure of an invite already in a mailbox before
   sending a new one. BT-7 and BT-9 stand either way. This only says how far
   the fork differs.
3. **Upstream's `/logo`.** Its exact path and parameters, whether it honors
   `domain=` and `Host`, and its status, content type and caching for data
   URLs, URL logos and no logo. The fork's own pages already call
   `/logo?domain=`. A plain `GET` settles this, and BT-5 is aligned to it where
   nothing more important is at stake.
4. **Reload.** Does a change to a template or a logo take effect upstream
   without a settings reload (BT-10, BT-18)?
5. **Invalid templates on write.** Does upstream refuse a template that
   doesn't parse, or store it and fall back? It matters only for how much
   invalid data INBUXA might already hold (BT-19).
6. **RSVP page headers.** What headers upstream sends with a custom RSVP page,
   so BT-21 is known as a difference or not.
7. **The stored `fromName`.** Whether INBUXA's `x:CalendarAlarm` stores
   `Stalwart Calendar` as a value or relies on the default. **Decision** until
   known: stored values are never rewritten (SPEC.md §7). If it's stored, the
   operator changes it once, by hand. (The packaged `schema.json.gz` carried
   upstream's default, `Stalwart Calendar`, until 2026-09-18. It now says
   `INBUXA Calendar`, matching the code.)
8. **INBUXA Admin's logo.** Upstream documents that its web interface picks its
   logo by request hostname. Check in `inbuxa-admin` (an ordinary AGPL fork,
   SPEC.md §5) whether it calls `/logo`, so it keeps working against BT-5.

## Implementation status

Built 2026-09-18 from this spec, clean-room, under the multi-tenancy hand-off
brief's rules. The rules live in `crates/features` (`inbuxa-features`, module
`branding`); the domain lookup in `crates/common/src/storage/branding.rs`;
`/logo` and the RSVP page's answer in `crates/http/src/branding.rs`; upstream
files carry hooks marked `inbuxa:`. Acceptance tests 1 to 17 pass as
`tests/src/system/branding.rs`.

- **BT-1 to BT-26:** built.
- **ihasmail changes** belong to inbuxa-webmail and aren't part of this
  repository.
- **Test 18 (compat)** is written as `branding_compat`, ignored, and unrun
  until a copy of INBUXA's data is provided. INBUXA holds no logos or
  templates (observed 1), so it has nothing to carry today.
- **Known limits, not requirements of this spec:**
  - Logos are read from the registry on each `/logo` request and each email,
    not cached. That is what makes BT-10 hold on every node with nothing to
    invalidate; the existing logo cache is left unused.
  - Test 9 runs on one node. The cluster half of BT-10 follows from reading
    the registry each time, and isn't exercised by a test.
  - Test 7 checks the sandboxing header. That the script doesn't run is the
    browser honouring it, which no test here drives.
  - Test 17 checks the pages' source, not a browser loading them.
  - `httpRsvpEnable` still needs a settings reload, as upstream (it isn't one
    of this spec's fields); the templates and logos don't (BT-18, BT-10).

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), read-only, as a server-level administrator and the throwaway test
account. No upstream code was read.

1. **What INBUXA holds** (open question 1). `x:Enterprise.logoUrl`, all three
   templates and every tenant logo are null. Six of nine domains had a logo:
   four held the same `https:` URL, pointing at a retired website that now
   answers with an HTML page, and two held the literal string `admin`. With
   the operator's approval, the four URL logos were removed the same day (a
   write). The two `admin` values were removed too, also with approval, so
   INBUXA holds no logos at all and compat test 18 has nothing to carry.
2. **Upstream fetches URL logos itself** (open questions 2 and 3). While the
   URL logos were set, `GET /logo` returned `200 text/html`: the retired
   site's page, served from the mail server's own origin with no
   `X-Content-Type-Options` and no CSP. So upstream fetches the URL on the
   server side and passes on whatever comes back, content type included.
   BT-7 (never fetch) and BT-8 (sandbox what is served) are deliberate
   differences, and this is why.
3. **`/logo` shape.** `/logo` with no parameter used the request's host, and
   `?domain=` selected a domain. `/logo/<domain>` answered the same as
   `/logo`, so the path segment is ignored. An unknown domain, a domain with
   an unusable value, and (after the removal) every domain answered `404`
   with `application/problem+json`. No caching headers were sent. BT-5 keeps
   `/logo?domain=` and `404`, and adds its own headers.
4. **Reload** (open question 4). Removing the logos took effect on the very
   next `/logo` request, with no settings reload.
5. **RSVP page headers** (open question 6). `GET /calendar/rsvp` sends only
   `Content-Type: text/html; charset=utf-8` and
   `Cache-Control: no-store, no-cache, must-revalidate`: no CSP and no
   `Referrer-Policy`. BT-21's headers are a difference.
6. **The stored `fromName`** (open question 7). INBUXA stores
   `INBUXA Calendar` as a value already. Nothing to change at cutover.

7. **INBUXA Admin's logo** (open question 8), checked 2026-09-18 in the
   `inbuxa-admin` source, not on a server. It requests `/logo` with no
   parameter (so the server goes by `Host`), through `fetch()`, and draws its
   built-in logo whenever the answer isn't an `image/*` response. It reads no
   logo fields and never asks the server to fetch a URL. Against BT-5, a
   data-URL logo shows; a URL logo's cross-origin redirect falls back to the
   built-in unless the logo's host sends CORS headers. Moving it to an image
   element, as BT-26 does for the server's own pages, is a change for that
   repository.

Not settled: open question 5 (invalid templates on write) needs a write.
