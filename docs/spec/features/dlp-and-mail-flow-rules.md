# Feature spec: data loss prevention and mail flow rules

Status: **draft for approval.** Phase 1 of DLP and the rule builder, specced
together because they need the same conditions, the same place in the mail
path and the same record of what matched. Not a rebuild of an upstream
feature, so it has no line in SPEC.md §4's table. Open questions are under
[For John](#for-john); nothing is built until they're answered.

## Provenance

Written for the record SPEC.md §3 rule 3 asks for. Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| This repository at `0502eb4` (2026-09-28): `crates/smtp/src/inbound/data.rs`, `crates/smtp/src/queue/`, `crates/jmap/src/submission/set.rs`, `crates/common/src/scripts/`, `vendor/sieve-rs`, `resources/schema/schema.json.gz` | AGPL-3.0-only | Where a check can run, what the queue stores, what a sender sees on a refusal |
| inbuxa-admin at `b82904c` | AGPL-3.0-only | Where the pages go |
| ihasmail-inbuxa (the webmail) at `290bc63` | AGPL-3.0-or-later | How a refused send reaches the person sending |
| `inbuxa-drafts/queue/dlp.md`, `rule-builder.md` | Own | What John asked for and settled |
| The personal-data catalog spec and the audit-hold-lock spec | Own | Roles, the audit log, legal holds, the catalog check |
| RFC 5321, RFC 3463 (enhanced status codes), RFC 8620/8621 (JMAP) | Public | Refusal codes and the submission error shape |

No Enterprise-only file or snippet was used, and no third-party DLP product
was consulted for design: the detectors are public checksum and format rules
(Luhn, ISO 13616 mod 97, the SSA's published SSN rules).

## What it is

1. **Data loss prevention (DLP).** Policies that look at mail as someone
   sends it, find what shouldn't leave (card numbers, bank accounts, national
   ID numbers, words and patterns an organization names, attachments of a
   kind), and then **block** it with a notice, **warn** and let the sender
   send anyway with a stated reason, or **hold** it until a reviewer releases
   or rejects it.
2. **Mail flow rules.** The same engine, for ordinary transport rules an
   administrator writes in a form instead of in Sieve: disclaimers, banners,
   headers, copies, redirects, refusals.
3. **One record of what matched**, in the audit log, and a **review queue**
   for held mail.

Settled before this spec (John, 2026-09-27 and 2026-09-28): DLP's first
version checks **outgoing mail only**, content and attachments, as it's sent;
its actions are block with a notice, warn with an override (audited), and hold
for review. A record-only action was not chosen. The rule builder goes
alongside DLP, one design; journaling comes after both.

**Out of scope** (later specs): inbound DLP, files and calendar sharing,
scanning mail already stored, a machine-learning classifier (the local AI
model could add one later; nothing here depends on it), mobile and ihasmail
screens, journaling.

Nothing in code, docs, UI text or output claims the product meets a legal
standard or prevents every leak. The pages say what a policy checks and what
it did.

## 1. What exists today

Checked by reading the code at `0502eb4`:

| Need | Today |
|---|---|
| A place in the send path that sees every outgoing message | Yes. SMTP submission and webmail sends both reach `Session::queue_message` (`inbound/data.rs`); JMAP submission builds a local session and runs MAIL, RCPT and DATA (`jmap/src/submission/set.rs` ~L690–760). Nothing reaches the queue around it. |
| Order at DATA | Authentication checks → spam filter → milters → MTA hooks → the DATA system Sieve script → headers, DKIM signing → queue. |
| Rules without code | System Sieve (`x:SieveSystemScript`): one script per stage, chosen by an expression on `x:MtaStageData.script`. Hand-written only; the console has a text field. |
| Refusing a message | A 5xx at DATA. The webmail gets `forbiddenToSend` with the text `Server rejected DATA: <reply>` and nothing structured. |
| Holding a message | **Nowhere.** "Quarantine" in the code is only DMARC's disposition. The queue's recipient status is `Scheduled`, `Completed`, `TemporaryFailure`, `PermanentFailure`, archived with rkyv. |
| Reading attachments | Text and HTML parts only. There's no PDF or Office text extraction: search indexes text parts and file names. |
| Recording what happened | The audit log, with system actors, reasons and outcomes (AU-1…AU-12). |
| Who is allowed | Roles with per-permission grants; server and tenant levels; the compliance roles from the catalog spec. |

## 2. Design

### 2.1 One engine, native, after the system script

Rules are evaluated by a new native engine at DATA, **after** the system Sieve
script and before headers and DKIM signing. Mail flow rules and DLP policies
are two views of the same rule list.

Why not generate Sieve: holding a message, a warning the sender can override,
counted detectors with checksums, and a per-rule match record are all things
Sieve doesn't have. Adding them means new extensions in `vendor/sieve-rs`,
which widens the fork of a crate we'd otherwise take from upstream, and a
generated script would have to share the single DATA script with whatever an
administrator wrote by hand. A native engine leaves hand-written Sieve exactly
as it is: it still runs, first, and the rules see its result.

The engine lives in `crates/features/src/mailflow/` (pure evaluation over a
parsed message and an envelope, unit-testable), called from `data.rs` behind
one `// inbuxa:` marked block.

### 2.2 Rules

A fork-owned JMAP object, `inbuxa:MailRule`, stored in inbuxa's own subspace
like legal holds (not a registry object, so upstream schema imports never
touch it):

| Property | |
|---|---|
| `name`, `description` | |
| `kind` | `dlp` or `transport`: which page shows it and which permission edits it |
| `enabled` | |
| `priority` | Order; lower runs first |
| `direction` | `outgoing` (authenticated senders), `incoming`, or `any`. **DLP rules are `outgoing` only** in this version. |
| `conditions` | All must match (list below) |
| `exceptions` | Any matching one skips the rule |
| `actions` | What happens (list below) |
| `stopProcessing` | Later rules don't run for this message |
| `tenantId` | Server-level (none) or one tenant's; see [For John](#for-john) Q3 |
| `createdBy`, `updatedAt` | |

Every create, update and delete is audited with its before and after, like
any setting, and appears on the compliance Overview's **Changes that affect
review**.

### 2.3 Conditions

Shared by both kinds:

| Condition | Matches when |
|---|---|
| Sender | the sender is one of the chosen accounts, or in a chosen group, domain or tenant |
| Recipient | any recipient is one of the chosen addresses, domains, groups |
| **Recipient outside** | any recipient isn't at a domain this server hosts (or, with a tenant rule, isn't in the tenant) |
| Subject or body contains | any of a list of words or phrases (whole words, case-insensitive) |
| Subject or body matches | a regular expression (the `regex` crate: linear time, no backtracking) |
| Header | a header exists, or its value contains or matches |
| Attachment | its detected type, extension or name matches; its size is over a limit; there are more than N |
| **Can't be inspected** | an attachment is encrypted or password-protected (ZIP, PDF, Office), or bigger than the inspection limit |
| Message size | over a limit |

DLP adds **detectors**, each with a minimum count (for example "5 or more card
numbers"):

| Detector | Rule |
|---|---|
| Payment card number | 13–19 digits, spaces or dashes allowed, a known issuer prefix, passes Luhn |
| IBAN | country code, check digits and length for that country, passes ISO 13616 mod 97 |
| US Social Security number | `AAA-GG-SSSS` or nine digits beside words like "SSN"; never area 000, 666 or 9xx, group 00, serial 0000 |
| Word list | a list the organization maintains (project names, "confidential"), counted |
| Pattern | the organization's own regular expression, counted |

What the detectors read: the subject, every text and HTML part (as text),
and attachments whose detected type is text (`text/*`, CSV, JSON, XML).
Office and PDF files are read only if Q2 says so; until then they count as
**can't be inspected** so a policy can still act on them. Inspection stops at
a limit per message (proposed 10 MB of text), and what's past it counts as
can't be inspected too.

### 2.4 Actions

**Transport actions** (both kinds): add a disclaimer (text and HTML, top or
bottom, once per thread), add or remove a header, prefix the subject, add a
recipient (a copy), redirect to other recipients, refuse with a text, send
through a chosen route (an existing `x:MtaVirtualQueue`).

**DLP actions**, exactly one per DLP rule:

| Action | Sender sees | Message |
|---|---|---|
| **Block** | SMTP `550 5.7.1` with the rule's notice text; in the webmail, the notice in the send dialog | Not accepted; nothing is stored |
| **Warn** | The notice and, once they give a reason, can send anyway | Sent after an override; the reason is audited |
| **Hold for review** | Accepted with "held for review"; a notice mail from the server if the rule asks | Waits in the queue for a reviewer |

When several DLP rules match, the strictest wins: block, then hold, then warn.

### 2.5 Warn and override

**Webmail (JMAP).** The first submission fails with a new error type,
`inbuxa:dlpWarning`, carrying the matched rules' names and notice texts (never
the matched text). The webmail shows them and asks for a reason; it
resubmits with `inbuxa:dlpOverride: {"reason": "..."}` on the
`EmailSubmission` create (capability `urn:inbuxa:jmap`). The server passes the
reason into the local SMTP session as trusted session data, not as a header,
so it can't be forged from the message. An override covers only the rules
that warned; if a block or hold rule also matches, that still applies.

**Mail apps (SMTP).** They show whatever text the server returns, so the
refusal says how to override: `550 5.7.1 <notice>. To send anyway, start the
subject with [override: your reason]`. On the next attempt the engine strips
the tag before DKIM signing, and records the reason. See Q1.

A block's refusal uses the same error path with `inbuxa:dlpBlocked` in the
webmail.

### 2.6 Hold for review

A held message is queued normally but **not scheduled**: its due time is set
to never, and a review record `inbuxa:HeldMessage` (queue id, sender,
recipients, subject, size, matched rules and counts, held at, expires at) is
written in inbuxa's own subspace. The queue's stored format is untouched, so a
node still on the previous version during a rolling upgrade reads the message
fine and simply never sends it.

The sender gets `250 2.0.0 Held for review`, and the rule may send them a
notice mail. The message stays in their Sent folder as usual.

A reviewer, under **Management › Compliance › Held mail**:

- sees the list, and opens one to read it (each opening is audited, like any
  access to someone else's mail);
- **releases** it with a reason: it's scheduled at once and delivered as
  normal;
- **rejects** it with a reason: it's removed from the queue and the sender
  gets a notice with the reviewer's note, not their name.

Unreviewed mail is rejected after a set time (Q5), with a notice to the
sender. Emails › Queue shows held mail as held and refuses **Retry** on it, so
nobody can deliver it around the review. The sender can't unsend it either
once it's held (the webmail says so).

Held messages count against no one's quota. Each held message and each
decision is in the audit log.

### 2.7 What's recorded

Every DLP match writes one audit record: actor **DLP** (a system actor),
target the message (queue id, sender, recipient domains), the rules and each
detector's count, the action, and for an override the sender's reason.
**Never the matched text**: the log would otherwise become a second copy of
what the policy was keeping in. A card number isn't written, even masked.

Transport rules that change a message record the rule and action the same way.
Unmatched mail writes nothing.

### 2.8 Permissions and who does what

New permissions (ids from 674):

| Permission | Gives |
|---|---|
| `sysMailRuleGet` / `Update` | See / change transport rules |
| `sysDlpPolicyGet` / `Update` | See / change DLP rules |
| `sysDlpReviewGet` | See held mail and open it |
| `sysDlpReviewUpdate` | Release or reject held mail |

Proposed defaults: **Administrator** has all; **Compliance Officer**
(server-level) has `sysDlpPolicyGet`, `sysDlpReviewGet`, `sysDlpReviewUpdate`;
tenant roles per Q3. See Q4 on who edits DLP rules.

### 2.9 Privacy catalog

New entries, so the catalog check passes: `inbuxa:MailRule` (administrator
identities), `inbuxa:HeldMessage` (sender, recipients, subject: held until
reviewed or expired, then removed), and the held message's content in the
queue (content, the sender's and correspondents'). The DLP audit records are
covered by the audit log's entry.

### 2.10 Mixed versions and clusters

Rules and review records live in the shared data store, so every node sees the
same ones. During a rolling upgrade a node still on the old version doesn't
check mail against rules; the Overview can't tell. The console says so when
nodes report different versions, and the release notes say to enable DLP
rules after every node is upgraded.

### 2.11 Cost

Rules are compiled once when they change (regexes, word lists as an
Aho-Corasick automaton) and shared by every session. Detectors only run on
mail that some enabled rule could match (direction, sender, recipient checks
first). The inspection limit caps the worst case.

## 3. Console

- **Management › Compliance › Data loss prevention**: DLP rules, a form with
  conditions, exceptions, detectors and the action; the notice text; what
  matched in the last 30 days (from the audit log).
- **Management › Compliance › Held mail**: the review queue.
- **Settings › Mail flow › Rules** (with the settings reorganization's
  approved order): transport rules, same form, ordered, with **Stop
  processing**.

Every form previews the rule in words ("If a recipient is outside and the
message contains 5 or more card numbers, hold it for review").

## 4. Webmail (ihasmail-inbuxa)

- A warning dialog: the notice, a reason field, **Send anyway** and **Edit
  message**.
- A block dialog with the notice.
- A held message shows as **Held for review** in Sent, and its undo is gone.

## 5. Tests

Unit: each detector against valid and near-miss numbers (Luhn-failing cards,
IBANs with a wrong check, SSN areas 000/666/9xx), word lists, regexes, the
inspection limit, the can't-be-inspected cases, rule order and stop
processing. Integration (`tests/src/smtp/`, `tests/src/jmap/`): block, warn
and override over SMTP and JMAP, hold then release and reject, expiry,
Retry refused on held mail, audit records carrying no matched text, a
message queued by a node without the engine (held message format unchanged).

## 6. Phases

1. This spec, approved.
2. Engine, conditions, detectors, transport actions; DLP block and warn over
   SMTP and JMAP; audit records; catalog entries.
3. Hold for review: review records, release, reject, expiry, queue guard.
4. Console: DLP rules, held mail, mail flow rules.
5. Webmail dialogs; docs; a row in `inbuxa-drafts/divergence-log.md`.

Each phase is its own PR with tests; releases as John decides.

## Known gaps

- Mail a user's own filter forwards automatically to an outside address isn't
  checked in this version (it leaves as generated mail, not a submission).
- What a mail app keeps in its own Sent folder, or sends through another
  server, is outside what this server sees.
- Detectors find formats, not meaning: a card number in a harmless test
  message matches; a number written in words doesn't.

## For John

1. **Override from mail apps.** Recommended: the `[override: reason]` subject
   tag, stripped before sending. Alternatives: no override outside the
   webmail (mail apps get warn rules as blocks), or a header only a few apps
   can set.
2. **Office and PDF attachments.** Recommended: read DOCX, XLSX, PPTX and ODF
   in this version (ZIP plus XML, done in-house, no new service), PDF later.
   Alternative: all of them count as can't be inspected until a later spec.
3. **Tenants.** Recommended: server-level rules only in this version, with a
   tenant condition, so a service provider sets policy for everyone.
   Alternative: tenant administrators write rules for their own tenant too
   (more to build: a tenant ceiling on actions, a tenant's review queue).
4. **Who edits DLP rules.** Recommended: administrators edit, compliance
   officers see rules and review held mail, keeping "officers change no
   setting" true. Alternative: officers edit DLP rules too.
5. **Unreviewed held mail.** Recommended: rejected back to the sender after 7
   days, with a notice. Alternatives: a different number, or held until
   someone decides.
6. **Detectors in the first version.** Recommended: the five above. Others
   (UK NI number, EU national IDs, passport numbers) are a table entry each
   later; name any that must be there from the start.
