# Feature spec: journaling

Status: **approved 2026-09-28**, with the answers under [Settled](#settled).
Not a rebuild of an upstream feature, so it has no line in SPEC.md §4's table.
Rule IDs: **JR-**.

## Provenance

Written for the record SPEC.md §3 rule 3 asks for. Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| This repository at `94a3a76` (2026-09-28): `crates/smtp/src/inbound/data.rs`, `inbound/rcpt.rs`, `queue/spool.rs`, `outbound/delivery.rs`, `crates/common/src/network/mta.rs`, `crates/features/src/{hold,audit,mailflow,undelete}`, `crates/store/src/write/{mod,blob}.rs`, `crates/jmap/src/inbuxa/hold_export.rs` | AGPL-3.0-only | Where every message passes, what the envelope holds, how holds keep blobs, how the audit chain and hold export work |
| `inbuxa-drafts/queue/journaling.md` | Own | What John asked for, and the gaps to settle |
| The DLP and mail flow rules spec, the audit-hold-lock spec, the personal-data catalog spec | Own | Conditions, the audit log, legal holds, roles, the catalog check |
| RFC 5321, RFC 3461 (DSN, ORCPT), RFC 2046 (`message/rfc822`), RFC 5322 | Public | The envelope, the original recipient of an expanded list, the report's shape |

No Enterprise-only file or snippet was used, and no third-party journaling
product or report format was consulted: the journal report below is our own
layout of the SMTP envelope around the untouched message.

## What it is

A **journal** is a copy of each message the server handles, captured in
transit with its **envelope** (the real sender and every recipient, including
Bcc and the members of lists), kept where nobody can change or remove it
until its retention ends, or sent to an outside archive. It sits beside two
things that exist:

- **Legal hold** keeps what's in chosen mailboxes, including what their owners
  delete. It starts when a hold is placed and can't see Bcc or what was sent
  from a mailbox that no longer exists.
- **The audit log** records what people and the server did, never the mail.

A journal answers the question neither can: *what went through, to whom,
from the day it was turned on*.

**Out of scope**: journaling mail stored before it's turned on, files,
calendar and contacts, IMAP APPEND (a mail app saving to its own Sent folder
sends nothing), and mail a mail app sends through another server.

Nothing in code, docs, UI text or output claims the product meets a legal or
regulatory standard. The pages say what's captured, where it's kept and for
how long.

## 1. What exists today

Checked by reading the code at `94a3a76`:

| Need | Today |
|---|---|
| One place all mail passes | `MessageWrapper::queue` (`queue/spool.rs` ~L375). SMTP, JMAP submission (`jmap/src/submission/set.rs` builds a local session and runs `queue_message`), inbound mail, Sieve redirects and vacation replies, and DSNs all queue through it. Local and remote delivery both start from the queue. |
| The envelope | At queue time: `mail_from`, every `rcpt_to` (Bcc included), the authenticated account with its groups and tenant, the queue id. Lists are **already expanded** at RCPT (`rcpt_resolve` → `RcptResolution::Expand`, `inbound/rcpt.rs`); the list address survives as each member's ORCPT (`dsn_info`). |
| A copy out | Sieve at DATA, milters and MTA hooks can send one, but all run **before** DLP and transport rules, so they miss recipients the rules add, and a Sieve copy carries no envelope. |
| Keeping a blob nobody can delete | No "undeletable" flag. Blobs are content-addressed (can't be edited); a `BlobLink::Temporary { until }` keeps one until `until`. Legal hold uses `until` = year 9999. |
| A record nobody can quietly change | The audit log's per-node SHA-256 chain (`features/src/audit/log.rs`): each entry carries `prev`, the head is asserted on append, purge leaves a floor hash, `verify` walks it. |
| Export | Hold export (LH-12): a ZIP of `.eml` files, `manifest.csv` with a SHA-256 per file, `manifest.sha256`, capped at 2 GiB. |
| Conditions by sender, recipient, group, tenant | The mail flow engine (`features/src/mailflow/engine.rs`), at DATA. |

## 2. Design

### 2.1 Where the copy is taken (JR-1, JR-2)

**JR-1.** The journal is taken in `MessageWrapper::queue`, after the message
is spooled, behind one `// inbuxa:` marked block. That's after DLP and
transport rules, so the envelope is the one the message actually leaves or
arrives with, and it covers every path that queues mail.

**JR-2.** What isn't journaled: journal reports themselves (they carry a
queue flag, so a report to an outside archive can't journal itself), and the
server's own DMARC and TLS reports. DSNs and Sieve redirects and vacation
replies are journaled (question 4). A message **refused** at DATA (DLP block,
a transport rule's refusal) was never accepted and isn't journaled; the
audit log already records it. A message **held** for DLP review is journaled
when it's queued, which is when it's held, with the hold noted in the entry.

### 2.2 The journal report (JR-3, JR-4)

**JR-3.** Each copy is a **journal report**: a new message whose first part
is `text/plain`, one field a line:

```
Sender: alice@example.com
Signed in as: alice@example.com
Subject: Q3 figures
Message-ID: <…>
Queue ID: 1a2b3c…
Received: 2026-09-28T14:03:11Z
Direction: outgoing
To: bank@elsewhere.example
Cc: bob@example.com
Bcc: carol@example.com
Expanded: finance@example.com -> dan@example.com, erin@example.com
Held for review: yes
```

and whose second part is the message as queued, **byte for byte**, as
`message/rfc822`. `Bcc:` lists envelope recipients that aren't in the
message's To or Cc headers. `Expanded:` groups the members of a list under
the list address, from their ORCPT. Recipients a transport rule added say so
(`Added by rule: <name>`). The field names are fixed English (they're a
record, not interface text), so a script can read them.

**JR-4.** One report per queued message, with the whole envelope, whatever
the scope matched on (§2.4). A message to 40 recipients is one report, not
40.

### 2.3 Where reports go (JR-5 to JR-8)

Each journal has a **destination** (question 1):

**JR-5. The built-in journal.** Records under a new prefix `J` in
`SUBSPACE_INBUXA`: queue id, received time, direction, sender, recipients,
the tenant(s), which journal matched, the report's blob hash and size, its
SHA-256, and the time it may be purged. The report blob is kept by a
`BlobLink::Temporary { until }` set to the end of its retention. There is no
JMAP `set` or `destroy` for entries: nothing in the product changes or
removes one before its time.

**JR-6. The chain.** Each entry carries the SHA-256 of the entry before it,
one chain per node, the same construction as the audit log (and its code,
generalized rather than copied). The console's **Check the journal** walks
it, and every blob's hash against its entry, and says what it found. Someone
with the server's disks can still remove data, and the chain is how that
shows; the docs say exactly that, and don't say it can't happen.

**JR-7. An outside archive.** The report is queued to an address (the
archive's journal mailbox) like any mail, with the queue's retries. A report
the archive refuses permanently, or can't take within the queue's limit, goes
into the built-in journal instead and raises a warning on the Overview
(question 6). Delivery is by the ordinary queue, so TLS and routing settings
apply; a queue route can be chosen for it.

**JR-8. Both**: the built-in journal and an outside archive.

### 2.4 Which mail: journals and their scope (JR-9 to JR-11)

**JR-9.** A **journal** is a named object (`inbuxa:Journal`): on or off, a
destination, a retention, and a scope. The scope is who: **everyone**, or
senders and recipients in chosen **accounts, groups, domains or tenants**,
and which **direction**: outgoing, incoming, internal, any. A message is
journaled once per journal whose scope any sender or recipient is in; two
journals with the same destination never write the same message twice.

**JR-10.** **By what's in it**: a new mail flow rule action, **Journal it**,
names a journal. The rule's conditions (detectors, words, attachments,
headers) decide; the copy is still taken at queue time (the rule only marks
the message). This is the rule-based journaling the queue note called
premium; here it's one more action, not a separate tier (question 2).

**JR-11.** Scope is evaluated from the envelope and directory membership at
queue time (`Server::member_of`), no message parsing, so journaling
everything costs a lookup per recipient and one blob write per message.

### 2.5 Retention and legal hold (JR-12 to JR-14)

**JR-12.** Each journal has a retention in days (question 3). An entry keeps
the retention it was written with: shortening a journal's retention applies
to new entries only, so nobody can empty the journal by editing a number.
Lengthening it applies to new entries too, and the console says so.

**JR-13.** Purge runs in the daily maintenance, removes entries past their
time and drops their blob link, and leaves a floor hash so the chain still
verifies, as the audit log does. An entry whose sender or any recipient is
under a **legal hold** isn't purged while the hold lasts (`holds_on`, read
uncached, as holds are everywhere).

**JR-14.** Deleting an account doesn't remove its journal entries; they end
with their retention (question 7). The privacy catalog says so.

### 2.6 Search, reading, export (JR-15 to JR-17)

**JR-15.** **Management › Compliance › Journal**: search by sender,
recipient, date range, direction, subject words (from the report's header
fields, not the body: no full-text index of the journal in this version).
Results list the envelope; **Read…** opens the report.

**JR-16.** **Export** a search as a ZIP in the hold export's shape: the
reports as `.eml`, `manifest.csv` with the envelope columns and a SHA-256
per file, `manifest.sha256`, the same 2 GiB cap. Export runs as a task and
the result is a blob owned by the person who asked for it.

**JR-17.** Every search, read and export is in the audit log, with who and
the search terms; so is every change to a journal.

### 2.7 Permissions (JR-18)

**JR-18.** New permissions after the DLP set (680 onward):
`sysJournalGet` / `sysJournalUpdate` (see and change journals),
`sysJournalSearch` (search and read entries), `sysJournalExport`. Superuser
only, by default. The officer grant audience adds Get, Search and Export to
the Compliance Officer; administrators configure journals but don't read
them unless granted Search (question 5). Journals are server-level, with a
tenant scope, as DLP rules are; nobody in a tenant reaches them.

### 2.8 Privacy catalog

New objects get catalog entries (`resources/privacy/catalog.toml`):
`inbuxa:Journal` (none), `inbuxa:JournalEntry` (mail content and envelope,
kept for the journal's retention, access audited, not erased with the
account). `privacy-check.py` enforces it.

### 2.9 Mixed versions, clusters, rollback

- Entries and journals live in the shared data store; report blobs in the
  blob store. A **node-local** blob store (FileSystem, or RocksDB/SQLite as
  the blob store) on a cluster means a node's journal lives on that node;
  the console warns when journaling is on and the blob store isn't shared.
- During a rolling upgrade a node on the old version doesn't journal. The
  console says so when nodes report different versions; the release notes
  say to turn journals on after every node is upgraded.
- Rollback: the new prefix and the queue flag are ignored by an older
  version; nothing in the queue's archived format changes (the "journal
  report" flag rides in the existing message flags if one is free, else in
  a side key by queue id; checked in phase 2 before writing code).

### 2.10 Cost

One extra blob per journaled message (the report wraps the original, so it
doesn't share its hash), plus one small record. The console shows the
journal's size and growth per day on the journal page, from the entries.

## 3. Console

- **Management › Compliance › Journaling**: journals (name, scope,
  destination, retention, on/off), described in words like DLP rules
  ("Journal all mail to and from Finance into the built-in journal, kept
  7 years"); **Check the journal**.
- **Management › Compliance › Journal**: search, read, export.
- The mail flow rule editor gains **Journal it**.
- The Overview warns about undelivered outside reports (JR-7) and a
  node-local blob store (§2.9).

## 4. Webmail

Nothing. People aren't told a message was journaled, as they aren't told
about legal hold; the docs say journaling exists and what it captures.

## 5. Tests

Unit: the report's fields (Bcc computed from headers, list expansion from
ORCPT, rule-added recipients), scope matching, retention arithmetic, the
chain. Integration (`tests/src/system/`): SMTP and JMAP sends, inbound
mail, internal mail, a list and a Bcc recipient, a DLP-held message, a
Sieve redirect; the report equals the queued bytes; no `set`/`destroy`;
shortening retention doesn't touch existing entries; a hold stops purge;
account deletion leaves entries; an outside archive that refuses falls back
to the built-in journal; export manifest hashes; audit records for search,
read, export.

## 6. Phases

1. This spec, approved.
2. Capture at the queue, the report, the built-in journal with its chain,
   retention and purge, holds; `inbuxa:Journal` and `inbuxa:JournalEntry`;
   catalog entries; tests.
3. Outside archive and the fallback; **Journal it** in mail flow rules.
4. Search, read and export (a task), audit records.
5. Console pages; docs; a row in `inbuxa-drafts/divergence-log.md`.

Each phase is its own PR with tests; releases as John decides. Like DLP, it
stays out of production until John says.

## Known gaps

- A message a person saves to Sent over IMAP, or sends through another
  server, never reaches the queue.
- Mail stored before journaling is on isn't journaled (legal hold covers
  mailboxes).
- Search reads envelope and header fields, not bodies.
- Group accounts (`GroupAccount`) resolve as one account, not members; their
  mail is journaled under the group's address.

## Settled

John, 2026-09-28, all seven as recommended:

1. **Destinations**: the built-in journal, an outside archive by address, or
   both, per journal (JR-5, JR-7, JR-8).
2. **Scope**: everyone, or chosen accounts, groups, domains and tenants by
   direction, plus a **Journal it** rule action; no standard/premium split
   (JR-9, JR-10).
3. **Retention**: no default; 30 days to 10 years, picked when a journal is
   turned on; existing entries keep theirs (JR-12).
4. **Which mail**: everything queued, including DSNs, Sieve redirects and
   vacation replies, except DMARC/TLS reports and journal reports (JR-2).
5. **Who reads it**: administrators configure; Compliance Officers search,
   read and export; administrators read only if granted Search (JR-18).
6. **An outside archive that won't take a report**: kept in the built-in
   journal, with a warning (JR-7).
7. **Deleted accounts**: journal entries stay until their retention ends,
   and the catalog says so (JR-14).
