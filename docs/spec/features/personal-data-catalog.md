# Feature spec: personal-data catalog, compliance role, and the Compliance section's first pages

Status: draft, 2026-09-28. Phase 1 of the GDPR auditor foundation: the
investigation and the design, for approval before anything is built. Not a
rebuild of an upstream feature, so it has no line in SPEC.md §4's table.

## Provenance

Written for the record SPEC.md §3 rule 3 asks for. Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| This repository at `de275ba` (2026-09-28): the code, `resources/schema/schema.json.gz`, `tools/fork/`, `.gitea/workflows/` | AGPL-3.0-only | Every claim in the source map: each row names the code that writes the data |
| inbuxa-admin (the console) at `8e281e5` | AGPL-3.0-only | How navigation, hand-built pages and visibility work |
| docs.inbuxa.org (the inbuxa.org repository at `6b12467`) | Own | What the documentation says, for "Contradictions" |
| `inbuxa-drafts/specs/audit-hold-lock.md`, `legacy-protocols.md` | Own | The Compliance pages that already exist, and the permission-rollout notes |
| Regulation (EU) 2016/679 (GDPR), Articles 5, 25, 30 and 32 | Public law | The shape of a record of processing: categories, whose data, where, how long, who receives it |

No Enterprise-only file or snippet was used. Claims were checked by reading the
code; where a search found nothing, the row says so rather than asserting a
negative.

## What it is

Three things, the foundation for a GDPR auditor:

1. **A personal-data catalog.** Every place the server can store or send
   personal data, with its categories, whose data it is, where it lives, what
   bounds its retention, and the settings that control it. What a particular
   server holds depends on how its operator configured it, so the catalog
   describes *possibilities*; the server evaluates it against live settings to
   say what *this* server does (Phase 3).
2. **A compliance role** that can see and act on compliance data without being
   able to change server settings.
3. **Two console pages** under Compliance: **Overview** and **Data
   inventory**.

The catalog records facts and the auditor reports findings. Neither judges:
nothing in code, docs, UI text or output claims the server meets a legal
standard, or that one is guaranteed. Nothing here changes a default; proposed
changes are listed under [Default profile](#default-profile) for John to
decide.

**Out of scope** (their own specs): retention policies, data subject requests,
the guided questionnaire, jurisdiction packs, mobile and ihasmail screens.
Legal hold and the audit log are built already (audit-hold-lock spec, phases
1–4); this spec places them in the Compliance navigation and gives the
compliance role access to them, nothing more.

## 1. Vocabulary

**Categories** (fixed; a source may have several):

| Category | Means |
|---|---|
| `identifier` | Names, email addresses, account and principal ids, login names |
| `contact` | Phone numbers, postal addresses, vCard details, contact addresses given for an object (an OAuth client's contacts) |
| `network` | IP addresses and ports, client hostnames (EHLO, PTR), user agents, device push URLs |
| `content` | Message bodies, subjects, attachments, events, contacts' cards, files, scripts, free-text descriptions and reasons |
| `metadata` | Timestamps, sizes, flags, envelopes, delivery status, message-ids, counts |
| `credential` | Passwords and their hashes, tokens, keys, secrets |

**Whose** (data subjects): `holder` (the account holder), `correspondent`
(people who send to or receive from the server, and people in contact cards
and events), `administrator` (people acting on the server).

**Where** (location): `data-store`, `blob-store`, `search-store`,
`in-memory-store` (the configured one; the data store by default),
`memory` (process RAM, per node), `log-file`, `external` (sent to an
endpoint). **Leaves the host** is a separate column: a store is local unless
the operator points it at a remote backend.

**Scope**: `tenant` (attributable to a tenant through the account or domain),
`server` (server-wide only).

## 2. Source map

Defaults are those of a new install: the struct defaults, plus what first boot
inserts (`crates/common/src/manager/defaults.rs`). "Unbounded" means no setting
or process removes the data on a schedule.

### 2.1 Mail, groupware and user content

| Source | Categories | Whose | Controlled by | Retention bound | Where / leaves host | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Emails, mailboxes, threads | content, identifier, metadata | holder, correspondent | always on; `x:Email.encryptAtRest`, `x:Email.maxMessages` | unbounded until deleted; Trash emptied after `x:DataRetention.expungeTrashAfter` | data + blob store; leaves when sent | tenant | `email/src/message/ingest.rs` `email_ingest`; `delivery.rs` `deliver_message`; `message/delete.rs` `emails_delete`, `emails_auto_expunge` | collected; Trash 30 d |
| Email submissions | metadata (envelopes) | holder, correspondent | always on | `x:DataRetention.expungeSubmissionsAfter` | data store | tenant | `message/delete.rs` `purge_email_submissions` (purge) | 3 d |
| Full-text index: mail | content, identifier, metadata | holder, correspondent | `x:Search.indexEmail`, `indexEmailFields` | follows the item | search store (external if Elasticsearch/Meilisearch) | tenant | `services/src/task_manager/index.rs` `build_email_document` | indexed, all fields |
| Calendars, events, iTIP | content, identifier, metadata | holder, correspondent | `x:CalendarScheduling.enable`, `httpRsvpEnable`; `x:CalendarAlarm.enable` | unbounded; scheduling inbox `expungeSchedulingInboxAfter`, share notices `expungeShareNotifyAfter` | data + blob store; **iMIP mails event details to external attendees** | tenant | `dav/src/calendar/update.rs`; `jmap/src/calendar_event/set.rs`; `groupware/src/calendar/storage.rs`; `services/src/task_manager/imip.rs` | collected; 30 d / 30 d |
| Contacts, address books | contact, identifier | correspondent, holder | always on | unbounded | data store | tenant | `dav/src/card/update.rs`; `jmap/src/contact/set.rs`; `groupware/src/contact/storage.rs` | collected |
| Full-text index: calendars, contacts | content, contact, identifier | correspondent, holder | `x:Search.indexCalendar`/`Fields`, `indexContacts`/`Fields` | follows the item | search store | tenant | `index.rs` `build_calendar_document`, `build_contact_document` | indexed |
| Files (FileNode, WebDAV) | content, metadata | holder | `x:FileStorage.maxSize`, `maxFiles` | unbounded | data + blob store | tenant | `dav/src/file/update.rs`; `jmap/src/file/set.rs`; `groupware/src/file/storage.rs` | collected |
| Sieve scripts, vacation responses | content | holder (scripts may name correspondents) | user-set | unbounded | data + blob store | tenant | `jmap/src/sieve/set.rs`; `managesieve/src/op/putscript.rs`; `jmap/src/vacation/set.rs` | when set |
| Sieve "seen" ids (vacation, duplicate) | identifier (blake3 hash) | correspondent | used only by scripts that call vacation/duplicate | the script's TTL | in-memory store | tenant | `email/src/sieve/ingest.rs` | when used |
| Identities | identifier, content (signatures) | holder | `x:Email.maxIdentities` | unbounded | data store | tenant | `jmap/src/identity/set.rs` | collected |
| Push subscriptions | network (push URL), credential (keys); **EmailPush can carry email properties to the push URL** | holder | client opt-in; `x:Jmap.maxSubscriptions` | expire within 7 days | data store → **external push service** | tenant | `jmap/src/push/set.rs`; `services/src/state_manager/http.rs` | client-driven |

### 2.2 Records kept by inbuxa's own features

These live in inbuxa's own key space (`SUBSPACE_INBUXA`) unless noted.
`Store::danger_destroy_account` doesn't clear that space, so a row's
"survives account deletion" note matters.

| Source | Categories | Whose | Controlled by | Retention bound | Where | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Archived items (undelete) | content, identifier, metadata | holder, correspondent | `x:DataRetention.archiveDeletedItemsFor`; a legal hold forces keeping | each item's `archivedUntil`; **held: year 9999** | registry (data store) + blob store | tenant | `features/src/undelete/records.rs` `insert`, `set_deadline`, `remove_expired`; `undelete/email.rs` `note`; `groupware/src/inbuxa.rs`; `services/.../index.rs` `archive_noted` | **off** |
| Deleted accounts kept | identifier (name, addresses), **credential (the whole account record, password hashes included)**, metadata | holder | `x:DataRetention.archiveDeletedAccountsFor`; a hold forces keeping | `kept_until`; held: year 9999 | data store | tenant | `jmap/src/inbuxa/deleted_account.rs` `keep`; `features/src/undelete/data.rs` `set_kept_account` | **off** |
| Legal holds | identifier, content (reference, description, reasons) | administrator, holder | `sysLegalHold*` | **unbounded, by design** | data store | server (scope may name tenants) | `features/src/hold/mod.rs` `create`, `update`, `pin_account`, `keep_moved` | none |
| Hold exports: records | identifier, content (reason), metadata | administrator | `sysLegalHoldExport` | **unbounded, by design** | data store | server | `hold/mod.rs` `create_export`, `update_export` | none |
| Hold exports: ZIP | content (everything the hold covers) | holder, correspondent | as above | `x:Jmap.uploadTtl`, then the next blob purge (`blobCleanupSchedule`) | blob store; **leaves when downloaded** | server | `jmap/src/inbuxa/hold_export.rs` `build` → `put_jmap_blob` | 1 h + up to a day |
| Account locks, delegations | identifier, content (reason), metadata | holder, administrator | `sysAccountLock*` | until the lock is removed; **no removal on account deletion found** | data store | tenant | `features/src/lock/mod.rs` `set`, `remove` | none |
| Audit log | identifier, **network (sign-in IPs)**, content (setting diffs, secrets redacted; reasons) | administrator, holder (as target), correspondent (e.g. banned IPs) | always on; `inbuxa:AuditSettings.keepForDays` (not a registry setting) | `keepForDays`, minimum 90; records about held accounts kept while held; **kept after account deletion** | data store (hash-chained) | tenant-filterable | `common/src/audit.rs` `audit_append`, `audit_sign_in`, `audit_sign_in_failed`, `audit_foreign_access`, `audit_delegate`; `jmap/src/inbuxa/audit.rs` `recorded`; purge `audit_purge` | **collected, 730 d** |
| Audit exports | as the audit log | as above | `sysAuditExport` | `x:Jmap.uploadTtl`, then the next blob purge | blob store; leaves when downloaded | server or tenant | `jmap/src/inbuxa/audit_log.rs` `build_export` | 1 h + up to a day |
| Masked addresses | identifier, content (description, site), metadata (last message) | holder | `x:Email.maxMaskedAddresses` | the registry object goes with the account; **the address tombstone is kept forever by design**; its `Mm`/`Mc` records aren't cleared on deletion (search found no clearing) | registry + data store | tenant | `features/src/masked_email/ops.rs`; `data.rs` `set_address`, `set_record`, `log_change` | when used (5 max) |
| Legacy-protocol last use | metadata (one timestamp per account and protocol; no IP) | holder | none | **unbounded; not cleared on account deletion** | data store | tenant | `features/src/security/legacy_use.rs` `record` (from `common/src/network/legacy.rs` `admit_legacy_session`) | **collected** |

### 2.3 Mail transport and reports

| Source | Categories | Whose | Controlled by | Retention bound | Where / leaves host | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Queue (`x:QueuedMessage`) | content, metadata, network (`receivedFromIp`) | holder, correspondent | always on | delivered, or `x:MtaDeliveryExpirationTtl.expire` | data + blob store; delivered out | server | `smtp/src/queue/spool.rs` `queue`, `save_changes`, `remove` | 3 d max |
| DSNs | content (**original headers**), metadata | correspondent, holder | `x:DsnReportSettings` | sent through the queue | **leaves** | server | `smtp/src/queue/dsn.rs` `send_dsn` | on |
| Received DMARC, TLS-RPT, ARF reports | network (source IPs), identifier (envelope/header from); ARF: **message and headers**, original recipient, user agent | correspondent | `x:ReportSettings.inboundReportAddresses`, `inboundReportForwarding` | `x:DataRetention.holdMtaReportsFor` | data store; also forwarded to the mailbox | tenant (by domain) | `smtp/src/reporting/analysis.rs` | collected, 30 d |
| DMARC aggregate reports we send | network (source IPs), identifier (domains) | correspondent | `x:DmarcReportSettings.aggregateSendFrequency`; only to domains publishing `rua` | kept until sent | data store → **external `rua`** | server | `smtp/src/reporting/dmarc.rs` | daily |
| DMARC/SPF/DKIM failure reports we send | content (**raw headers**), network, identifier | correspondent | `x:DmarcReportSettings.failureSendFrequency`, `x:SpfReportSettings`, `x:DkimReportSettings`; only when requested | through the queue | **external `ruf`** | server | `reporting/dmarc.rs` `send_dmarc_report`; `spf.rs`; `dkim.rs` | on, rate-limited |
| TLS-RPT we send | network (remote MX hosts) | operators of other servers | `x:TlsReportSettings.sendFrequency` | until sent (deletion path not confirmed) | **external** | server | `smtp/src/reporting/tls.rs` | daily |
| Relay (smart host) | everything in the message | holder, correspondent | `x:MtaRoute` (Relay) | receiver's | **external** | server | `smtp/src/outbound` | none |
| Milters, MTA hooks | network (client IP, PTR, HELO), identifier (SASL login), **full message** | holder, correspondent | `x:MtaMilter`, `x:MtaHook` | receiver's | **external** | server | `smtp/src/inbound/milter`, `inbound/hooks/mod.rs` | none |

### 2.4 Telemetry and logs

| Source | Categories | Whose | Controlled by | Retention bound | Where / leaves host | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Stored traces (`x:Trace`) | network (IP, EHLO), identifier (envelope addresses, account names), metadata (message-ids, results) | correspondent, holder | `x:TracingStore`; `x:EventTracingLevel` | `x:DataRetention.holdTracesFor` (unset = unbounded) | data store, or a remote PostgreSQL/MySQL/FDB | server (records name accounts) | `common/src/telemetry/tracers/store.rs` `spawn_store_tracer`; purge `purge_spans` | **collected** (first boot inserts `TracingStore::Default` although the struct default is off); 30 d |
| Trace search index | same keywords, lowercased | as above | `x:Search.indexTelemetry`, `indexTracingFields` | purged with the traces | search store | server | `index.rs` `trace_search_document` | indexed |
| Stored metrics | none personal (aggregates) | — | `x:MetricsStore`, `x:Metrics` | `holdMetricsFor` | data store | server | `telemetry/metrics/store.rs` | collected, 90 d |
| Log file | network (**client IP on every in-session line**, from the span), identifier (MAIL FROM, RCPT TO, account names), metadata (message-ids). No subject key exists; bodies only in trace-level raw-I/O events | correspondent, holder, administrator | `x:TracerLog` (`level`, `events`, `path`, `rotate`) | **unbounded: rotated daily, never deleted** | log file (`/var/log/inbuxa`); read back as `x:Log` and fed to Explain | server | `common/src/telemetry/tracers/log.rs` | **collected, info level** |
| Console / journald tracers | as the log file | as above | `x:Tracer` Stdout/Journal | the host's journal policy | stdout / journald (leaves only if the host forwards it) | server | `tracers/stdout.rs`, `journald.rs` | none (recovery mode adds a console tracer) |
| OpenTelemetry tracer | as the log file, every event and span key | as above | `x:Tracer` OtelHttp/OtelGrpc (`level`, `events`, `endpoint`) | receiver's | **external** | server | `tracers/otel.rs` | none |
| Webhooks | as the log file; **can include raw SMTP input (message content) and model replies** — see [Findings](#findings) 1 | as above | `x:WebHook` (`events`, `eventsPolicy`, `url`) | receiver's; retried up to `discardAfter` | **external** | server | `telemetry/webhooks/mod.rs` `post_webhook_events` | none |
| Alerts | contact (the addresses an administrator sets) | administrator | `x:Alert` | as mail | mail; may leave | server | `telemetry/alerts.rs` | none |
| Failed tasks | identifier (account names, e.g. a failed account destroy), content (iTIP messages) | holder, correspondent | none | **not confirmed: failed tasks are rescheduled at `u64::MAX` and no purge was found** | data store | server | `services/src/task_manager/manager.rs` | when a task fails |

### 2.5 Sign-in and network defence

| Source | Categories | Whose | Controlled by | Retention bound | Where | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Accounts, groups, lists, domains, tenants (registry) | identifier, contact, metadata | holder | registry | the object's life | data store | tenant | registry writes (`jmap/src/registry/`) | — |
| Passwords, app passwords, API keys | credential (argon2id hashes), network (`allowedIps`), metadata | holder | `x:Authentication.passwordHashAlgorithm`; `maxAppPasswords`, `maxApiKeys`; `expiresAt` | the account's life or `expiresAt` | data store | tenant | `jmap/src/registry/mapping/account.rs` | — |
| OAuth clients | identifier, contact (`contacts`), credential (secret hash) | administrator, third-party developer | `x:OidcProvider.requireClientRegistration` | `expiresAt` or unbounded | data store | tenant | `http/src/auth/oauth/registration.rs` | none |
| OAuth codes and tokens | credential | holder | `x:OidcProvider.*Expiry` | tokens are sealed and stateless (not stored); codes in the in-memory store with TTL | in-memory store | tenant | `http/src/auth/oauth/auth.rs`, `token.rs` | codes 10 min |
| Rate-limit state | network, identifier (login names) | holder, correspondent | `x:Http.rateLimit*`, `x:Imap.maxRequestRate`, `x:Security.*BanRate` | the rate's period | in-memory store | server | `common/src/auth/rate_limit.rs`, `network/security.rs` | on |
| Greylist | identifier (sender/recipient pairs, plain) | correspondent, holder | `x:SpamSettings.greylistFor` | that period | in-memory store | server | `smtp/src/inbound/rcpt.rs` | **off** |
| Automatic IP bans (`x:BlockedIp`) | network | correspondent, holder | `x:Security.authBanRate`, `abuseBanRate`, `loiterBanRate`, `scanBanRate` (on); `*BanPeriod` (**no default**) | **unbounded: a ban with no period never expires, and no purge of expired bans was found**; each ban is also an audit record | data store (registry) | server | `common/src/network/security.rs` `block_ip` | **collected, permanent** |
| Allowed IPs | network | administrator's choice | manual; `expiresAt` | optional | data store | server | registry | none |

### 2.6 Spam filter and AI

| Source | Categories | Whose | Controlled by | Retention bound | Where / leaves host | Scope | Written by | Default |
|---|---|---|---|---|---|---|---|---|
| Training samples (`x:SpamTrainingSample`) | content (**the whole message, pinned**), identifier (`from`), content (`subject`) | correspondent, holder | `x:SpamClassifier.model`, `learnSpamFromTraps`, `learnSpamFromRblHits`, `learnHamFromCard`, `learnHamFromReply`; users' Junk moves | `x:SpamClassifier.holdSamplesFor`; **outlives the user deleting the mail** | data + blob store | tenant for users' samples; **server, unattributed, for SMTP autolearn** | `email/src/message/ingest.rs` `add_spam_sample`; `smtp/src/queue/spool.rs` | **collected, 180 d** |
| Trainer state (`INBUXA_SPAM_TRAIN_DATA`) | metadata (blob hashes with account ids; hashed tokens that include addresses and domains) | correspondent, holder | as above | **unbounded (overwritten on training, never expired)** | blob store | server | `spam-filter/src/modules/classifier.rs` `spam_train` | after 100 + 100 samples |
| Trained model | hashed weights, not directly personal | — | as above | unbounded | blob store | server | same | same |
| AI spam classification | content (subject + up to `inbuxa:AiLimits.maxContentBytes` of text) | correspondent | `x:SpamLlm`, `x:AiModel` (`url`), `inbuxa:AiLimits` | the endpoint's; the verdict is written into the stored message | **external endpoint** (local or hosted; a remote URL only warns) | server | `spam-filter/src/analysis/llm.rs`; `common/src/enterprise/llm.rs` | **off** |
| Sieve `llm_prompt` | whatever a script sends | any | `x:AiModel`; `interactAi` | endpoint's | **external** | per account | `enterprise/llm.rs` `sieve_prompt` | no model |
| Explain | identifier (return path, recipients), network (trace IPs), metadata (remote replies, log details); never contents or raw I/O | correspondent, holder | `inbuxa:AiLimits.explainEnabled`, `explainModelId` | answer cache: memory, per node, 24 h, 1000 answers | **external endpoint** + memory | server | `jmap/src/inbuxa/explanation.rs`; `features/src/ai/explain/memory.rs` | no model |
| DNSBL lookups | network (client IPs), identifier (domains; **SHA-1 of addresses** to msbl.org), metadata (MD5 of URLs) | correspondent | bundled `x:SpamDnsblServer` rules; `x:SpamDnsblSettings` | receiver's | **external (DNS)** | server | spam-filter DNSBL module | **on: 17 of 18 bundled lists** |
| Pyzor | content (SHA-1 digest of normalized body) | correspondent | `x:SpamPyzor` | receiver's | **external: `public.pyzor.org`** | server | `spam-filter/src/modules/pyzor.rs` | **on** |
| URL-shortener expansion | network (fetches links, which can carry per-recipient tracking tokens) | correspondent, holder | bundled redirector list | — | **external (HTTP)** | server | `spam-filter/src/analysis/url.rs` | **on** |

### 2.7 Stores and directories an operator can point elsewhere

| Registry object | Receives | Default |
|---|---|---|
| `x:DataStore` | everything above that says data store | RocksDB, local |
| `x:BlobStore` (S3, Azure, FS, SQL, FDB) | message bodies, attachments, files, samples, exports | the data store |
| `x:SearchStore` (Elasticsearch, Meilisearch, SQL, FDB) | full text of mail, contacts, calendars; trace keywords | the data store |
| `x:InMemoryStore` (Redis) | rate limits, greylist, OAuth codes, Sieve seen ids | the data store |
| `x:TracingStore`, `x:MetricsStore` | traces, metrics | the data store |
| `x:Coordinator` (Kafka, NATS, Zenoh, Redis) | cluster broadcasts (whether personal: not confirmed) | off |
| `x:Directory` (LDAP, SQL, OIDC) | login names, passwords to verify, address lookups | internal |
| `x:AcmeProvider`, `x:DnsServer` | hostnames, a role address; no personal data found | Let's Encrypt if chosen; manual DNS |

## Findings

Facts from the investigation that matter beyond the catalog. Each is a finding,
not a judgment; what to do about each is John's call.

1. **A webhook ignores levels and, left at its defaults, receives every
   event, message content included.** `config/telemetry.rs` builds a webhook's
   interests with `apply_events` alone: no level check. With the default
   `eventsPolicy` (exclude) and no events listed, that is every event type,
   including trace-level `smtp.raw-input` (the raw SMTP bytes, `DATA`
   included) and `ai.llm-response`. The audit-log docs suggest a webhook to
   pass records to a SIEM. Probably upstream behavior; not yet checked
   against upstream.
2. **Log files are never deleted.** Daily rotation opens a new file; nothing
   removes old ones, and no logrotate configuration ships. At the default
   level every in-session line carries the client IP.
3. **Automatic IP bans are permanent.** No `*BanPeriod` has a default, and no
   purge of expired `x:BlockedIp` records was found.
4. **Some records outlive the account.** Deleting an account doesn't clear
   inbuxa's own key space: legacy-protocol last use, account locks, masked
   address records and audit records stay (audit records by design).
5. **A kept deleted account keeps its password hashes** for
   `archiveDeletedAccountsFor`, or indefinitely under a legal hold.
6. **Spam training keeps whole messages for 180 days**, after the user
   deleted them, and SMTP autolearn keeps them with no account attribution, so
   they can't be found by person. The trainer state never expires.
7. **Traces are on in a new install** although the struct default says off:
   first boot inserts the tracing and metrics stores.
8. **Data leaves the host by default** through the spam filter (DNSBL queries
   with IPs, domains and hashed addresses to 17 lists; Pyzor body digests;
   shortener URL fetches) and through reports (DMARC aggregate daily; failure
   reports with headers where requested). No AI, webhook, OpenTelemetry,
   milter, hook or relay endpoint is configured by default.
9. **Export files outlive their stated lifetime by up to a day.** The link
   expires with `uploadTtl`; the bytes stay until the next blob purge
   (04:00 daily).
10. **Failed tasks may stay forever** (rescheduled at `u64::MAX`; no purge
    found), holding account names or iTIP messages. Not confirmed by a test.

## 3. How the schema is produced, and what the catalog works from

The prompt says not to hand-edit generated files and to work from the source
of truth. What the investigation found:

- **`resources/schema/schema.json.gz` and the registry Rust code
  (`crates/registry/src/schema/*.rs`, headed "auto-generated") come from
  upstream's generator, which isn't in this repository or upstream's public
  tree.** Nothing here regenerates them.
- **The fork edits both by hand.** Since the v0.16.22 import the gz has
  changed in 18 commits: the Compliance layout (Audit Log, Legal Holds, Locked
  Accounts), the Local AI and Legacy Protocols pages, the fork's permissions
  (`sysAudit*`, `sysAccountLock*`, `sysLegalHold*`, `sysAiExplain`), always
  paired with `enums.rs`/`enums_impl.rs` edits marked `// inbuxa:`. Scripted
  edits go through `tools/fork/renames.py` (`schema_bytes`), which writes the gz
  with `gzip.compress(compresslevel=9, mtime=0)` and the `.sha256` sidecar as
  unpadded URL-safe base64 of the gz's SHA-256.
- **`/api/schema`** (`crates/http/src/api/mod.rs`, `"schema"` arm) serves the
  embedded gz as-is to any authenticated caller, unfiltered; the console
  hides what a person can't use from the permission list `/api/account`
  returns.
- **The schema carries 150 objects and 2,102 properties** (316 field
  schemas). About 34 objects hold data about people, roughly 150–180
  properties counting nested structs; about 20 configuration objects carry
  about 100 credential or contact properties. inbuxa's own objects
  (`inbuxa:AuditEvent`, `LegalHold`, `HoldExport`, `AccountLock`,
  `DeletedAccount`, `ProtocolPolicy`, `TenantProtocolPolicy`,
  `Explanation`, `AiLimits`, Fastmail `MaskedEmail`) aren't in the schema
  at all: they are defined in `crates/jmap-proto/src/object/inbuxa_*.rs`.

So the source of truth for *what exists* is the schema (for registry objects)
and `jmap-proto` (for inbuxa's own). Neither should carry the catalog:
**Decision proposed:** the catalog is a sidecar, and the schema and generated
code are read, never annotated, by it. The fork's existing hand edits to the
schema (layout entries, permissions) continue as today for the Compliance
pages and the new permissions, because the console's navigation comes from
the schema and there is no other way in; each is marked in the commit and
listed in the strip report as now.

## 4. The catalog: format and location

**Location:** `resources/privacy/catalog.toml`, a fork-owned file. The server
embeds it (`include_str!`) and parses it at start, as it does the schema.

**Why a sidecar** rather than annotating in place:

- The schema and registry code are upstream's generated output; annotations
  there are overwritten or conflict on every import (SPEC.md §2.2, §2.3).
- Many sources aren't registry objects: log files, telemetry exporters,
  inbuxa's key-space records, DNSBL and Pyzor, the in-memory cache. An
  in-place annotation has nowhere to put them.
- One file is one diff to review when an import brings new fields, and it is
  what the CI check and the strip report read.

**Shape.** Three kinds of entry:

```toml
# A registry object: a default for its properties, and the ones that differ.
[object."x:Account"]
default = "none"                  # properties not listed hold no personal data
whose = ["holder"]
where = ["data-store"]
scope = "tenant"
retention = "object-life"
[object."x:Account".properties]
name = ["identifier"]
emailAddress = ["identifier"]
aliases = ["identifier"]
description = ["content"]
credentials = ["credential", "network"]   # secrets, allowedIps
locale = ["metadata"]

# One of inbuxa's own JMAP objects (not in the schema).
[object."inbuxa:AuditEvent"]
default = "none"
whose = ["administrator", "holder", "correspondent"]
where = ["data-store"]
scope = "tenant"
retention = { setting = "inbuxa:AuditSettings.keepForDays" }
[object."inbuxa:AuditEvent".properties]
actor = ["identifier"]
remoteIp = ["network"]
changes = ["content"]
reason = ["content"]

# A source that is no object: files, exporters, lookups, caches.
[source."log-file"]
categories = ["network", "identifier", "metadata"]
whose = ["correspondent", "holder", "administrator"]
where = ["log-file"]
scope = "server"
enabled_by = ["x:TracerLog.enable"]
captures = ["x:TracerLog.level", "x:TracerLog.events", "x:EventTracingLevel"]
retention = "unbounded"
leaves_host = false
written_by = ["crates/common/src/telemetry/tracers/log.rs"]

[source."spam-dnsbl"]
categories = ["network", "identifier", "metadata"]
whose = ["correspondent"]
where = ["external"]
scope = "server"
enabled_by = ["x:SpamDnsblServer.enable"]
retention = "receiver"
leaves_host = true
written_by = ["crates/spam-filter/src/modules/dnsbl.rs"]
```

Rules: `retention` is `unbounded`, `object-life`, `receiver` (it left the
host), or `{ setting = "<object>.<property>" }`; every setting named is a real
`x:` or `inbuxa:` property. Every object in the schema and every `inbuxa:`
object has an entry, even if only `default = "none"` (configuration objects
with nothing personal). The file holds facts only: no wording about legal
status.

**Evaluation (Phase 3).** Each entry's `enabled_by`, `retention` and
`leaves_host` are evaluated against the live registry: a store pointed at a
remote backend makes everything in it `leaves_host = true`; an unset
retention setting reads `unbounded`; an external endpoint lists its URL's
host as a candidate processor.

## 5. The CI check

`tools/fork/privacy-check.py`, modeled on `name-check.py` and
`notice-check.py` (plain Python, no dependencies, exit 1 on findings). Wired
into the `fork-checks` job in `.gitea/workflows/ci.yml`, beside them. It fails
when:

1. an object in `schema.json.gz` `fields`, or an `inbuxa:` object in
   `crates/jmap-proto/src/object/`, has no catalog entry;
2. a property whose schema format is `emailAddress`, `ipAddress`,
   `ipNetwork`, `secret`/`secretText`, or whose type is `x:SecretKey*` or
   `x:HttpAuth`, is covered only by an object's `default = "none"` — those
   must be classified explicitly, so a new personal field can't hide behind a
   default;
3. an entry names an object, property or setting that no longer exists
   (stale);
4. an entry uses a category, subject or location outside the vocabulary.

`tools/fork/strip.py` gains `privacy_flags(tree)`, beside `schema_flags`:
objects and properties new in an import and not in the catalog, reported in
`STRIP-REPORT.md` under "Unclassified in the privacy catalog", the way
Enterprise flags are reported. Informational, as the Enterprise list is; CI
is what fails.

Tests (Phase 2): the check passes on main; fails on a synthetic unclassified
field; fails on a synthetic `emailAddress` property covered only by a
default; fails on a stale entry.

## Default profile

**Today's defaults in a new install** that collect or send personal data:

| Source | Collected | Retention |
|---|---|---|
| Traces + trace index | yes | 30 days |
| Log file | yes, info level | **unbounded** |
| Audit log | yes | 730 days |
| Spam training samples (whole messages) | yes | 180 days |
| Spam trainer state | yes, after 200 samples | **unbounded** |
| Automatic IP bans | yes | **unbounded** |
| Legacy-protocol last use | yes | **unbounded** |
| Received DMARC/TLS/ARF reports | yes | 30 days |
| DNSBL lookups (17 lists), Pyzor, URL-shortener fetches | yes | leave the host |
| Outbound DMARC aggregate and failure reports | yes, where the domain asks | leave the host |
| Trash | yes | 30 days |
| Undelete, deleted-account keeping | **off** | — |
| AI classification, Explain | **off** (no model) | — |
| Greylisting | **off** | — |

**Proposed changes, new installs only**, each for John to decide. None is
made by this spec.

| # | Change | Trade-off |
|---|---|---|
| D1 | A **log retention** setting on `x:TracerLog` (delete rotated files older than N days), default 30 days for new installs | Needs code (a new field, so a schema edit); older logs gone for troubleshooting; operators wanting longer set it |
| D2 | A default **ban period**, e.g. 30 days, for the four ban rates, and a purge of expired `x:BlockedIp` | A persistent attacker is re-banned after expiry rather than kept out; permanent bans of shared/NAT addresses stop being permanent |
| D3 | **Spam sample retention** 180 → 90 days | Fewer samples to retrain from; the classifier is retrained regularly, so the effect on accuracy is likely small (not measured) |
| D4 | **Pyzor off** by default | One fewer spam signal; no body digests leave the host |
| D5 | **msbl.org EBL off** by default (the list that receives hashed addresses) | One fewer signal on address-based spam; no hashed addresses leave the host |
| D6 | **Trace retention** 30 → 14 days | Shorter delivery history in **Emails › History** and for support |
| D7 | Webhooks default to `eventsPolicy = include` with no events, and never receive raw-I/O events unless listed by name | A webhook does nothing until events are chosen; closes finding 1 |

Separately, **not defaults but gaps** a later spec should close (listed so
they aren't lost): clearing inbuxa's own records on account deletion
(finding 4); an expiry for the spam trainer state; a purge for failed tasks
(finding 10, once confirmed); removing export blobs when their link expires
(finding 9).

## 6. The inventory, over JMAP (Phase 3)

Under `urn:inbuxa:jmap`, read-only.

### `inbuxa:DataInventory/get`

A singleton, evaluated on request.

Request: `{ accountId, ids: null | ["singleton"], properties? }`.

Response `list[0]`:

```json
{
  "id": "singleton",
  "evaluatedAt": "2026-09-28T10:00:00Z",
  "catalogVersion": "2026.9.28.3",
  "sources": [
    {
      "id": "log-file",
      "kind": "source",
      "categories": ["network", "identifier", "metadata"],
      "whose": ["correspondent", "holder", "administrator"],
      "where": ["log-file"],
      "collected": true,
      "retention": { "unbounded": true },
      "leavesHost": false,
      "scope": "server",
      "controlledBy": ["x:TracerLog.enable", "x:TracerLog.level"],
      "endpoints": []
    },
    {
      "id": "x:Trace",
      "kind": "object",
      "categories": ["network", "identifier", "metadata"],
      "collected": true,
      "retention": { "days": 30, "setting": "x:DataRetention.holdTracesFor" },
      "leavesHost": false,
      "scope": "server",
      "endpoints": []
    }
  ],
  "processors": [
    { "host": "public.pyzor.org", "receives": ["content"], "sources": ["spam-pyzor"] }
  ]
}
```

`collected` is false when the source's switch is off; `retention` reads the
live setting; `leavesHost` is true when the source's location is a remote
store or an external endpoint; `processors` lists each external host once,
with what it receives — candidates, since whether a host is a processor in
law is the operator's determination.

**Permission:** `sysComplianceGet`. **Tenant scoping:** inside a tenant,
`sources` holds only `scope = "tenant"` entries, evaluated with the tenant's
own settings where it has them (its protocol switches, its domains' stores
are the server's); server-scope sources and `processors` are left out, because
they describe the whole server. A tenant principal without the permission gets
`forbidden`.

### `inbuxa:InventorySnapshot/get`, `/query`

A dated copy of the evaluated inventory, taken when a setting the catalog
references changes (hooked where the audit log already sees registry writes)
and at most once a day otherwise. `query` filters by `after`/`before`,
newest first. Fields: `id`, `takenAt`, `trigger` (`setting-changed` with the
setting, or `daily`), `summary` (counts: sources collected, unbounded,
leaving the host, processors), and on `get` the full inventory as above.
Kept for `inbuxa:AuditSettings.keepForDays`, so history is as long as the
audit log's. Same permission and tenant scoping as the inventory.

## 7. The compliance role

### What it holds

A new built-in role, **Compliance Officer**, at server level:

| Permission | New? | Gives |
|---|---|---|
| `sysComplianceGet` | new | Overview, Data inventory, snapshots |
| `sysAuditGet`, `sysAuditExport` | existing | read and export the audit log, verify the chain |
| `sysLegalHoldGet`, `sysLegalHoldCreate`, `sysLegalHoldUpdate`, `sysLegalHoldExport` | existing | place, widen, release and export holds |
| `sysAccountLockGet` | existing | see locks and delegations |
| read (`*Get`, `*Query`) on accounts, groups, lists, domains, tenants, roles | existing | know who and what the records refer to |

It holds **no** `*Create`/`*Update`/`*Destroy` on registry objects, no
`sysAuditSettingsUpdate`, no `impersonate`, no `fetchAnyBlob`. It can't
change a server setting.

**Decision proposed on holds:** the officer *places and releases* holds,
because that is the job; every placing, widening and release is already
recorded with its reason, under the officer's own identity (AU-12), and a
release can't be undone silently (LH-10). If John prefers holds to need a
server administrator, drop Create/Update from the role.

A **Tenant Compliance Officer** variant (inside a tenant: `sysComplianceGet`,
`sysAuditGet`, `sysAuditExport`, `sysAccountLockGet`, reads) is proposed
for later, since legal holds are server-only by the tenant ceiling (LH-13).
Open question 3.

### Reaching existing servers

New permissions get ids 673 onward and `COUNT` grows (`enums.rs`,
`enums_impl.rs`, and the schema's `Permission` enum, a marked hand edit as
before). `DefaultPermissions` places `sysComplianceGet` with superusers;
`granted_permissions.rs` `ADMIN_GRANTS` adds it once to stored administrator
roles, as it did for the audit and hold permissions. The **role object**
itself is seeded only on a fresh install (`defaults.rs`, `count == 0`); for
existing servers a one-time step modeled on `granted_permissions.rs` creates
it once, recorded so that deleting it sticks. That step is new code.

### Keeping administrators reviewable

What already holds: every administrator's change to the registry and to
inbuxa's own objects is recorded before it is allowed, under their identity,
with a reason where required; sign-ins by anyone holding `sys*` permissions
are recorded; records can't be deleted over JMAP; the chain is verifiable;
changing retention is itself recorded.

What this adds: the compliance officer reads all of it, server administrators'
actions included, without being an administrator. The Overview (§8) puts on
top anything that weakens review: audit retention shortened, a tracer or the
audit export webhook removed, a change to who holds the compliance or
administrator roles, a hold released — each with who and when.

What remains open: a server administrator can still shorten audit retention
to 90 days (recorded, and now surfaced), and anyone with shell access can edit
the store directly. Open question 4.

## 8. The Compliance section in the console

The navigation comes from the schema's `layouts` (`/api/schema`); a
hand-built page is a `CustomComponent/<Name>` link there, a render branch in
`MainContent.tsx`, and a visibility rule in `layout.ts` `checkSpecialLink`.
The section shows when at least one of its pages is visible to the person
(Phase 4 confirms the container behaves so with every child hidden).

Planned navigation, in order:

| Page | This task | Built as | Visible with |
|---|---|---|---|
| **Overview** | **builds** | hand-built (`CustomComponent/ComplianceOverview`) | `sysComplianceGet` |
| **Data inventory** | **builds** | hand-built (`CustomComponent/DataInventory`) | `sysComplianceGet` |
| Retention | later spec | likely hand-built over `x:DataRetention`, `x:SpamClassifier`, `x:TracerLog` and `inbuxa:AuditSettings`, since they're spread across objects | — |
| Legal holds | exists | hand-built | `sysLegalHoldGet` |
| Audit log | exists | hand-built | `sysAuditGet` |
| Locked accounts | exists | hand-built | `sysAccountLockGet` |
| Data subject requests | later spec | hand-built | — |
| Records and documents | later spec | could be schema-driven if it becomes a registry object | — |
| Jurisdiction packs | later spec | hand-built | — |

**Decision proposed:** later pages are left out of the navigation until
built, not shown disabled: a disabled entry reads as a feature that exists.

**Overview** shows the latest snapshot's findings as facts ("Log files are
kept with no limit", "Sent to a host outside this network: public.pyzor.org"),
the review items from §7, and the snapshot history (when and why the inventory
changed). **Data inventory** lists the evaluated sources, filterable by
source, category and location, with each external endpoint listed as a
candidate processor. UI text states facts and never claims a legal standard is met.

## Contradictions with the docs and SPEC.md

1. **docs, Security › "What the AI features do and do not send":** "message
   content is never written to the logs". True at the default level. The
   model's reply to the spam classifier is logged as `ai.llm-response` at
   trace level (up to 1,024 characters, which can restate the message), so a
   trace-level tracer writes it, and any webhook at its defaults receives it,
   along with raw SMTP input (finding 1).
2. **docs, Audit log:** suggests a webhook to pass records to a SIEM, without
   saying a webhook's `level` is ignored and its default policy sends every
   event.
3. **docs, Monitoring:** "rotated daily" is right, but doesn't say old files
   are never removed (finding 2). Not strictly a contradiction; an omission
   that matters here.
4. **SPEC.md §2.3** calls `schema.json.gz` upstream's published schema and
   the checklist for rebuilt features. It doesn't say the fork now hand-edits
   it (layout, permissions); §2.2's strip step would overwrite those edits on
   an import unless they're re-applied. Worth a sentence in SPEC.md.
5. **The schema's `TracingStore`/`MetricsStore` defaults** say disabled; first
   boot turns both on. The docs describe the real behavior; the schema default
   (what the console shows as the default) doesn't.

The rest checked out: tracing 30 days, metrics 90 days, the Explain cache (in
memory, a day), audit retention (two years, minimum 90), undelete off by
default.

## Open questions for John

1. **The catalog's home and the schema edits.** Sidecar `catalog.toml` as
   proposed, with the Compliance pages and new permission added to the schema
   by hand as the audit and hold work did — or something else?
2. **Holds in the compliance role.** Can the officer place and release holds,
   or only see and export them?
3. **A tenant compliance role** now, or after data subject requests?
4. **Audit retention floor.** Should shortening audit retention need a second
   person, or is recording and surfacing it enough?
5. **Defaults D1–D7.** Which, if any, for new installs?
6. **Finding 1 (webhooks).** Fix now as a bug, separately from this work, or
   wait for D7?
7. **Snapshots:** kept as long as the audit log, as proposed, or their own
   setting?

## Phases

1. **This spec.** Stop for approval.
2. **The catalog and its check:** `resources/privacy/catalog.toml`,
   `tools/fork/privacy-check.py` in `fork-checks`, the strip report section,
   and the tests in §5.
3. **Server:** `sysComplianceGet` and the role (with the existing-server
   step), `inbuxa:DataInventory`, `inbuxa:InventorySnapshot`, tests with
   several configurations (defaults, a remote store, a hosted AI endpoint,
   telemetry off), tenant scoping, refusal without the permission.
4. **Console:** Overview and Data inventory, the navigation entries, a PR
   linking this spec.
