# Feature spec: monitoring history, live tracing and alerts

Status: draft, 2026-09-18. Feature 6 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `crates/registry/src/schema/*.rs` and `resources/schema/schema.json.gz` (objects, fields, defaults, enums, permissions, lists, forms, the `dashboards` and `layouts` sections), upstream `v0.16.22` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Object shapes, field meanings, defaults, what upstream flags as Enterprise, the admin views and dashboards the server has to feed |
| The AGPL telemetry code left after the strip: `crates/common/src/telemetry/`, `crates/common/src/config/telemetry.rs`, `crates/trc` (event, key and metric definitions, the collector, span tracking, the JSON serializer), `crates/http/src/api/mod.rs` and `diagnose.rs`, `crates/store` key layout, `crates/services/src/task_manager/`, `crates/common/src/auth/permissions.rs`, `crates/common/src/expr/`, `crates/common/src/manager/defaults.rs`, `crates/jmap/src/registry/` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | What already exists and must be kept: webhooks, exporters, the `metric()` expression function, span ids, storage subspaces, route and token names, default permissions |
| The integration suites `tests/src/telemetry/*.rs` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Tested behavior of alerts, metrics history, trace history and webhooks |
| The strip report, `docs/fork/strip-reports/v0.16.22.json` | This repository | Which files and snippets were removed, so which behavior is missing |
| Stalwart documentation (`website` repo): `docs/telemetry/{index,alerts,history,live,management,webhooks}.md`, `docs/0.15/telemetry/{alerts,live,history}.md`, `docs/ref/object/{trace,metric,log,alert,metrics-store}.md`, blog post "Announcing Dashboards" (0.9.3) | Unlicensed public documentation: facts used, prose not copied | Retention defaults, alert semantics, the live endpoints' parameters, which parts are Enterprise |
| ihasmail's admin dashboard (`web/src/lib/admin/adminDashboard.ts`, `adminAccess.ts`) | AGPL-3.0, ours | `x:Metric` query behavior as observed against INBUXA's live Enterprise server when ihasmail was built |
| RFC 8620, RFC 5322, RFC 3834 | IETF | JMAP semantics; the alert message format |

No Enterprise-only file or snippet was used. The drafting session never saw
Enterprise code. It writes specs only. Gaps are marked **Decision** or listed
under "Open questions / to observe", never filled from memory of upstream code.

## What it is

Three things an operator uses to see what the server is doing:

- **History.** The server keeps a record of every message delivery (a
  *trace*: the inbound SMTP session or the outbound delivery attempt, with its
  events) and a periodic sample of its metrics. Both are kept for a set
  period, searchable, and drawn by the dashboards.
- **Live telemetry.** An administrator watches events and metrics as they
  happen, filtered, in INBUXA Admin.
- **Alerts.** Rules over metrics that send an email, raise an event (which a
  webhook can forward), or both, when a threshold is crossed.

Upstream ships these only in its Enterprise Edition. inbuxa-server ships them
to everybody. Webhooks, the log tracers, OpenTelemetry and Prometheus export
and the `x:Log` view are already AGPL and aren't part of this rebuild, except
where noted.

## Data model

Registry objects are unchanged from upstream, so INBUXA's existing settings
open as they are (SPEC.md §7). The upstream schema flags as Enterprise:
objects `x:Alert`, `x:MetricsStore`, `x:Trace`, `x:TracingStore`; fields
`x:DataRetention.holdMetricsFor`, `holdTracesFor`, `metricsCollectionInterval`,
`x:Search.indexTelemetry`, `indexTracingFields`. In inbuxa-server they're
ordinary.

### Settings

| Where | Field | Default | Meaning |
|---|---|---|---|
| `x:TracingStore` (singleton) | `@type` | schema `Disabled`; first boot inserts `Default` | `Disabled`: no trace history. `Default`: the data store. `FoundationDb`, `PostgreSql`, `MySql`: a store of its own |
| `x:MetricsStore` (singleton) | `@type` | as above | The same, for metric history |
| `x:DataRetention` | `holdTracesFor` | 30 days | Duration, nullable. How long a trace is kept |
| | `holdMetricsFor` | 90 days | Duration, nullable. How long a metric sample is kept |
| | `metricsCollectionInterval` | hourly, minute 0 | `x:Cron`: `Hourly`, `Daily` or `Weekly`. When metric history is sampled |
| `x:Search` | `indexTelemetry` | true | Whether traces are added to the search index |
| | `indexTracingFields` | `eventType`, `queueId`, `keywords` | Which trace fields are indexed |
| `x:Metrics` | `metrics`, `metricsPolicy` | all (`exclude`, empty list) | Which metrics are collected. Already AGPL, shared with the exporters |

Clean-up of expired history runs on the existing `dataCleanupSchedule`.

### The alert, `x:Alert`

| Field | Meaning |
|---|---|
| `enable` | Boolean, default true |
| `condition` | `x:Expression` (`match` list and `else`). The alert fires when it evaluates true |
| `eventAlert` | `Disabled`, or `Enabled` with `eventMessage` (text, nullable) |
| `emailAlert` | `Disabled`, or `Enabled` with `fromName` (nullable), `fromAddress`, `to` (a set of one or more addresses), `subject`, `body` |

### The trace, `x:Trace` (read-only)

`events`: a list of `x:TraceEvent`, each with `event` (an `EventType`),
`timestamp`, and `keyValues`: a list of `key` (a `Key`) and `value` (a
`TraceValue`: `String`, `UnsignedInt`, `Integer`, `Boolean`, `Float`,
`UTCDateTime`, `Duration`, `IpAddr`, `List`, `Event`, `Null`). Server-set:
`timestamp`, `from`, `to` (a string), `size`. Views: `x:Trace/InboundDelivery`
and `x:Trace/OutboundDelivery`.

### The metric sample, `x:Metric` (read-only)

Three variants by `@type`: `Counter` and `Gauge` (`metric`, `count`,
`timestamp`) and `Histogram` (`metric`, `count`, `sum`, `timestamp`).
`metric` is a `MetricType` (369 values at `v0.16.22`).

### The index task, `x:TaskIndexTrace`

`traceId`, `status`, `due`. Task type `IndexTrace`, permission
`taskIndexTrace`. Store maintenance type `reindexTelemetry` rebuilds the
trace index. Both already exist in AGPL code.

### Permissions

`sysAlert{Get,Query,Create,Update,Destroy}`, `sysTrace{Get,Query,Create,Update,Destroy}`,
`sysMetric{Get,Query,Create,Update,Destroy}`, `sysTracingStore{Get,Update}`,
`sysMetricsStore{Get,Update}`, `sysDataRetention{Get,Update}`, `liveTracing`,
`liveMetrics`, `taskIndexTrace`. The AGPL default-permission table gives all
of these to the superuser set only: not to tenant administrators and not to
users (`crates/common/src/auth/permissions.rs`).

### Storage

The AGPL store layout is kept: traces in subspace `o`
(`SUBSPACE_TELEMETRY_SPAN`), metric samples in subspace `x`
(`SUBSPACE_TELEMETRY_METRIC`), each keyed by a big-endian `u64` id. A trace's
id is its span id, which the server already assigns from its snowflake
generator (milliseconds since an epoch in the high bits), so key order is time
order. The trace search index is `SearchIndex::Tracing`, with fields
`EventType`, `QueueId` and `Keywords`.

**Existing data at cutover, Decision** (revised 2026-09-19). Traces and
samples are stored under the AGPL telemetry key classes the surviving code
reads (`TelemetryClass::Span` and `TelemetryClass::Metric`, used by
`reindex_telemetry` and the index task), each value encoded as the matching
registry object (`x:Trace`, `x:Metric`) with the registry's own AGPL encoding,
so no new format is invented. INBUXA's existing history sits under the same
keys but in the encoding the strip removed (`trc/src/serializers/binary.rs`),
so it can't be read. Records that can't be decoded are skipped, never an
error, and are removed by the normal age purge (MON-17), so INBUXA's old
history ages out within 30 and 90 days. At cutover, run `reindexTelemetry`
once so the search index holds only readable traces. Settings, alerts and every other registry object open
unchanged.

## Required behavior

### Switches and defaults

- **MON-1.** History is on when its store isn't `Disabled`. The fork's first
  boot inserts `TracingStore::Default` and `MetricsStore::Default` when none
  exists (`manager/defaults.rs`, already in place), so a new install records
  trace and metric history in its data store from the start, kept 30 and 90
  days. An upgraded install keeps whatever it has.
- **MON-2.** A store that can't be opened (a separate PostgreSQL that's down,
  or a backend not compiled in) turns that history off with a build warning,
  as the AGPL store builder already does. Startup continues and mail flows.
- **MON-3.** A change to a store setting takes effect on the next settings
  reload, with no restart, like every other setting. **Decision**, in line
  with undelete UD-6a: a change to the `DataRetention` fields in this spec or
  to an `x:Alert` takes effect without a reload, since an operator who lowers
  retention or disables a noisy alert expects it at once.

### Metric history

- **MON-4.** At each `metricsCollectionInterval` tick, every node writes one
  sample per metric selected by `x:Metrics.metrics` and `metricsPolicy`:
  - **Counter:** `count` is the increase since the node's previous sample.
    Counters in memory are totals since the process started, so the node keeps
    the last totals it wrote. The first sample after a start counts from the
    start. A counter that didn't move writes nothing.
  - **Gauge:** `count` is the reading at the tick.
  - **Histogram:** `count` and `sum` are the totals since the process
    started, cumulative. **Decision** (2026-09-19): INBUXA Admin computes the
    per-interval change between consecutive samples itself
    (`features/dashboard/helpers.ts`, `deltaHistograms`), so increases would
    be differenced twice. A histogram that hasn't changed since the node's
    previous sample writes nothing.
  All samples of one tick share its `timestamp`. That's the shape ihasmail
  already reads from INBUXA: a counter holds what happened in the interval, a
  gauge the reading at its end.
- **MON-5.** Gauges are always written, even when unchanged, so a window with
  no samples at all means history is off, not a quiet period. ihasmail relies
  on this.
- **MON-6.** There's one edition, so every gauge and histogram the collector
  has is collected, stored and exported: `server.memory`, `queue.count`,
  `user.count`, `domain.count`, the active-connection gauges, and all eleven
  histograms, including ingest, index, store read and write, and DNS lookup
  times. The `is_enterprise` arguments in `trc` and `common::telemetry` go.
  Prometheus and OpenTelemetry exports gain the same metrics.
- **MON-7.** `queue.count` is set from the queue itself on the existing
  five-minute metrics calculation, not only moved by queue events, so it's
  right after a restart. **Decision**: the in-memory gauge starts at zero on
  restart, and nothing in the AGPL code corrects it.
- **MON-8.** In a cluster, samples carry no node field (the schema has none).
  Each node writes its own values under the same timestamp, and dashboards
  aggregate them with the `sum` or `avg` their cards name. A one-node install
  is unaffected.
- **MON-9.** After writing a tick's samples the node emits
  `telemetry.metrics-stored`.

### Trace history

- **MON-10.** A trace is stored for each **inbound SMTP session** (span opened
  by `smtp.connection-start`) and each **delivery attempt** (span opened by
  `delivery.attempt-start`, which includes local delivery). Other spans
  (IMAP, POP3, HTTP, ManageSieve) aren't stored. The upstream suite confirms
  this: one LMTP delivery, made while the admin was busy over HTTP, left
  exactly two traces.
- **MON-11.** **Decision**: an inbound session in which no `MAIL FROM` was
  accepted or refused (a probe, a scanner, a banned address dropped at
  connect) isn't stored. These are most of a public server's connections and
  none is a message delivery. The live view and the log still show them.
- **MON-12.** A trace holds the span's events, from the opening event to the
  closing one, that are at `info` level or above after `x:EventTracingLevel`
  overrides. **Decision** on the level. It never holds raw I/O events
  (`*.raw-input`, `*.raw-output`, milter read and write). Those carry message
  content and authentication exchanges.
- **MON-13.** The trace is written once, when the span closes. A span still
  open after one day is dropped, matching the collector's own `SPAN_MAX_HOLD`.
- **MON-14.** Server-set fields: `timestamp` is the opening event's time;
  `from` is the first `from` value in the trace; `to` is every distinct `to`
  value, comma-separated; `size` is the message size from the trace's events,
  or 0. **Decision** on the derivation. Compare with upstream (to observe, 3).
- **MON-15.** Bounds per trace. **Decision**: at most 1,000 events, then one
  final marker event noting how many were cut; string values over 4 KiB are
  truncated. A trace is diagnostic, not an archive.

### Search

- **MON-16.** With `indexTelemetry` on, storing a trace schedules an
  `IndexTrace` task. The task builds one document for `SearchIndex::Tracing`
  with the fields named in `indexTracingFields`:
  - `eventType`: every event type in the trace;
  - `queueId`: every `queueId` value;
  - `keywords`: every address in `from` and `to`, each address's domain, every
    `domain`, `hostname`, `remoteIp`, `messageId` and `accountName` value.
  So searching `example.org` finds every trace to or from that domain, as the
  upstream suite expects. With `indexTelemetry` off nothing is indexed, and
  the `text` and `queueId` filters are refused (see "Interfaces").

### Retention and growth

- **MON-17.** On each `dataCleanupSchedule` run, traces older than
  `holdTracesFor` and samples older than `holdMetricsFor` are deleted, with
  their search-index documents. Keys are time-ordered, so this is a range
  delete. A record past its deadline is never returned, even before clean-up
  has run.
- **MON-18.** A null `holdTracesFor` or `holdMetricsFor` means no age limit.
  **Decision**: that's what "unset" means for the other retention durations
  except the archive ones. INBUXA Admin and ihasmail show a warning next to a
  null value. Confirm upstream's meaning (to observe, 7).
- **MON-19.** Growth is bounded by settings, not by a byte cap:
  - Metrics: the smallest interval is hourly, so at most 24 ticks a day, each
    at most one sample per selected metric per node. At the defaults that's
    at most 2,160 ticks over 90 days, and in practice a few hundred samples a
    tick.
  - Traces: one per delivered or attempted message, at most 1,000 events each
    (MON-15), kept 30 days. Connections that send nothing aren't stored
    (MON-11).
  The storage dashboard reports the size of both subspaces, so an operator
  sees what history costs.

### Live telemetry

- **MON-20.** **Live tracing.** `GET /api/live/tracing` returns a
  `text/event-stream`. Each frame is `event: trace` and `data:` a JSON array
  of events in the `x:TraceEvent` shape: `event`, `timestamp`, and
  `keyValues`, a list of `key` and a typed `value` (`@type` as in
  `TraceValue`). While idle it sends `event: ping` with
  `data: {"interval": 30000}` every 30 seconds, as upstream does (observed
  5). **Decision** (2026-09-19), replacing the webhook format first drafted
  here: this is what INBUXA Admin reads
  (`features/tracing/components/LiveTracingPage.tsx`). Query parameters:
  `filter` matches a value in any key; any `Key` name (for example
  `remoteIp`, `domain`, `queueId`) matches that key only; several combine with
  AND. **Decision**: keys are given in their camel-case `Key` names; the
  hyphenated names in upstream's docs (`remote-ip`) are accepted too.
- **MON-21.** The live tracing stream never carries raw I/O events
  (MON-12). **Decision**: raw protocol lines include credentials, and anyone
  who needs them can set a file tracer at `trace` level on the host.
- **MON-22.** **Live metrics.** `GET /api/live/metrics` returns a
  `text/event-stream` of the current values of the metrics listed in
  `metrics` (comma-separated names; all selected metrics when absent), every
  `interval` seconds (default 30, minimum 1). Each frame is `event: metrics`,
  its data a JSON array of `{"@type": "Counter" | "Gauge", "metric",
  "count"}` and `{"@type": "Histogram", "metric", "count", "sum"}`, holding
  totals since the process started. **Decision** (2026-09-19): this is what
  upstream sent on INBUXA (observed 5) and what INBUXA Admin reads
  (`features/dashboard/stores/liveMetricsStore.ts`).
- **MON-23.** **Tokens.** Browsers can't put headers on an event stream, so
  as with the delivery tester, `GET /api/token/tracing` and
  `/api/token/metrics` return a token, valid 60 seconds, bound to
  the account and to grant type `live_tracing` or `live_metrics` (both already
  defined). The token is the response body as plain text, as upstream sends
  it and INBUXA Admin reads it (observed 5). The stream accepts it as
  `?token=`, or a normal `Authorization` header. Issuing the token needs
  `liveTracing` or `liveMetrics`, and on this fork a token with the
  `inbuxa:admin` scope (contract.md C-18). **Decision** (2026-09-19): the
  token can be used again within its 60 seconds, not once only. INBUXA Admin
  reconnects a dropped stream up to five times with the same token URL
  (`LiveTracingPage.tsx`), in line with the choice to match INBUXA Admin for
  these streams. The `inbuxa:admin` scope check applies once the auth
  contract's scopes are built; until then the permission is the gate.
- **MON-24.** A live subscriber is lossy: a slow client loses events, never
  slows the server. At most 8 live streams run at once per node, and each ends
  after 30 minutes, when the client reconnects with a fresh token.
  **Decision** on both numbers. The time limit means a revoked grant
  (contract.md C-12) or a removed permission stops a stream within 30 minutes.

### Alerts

- **MON-25.** **Evaluation.** Each enabled alert's condition is evaluated
  every 60 seconds (**Decision**) on every node that holds the
  `metricsCalculate` task role, against that node's current values. A
  one-node install always holds it. The condition language is the server's
  expression language, and a metric is read two ways, both accepted:
  - `metric('queue.count')`, which the AGPL expression code already supports;
  - the name with dots and hyphens as underscores (`queue_count`), as
    upstream's docs describe.
  Counter values in a condition are totals since the process started, as
  `metric()` already reads them. Gauges are the current reading, histograms
  their average.
- **MON-26.** **Firing.** An alert fires when its condition goes from false to
  true, including the first evaluation after start. While it stays true it
  doesn't fire again. Once false, it can fire again. **Decision**: upstream's
  docs say email goes out "each time the condition becomes true". State is in
  memory, so a restart while the condition holds fires once more. A condition
  that fails to evaluate (a metric name that doesn't exist, a type error) is
  rejected when the alert is saved, and never fires.
- **MON-27.** **Placeholders.** In `eventMessage`, `subject` and `body`,
  `%{metric.name}%` (the dotted name) is replaced by the value used in that
  evaluation. Whole numbers print without decimals ("3", not "3.0"); others
  with at most two. An unknown name is left as written.
- **MON-28.** **Event notification.** With `eventAlert` enabled, firing emits
  `telemetry.alert-event` (level `warn`), with `details` set to the rendered
  message and the alert's id. Webhooks subscribed to that event forward it.
- **MON-29.** **Email notification.** With `emailAlert` enabled, firing queues
  one message to every address in `to`, through the normal outbound queue, so
  it's retried, DKIM-signed for a local sender domain, and visible in the
  queue like any other. Headers: `From: "fromName" <fromAddress>` (bare
  address when `fromName` is null), `To`, `Subject`, `Date`, `Message-ID`,
  and `Auto-Submitted: auto-generated` (RFC 3834). Body: `text/plain`, UTF-8.
  The server emits `telemetry.alert-message` once it's queued.
- **MON-30.** An alert email is sent even when the queue itself is the
  problem the alert reports. It's queued like any message. If queueing fails,
  the event notification (MON-28) still happens and the failure is logged.

### Who may see what

- **MON-31.** Traces, metric samples, alerts, the two store settings and live
  telemetry are server-level. By default only the superuser permission set
  holds their permissions (see "Permissions"). A tenant administrator gets
  `forbidden` for all of them, even if a role grants the permission, unless
  its tenant allows it (multi-tenancy MT-13). **Decision**: traces carry other
  tenants' addresses and IP addresses, and metrics describe the whole server.
  A tenant-scoped trace view is a possible later addition (open question 11).
- **MON-32.** `x:Trace` and `x:Metric` can't be created or updated, as the
  AGPL registry already enforces. **Decision**, an addition: a trace can be
  destroyed with `sysTraceDestroy`, so an operator can honor a request to
  erase someone's delivery records before they age out. Samples can't be
  destroyed one by one.
- **MON-33.** Traces are personal data: they hold addresses, IP addresses,
  host names and message ids, never message content (MON-12). Retention
  (MON-17) is the main control, and INBUXA Admin's retention form says what's
  kept. Nothing in this feature sends traces off the host. Webhooks and
  OpenTelemetry send only what an operator configures.

### Failure behavior: telemetry never blocks mail

- **MON-34.** Trace and sample writes happen off the mail path, through a
  lossy collector subscriber with a bounded buffer. When the buffer is full,
  events are dropped and counted, and one error event is logged per minute at
  most. No SMTP, IMAP, JMAP or delivery step ever waits on history.
- **MON-35.** A failing tracing or metrics store (full, unreachable, slow)
  loses history and logs, rate-limited. It never fails a delivery, a login or
  startup.
- **MON-36.** A failed `IndexTrace` task is retried by the task manager as
  now. The trace stays readable by id and by date meanwhile.
- **MON-37.** A failed alert evaluation or notification is logged and retried
  on the next evaluation. It never stops the other alerts.
- **MON-38.** A failed clean-up leaves the records for the next run. Expired
  records are still hidden (MON-17).

### Edition cleanup

- **MON-39.** Remove the `is_enterprise` and `_is_enterprise` parameters and
  their `inbuxa:` signposts in `telemetry/mod.rs` and `config/telemetry.rs`;
  `Tracers::parse` uses `storage` again. Drop `Metric` and `Trace` from
  `assert_enterprise_object`. Replace the "Enterprise feature" stubs for
  `/api/token/{tracing,metrics}` and `/api/live/{tracing,metrics}`, and the
  `cfg(not(feature = "enterprise"))` branch in `management_access_token`.

## Interfaces

- **JMAP, existing names, unchanged.** Over `urn:inbuxa:jmap:registry`:
  - `x:Alert/get`, `/query`, `/set`, and the `x:TracingStore`,
    `x:MetricsStore`, `x:DataRetention`, `x:Search` singletons.
  - `x:Trace/get` and `/query`. Filters: `text`, `timestamp` (comparison names
    such as `timestampIsGreaterThan`), `queueId`, `event` (the type of the
    trace's opening event: the list views use `smtp.connection-start` and
    `delivery.attempt-start`). Sort by `timestamp`, newest first by default.
    `/set` refuses create and update, and allows destroy (MON-32).
  - `x:Metric/get` and `/query`. Filters: `metric` (one name or a list) and
    the `timestamp` comparisons `timestampIsGreaterThan`,
    `timestampIsGreaterThanOrEqual`, `timestampIsLessThan`,
    `timestampIsLessThanOrEqual`. A bare `timestamp` filter is
    `unsupportedFilter`, as upstream. Sort by `timestamp` either way, with
    `position`, `anchor` and `anchorOffset` paging and `calculateTotal`.
  - `x:Trace` text or `queueId` filters when `indexTelemetry` is off:
    `unsupportedFilter`, with a description saying trace search is off.
- **HTTP.** `/api/token/tracing`, `/api/token/metrics`, `/api/live/tracing`,
  `/api/live/metrics` as MON-20 to MON-24. These are the route names in the
  AGPL code. Upstream's docs name `/api/telemetry/traces/live` and
  `/api/telemetry/metrics/live`. **Decision**: serve those as aliases too.
- **Webhooks, unchanged.** Already AGPL, and intact after the strip: the
  webhook tracer is in neither the removed-file list nor the snippet list,
  and upstream's docs don't mark webhooks as Enterprise. `POST` of
  `{"events": [...]}`, HMAC-SHA256 in `X-Signature`, batched by `throttle`,
  stale events dropped after `discardAfter`.
- **Dashboards.** The schema's six dashboards (Overview, Network, Security,
  Delivery, Performance, Storage) name, per card, `live` (MON-22) or
  `history` (`x:Metric`) and an aggregate. The server serves what they name.
  INBUXA Admin draws them unchanged.

## ihasmail changes

These go in ihasmail-inbuxa, not public ihasmail, which stays Stalwart-facing
(SPEC.md §5).

- The dashboard already reads `x:Metric` for received, sent and memory. Keep
  it. Drop the Enterprise wording from its comments and code paths, and the
  "refused as `forbidden`" branch becomes a plain error.
- Change the footer line that sends people to "Stalwart's own
  administration" to name INBUXA Admin, with its link.
- Warn on the dashboard when metric history is off (no samples in the window,
  MON-5), with a link to INBUXA Admin's Metrics Store page.
- Live tracing, trace history and alerts stay in INBUXA Admin (SPEC.md §5.4).
  ihasmail doesn't grow screens for them.
- contract.md C-19 has to list `x:Metric` (get and query) among the object
  types the `inbuxa:account-admin` scope reaches, or the dashboard loses its
  message cards.
- Translation work: two changed strings (the footer line and the error that
  replaces the refused case) and one new one (the history-off warning), each
  in ihasmail's nine languages.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code.

1. New install: `TracingStore` and `MetricsStore` read `Default`, retention
   30 and 90 days, hourly collection (MON-1).
2. Tracing store set to an unreachable PostgreSQL: the server starts, and
   mail is delivered (MON-2, MON-35).
3. Two collection ticks with traffic between: counters hold the increase,
   gauges the reading, idle counters write nothing (MON-4, MON-5).
4. `queue.count` is right after a restart with mail queued (MON-7).
5. Prometheus output includes `queue_count` and the store and DNS histograms
   (MON-6).
6. One LMTP delivery, with HTTP traffic alongside: exactly two traces, one
   `smtp.connection-start`, one `delivery.attempt-start` (MON-10).
7. An SMTP connection that quits without `MAIL FROM`: no trace (MON-11).
8. A trace holds no raw I/O event, and nothing below `info` (MON-12).
9. `from`, `to`, `size` and `timestamp` set as MON-14.
10. Text search for the sender, the recipient and their domain each finds both
    traces (MON-16).
11. `indexTelemetry` off: `text` filter is `unsupportedFilter`, `timestamp`
    still works (MON-16, Interfaces).
12. Purge with retention 1 second: all traces and their index entries gone.
    With 2 seconds, nothing gone yet (MON-17).
13. Metric query with `timestampIsGreaterThan`, and paging forward, backward
    and by anchor, returns consistent pages (Interfaces).
14. Live tracing with `?remoteIp=` shows only that client's events, and no
    raw I/O (MON-20, MON-21).
15. Live metrics with `metrics=server.memory&interval=1` yields a frame a
    second (MON-22).
16. Live token: expires after 60 seconds, works once, refused without
    `liveTracing` (MON-23).
17. A ninth live stream is refused. A stream closes after 30 minutes
    (MON-24).
18. Alert on `metric('domain.count') > 1 && metric('cluster.publisher-error') > 3`
    with both conditions met: one email with the placeholders filled ("3
    domains and 5 cluster errors"), `From: "Alert Subsystem"
    <alert@example.com>`, one `telemetry.alert-event`. The opposite condition
    fires nothing (MON-25 to MON-29).
19. The same alert with an underscore condition (`domain_count > 1`) fires
    the same way (MON-25).
20. The alert fires once while the condition stays true, and again after it
    has been false (MON-26).
21. An alert with an unknown metric name is refused on save (MON-26).
22. A webhook subscribed to `telemetry.alert-event` receives the alert
    (MON-28).
23. A tenant administrator with `sysTraceGet` in a role, in a tenant that
    doesn't allow it: `forbidden` (MON-31).
24. `x:Trace/set` destroy by a superuser removes the trace and its index
    entry. Create and update are refused (MON-32).
25. A full tracing store buffer drops events without delaying an SMTP session
    (MON-34).
26. **(compat)** A copy of INBUXA's data opens: alerts, store settings and
    retention read back unchanged. Old traces and samples it can't decode are
    skipped, and are gone after one purge past their age (Data model).

### The gated integration suites

`tests/src/telemetry/mod.rs` gates four suites behind `pending-rebuild`:

| Suite | Needs rebuilding | Why it's gated |
|---|---|---|
| `alerts.rs` | Yes | It calls `process_alerts()`, which lived in the removed `enterprise/alerts.rs`. The rebuild provides a function of that shape (returns the messages it would send) so the suite runs unchanged |
| `metrics.rs` | Yes | It needs the metrics store's `purge_metrics` and the test-data generator `insert_test_metrics`, from the removed `metrics/store.rs` and `metrics/test_data.rs` (the latter is the dangling `test_data` module in `metrics/mod.rs`) |
| `tracing.rs` | Yes | It needs the tracing store's `purge_spans`, from the removed `tracers/store.rs` |
| `webhooks.rs` | No | Webhooks are AGPL and intact. The suite is gated only because its clean-up calls `purge_spans` through the shared harness. Dropping or guarding that one call lets it run now, before the rebuild |

Recommended: un-gate `webhooks.rs` straight away (a separate change, not made
here), so webhooks are tested while the rest is rebuilt.

## Open questions / to observe

To check read-only against INBUXA's live Enterprise server later. None of
these needs a write.

1. How many traces a day INBUXA stores against its SMTP connection count:
   whether upstream stores connection-only sessions (MON-11).
2. Which events and levels a stored trace holds, and whether raw I/O ever
   appears (MON-12, MON-15).
3. How upstream fills `from`, `to` and `size` on a trace with several
   recipients (MON-14).
4. Whether INBUXA's samples include `Histogram` records, which gauges appear
   every tick, and whether counter samples are per-interval increases
   (MON-4 to MON-6). ihasmail's code says they are.
5. Whether `queue.count` in INBUXA's history matches the real queue after a
   restart (MON-7).
6. INBUXA's current `holdTracesFor`, `holdMetricsFor`,
   `metricsCollectionInterval`, `indexTelemetry` and store settings, so the
   cutover keeps them.
7. What a null `holdTracesFor` or `holdMetricsFor` does upstream: keep
   forever, or store nothing (MON-18).
8. The `x:Trace/query` filters upstream accepts beyond `text`, `timestamp`,
   `queueId` and `event`, and the `x:Metric/query` comparison names.
9. The live endpoints: the token response body, the SSE frame shape for
   tracing and metrics, keep-alive comments, and which path INBUXA Admin
   calls (MON-20 to MON-23). A `GET` of each is read-only.
10. Whether INBUXA has any `x:Alert` objects, and whether their conditions use
    `metric()` or underscore names (MON-25). Whether INBUXA's logs show
    `telemetry.alert-event` repeating while a condition held, which settles
    the cadence and repeat behavior (MON-25, MON-26).
11. Whether upstream's tenant `Admin` role holds any `sysTrace*`,
    `sysMetric*` or live permission, and whether a tenant view of its own
    domains' traces is wanted (MON-31).
12. Size of INBUXA's `o` and `x` subspaces, to check MON-19's estimate.

## Implementation status

Built 2026-09-19 from this spec, clean-room, under the multi-tenancy hand-off
brief's rules. Metric history is in `crates/common/src/telemetry/metrics/store.rs`,
trace history in `crates/common/src/telemetry/tracers/store.rs`, alerts in
`crates/common/src/telemetry/alerts.rs`, the live streams in
`crates/http/src/live.rs`, and `x:Metric` and `x:Trace` in
`crates/jmap/src/inbuxa/telemetry.rs`, at the paths the shared tests name;
upstream files carry hooks marked `inbuxa:`. All four suites in
`tests/src/telemetry` are un-gated and pass, so the table above is history:
they cover tests 10 and 12 (`tracing.rs`), 13 (`metrics.rs`) and 18
(`alerts.rs`). Tests 1, 3, 5 to 9, 11, 14 to 17, 19 to 21, 23 and 24 pass as
`tests/src/system/monitoring.rs`.

- **MON-1 to MON-39:** built, with the limits below.
- **Test 26 (compat)** is written as `monitoring_compat`, ignored, and unrun
  until a copy of INBUXA's data is provided. It checks observed 1, reads the
  old history without an error, and purges it. It deletes history, so only
  ever run it against a copy.
- **Not exercised by a test:** 2 (an unreachable PostgreSQL tracing store),
  4 (`queue.count` after a restart; the gauge is set from the queue on each
  calculation), 22 (a webhook for `telemetry.alert-event`; webhooks are the
  shared, unchanged path), 25 (a full buffer; the subscriber is lossy by
  construction), and test 17's 30-minute close.
- **Known limits, not requirements of this spec:**
  - A trace cut at 1000 events (MON-15) carries the number cut as a `total`
    value on its closing event, since no event type fits a separate marker.
  - The `inbuxa:admin` scope check on live tokens (MON-23) waits for the auth
    contract; until then the permission and server-level checks apply.
  - A live token can be reused within its 60 seconds (Decision, MON-23).
  - The alert edge trigger (MON-26) is held in memory, so an alert whose
    condition holds across a restart fires once more.
  - The stream limit (MON-24) is per node.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22), read-only, as a server-level administrator and the throwaway test
account. No upstream code was read.

1. **Settings** (open question 6). `holdTracesFor` 30 days, `holdMetricsFor`
   90 days, `metricsCollectionInterval` hourly at minute 0, `indexTelemetry`
   on with `eventType`, `queueId` and `keywords` indexed. Tracing and metrics
   stores are both `Default`. No `x:Alert` exists (open question 10).
2. **Traces** (open questions 1 to 3). 395 stored, the oldest exactly one day
   old, although retention is 30 days. Why is unexplained: the history may
   have been cleared a day earlier. Worth checking before cutover, since
   metrics go back 24 days. Each trace is one message's journey: 4 to 44
   events (10 on average), mostly delivery, queue, SMTP and authentication
   results. Every stored inbound SMTP session reached `MAIL FROM` (82 of 82),
   so connection-only sessions aren't stored, which matches MON-11. Events
   carry `event`, `timestamp` and typed `keyValues`. There is no level field
   and no raw I/O (MON-12). `to` is a string. No stored trace had more than
   one recipient, so MON-14's multi-recipient case wasn't seen.
3. **Trace queries** (open question 8). `timestampAfter` and `after` are
   refused with `unsupportedFilter`. The accepted filters weren't listed
   further.
4. **Metrics** (open questions 4 and 5). 10,755 samples over 597 hourly ticks
   since 2026-08-25, with no gaps: 5,598 `Counter`, 4,025 `Histogram` and
   1,132 `Gauge`. Histograms are stored for eight metrics: delivery attempt
   and total time, DNS lookup time, ingest time, and blob and data store
   read and write times. Gauges are `queue.count` and `server.memory`. Only
   four metrics appear in every tick, so a counter with nothing to report
   isn't stored for that tick. Counter values read as per-interval
   increases, not running totals. `queue.count` moved between 20 and 30 over
   the last eight hours, so it tracks the queue. Whether it's right straight
   after a restart wasn't tested.
5. **Live telemetry** (open question 9).
   - `GET /api/token/tracing` and `/api/token/metrics` answer `200` with the
     token as a bare 90-byte body and no content type.
   - The streams are `GET /api/live/tracing` and `/api/live/metrics`, with
     the token in the `token` query parameter. The same token in an
     `Authorization: Bearer` header is refused (`401`).
   - Both answer `text/event-stream`. Tracing sends
     `event: ping` with `data: {"interval": 30000}` while idle. Metrics sends
     `event: metrics` with a JSON array of `{metric, @type, count}` holding
     totals since the server started.
   - `/api/telemetry/traces/live` and `/api/telemetry/metrics/live` don't
     exist upstream (`404`). The aliases in "Interfaces" are the fork's own.
6. **Tenant administrators** (open question 11). The default
   `Tenant Administrator` role holds 50 permissions and none for telemetry.
   The `System Administrator` role holds all of them, live ones included.

Not settled: open question 7 (null retention) needs a write, and question
12 (subspace sizes) needs access to the store itself.
