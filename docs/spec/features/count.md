# Feature spec: the opt-in count

Status: building, 2026-11-27. Not a rebuild (SPEC.md §4): inbuxa's own
design.

## Provenance

| Source | Used for |
|---|---|
| inbuxa's promise of no telemetry | The constraint: nothing leaves a server that didn't choose to send it |
| This server's `inbuxa:LogSettings` (`crates/features/src/security/log_files.rs`) | How a fork-owned singleton is stored, served, permitted and audited |
| This server's deliverability check (`crates/services/src/inbuxa_deliverability.rs`) and singleton leases (`crates/common/src/manager/singleton_lease.rs`) | A background task that waits for a change and acts on one node of a cluster |
| RFC 9562 §5.4 | The install ID's format (UUID version 4) |

Upstream's open code has nothing like it, and nothing here comes from
Enterprise code.

## What it is

The project would like to say how many inbuxa servers run. inbuxa promises
no telemetry, so the only honest way to count is to ask: an administrator
who chooses to be counted lets the server send a random install ID and its
version once a week. Nothing else is sent. A server that doesn't opt in
never contacts anyone for this, and the promise stays true for it.

The setting is `inbuxa:CountSettings` under `urn:inbuxa:jmap`, a singleton
(id `singleton`), with `/get` and `/set`. It is server-level, with the
tracers' permissions (`sysTracerGet`, `sysTracerUpdate`), as
`inbuxa:LogSettings` is. It is stored as JSON under `Yc` in the fork's
subspace, not on a generated registry object.

| Property | Type | Default | |
|---|---|---|---|
| `enabled` | Boolean | `false` | Settable |
| `decided` | Boolean | `false` | Settable. True once an administrator answered the one-time question, either way |
| `endpoint` | String | `https://inbuxa.org/count/v1` | Settable. `null` or `""` goes back to the default |
| `installId` | String\|null | `null` | Server-set. `null` while off |
| `lastCheckIn` | String\|null | `null` | Server-set. UTC date `YYYY-MM-DD` of the last check-in that succeeded |
| `preview` | String | | Server-set. The exact body that is, or would be, sent |

`preview` while off reads
`{"id":"00000000-0000-4000-8000-000000000000","version":"27.1-rc.50"}`
(with the running version); on, it carries the install ID. `/set` refuses
the server-set properties (`invalidProperties`), and its `updated` entry
carries their new values.

## Requirements

- **CNT-1.** Off by default, on new installs and on upgrades: no stored
  settings read as `enabled: false`, `decided: false`. A new install writes
  nothing for it.
- **CNT-2.** Off, the count's task does nothing on the network: it builds
  no HTTP client, looks up no name and opens no connection. It waits for the
  settings to change: at once on the node where they were changed, and
  within the hour on the other nodes of a cluster (a store read, not a
  network request to anyone outside).
- **CNT-3.** Turning it on generates a fresh random UUID version 4,
  lower-case and hyphenated, and stores it as `installId`. Turning it off
  deletes it, with `lastCheckIn`. Turning it on again makes a new one, and
  nothing links the two: the audit log records the change without the ID
  (CNT-10).
- **CNT-4.** Schedule. The first check-in is at a random moment within 24
  hours of being turned on, or of start-up while on (after the two-minute
  settle delay every start has). Then one every 7 days, give or take a
  random amount up to 12 hours. A check-in that fails is tried again 6
  hours later, at most 3 times; after that it waits for the next weekly
  slot. Failures are logged at debug level only: no
  warnings, no errors, nothing a host with no way out would be told every
  week.
- **CNT-5.** The request is `POST {endpoint}/checkin` with
  `Content-Type: application/json` and the body exactly
  `{"id":"<installId>","version":"<version>"}`, where the version is how
  tags and `--version` name it (`27.1-rc.50`). It times out after 10
  seconds. Any 2xx is success; the response body is never read. No other
  header carries data: only Host, Content-Type, Content-Length, Accept
  and Accept-Encoding go, with no user agent, cookie or authorization. Redirects aren't followed, so the body goes
  only to the endpoint the administrator saw. A proxy named by
  `HTTPS_PROXY`/`HTTP_PROXY` is used.
- **CNT-6.** In a cluster, only the node holding the task scheduler's
  singleton lease sends. The install ID lives in the stored settings,
  shared by every node, so a cluster is counted once. A node that doesn't
  hold the lease when its slot comes moves on to its next weekly slot.
- **CNT-7.** Turning it off while an ID exists sends one best-effort
  `POST {endpoint}/forget` with the body exactly `{"id":"<installId>"}`,
  to the endpoint the ID was sent to, with the same timeout, from the node
  that handled the change. The ID is deleted whatever the result. This one
  request happens because the administrator just acted; it is never
  retried and never stored.
- **CNT-8.** `/set` refuses an endpoint that isn't an absolute `https://`
  URL (lower-case scheme) with a host, or that has a query, a fragment, a
  user name or password, spaces or non-ASCII characters, or is longer than
  200 characters. Forks and private builds point it at their own
  collector. A trailing `/` is allowed and not doubled.
- **CNT-9.** The personal-data catalog lists the data flow
  (`source."opt-in-count"`): it leaves the host, is switched on by
  `inbuxa:CountSettings.enabled`, and carries exactly the install ID and
  the version. The inventory names the endpoint as a processor while on.
- **CNT-10.** The audit log records each `/set`, with `enabled`,
  `decided` and `endpoint` before and after, as it does for
  `inbuxa:LogSettings`. Not the install ID (CNT-3).
- **CNT-11.** Recovery mode never sends: the count's task is one of the
  services recovery mode doesn't start, and a `/set` there queues no
  `/forget`.

## Out of scope

- The collector (`inbuxa-count`), what it stores and what it publishes.
- Anything more about a server than its version. Adding a field is a new
  requirement, a new catalog entry and a change to what the console shows
  before an administrator says yes.
