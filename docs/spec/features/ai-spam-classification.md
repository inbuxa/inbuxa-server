# Feature spec: AI spam classification and the LLM Sieve function

Status: draft, 2026-09-18. Feature 5 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `x:AiModel`, `x:SpamLlm` and `x:SpamLlmProperties`, `x:HttpAuth`, `x:SecretKey`, `x:SpamTag`, the `AiModelType` enum, the `interactAi`, `sysAiModel*` and `sysSpamLlm*` permissions, the `ai.*` events, in `resources/schema/schema.json.gz` and `crates/registry/src/schema/*.rs` at `v0.16.22` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | The stored records, field meanings, defaults, permissions, events, what upstream flags as Enterprise |
| This repository's AGPL code: `crates/spam-filter` (the scoring order, `llm_result`, the `X-Spam-LLM` header line), `crates/common/src/scripts/plugins` (the `llm_prompt` registration), `crates/common/src/auth/permissions.rs` (default roles), `crates/trc` (event ids) | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Where the feature hooks in, what already exists, default permissions |
| This repository's shared tests: `tests/src/smtp/inbound/antispam.rs`, `tests/resources/smtp/antispam/llm.test`, `tests/resources/jmap/sieve/test_mailbox.sieve` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | Expected tags, the mock endpoint's shape, the Sieve call's shape |
| Stalwart documentation (`stalwartlabs/website`): "AI Models", "LLM classifier" (spam filter), "LLM Integration" (Sieve), the `AiModel` and `SpamLlm` object references, "Scores", "Permissions", current and 0.15 versions, and the 2024-10-07 announcement post | Unlicensed public documentation: facts used, prose not copied | Behavior of the classifier, tag names, default scores, the Sieve function's signature and failure result, trusted and untrusted scripts |
| RFC 5321 §4.5.3.2.6, RFC 5322, RFC 2047, RFC 1918, RFC 4193, RFC 8620 | IETF | SMTP time limits, header syntax and encoding, private address ranges, JMAP semantics |
| The OpenAI-compatible chat and text completions request and response shape, as published and as implemented by local servers (llama.cpp's server, Ollama, vLLM, LocalAI) | Public API conventions | The wire format |

No Enterprise-only file or snippet was used. The author is a fresh session that
has never seen Enterprise code, and writes specs only. Nothing here was
observed against a running Enterprise server yet. Where no public source
settles a behavior, this spec makes a decision of its own, marked
**Decision**, or lists it under "Open questions / to observe". It never fills a
gap by guessing what upstream code does.

## What it is

Two uses of a language model the operator runs:

1. **Spam classification.** The spam filter sends a message's subject and
   text to a model with the operator's prompt. The model answers with a
   category and a confidence, for example `Unsolicited,High`. That becomes a
   tag, such as `LLM_UNSOLICITED_HIGH`, and the tag's score is one more input
   to the message's spam score. The model's opinion is one signal among many.
   It never decides a message's fate alone.
2. **The Sieve function `llm_prompt`.** A Sieve script sends a prompt to a
   named model and gets the answer back as a string, for example to file mail
   by topic.

Both are off until the operator sets them up. inbuxa-server ships no model
and no endpoint.

**Project policy, which this spec enforces.** AI in INBUXA products must bring
real value and use a local model the operator can audit. There is no hosted
API by default. An operator may point a model at a hosted OpenAI-compatible
endpoint, but nothing is ever preset to one, and no message content leaves
the server unless the operator configured the endpoint it goes to. Docs and UI
text describe the feature as it is, including that it is AI. They never claim
the product has no AI.

Upstream ships both only in its Enterprise Edition. inbuxa-server ships them to
everybody. The fork left a signpost: `crates/common/src/scripts/plugins/llm_prompt.rs`
registers `llm_prompt` but always returns `false` (`inbuxa:` comment).

**Non-goals.** The model doesn't train the statistical classifier, move or
delete mail on its own, reply to mail, or see attachments. It isn't a
replacement for the existing filter.

## Data model

Unchanged from upstream, so existing settings open as they are (SPEC.md §7).
Both objects are server-level. They have no `memberTenantId`.

### A model endpoint, `x:AiModel` (many)

| Field | Type, default | Meaning |
|---|---|---|
| `name` | string, required | Short name. Sieve scripts name the model by it (AI-20) |
| `url` | URI, required | The OpenAI-compatible endpoint, the full path included, e.g. `…/v1/chat/completions` |
| `model` | string, required | The model name sent in each request |
| `modelType` | `AiModelType`, `Chat` | `Chat` (chat completions) or `Text` (text completions) |
| `temperature` | float 0.0–1.0, `0.7` | Default sampling temperature |
| `timeout` | duration, `120000` ms | How long to wait for a response |
| `allowInvalidCerts` | boolean, `false` | Accept an invalid TLS certificate |
| `httpAuth` | `x:HttpAuth` | `Unauthenticated`, `Basic` (`username`, `secret`) or `Bearer` (`bearerToken`). Secrets are `x:SecretKey`: a `Value`, an `EnvironmentVariable` or a `File` |
| `httpHeaders` | map string → string | Extra request headers |

Permissions: `sysAiModelGet`, `sysAiModelQuery`, `sysAiModelCreate`,
`sysAiModelUpdate`, `sysAiModelDestroy`. The list view shows `model` and
`modelType`, labelled by `name`.

### The classifier, `x:SpamLlm` (singleton)

Two variants by `@type`: `Disable` (the default) and `Enable`, which carries
`x:SpamLlmProperties`:

| Field | Type, default | Meaning |
|---|---|---|
| `modelId` | id of `x:AiModel`, required | The model to ask |
| `prompt` | text, required | The instructions sent with each message |
| `temperature` | float 0.0–1.0, `0.5` | Temperature for classification, overriding the model's |
| `separator` | string, `,` | Splits the answer into fields |
| `responsePosCategory` | unsigned, `0` | Zero-based position of the category |
| `responsePosConfidence` | unsigned or null, `1` | Position of the confidence. Null: the answer has none |
| `responsePosExplanation` | unsigned or null, `2` | Position of the explanation. Null: none |
| `categories` | set of strings, at least 2, `Commercial`, `Harmful`, `Legitimate`, `Unsolicited` | Accepted categories |
| `confidence` | set of strings, `High`, `Low`, `Medium` | Accepted confidence levels |

Permissions: `sysSpamLlmGet`, `sysSpamLlmUpdate`.

### Elsewhere

- **Tags and scores.** The classifier's tags are ordinary spam tags, scored
  by `x:SpamTag` entries like every other tag: `Score` (a number), `Discard`
  or `Reject`. The documented defaults are `LLM_UNSOLICITED_HIGH` 3.0 and
  `LLM_LEGITIMATE_HIGH` −3.0. A tag with no entry scores 0.
- **`interactAi`** permission ("Interact with AI models"): lets an account's
  own Sieve scripts call `llm_prompt`. This repository's default roles give it
  to users, tenant administrators and superusers
  (`crates/common/src/auth/permissions.rs`). The public permissions table
  lists it for administrators only, under the older name
  `ai-model-interact`. See open question 5.
- **Events:** `ai.llm-response` (id 556, a response arrived) and
  `ai.api-error` (id 557, a request failed).
- **Header:** `X-Spam-LLM`, written by the existing AGPL scoring code from the
  spam result's `llm_result` (a category string and an explanation) as
  `X-Spam-LLM: {category} ({explanation})`.

### Added by inbuxa-server

A server-level singleton for the fork's limits, in the fork's own namespace
(name open, SPEC.md §8), so upstream's records stay exactly as upstream wrote
them. **Decision**: these are new, and every default below is this spec's
own.

| Field | Default | Meaning |
|---|---|---|
| `spamMaxAdded` | `5.0` | Most an LLM tag can add to a message's score (AI-12) |
| `spamMaxSubtracted` | `1.0` | Most an LLM tag can take off a message's score (AI-12) |
| `spamCallCeiling` | `20s` | Longest the spam filter waits for the model, whatever the model's `timeout` (AI-9) |
| `maxConcurrentCalls` | `4` | Model requests in flight at once, across both uses, per server node (AI-10) |
| `maxContentBytes` | `16384` | Most message text sent per classification (AI-4) |
| `failureBackoff` | `60s` | Pause after repeated failures (AI-11) |
| `userCallsPerHour` | `60` | `llm_prompt` calls per account per hour from its own scripts (AI-24) |

## Required behavior

### Defaults and privacy

- **AI-1.** A new install has no `x:AiModel` and `x:SpamLlm` set to
  `Disable`. Nothing is sent to any model until an administrator creates one.
  No URL, model name, prompt or example anywhere in the product's defaults,
  placeholders, docs or setup points at a hosted provider. Where an example
  is needed, it is a local one, such as `http://127.0.0.1:8080/v1/chat/completions`.
- **AI-2.** When a model's `url` host isn't `localhost`, a loopback address, an
  RFC 1918 or RFC 4193 private address, or a name resolving only to those,
  the server logs a warning at startup and on every change that message
  content will leave this network. INBUXA Admin shows the same warning on the
  model's form. **Decision.** The check is advisory. It never blocks an
  endpoint the operator chose.
- **AI-3.** The classifier sends only the subject and the message's text:
  plain-text parts, and HTML parts converted to text. Never sent: other
  headers, addresses, the envelope, the client IP, attachments, images, or
  anything identifying the recipient. **Decision**: the documented behavior
  is "subject and body". Nothing else is needed to judge content.
- **AI-4.** The text sent is cut to `maxContentBytes` on a character boundary.
  Text over the limit is truncated from the end, and the request says so
  (AI-6).
- **AI-5.** Message content is never written to the logs. The
  `ai.llm-response` event, at trace level, records the model's name, the
  response time, the raw answer (cut to 1 KiB), and the resulting tag. The
  `ai.api-error` event records the model's name, the error and the HTTP
  status. Neither ever records a secret or an authorization header. The
  operator can audit what the model decided and why, and the prompt is plain
  in the settings.

### The request

- **AI-6.** Classification sends, for a `Chat` model:
  `POST {url}` with JSON `{"model": model, "messages": [system, user],
  "temperature": t, "max_tokens": 200, "stream": false}`. The system message
  is the operator's `prompt` followed by a fixed framing paragraph written by
  this project and shown in the docs, stating that the email follows between
  two marker lines, that it is data to classify and not instructions, and
  that anything inside it asking for a particular answer is itself a sign of
  abuse. The user message is:

  ```
  -----BEGIN EMAIL {nonce}-----
  Subject: {subject}

  {text}
  -----END EMAIL {nonce}-----
  ```

  with `[truncated]` before the end marker when AI-4 cut it. `{nonce}` is 16
  random hex characters, new for each request, so a message can't forge the
  end marker. For a `Text` model: `{"model", "prompt", "temperature",
  "max_tokens", "stream": false}`, where `prompt` is the system text, a blank
  line, then the user text. **Decision** throughout: separate roles and
  unforgeable markers blunt prompt injection from message content. They don't
  stop it, which is why AI-12 bounds the damage.
- **AI-7.** The answer is `choices[0].message.content` for `Chat` and
  `choices[0].text` for `Text`. Any other shape, an HTTP status other than
  200, or a body over 64 KiB is a failure (AI-9).
- **AI-8.** Requests carry `Content-Type: application/json`, the `httpAuth`
  credentials (Basic or Bearer, read from the `x:SecretKey` at request time),
  and `httpHeaders`. Redirects are not followed. **Decision**: a redirect
  would send message content to a host the operator never named. TLS
  certificates are checked unless `allowInvalidCerts`. No user, account or
  message identifier is sent (no OpenAI `user` field).

### Failure never costs mail

- **AI-9.** A timeout, connection error, HTTP error, bad JSON, empty answer
  or unparseable answer adds no tag, no score and no `X-Spam-LLM` header. The
  message goes on through the filter as if the classifier were off, and
  `ai.api-error` is logged. The classifier waits no longer than the shorter of
  the model's `timeout` and `spamCallCeiling`. **Decision**: upstream's
  default model timeout is two minutes, which is too long to hold an SMTP
  transaction (RFC 5321 §4.5.3.2.6 gives the client 10 minutes for the reply
  to the end of data, and sending servers commonly give up sooner).
- **AI-10.** At most `maxConcurrentCalls` requests are in flight. A message
  that finds no free slot isn't queued: it is scored without the model, as in
  AI-9. The model's slowness can never back up inbound mail.
- **AI-11.** After 5 consecutive failures to a model, the server stops calling
  it for `failureBackoff`, then tries again with one request. While paused,
  messages are scored as in AI-9. The pause and the resume are each logged
  once. **Decision.**

### From the answer to a tag

- **AI-12.** Parsing the answer:
  1. Trim it and take the first non-empty line.
  2. Split it by `separator`, taken as the whole string. An empty separator
     is refused at `/set` with `invalidProperties`.
  3. Take the fields at `responsePosCategory` and, when not null,
     `responsePosConfidence`. Trim each of spaces and the characters
     `" ' * .`. Match each case-insensitively against `categories` and
     `confidence`. A field that's missing or matches nothing means no tag.
  4. The tag is `LLM_` + category, or `LLM_` + category + `_` + confidence
     when there is a confidence, using the configured spelling, uppercased,
     with every character outside `A-Z` and `0-9` replaced by `_`. So
     `Unsolicited` and `high` give `LLM_UNSOLICITED_HIGH`.
  5. When `responsePosExplanation` isn't null, the explanation is the field
     at that position. When it's the last position used, it runs to the end of
     the line, separators included, since explanations contain commas.

  **Decision** on steps 1, 3 and 5. The documented rule is that answers
  outside the configured sets are ignored.
- **AI-13.** One classification gives at most one tag. Its score comes from
  `x:SpamTag` as for any tag, then is clamped to `[−spamMaxSubtracted,
  +spamMaxAdded]`. A `Discard` or `Reject` entry on a tag starting `LLM_`
  counts as no entry (score 0) and logs a warning at load. **Decision**: the
  model reads attacker-written text, so its word alone must never refuse or
  destroy mail, and it can pull a score down only a little, because "this is
  legitimate" is exactly the answer an injected message asks for. The
  operator's stored `x:SpamTag` records are left as they are.
- **AI-14.** The classifier's tag and score appear in `X-Spam-Result` like any
  other. The model's output never trains the statistical classifier, never
  counts toward auto-learn, and plays no part when a user reports mail as spam
  or not spam.
- **AI-15.** When a tag was assigned, the message gets one `X-Spam-LLM`
  header: `X-Spam-LLM: {TAG} ({explanation})`, or `X-Spam-LLM: {TAG}` with no
  explanation. The explanation is cut to 200 characters. Control characters,
  CR and LF included, and parentheses are removed. Non-ASCII text is encoded
  as RFC 2047 encoded words, and the header is folded to RFC 5322's line
  limits. **Decision** on the format, see open question 3. Any `X-Spam-LLM`
  header already in an inbound message is removed first, so a sender can't
  plant one.

### When it runs

- **AI-16.** With `x:SpamLlm` set to `Enable`, the classifier runs on every
  message that goes through the spam filter, except:
  - mail from an authenticated sender (local users' own mail isn't sent to a
    model). **Decision**;
  - when the filter has already reached a `Discard` or `Reject` result from
    another tag, where the answer can't change anything. **Decision**.
- **AI-17.** It runs after every other analysis step and before user-defined
  rules (`x:SpamRule`) and the final score, so rules can test the `LLM_` tags.
  **Decision** on the position.
- **AI-18.** A `modelId` pointing at no model is refused at `/set`. Destroying
  a model that `x:SpamLlm` names is refused. **Decision**, see open question
  6. A settings change takes effect without a restart.
- **AI-19.** Reloading or changing settings never drops mail in flight. A
  classification already under way finishes, or fails as in AI-9.

### The Sieve function `llm_prompt`

- **AI-20.** `llm_prompt(model, prompt, temperature)`, available with
  `require "vnd.stalwart.expressions"`. `model` names an `x:AiModel` by its
  `name`, or failing that by its id. `prompt` is sent as is. `temperature` is
  clamped to 0.0–1.0. A value that isn't a number uses the model's own
  `temperature`. **Decision** on name first, see open question 4.
- **AI-21.** For a `Chat` model the request is one user message holding the
  prompt. For `Text`, the prompt itself. `max_tokens` is 1,000 and
  `stream: false`. The same rules as AI-7 and AI-8 apply. The script builds
  its own prompt, so no framing is added.
- **AI-22.** It returns the answer, trimmed and cut to 8 KiB, as a string.
  On any failure (unknown model, no permission, rate limit, timeout, error) it
  returns `false`, as documented, and logs `ai.api-error`. The script carries
  on. The answer is always plain data. It's never evaluated as an expression
  or as Sieve.
- **AI-23.** Trusted scripts (the system scripts run at SMTP stages) can
  always call it. An account's own scripts can only when the account holds
  `interactAi`. The prompt is cut to 32 KiB. The wait is the shorter of the
  model's `timeout` and `spamCallCeiling` in trusted scripts. In an account's
  own scripts it is the model's `timeout`, capped at 60 s. **Decision**.
- **AI-24.** An account's own scripts may make `userCallsPerHour` calls an
  hour and one at a time. Calls over the limit return `false` at once. Calls
  share the `maxConcurrentCalls` slots and the back-off in AI-10 and AI-11.
  **Decision**: without this, any user could keep a CPU-only model busy for
  everyone.
- **AI-25.** Every account-script call logs the account, the model's name and
  the response time, never the prompt, so an operator can see who uses the
  model and how much.

### Administration

- **AI-26.** `x:AiModel` and `x:SpamLlm` are available on every server,
  answering normally, with no edition check. The Enterprise upsell error in
  `crates/jmap/src/registry/mod.rs` no longer applies to them.
- **AI-27.** They're server-level. A tenant administrator can't read or change
  them, whatever its role, since a model's URL and secrets are server
  configuration. Tenant users' scripts can still call models they know the
  name of, subject to AI-23 and AI-24.
- **AI-28.** Secrets in `httpAuth` are never returned by `/get`, as for every
  other `x:SecretKey` field.

## Interfaces

- **Existing, unchanged:** `x:AiModel/get`, `/query`, `/set`; `x:SpamLlm/get`
  and `/set` (singleton); the field names, enums and defaults above; the
  permission names; the `ai.llm-response` and `ai.api-error` events; the
  `LLM_*` tag names; the `X-Spam-LLM` header name; the Sieve function name,
  arity and `false`-on-failure result.
- **Errors:** RFC 8620 `SetError` types. `invalidProperties` names the field
  (an empty `separator`, a `categories` set under 2, an out-of-range
  `temperature`, a `modelId` that doesn't exist). Destroying a model in use is
  refused with the registry's existing error for a linked object, naming
  `x:SpamLlm`.
- **New:** the limits singleton, in the fork's namespace.
- **The model's wire format** is AI-6 to AI-8 and AI-21. Any server that speaks
  the OpenAI-compatible chat or text completions API works. The docs name
  local servers first.

## ihasmail changes

These go in the INBUXA fork of ihasmail, ihasmail-inbuxa, never in public
ihasmail, which stays Stalwart-facing (SPEC.md §5).

- **Reading:** when a message has an `X-Spam-LLM` header, the message details
  (and the Junk banner, when the message is in Junk) show "Language model's
  opinion" with the tag's category and confidence and the explanation. It's
  labelled as one signal among several, never as the reason on its own.
- **Administration:** nothing new. Model and classifier settings are server
  configuration, and live in INBUXA Admin (SPEC.md §5.4). ihasmail's dashboard
  may link there.
- **Translation:** 2 new strings ("Language model's opinion" and "One of
  several signals the spam filter weighed"), each needed in all nine language
  catalogues: 18 entries. Categories and explanations come from the server
  and aren't translated.

**INBUXA Admin** (schema-driven, so it picks up both objects with no work)
needs only: the locality warning on the model form (AI-2); a local example
URL as the `url` placeholder; the fork's default prompt prefilled when the
classifier is switched to `Enable` (see below); and a note on the classifier
page that failures never hold up mail.

**Default prompt.** Upstream's documented prompt isn't copied. The fork's
default, prefilled only when an administrator enables the classifier, is this
project's own:

> Classify the email below as one of: Unsolicited, Commercial, Harmful,
> Legitimate. Unsolicited: bulk mail the recipient didn't ask for. Commercial:
> selling something. Harmful: phishing, fraud or malware. Legitimate: anything
> else. Then give your confidence: High, Medium or Low. Answer on one line as
> Category,Confidence,Reason with a reason of at most 20 words.

## Acceptance tests

Every test runs against inbuxa-server built with no Enterprise code. None
needs a hosted model. Each uses a local stub endpoint on loopback, spawned by
the test (the suite already has `spawn_mock_http_server`), which records what
it received and answers as each test needs. The gated `llm` case in
`tests/src/smtp/inbound/antispam.rs` is re-enabled, with its mock updated to
read the last message rather than the first (AI-6).

1. Fresh install: no `x:AiModel`, `x:SpamLlm` is `Disable`, and the stub
   receives nothing while mail flows (AI-1).
2. The twelve cases in `llm.test`: stub answers `Unsolicited,High,Test` and
   the rest give `LLM_UNSOLICITED_HIGH` and so on (AI-12).
3. Stub answers `unsolicited , HIGH , Lots of commas, here` gives
   `LLM_UNSOLICITED_HIGH`, and the header's explanation is
   `Lots of commas, here` (AI-12, AI-15).
4. Stub answers `Maybe,High,x`, an empty body, and text with no separator: no
   tag, no header, message delivered (AI-9, AI-12).
5. `responsePosConfidence: null` gives `LLM_UNSOLICITED` (AI-12).
6. The request the stub receives: system message is the prompt plus framing;
   user message carries the subject, the text, and markers with a fresh nonce
   each time; no addresses, other headers or attachment content anywhere
   (AI-3, AI-6, AI-8).
7. A 100 KiB body: the stub receives at most `maxContentBytes` of text and
   `[truncated]` (AI-4).
8. Stub never answers: the message is delivered within `spamCallCeiling`
   plus normal processing time, with no tag (AI-9).
9. Stub down for 5 messages: the next messages are scored without calling it
   until `failureBackoff` ends, then one probe request (AI-11).
10. `maxConcurrentCalls` 1, stub slow, two messages at once: one is
    classified, the other is delivered without a tag (AI-10).
11. `LLM_UNSOLICITED_HIGH` scored 50: the message's score rises by 5.0.
    `LLM_LEGITIMATE_HIGH` scored −50: it falls by 1.0.
    `LLM_HARMFUL_HIGH` set to `Reject`: the message isn't rejected (AI-13).
12. Stub's explanation contains CRLF, a fake header and non-ASCII text: one
    well-formed `X-Spam-LLM` header, RFC 2047-encoded. An inbound message
    carrying its own `X-Spam-LLM` loses it (AI-15).
13. An authenticated submission: the stub receives nothing (AI-16).
14. A `SpamRule` testing `LLM_HARMFUL_HIGH` fires (AI-17).
15. Stub replies with a 302 to another loopback port: not followed, counted
    as a failure (AI-8).
16. Bearer and Basic auth reach the stub, read from `Value`,
    `EnvironmentVariable` and `File` secrets. `/get` doesn't return them. The
    logs don't contain them (AI-5, AI-8, AI-28).
17. `llm_prompt('echo-test', 'hello world', 0.5)` in `test_mailbox.sieve`,
    with an `x:AiModel` named `echo-test` pointing at an echoing stub, returns
    `hello world` (AI-20 to AI-22).
18. `llm_prompt` with an unknown model, a failing stub, and from an account
    without `interactAi`: each returns `false` and delivery continues (AI-22,
    AI-23).
19. The 61st call in an hour from one account's script returns `false`
    without reaching the stub (AI-24).
20. A tenant administrator gets `forbidden` on `x:AiModel/get` and
    `x:SpamLlm/set` (AI-27).
21. A model on `https://mail.example.net/…` logs the locality warning. One on
    `127.0.0.1` or `10.0.0.5` doesn't (AI-2).
22. **(compat)** INBUXA's `x:AiModel` and `x:SpamLlm` records, if any, and
    its `LLM_*` `x:SpamTag` entries read back unchanged after cutover.

## Open questions / to observe

To check read-only against INBUXA's live Enterprise server later, as the
throwaway account and an administrator, with no settings changed:

1. Whether INBUXA has any `x:AiModel` (`/query`) or `x:SpamLlm` set to
   `Enable`, and where any model points. If none, compat test 22 has nothing
   to carry.
2. The `LLM_*` entries in `x:SpamTag/query`, and their scores. They show
   upstream's defaults for the ten tags not documented.
3. The exact `X-Spam-LLM` format upstream writes, from any message in the
   mail store that carries one. Only possible if INBUXA ever ran the
   classifier. AI-15 is a **Decision** until then.
4. Whether `llm_prompt` names a model by `name` or by id. The shared Sieve
   test uses `echo-test`, which reads like a name. Where upstream's
   `echo-test` model comes from in its tests isn't settled by any allowed
   source, so test 17 creates it.
5. Whether ordinary accounts hold `interactAi`, from an account's effective
   permissions. This repository's defaults say yes; the public table says
   administrators only.
6. What upstream does when a model that `x:SpamLlm` uses is destroyed (only
   observable by changing settings, so it needs the operator's approval and a
   stub model). AI-18 is a **Decision** meanwhile.
7. Whether upstream classifies authenticated submissions, and what it does on
   a timeout (again, needs a temporary stub model and the operator's
   approval).

Not for observation, but open:

8. A per-account or per-domain opt-out from classification, for users who
   don't want their mail read by a model even locally. Not in upstream's
   schema. A later addition in the fork's namespace if asked for.
9. A "test this model" action for INBUXA Admin. Useful, not required.
10. The name of the fork's limits singleton, with the namespace (SPEC.md §8).
