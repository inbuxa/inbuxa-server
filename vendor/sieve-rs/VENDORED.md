# sieve-rs, vendored

The published [sieve-rs](https://crates.io/crates/sieve-rs) **0.7.3**, taken
from crates.io under AGPL-3.0-only, with the upstream project's name taken
out of the identifiers it spells into the Sieve language (docs/spec/SPEC.md
§2.4). The root `Cargo.toml` patches it in with `[patch.crates-io]`.

## Changes

Every changed file carries the AGPL 5(a) notice in its header.

- `src/compiler/grammar/mod.rs`: the extensions scripts `require` and
  ManageSieve advertises are `vnd.inbuxa.while` and
  `vnd.inbuxa.expressions`. The pre-rename `vnd.stalwart.*` spellings are
  still accepted, never advertised, so a script written for upstream compiles
  when it's edited. Without them, the name is treated as an unknown extension
  and `let` or `eval` fails with "Undeclared capability". The
  `legacy_extension_names` tests cover both.
- `src/runtime/mod.rs`: the default `environment "name"` is `inbuxa Sieve`
  (the server sets its own name on both of its runtimes anyway), and the
  test-only capability is `vnd.inbuxa.testsuite`.
- `src/lib.rs`: the test-suite environment variables are `vnd.inbuxa.*`.
- `src/runtime/tests/comparator.rs`, `src/compiler/grammar/mod.rs`: every
  `:regex` pattern is built through `build_regex`, which holds the compiled
  matcher and its lazy DFA to 1 MiB each (fancy-regex's default is 10 MiB),
  and a pattern built from variables is compiled once per run (`RegexCache`,
  32 patterns, a field of `Context` in `src/lib.rs` and
  `src/runtime/context.rs`) instead of once for every value it is tested
  against. Every caller of `Comparator::regex` passes the cache. The
  `sieve_regexes_are_size_limited` and `sieve_variable_patterns_compile_once`
  tests in `crates/common` cover both.
- `src/runtime/context.rs`, `src/lib.rs`, `src/runtime/tests/test_header.rs`,
  `test_address.rs`, `test_body.rs`, `test_string.rs`, `test_exists.rs`,
  `src/runtime/actions/action_editheader.rs`: the bytes that tests scan count
  against the cpu limit, one instruction for every 64 KiB
  (`SCAN_BYTES_PER_INSTRUCTION`). Header, address, body and string tests and
  `deleteheader` charge each value they compare times the number of keys, and
  every search for a header charges the part's header block; the total is
  `Context::scanned_bytes`. A test stops scanning once the run is over the
  limit, and the run fails with `CPULimitReached` as it does for too many
  instructions (`deleteheader` then deletes nothing). The `scan_limit_tests`
  in `context.rs` cover it; they run from this directory with `cargo test
  --offline --target-dir ../../target/sieve-rs-tests scan_limit` (the crate's
  `test_suite` and `parse_rfc` need upstream's `tests/`, which isn't kept).
- `src/runtime/actions/action_vacation.rs`, `action_notify.rs`: vacation
  and notify stay silent for mail with `Auto-Submitted` other than `no`
  (RFC 3834). Upstream looked for the header as `HeaderName::Other`, but
  mail-parser 0.11 parses it as `HeaderName::AutoSubmitted`, so the check
  never ran and both answered other programs' mail, autoresponders included.
  Upstream 0.7.3 fails its own svtests "No reply to auto-submitted mail" and
  "Notifying on automated messages" for this reason. The
  `sieve_auto_submitted_mail_gets_no_reply` test in `crates/common` covers it.
- `src/runtime/tests/test_string.rs`: `string` is true when any key matches
  any source. Upstream's `break` on a match only left the loop over sources,
  so the next key overwrote the result: `string :is "a" ["a", "b"]` was
  false while `["b", "a"]` was true.
- `src/runtime/tests/test_date.rs`: `date :regex` and `currentdate :regex`
  compare with the regex comparator (through the same size limit and
  cache); upstream compared them as `:matches` wildcard patterns, so
  `"^20[0-9]{2}$"` never matched a year. The
  `sieve_tests_match_any_key_and_regex_dates` test in `crates/common`
  covers both.
- `src/runtime/actions/action_mime.rs`, `src/runtime/tests/mime.rs`,
  `action_editheader.rs`: `replace` removes the replaced part's children
  with `Context::remove_parts`, which renumbers the parts left (every
  multipart's child list, the body and attachment lists, and every
  `foreverypart` iterator with the part it returns to), and `enclose` ends
  any `foreverypart` loop it runs in. Upstream shifted the parts with
  `Vec::remove` and left the loop's ids stale, so `replace` or `enclose`
  inside `foreverypart` (RFC 5703's attachment stripping) panicked the
  delivery on a message with nested parts. Headers are added and removed
  only on a part that exists, and the message size can't wrap below zero.
  The `sieve_replace_inside_foreverypart` test in `crates/common` covers it.
- `src/runtime/actions/action_vacation.rs`, `action_notify.rs`,
  `action_mime.rs`, `action_editheader.rs`, `src/runtime/context.rs`: every
  header value written into a message the runtime builds (the vacation
  reply, the notify mailto message, `enclose`, `replace`, `addheader`) goes
  through `remove_crlf`, which drops CR, LF and every other control but tab
  and caps it at the runtime's `max_header_size`. That covers values from
  the script (`:subject`, `:from`, `:message`), from the mailto URI and
  from the inbound message (its Subject, decoded, so an RFC 2047 word can
  carry a CR or LF; its Message-ID), and the account's name in From. Upstream wrote the
  vacation and notify headers raw and enclose's Subject fallback raw, so a
  Subject like `=?utf-8?b?eA0KQmNjOiB2aWN0aW1AZXhhbXBsZS5jb20=?=` put a
  `Bcc:` line into a signed auto-reply. A mailto URI whose parameter name
  isn't a field name, or whose address holds a control (a `%0D%0A`), is
  refused. The `header_injection_tests` in `action_editheader.rs` cover it
  (run like `scan_limit_tests`).
- `src/runtime/context.rs`: `Context::main_message_id()` returns the id of
  the inbound message as the script left it (0, or its edited copy), so the
  server can tell a redirect (a `SendMessage` of that message) from a
  vacation reply or a notification, which send messages of their own. A
  redirected copy keeps the spam verdict of the recipient who redirected it.
  The delivery test in the system suite covers it.
- `src/runtime/actions/action_vacation.rs`: vacation stays silent for mail
  the server's spam filter classified as spam: a spam status of 50% or more,
  which the server sets from its own verdict, the line at which it files mail
  into Junk. Before, spam was answered, and replies went to forged senders.
  The `sieve_spam_gets_no_vacation_reply` test in `crates/common` covers it.
- `src/runtime/actions/action_vacation.rs`, `src/lib.rs`,
  `src/runtime/context.rs`: one vacation reply per message (RFC 5230, 4.7).
  `Context::vacation_sent` is set when a reply is queued, and a later
  `vacation` in the same run (another branch, an include) sends nothing.
  Upstream answered once for every `vacation` the script reached, up to
  `max_out_messages`. The `sieve_one_vacation_reply_per_message` test in
  `crates/common` covers it.
- `src/runtime/actions/action_notify.rs`: a notify `mailto:` URI can't set
  the header fields RFC 5436 (2.7) says to ignore, `From`,
  `Auto-Submitted`, `Received`, `Date` and `Message-ID`, or the ones the
  runtime writes about the message itself, `X-Sieve`, `Content-Type` and
  `Content-Transfer-Encoding` (`URI_HEADERS_IGNORED`, compared by name, so a
  parameter without a value is caught too). The notification always has
  one `Auto-Submitted: auto-notified` and its own `Date` and `Message-ID`.
  Upstream skipped only `From`, copied the rest (`?auto-submitted=no` gave
  a second `Auto-Submitted`), and let a URI's `Date` or `Message-ID`
  replace the generated one. The `sieve_notify_mailto_ignores_unsafe_uri_headers`
  test in `crates/common` covers it.
- `src/runtime/expression.rs`: a string or array that `+` builds holds at
  most `max_variable_size` bytes (counted as `Variable::len` counts them),
  cut at a character or before the item that doesn't fit
  (`Variable::op_add_limited`). Upstream built every sum in full, and only
  `let` truncated the end result, so one expression of thousands of terms
  copied gigabytes in one instruction, which the cpu limit doesn't see. The
  `concat_limit_tests` in `expression.rs` cover it (run like
  `scan_limit_tests`).
- `src/runtime/actions/action_mime.rs`: the message `enclose` builds
  carries the Received headers of the message it encloses at its top level
  (CR and LF taken out, each cut to `max_header_size`). Upstream started it
  with none, so the server's hop limit, which counts the Received headers
  of each message it delivers, never stopped a script that encloses and
  redirects to an account that sends the mail back. The
  `enclose_hop_tests` in `action_mime.rs` cover it (run like
  `scan_limit_tests`).
- `Cargo.toml`: the example target is dropped, with the top-level
  `examples/` and `tests/`, which the server never builds. (`src/` keeps its
  own `tests` modules: the crate declares them.)

## Updating

When the server's `Cargo.lock` moves sieve-rs to a new version, Cargo stops
using this copy and only warns that the patch went unused. The unit test
`sieve_extensions_carry_the_fork_name` in `crates/common` fails when that
happens. Re-vendor the new version from `~/.cargo/registry/src/*/sieve-rs-*`,
dropping the top-level `tests/` and `examples/` (only those: `rsync
--exclude /tests --exclude /examples`), `Cargo.lock` and `Cargo.toml.orig`, repeat
the changes above, and update the version here and in the root `Cargo.toml`
comment. `tools/fork/name-check.py` covers `vendor/` too, so a rename missed
in a new version fails CI.
