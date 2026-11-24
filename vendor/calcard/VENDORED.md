# calcard, vendored

The published [calcard](https://crates.io/crates/calcard) **0.3.14**, taken
from crates.io (`.crate` sha256
`c601473ec15a875626bce73db1a1f0fc81e9c949ca25f1463b714947c0a70a1f`, the
checksum the server's `Cargo.lock` had for it) under Apache-2.0 OR MIT.
INBUXA takes it under MIT. The root `Cargo.toml` patches it in with
`[patch.crates-io]`.

Left out: the top-level `resources/` (26 MB of iCalendar, vCard,
JSCalendar and JSContact samples) and `.github/`, which the server never
builds, and `Cargo.lock`, `Cargo.toml.orig`, `.cargo_vcs_info.json` and
`.cargo-ok`. The crate's own tests that read `resources/` (`expand_rrule`, `parse_ical`, `parse_vcard`,
`convert_jscalendar`, `convert_jscontact` and `remove_component_ids`) can't
run here; the crate's other tests run from this directory with:

    cargo test --offline --target-dir ../../target/calcard-tests -- \
      --skip expand_rrule --skip parse_ical --skip parse_vcard \
      --skip convert_jscalendar --skip convert_jscontact \
      --skip remove_component_ids

## Changes

Every changed file carries a Coffey Labs notice in its header.

- `.gitignore`: `VENDORED.md` is tracked (upstream ignores every `*.md`
  but the changelog and README).
- `src/datecalc/mod.rs`, `src/datecalc/rrule_iter.rs`,
  `src/datecalc/counter_date.rs`, `src/icalendar/dates.rs`: one
  `expand_dates` call has a single work budget for all its recurrence rules
  (`MAX_EXPANSION_WORK`, 1,000,000 units, about 50 ms in a release build).
  Upstream only stops a rule after 100,000 passes that find nothing, counted
  afresh for every instance and every rule, so a calendar of a few thousand
  rules that never match (`FREQ=MONTHLY;BYMONTH=2;BYMONTHDAY=31`), or one
  sparse rule, took seconds to minutes. A pass over a period costs one unit,
  a pass that finds nothing one per 16 days it scanned, each candidate a
  pass looks at without producing it one, and each time skipped while
  looking for the next `BYHOUR`/`BYMINUTE`/`BYSECOND` match one
  (`DateTimeIter::increment_counted` counts those). When the budget runs
  out, expansion stops: the instances found so far are kept, as when the
  instance limit is reached, later rules aren't expanded, and the result
  carries a `CalendarErrorType::ExpansionBudgetExhausted` error for the
  component it stopped at. Rules are no longer started once the instance
  limit is reached (they couldn't add anything). The `budget_tests` in
  `dates.rs` cover it, and `rule_expansion_shares_one_budget` in
  `crates/groupware` fails to build if the server stops using this copy.
- `src/icalendar/dates.rs`: a component whose DTSTART carries an offset
  (`DTSTART:20261102T180000Z`) has that zone as its start zone. Upstream
  took the default zone, which the server passes as floating, so every
  instance of a UTC rule came out floating (one-off events were already
  right), and the server then read the series in the zone each request asked
  for. The `start_zone_tests` in `dates.rs` cover it. calcard 0.4 makes the
  same change.
- `src/jscontact/export/convert.rs`, `src/jscontact/import/convert.rs`: a
  JSContact online service with a `user` and no `uri` is written as a
  `SOCIALPROFILE;VALUE=TEXT` whose value is the user name, and a TEXT
  `SOCIALPROFILE` reads back as `user` (RFC 9555, Section 2.7.5). Upstream
  wrote the user name in a `USERNAME` parameter on an empty value, which read
  back as nothing (or as `"uri": ""`), so the service was lost; such a stored
  vCard now reads back as `user` too. A service with a `uri` still carries
  its user name in `USERNAME`. The crate's `resources/jscontact/017_rfc9554.txt`
  case "RFC9554 SOCIALPROFILE" expects the TEXT value as `uri`; with this
  change it is `user` (the only case in `convert_jscontact` that changes).
  The `online_service_tests` in `src/jscontact/mod.rs` cover it.

- `src/icalendar/timezone.rs`: `add_missing_timezones` leaves an object
  with at most `MAX_ADDED_TIMEZONES` (32) time zone definitions: it adds
  definitions for the zones it names first, until the object holds 32,
  and none for the rest. One event and its overrides name one to three
  zones. The zones defined and named are looked up in sets. Upstream
  generated a definition, a scan of the zone's rules over the event's
  years, for every zone an object named, and checked each name against
  lists, so an iTIP message naming hundreds of zones cost seconds and grew
  the stored event by hundreds of definitions. The
  `test_add_missing_timezones_is_capped` test in `timezone.rs` covers it.

## Updating

When the server's `Cargo.lock` moves calcard to a new version, Cargo stops
using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `calcard` entry with a `source` line. Re-vendor the new
version from `~/.cargo/registry/src/*/calcard-*`, dropping the top-level
`resources/` and `.github/`, `Cargo.lock`, `Cargo.toml.orig`,
`.cargo_vcs_info.json` and `.cargo-ok` (`rsync --exclude /resources
--exclude /.github ...`), repeat the changes above, and update the version
here and in the root `Cargo.toml` comment.
