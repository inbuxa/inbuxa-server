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

## Updating

When the server's `Cargo.lock` moves calcard to a new version, Cargo stops
using this copy and only warns that the patch went unused, so check
`Cargo.lock` has no `calcard` entry with a `source` line. Re-vendor the new
version from `~/.cargo/registry/src/*/calcard-*`, dropping the top-level
`resources/` and `.github/`, `Cargo.lock`, `Cargo.toml.orig`,
`.cargo_vcs_info.json` and `.cargo-ok` (`rsync --exclude /resources
--exclude /.github ...`), repeat the changes above, and update the version
here and in the root `Cargo.toml` comment.
