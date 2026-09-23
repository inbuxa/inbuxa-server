# Fork tooling

## strip.py

Makes an Enterprise-free snapshot of an upstream release. See the docstring
and docs/spec/SPEC.md §2.2 for what it does and why.

```bash
git clone https://github.com/stalwartlabs/stalwart.git ~/src/stalwart-upstream   # outside this repo
git -C ~/src/stalwart-upstream fetch --tags
tools/fork/strip.py --upstream ~/src/stalwart-upstream --ref v0.16.22 --out /tmp/strip-v0.16.22
```

It writes `OUT/tree` (the stripped source) and `OUT/STRIP-REPORT.md` and
`.json`. Exit 0 means verified clean. Exit 1 means malformed markers, or
something Enterprise-only survived. Read the report's Problems section.

The report's Third-party code section lists upstream code under other
licenses. Files marked **new** need their notice added to `THIRD-PARTY.md`
at the repository root before the import is merged.

It needs Python 3.12+ (for `tarfile`'s `data` filter), git and cargo.

Two passes run after the strip:

- **Renames.** The upstream name is replaced where it's an identifier
  clients, users or operators meet: wire-protocol names, the web interface's
  client id, store keys, configuration defaults and the served schema, as
  `renames.py` lists them. `main` was renamed with the same module. A
  re-import arrives purged, so those lines never conflict. Copyright notices
  and prose are left alone. The report lists every substitution by file.
- **Build check.** The stripped tree is compiled (`cargo check --workspace
  --all-targets`) into `target/strip-check`, which stays warm between
  imports. A file that survived the strip but calls code that didn't fails
  the run; the report names it. Handle it in the merge into `main`, never on
  `upstream`: `upstream` holds the strip's output and nothing else. Imports
  the strip left unused are listed without failing. `--no-build-check`
  skips the pass.

## name-check.py

Fails when the upstream project's name appears in a Rust string literal that
`name-allowlist.txt` doesn't list. CI runs it on every push and pull request,
so an upstream merge can't bring the name back into what users and operators
see. Comments, copyright headers and test directories aren't checked.

```bash
tools/fork/name-check.py          # exit 1 on anything new
tools/fork/name-check.py --list   # every finding, in allowlist format
```

Rename what it reports. If a string has to stay, such as a key-derivation
context or a wire-protocol identifier, add its `--list` line to the allowlist
under the reason it stays.

## notice-check.py

Fails when an upstream file the fork changed doesn't carry the AGPL 5(a)
notice, `Modified by Coffey Labs in <year> for INBUXA.`, under upstream's
license line. "Changed" means it differs from the `upstream` branch, so the
list comes from the diff, not from memory. CI runs it beside the name check.

```bash
tools/fork/notice-check.py          # exit 1 on a missing notice
tools/fork/notice-check.py --fix    # add it where it's missing
```

Run `--fix` after resolving an upstream merge: a conflict resolved by taking
upstream's side can drop a notice the file had.

## record-compat.py

Records what the `*_compat` tests compare against, from the Enterprise
server, while it is still running. Read-only: `/get` and `/query` only.
See `docs/spec/compat-tests.md`.

```bash
tools/fork/record-compat.py --server https://mail.example.org \
    --admin 'admin@example.org:PASSWORD' --out ./compat \
    --tenant-admin 'tenant-admin@example.org:PASSWORD'
```

## run-compat.sh

Runs the `*_compat` tests against a copy of INBUXA's RocksDB store, making
a fresh copy for each one. See `docs/spec/compat-tests.md`.

```bash
tools/fork/run-compat.sh --store /srv/inbuxa-copy/rocks.db \
    --admin 'admin@example.org:PASSWORD' --recordings ~/compat
```
