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

It needs Python 3.12+ (for `tarfile`'s `data` filter) and git.

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
