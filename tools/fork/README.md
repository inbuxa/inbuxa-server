# Fork tooling

## strip.py

Makes an Enterprise-free snapshot of an upstream release. See the docstring
and SPEC.md §2.2 for what it does and why.

```bash
git clone https://github.com/stalwartlabs/stalwart.git ~/src/stalwart-upstream   # outside this repo
git -C ~/src/stalwart-upstream fetch --tags
tools/fork/strip.py --upstream ~/src/stalwart-upstream --ref v0.16.22 --out /tmp/strip-v0.16.22
```

It writes `OUT/tree` (the stripped source) and `OUT/STRIP-REPORT.md` and
`.json`. Exit 0 means verified clean. Exit 1 means malformed markers, or
something Enterprise-only survived. Read the report's Problems section.

It needs Python 3.12+ (for `tarfile`'s `data` filter) and git.
