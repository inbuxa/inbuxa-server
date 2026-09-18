<p align="center">
  <img src="./img/brand/inbuxa-lockup-light.svg" alt="inbuxa" height="140">
</p>

<h3 align="center">
  A complete mail and collaboration server, every feature included, under the AGPL
</h3>

---

**INBUXA** is a mail and collaboration server: JMAP, IMAP, POP3, SMTP,
CalDAV, CardDAV and WebDAV, in one Rust binary, with ihasmail as its web front
end. It is a fork of [Stalwart](https://github.com/stalwartlabs/stalwart).
Project site: [inbuxa.org](https://inbuxa.org) (not up yet).

Stalwart ships some features only in a paid Enterprise Edition: multi-tenancy,
masked email, undelete and others. INBUXA ships everything to everybody under
the AGPL-3.0, rebuilding those features independently and without using any
of Stalwart's Enterprise code.

> **Status: in development, not released.** The fork builds, passes its unit
> tests, and runs as a working mail server. The Enterprise features are being
> specified and haven't been rebuilt yet. Don't run it in production.

## What's different from Stalwart

- **Every feature, one edition.** No license key, no edition checks, no
  upsell. See `docs/spec/SPEC.md` §4 for the features being rebuilt, and
  `docs/spec/features/` for each one's specification.
- **Webmail and administration by ihasmail,** as a separate service that can
  run beside the server or elsewhere. Stalwart's own web interface is removed,
  so there's no web front end on the mail host.
- **Clean-room rebuilds.** Enterprise-only code is stripped from every
  upstream release before it's imported. The rebuilt features are written
  from specifications that use only public sources (`docs/spec/SPEC.md` §3).

## How the fork is kept

Upstream releases arrive as stripped snapshots, never with upstream's git
history, which contains Enterprise code. `tools/fork/strip.py` builds each
snapshot on top of upstream's own `ossify.py`, then verifies it independently.
The report for every import is in `docs/fork/strip-reports/`. See
`docs/spec/SPEC.md` §2.

## Building

```bash
cargo build --release -p inbuxa          # the binary is target/release/inbuxa
docker build -t inbuxa .                 # or the container image
```

Settings are read from `INBUXA_*` environment variables. An existing Stalwart
install's `STALWART_*` variables still work, with a warning to rename them.
New installs keep their data in `/var/lib/inbuxa` and logs in
`/var/log/inbuxa`. Existing installs keep the paths their configuration
already names, so none of their data moves.

## License and credits

INBUXA is free software under the [GNU Affero General Public License,
version 3](./LICENSES/AGPL-3.0-only.txt).

It is a fork of Stalwart, copyright © Stalwart Labs LLC. Upstream's
copyright notices are kept on every file they cover. Stalwart's files are
dual-licensed AGPL-3.0-only or Stalwart's Enterprise License, and INBUXA takes
them under the AGPL-3.0 only. "Stalwart" is Stalwart Labs' name. INBUXA isn't
affiliated with or endorsed by Stalwart Labs.

The INBUXA mark reuses ihasmail's cat-and-envelope artwork.
