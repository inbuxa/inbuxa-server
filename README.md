<p align="center">
  <img src="./img/brand/inbuxa-lockup-light.svg" alt="inbuxa" height="140">
</p>

<h3 align="center">
  A complete mail and collaboration server, every feature included, under the AGPL
</h3>

<p align="center">
  <a href="LICENSES/AGPL-3.0-only.txt"><img alt="License: AGPL-3.0-only" src="https://img.shields.io/badge/license-AGPL--3.0--only-2dd4bf?style=flat-square"></a>
  <a href="https://git.coffeylabs.org/inbuxa/inbuxa-server/releases/latest"><img alt="Latest release" src="https://img.shields.io/gitea/v/release/inbuxa/inbuxa-server?gitea_url=https%3A%2F%2Fgit.coffeylabs.org&label=release&color=2dd4bf&style=flat-square"></a>
  <a href="https://docs.inbuxa.org/install/server/"><img alt="Documentation: docs.inbuxa.org" src="https://img.shields.io/badge/docs-docs.inbuxa.org-0ea5e9?style=flat-square"></a>
  <a href="https://community.coffeylabs.org/c/inbuxa/5"><img alt="Forum: community.coffeylabs.org" src="https://img.shields.io/badge/forum-community.coffeylabs.org-0f766e?style=flat-square"></a>
  <a href="https://discord.gg/nqcY4TKfAn"><img alt="Chat on Discord" src="https://img.shields.io/discord/1523538164084637797?label=discord&logo=discord&logoColor=white&color=5865f2&style=flat-square"></a>
</p>

---

> [!NOTE]
> Development happens on [git.coffeylabs.org/inbuxa/inbuxa-server](https://git.coffeylabs.org/inbuxa/inbuxa-server); the copy on GitHub is a read-only mirror.
> Report issues at **[git.coffeylabs.org/inbuxa/inbuxa-server/issues](https://git.coffeylabs.org/inbuxa/inbuxa-server/issues)**, join discussions at **[community.coffeylabs.org](https://community.coffeylabs.org)**, or chat on **[Discord](https://discord.gg/nqcY4TKfAn)**.

**inbuxa** is a mail and collaboration server: JMAP, IMAP, POP3, SMTP,
CalDAV, CardDAV and WebDAV, in one Rust binary, with ihasmail as its web front
end. It is a fork of [Stalwart](https://github.com/stalwartlabs/stalwart).
Project site: [inbuxa.org](https://inbuxa.org). Documentation: [docs.inbuxa.org](https://docs.inbuxa.org).

Stalwart ships some features only in a paid Enterprise Edition: multi-tenancy,
masked email, undelete and others. **inbuxa** ships everything to everybody under
the AGPL-3.0, rebuilding those features independently and without using any
of Stalwart's Enterprise code.

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
install's `STALWART_*` variables aren't read: the server stops at startup and
names each one to rename.
New installs keep their data in `/var/lib/inbuxa` and logs in
`/var/log/inbuxa`. Existing installs keep the paths their configuration
already names, so none of their data moves.

## License and credits

**inbuxa** is free software under the [GNU Affero General Public License,
version 3](./LICENSES/AGPL-3.0-only.txt).

It is a fork of Stalwart, copyright © Stalwart Labs LLC, **modified by
Coffey Labs in 2026**. Upstream's copyright notices are kept on every file
they cover, and every upstream file this fork changed says so in its header,
under the notice it came with. Stalwart's files are dual-licensed
AGPL-3.0-only or Stalwart's Enterprise License, and **inbuxa** takes them under
the AGPL-3.0 only. A few of those files also carry code from other projects
under MIT or BSD licenses, which stays under those licenses;
[THIRD-PARTY.md](./THIRD-PARTY.md) lists it with its notices. "Stalwart" is
Stalwart Labs' name. **inbuxa** isn't affiliated with or endorsed by Stalwart
Labs.

The **inbuxa** mark reuses ihasmail's cat-and-envelope artwork.
