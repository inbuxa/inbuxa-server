<p align="center">
  <img src="./img/brand/inbuxa-lockup-light.svg" alt="inbuxa" height="140">
</p>

<h3 align="center">
  Self-hosted mail, calendars, contacts and files, enterprise features included
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

**inbuxa** is a self-hosted mail and collaboration server from Coffey Labs. It
speaks JMAP, IMAP, POP3, SMTP, CalDAV, CardDAV and WebDAV from one Rust binary.
Project site: [inbuxa.org](https://inbuxa.org). Documentation:
[docs.inbuxa.org](https://docs.inbuxa.org).

The server is one part of a suite. [inbuxa Admin](https://git.coffeylabs.org/inbuxa/inbuxa-admin)
is the console that runs it, and [inbuxa Webmail](https://git.coffeylabs.org/inbuxa/inbuxa-webmail)
is where people read their mail. Each is its own program, so the mail host
doesn't have to serve a web front end at all.

## What's included

There is one edition and no paid tier. Nothing checks a license key.

- **For organizations:** tenants, SCIM provisioning, single sign-on, per-domain
  directories and branding.
- **For compliance:** audit log, [legal holds](https://docs.inbuxa.org/run/legal-holds/),
  data loss prevention, mail flow rules and journaling.
- **For people:** masked addresses, undelete, shared mailboxes, calendars,
  contacts and files.
- **For operators:** monitoring and alerts, [clustering](https://docs.inbuxa.org/run/clustering/)
  and scale-out storage, plus [inbuxa Relay](https://docs.inbuxa.org/run/relay/)
  for a server that can't take mail from the internet directly.
- **Local AI, if you want it:** a model you run yourself. It stays off until you
  turn it on.

## Where it's going

**inbuxa** is its own project now, and it's built to stay that way.

- **Its own release line.** Two series a year, in January and July, with one
  version number across the suite. 27.1 ships in January 2027, and its release
  candidates are out now. See [Versions and upgrades](https://docs.inbuxa.org/versions/).
- **Its own data layout.** From 27.1 the store's format belongs to **inbuxa** and
  changes when **inbuxa** needs it to.
- **Its own security work.** Fixes are written and released here, under a
  published support window. See [SECURITY.md](./SECURITY.md).
- **Your way out stays open.** inbuxa-migrate brings accounts in from other mail
  servers. It also writes them back out as plain files, in a
  [published layout](https://coffeylabs.org/specs/account-export/) that any
  software can read. See [Leaving inbuxa](https://docs.inbuxa.org/install/accounts/#leaving).
- **Open standards.** We work on JMAP at the IETF. Our undelete work is now part
  of [JMAP Object History](https://datatracker.ietf.org/doc/draft-ietf-jmap-object-history/),
  a working group draft we co-author.
- **Source you can check.** A running server names the exact source of its build
  at `/.well-known/source`.

## Where it came from

**inbuxa** started as a fork of Stalwart.
[Where the code comes from](https://docs.inbuxa.org/provenance/) has the full
record. Moving from a Stalwart 0.16 server is an export and an import, covered
in [Coming from Stalwart](https://docs.inbuxa.org/install/migrating/).

## Building

```bash
cargo build --release -p inbuxa          # the binary is target/release/inbuxa
docker build -t inbuxa .                 # or the container image
```

Settings are read from `INBUXA_*` environment variables. New installs keep
their data in `/var/lib/inbuxa` and logs in `/var/log/inbuxa`. Existing installs
keep the paths their configuration already names, so none of their data moves.

## License and credits

**inbuxa** is free software under the [GNU Affero General Public License,
version 3](./LICENSES/AGPL-3.0-only.txt). It is a Coffey Labs project.

It started as a fork of Stalwart, copyright © Stalwart Labs LLC, **modified by
Coffey Labs in 2026**. Upstream's copyright notices are kept on every file
they cover, and every upstream file changed for **inbuxa** says so in its header,
under the notice it came with. Stalwart's files are dual-licensed
AGPL-3.0-only or Stalwart's Enterprise License, and **inbuxa** takes them under
the AGPL-3.0 only. A few of those files also carry code from other projects
under MIT or BSD licenses, which stays under those licenses;
[THIRD-PARTY.md](./THIRD-PARTY.md) lists it with its notices. Stalwart is a
trademark of Stalwart Labs LLC. **inbuxa** is not affiliated with or endorsed by
Stalwart Labs.

`LICENSES/LicenseRef-SEL.txt` (and its copy in `vendor/sieve-rs/`) is there
only because the inherited headers name it as upstream's other option, and
a license a header names has to be in `LICENSES/`. It isn't a license for
**inbuxa** and grants nothing: **inbuxa** is distributed under the
AGPL-3.0-only.
