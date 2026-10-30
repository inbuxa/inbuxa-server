# Security policy

## Supported versions

Security fixes go into the newest release and into every older line still
inside its security window. When a new series ships, the one before it gets
three more months of security fixes. The full policy is on
[Versions and upgrades](https://docs.inbuxa.org/versions/).

| Version | Supported |
| --- | --- |
| `main` and the newest release | :white_check_mark: |
| The previous series, for three months after a new one ships | Security fixes only |
| 2026.x, until three months after 27.1 ships | Security fixes only |
| Release candidates | Replaced by the next candidate |
| Anything older | :x: |

## Reporting a vulnerability

**Please don't open a public issue for a security problem.** An issue is
visible to everyone, including whoever would use it, before there is a fix.

Report it privately by email to:

**securityATcoffeylabsDOTorg**

Include as much as you can of:

- what the vulnerability is, and what it lets someone do;
- how to reproduce it, or a proof of concept;
- the version or commit affected;
- anything about the deployment that matters — backend, front ends, whether
  it needs an authenticated account.

You'll get an acknowledgement within a few days. If a report turns out to
affect upstream Stalwart rather than this fork's own code, it will be passed
to Stalwart Labs with credit to you, and you'll be told that has happened.

## Scope

This repository is the mail server. The web front ends have their own:

- [inbuxa-admin](https://git.coffeylabs.org/inbuxa/inbuxa-admin)
- [inbuxa-webmail](https://git.coffeylabs.org/inbuxa/inbuxa-webmail)

Upstream's own security documents are kept in `.github-upstream/` for
reference. They describe Stalwart Labs' process, not this project's.
