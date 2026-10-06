# Security policy

## Supported versions

INBUXA is developed on `main`, and security fixes are applied there and in
the latest release. Older tags are not backported.

| Version | Supported |
| --- | --- |
| `main` and the latest release | :white_check_mark: |
| Older releases | :x: |

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
