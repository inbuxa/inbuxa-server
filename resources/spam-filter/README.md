# Bundled spam filter rules

`spam-filter-rules.json.gz` holds the server's default spam rules. The server
embeds it (`crates/common/src/manager/spam_rules.rs`) and loads it whenever no
other rules source is configured, so a release scores mail with the rules it
was tested with, offline and with nothing to fetch. The rules URL setting
stays an operator override.

The file started as the published rules of
[spam-filter](https://github.com/stalwartlabs/spam-filter) **v3.0.2**. Since
2026-10-28 the fork maintains it here: spam-filter's later releases follow
upstream's 1.0 server (its `AI_*` tag names, its lookup settings), which this
server doesn't use, so they aren't taken in. `BUNDLED_SPAM_RULES_VERSION`
names the release the rules started from and the fork's revision of them,
for example `3.0.2-inbuxa.1`.

The v3.0.2 rules are dual-licensed MIT or Apache-2.0, Copyright (C) 2024,
Stalwart Labs LLC; the fork takes them under MIT, with the notice in
`THIRD-PARTY.md`.

They include the scores for the AI classifier's tags (`LLM_*`, 3.0 for the
high-confidence spam categories, −3.0 for legitimate), which match
`docs/spec/features/ai-spam-classification.md`.

## Changes since v3.0.2

| Revision | Change |
|---|---|
| `inbuxa.1` | Scores for the DKIM2 result tags the server already emits (`crates/spam-filter/src/analysis/dmarc.rs`): `DKIM2_ALLOW` −0.2, `DKIM2_REJECT` 1.0, and `DKIM2_NA`, `DKIM2_PERMFAIL`, `DKIM2_TEMPFAIL` 0.0. The values are spam-filter v3.0.3's. |

## Changing the rules

1. Edit the JSON (`gunzip -c` it; it's one line, keys in their original
   order) and write it back compact, then compress it without a name or
   timestamp so the file is reproducible: `gzip -n -9`.
2. Bump the revision in `BUNDLED_SPAM_RULES_VERSION` and
   `BUNDLED_SPAM_RULES_APPLIED` (`spam_rules.rs`), and add a row above.
3. Run the antispam test (`STORE=RocksDb RUST_MIN_STACK=16777216 cargo test
   -p tests --lib -- smtp::inbound::antispam::antispam --exact`) and fix
   expectations the change affects, knowingly.

On the next start each server loads the new version once. Loading only adds
rules and tags that are missing; it never changes an existing one, so an
operator's own adjustments survive.
