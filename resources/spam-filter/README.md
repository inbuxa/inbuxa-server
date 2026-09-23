# Bundled spam filter rules

`spam-filter-rules.json.gz` is the published rules file of
[spam-filter](https://github.com/stalwartlabs/spam-filter) **v3.0.2**,
unmodified. The server embeds it (`crates/common/src/manager/spam_rules.rs`)
and loads it whenever no other rules source is configured, so a release
scores mail with the rules it was tested with, offline and with nothing to
fetch. The rules URL setting stays an operator override.

The rules are dual-licensed MIT or Apache-2.0, Copyright (C) 2024, Stalwart
Labs LLC; the fork takes them under MIT, with the notice in `THIRD-PARTY.md`.

They include the scores for the AI classifier's tags (`LLM_*`, 3.0 for the
high-confidence spam categories, −3.0 for legitimate), which match
`docs/spec/features/ai-spam-classification.md`.

## Updating

The `upstream-watch` workflow opens an issue when spam-filter publishes a
newer release. To take it:

1. Download `spam-filter-rules.json.gz` from that release, pinned by tag
   (`releases/download/vX.Y.Z/…`, not `latest`), over this file.
2. Set `BUNDLED_SPAM_RULES_VERSION` in `spam_rules.rs` and the version in
   this README and in `THIRD-PARTY.md`.
3. Run the antispam test (`STORE=RocksDb RUST_MIN_STACK=16777216 cargo test
   -p tests --lib -- smtp::inbound::antispam::antispam --exact`) and fix
   expectations the new rules change, knowingly.

On the next start each server loads the new version once. Loading only adds
rules and tags that are missing; it never changes an existing one, so an
operator's own adjustments survive.
