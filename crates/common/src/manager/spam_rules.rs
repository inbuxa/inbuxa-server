/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the spam filter rules that ship with the server.
//!
//! Upstream fetches its latest published rules from GitHub at run time, so
//! scoring changes with a release nobody here tested and depends on reaching
//! it. The fork embeds a pinned copy (resources/spam-filter/, with its version
//! and license) and uses it whenever no other source is configured. The rules
//! URL remains an operator override (`https://` or `file://`).
//!
//! Loading rules adds what's missing and brings an existing rule up to date,
//! but never touches one an admin edited: every object an update writes is
//! fingerprinted, and one that no longer matches its fingerprint is kept as
//! it is. Tags (scores) are never replaced. Switching a rule on or off isn't
//! an edit, and is kept either way. They load on first boot, and again
//! whenever the bundled rules differ from the ones last applied, so an
//! upgrade brings new tags (the AI classifier's `LLM_*` scores, say) and
//! fixed rules to an install that already had rules.

use registry::{schema::prelude::ObjectType, types::EnumImpl};
use std::io::Read;
use store::{
    SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// The version of spam-filter the embedded rules come from.
pub const BUNDLED_SPAM_RULES_VERSION: &str = "3.0.2";

/// What's recorded once the bundled rules are loaded: their version, then the
/// fork's own generation of the update, so a change to how an update applies
/// runs it once more. Generation 2 fingerprints (upstream v0.16.24).
pub const BUNDLED_SPAM_RULES_APPLIED: &str = "3.0.2+2";

static BUNDLED_SPAM_RULES: &[u8] =
    include_bytes!("../../../../resources/spam-filter/spam-filter-rules.json.gz");

/// Upstream's default rules source, the value every install created before
/// the rules were bundled has saved. Read only to treat it as unset.
const LEGACY_DEFAULT_URL: &str = "https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz";

/// The URL to fetch rules from, or `None` for the bundled rules. An empty
/// setting and upstream's old default both mean the bundled rules.
pub fn rules_url(configured: Option<String>) -> Option<String> {
    configured.filter(|url| !url.trim().is_empty() && url != LEGACY_DEFAULT_URL)
}

/// The bundled rules, uncompressed: the same JSON the rules URL serves.
pub fn bundled_rules() -> Result<Vec<u8>, String> {
    let mut json = Vec::new();
    mail_auth::flate2::read::GzDecoder::new(BUNDLED_SPAM_RULES)
        .read_to_end(&mut json)
        .map_err(|err| format!("Failed to decompress the bundled spam rules: {err}"))?;
    Ok(json)
}

fn applied_key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Sr".to_vec(),
    })
}

fn fingerprint_key(object: ObjectType, id: u64) -> ValueClass {
    let mut key = b"Sf".to_vec();
    key.extend_from_slice(object.as_str().as_bytes());
    key.push(0);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

/// The fingerprint of what a rules update last wrote to this object, if one
/// did.
pub async fn fingerprint(data: &Store, object: ObjectType, id: u64) -> trc::Result<Option<String>> {
    data.get_value::<String>(ValueKey::from(fingerprint_key(object, id)))
        .await
        .caused_by(trc::location!())
}

/// Records the fingerprint of what a rules update wrote to this object.
pub async fn set_fingerprint(
    data: &Store,
    object: ObjectType,
    id: u64,
    fingerprint: &str,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(fingerprint_key(object, id), fingerprint.as_bytes().to_vec());
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// The bundled rules last loaded into the registry, if any
/// ([`BUNDLED_SPAM_RULES_APPLIED`]'s form).
pub async fn applied_version(data: &Store) -> trc::Result<Option<String>> {
    data.get_value::<String>(ValueKey::from(applied_key()))
        .await
        .caused_by(trc::location!())
}

/// Records that the bundled rules have been loaded.
pub async fn set_applied_version(data: &Store, version: &str) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(applied_key(), version.as_bytes().to_vec());
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_default_and_empty_mean_bundled() {
        assert_eq!(rules_url(None), None);
        assert_eq!(rules_url(Some(String::new())), None);
        assert_eq!(rules_url(Some("  ".into())), None);
        assert_eq!(rules_url(Some(LEGACY_DEFAULT_URL.into())), None);
        assert_eq!(
            rules_url(Some("file:///srv/rules.json.gz".into())).as_deref(),
            Some("file:///srv/rules.json.gz")
        );
    }

    #[test]
    fn applied_marker_names_the_bundled_version() {
        assert!(
            BUNDLED_SPAM_RULES_APPLIED
                .strip_prefix(BUNDLED_SPAM_RULES_VERSION)
                .is_some_and(|generation| generation.starts_with('+'))
        );
    }

    #[test]
    fn bundled_rules_parse_and_score_the_ai_tags() {
        let rules: serde_json::Value = serde_json::from_slice(&bundled_rules().unwrap()).unwrap();
        let tags = rules["SpamTag"].as_array().unwrap();
        for (tag, score) in [("LLM_UNSOLICITED_HIGH", 3.0), ("LLM_LEGITIMATE_HIGH", -3.0)] {
            let found = tags.iter().find(|t| t["tag"] == tag).unwrap();
            assert_eq!(found["score"].as_f64(), Some(score), "{tag}");
        }
        assert!(!rules["SpamRule"].as_array().unwrap().is_empty());
    }
}
