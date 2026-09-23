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
//! Loading rules only ever adds what's missing, never changes an existing rule
//! or score. They load on first boot, and again whenever the bundled version
//! differs from the one last applied, so an upgrade brings new tags (the AI
//! classifier's `LLM_*` scores, say) to an install that already had rules.

use std::io::Read;
use store::{
    SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// The version of spam-filter the embedded rules come from.
pub const BUNDLED_SPAM_RULES_VERSION: &str = "3.0.2";

static BUNDLED_SPAM_RULES: &[u8] =
    include_bytes!("../../../../resources/spam-filter/spam-filter-rules.json.gz");

/// Upstream's default rules source, the value every install created before
/// the rules were bundled has saved. Read only to treat it as unset.
const LEGACY_DEFAULT_URL: &str =
    "https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz";

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

/// The bundled version last loaded into the registry, if any.
pub async fn applied_version(data: &Store) -> trc::Result<Option<String>> {
    data.get_value::<String>(ValueKey::from(applied_key()))
        .await
        .caused_by(trc::location!())
}

/// Records that the bundled rules of this version have been loaded.
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
