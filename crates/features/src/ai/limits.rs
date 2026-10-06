/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:AiLimits`, the fork's limits on model calls ("Added by
//! inbuxa-server" in the spec). Stored as JSON under `A` + `l` in the fork's
//! subspace; unset fields read as the defaults.

use registry::types::duration::Duration;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AiLimits {
    pub spam_max_added: f64,
    pub spam_max_subtracted: f64,
    pub spam_call_ceiling: Duration,
    pub max_concurrent_calls: u64,
    pub max_content_bytes: u64,
    pub failure_backoff: Duration,
    pub user_calls_per_hour: u64,
    /// "Explain this" (`inbuxa-drafts/specs/ai-explain.md`, EX-2, EX-3,
    /// EX-13, EX-15).
    pub explain_enabled: bool,
    pub explain_model_id: Option<u64>,
    pub explain_calls_per_hour: u64,
    pub explain_ceiling: Duration,
}

impl Default for AiLimits {
    fn default() -> Self {
        AiLimits {
            spam_max_added: 2.0,
            spam_max_subtracted: 1.0,
            spam_call_ceiling: Duration::from_millis(20_000),
            max_concurrent_calls: 4,
            max_content_bytes: 2_048,
            failure_backoff: Duration::from_millis(60_000),
            user_calls_per_hour: 60,
            explain_enabled: true,
            explain_model_id: None,
            explain_calls_per_hour: 30,
            explain_ceiling: Duration::from_millis(45_000),
        }
    }
}

/// The properties `inbuxa:AiLimits` has, as they appear over JMAP.
pub const PROPERTIES: &[&str] = &[
    "spamMaxAdded",
    "spamMaxSubtracted",
    "spamCallCeiling",
    "maxConcurrentCalls",
    "maxContentBytes",
    "failureBackoff",
    "userCallsPerHour",
    "explainEnabled",
    "explainModelId",
    "explainCallsPerHour",
    "explainCeiling",
];

impl AiLimits {
    /// The gate's limits.
    pub fn gate(&self) -> crate::ai::gate::Limits {
        crate::ai::gate::Limits {
            max_concurrent: self.max_concurrent_calls as usize,
            backoff: self.failure_backoff.into_inner(),
            account_calls_per_hour: self.user_calls_per_hour.min(u32::MAX as u64) as u32,
        }
    }

    /// What's wrong with these values, naming the property.
    pub fn check(&self) -> Result<(), (&'static str, String)> {
        for (name, value) in [
            ("spamMaxAdded", self.spam_max_added),
            ("spamMaxSubtracted", self.spam_max_subtracted),
        ] {
            if !value.is_finite() || value < 0.0 || value > 1000.0 {
                return Err((name, "must be a number from 0 to 1000".into()));
            }
        }
        if self.spam_call_ceiling.into_inner().as_millis() < 100
            || self.spam_call_ceiling.into_inner().as_secs() > 600
        {
            return Err(("spamCallCeiling", "must be from 100ms to 10 minutes".into()));
        }
        if !(1..=1024).contains(&self.max_concurrent_calls) {
            return Err(("maxConcurrentCalls", "must be from 1 to 1024".into()));
        }
        if !(256..=1024 * 1024).contains(&self.max_content_bytes) {
            return Err(("maxContentBytes", "must be from 256 bytes to 1 MiB".into()));
        }
        if self.failure_backoff.into_inner().as_secs() > 86_400 {
            return Err(("failureBackoff", "must be at most a day".into()));
        }
        if !(1..=10_000).contains(&self.explain_calls_per_hour) {
            return Err(("explainCallsPerHour", "must be from 1 to 10000".into()));
        }
        if self.explain_ceiling.into_inner().as_secs() < 1
            || self.explain_ceiling.into_inner().as_secs() > 600
        {
            return Err(("explainCeiling", "must be from 1 second to 10 minutes".into()));
        }
        Ok(())
    }
}

fn key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Al".to_vec(),
    })
}

struct Json(AiLimits);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// The limits in force.
pub async fn get(data: &Store) -> trc::Result<AiLimits> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(limits)| limits)
        .unwrap_or_default())
}

/// Stores new limits.
pub async fn set(data: &Store, limits: &AiLimits) -> trc::Result<()> {
    let bytes = serde_json::to_vec(limits).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(key(), bytes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_partial_json() {
        let limits = AiLimits::default();
        assert!(limits.check().is_ok());
        let partial: AiLimits = serde_json::from_str(r#"{"maxConcurrentCalls": 1}"#).unwrap();
        assert_eq!(partial.max_concurrent_calls, 1);
        assert_eq!(partial.user_calls_per_hour, 60);
        let json = serde_json::to_value(&limits).unwrap();
        for property in PROPERTIES {
            assert!(json.get(property).is_some(), "{property}");
        }
        assert_eq!(json["spamCallCeiling"], 20_000);
        assert_eq!(json["explainCeiling"], 45_000);
        assert_eq!(partial.explain_calls_per_hour, 30);
        assert!(partial.explain_enabled);
        let bad = AiLimits {
            max_concurrent_calls: 0,
            ..Default::default()
        };
        assert_eq!(bad.check().unwrap_err().0, "maxConcurrentCalls");
    }
}
