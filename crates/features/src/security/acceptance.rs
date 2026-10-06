/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Accepted security to-do items (security to-do list spec, SS-23 to SS-26).
//!
//! The console runs the checks; the server only keeps what an administrator
//! accepted, so every administrator sees the same accepted risks. An
//! acceptance names the check, what within it (a domain, a certificate…),
//! the value the check saw, and why. It holds only while the check still
//! sees that value, which the console compares. Acceptances are created and
//! removed, never edited.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `Q`, then one byte for the kind:
//!
//! - `a` + acceptance id (u32): the acceptance, as JSON.
//!
//! Numbers are big-endian. There are at most [`MAX_ACCEPTANCES`], so
//! they're read whole.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'Q';
const KIND_ACCEPTANCE: u8 = b'a';
const CREATE_ATTEMPTS: usize = 5;

pub const MAX_ACCEPTANCES: usize = 200;
/// The checks are SS-1 to SS-18; a few spare for checks added later.
const MAX_CHECK: u32 = 40;
const MAX_SUBJECT: usize = 255;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_NOTE: usize = 500;

#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Acceptance {
    #[serde(default)]
    pub id: u32,
    /// Which check: `SS-1`, `SS-2`…
    pub check: String,
    /// What within the check: empty for a server-wide setting, else the
    /// domain, strategy or certificate it names.
    #[serde(default)]
    pub subject: String,
    /// The value the check saw when it was accepted.
    #[serde(default)]
    pub accepted_value: serde_json::Value,
    /// Why. Required.
    pub note: String,
    #[serde(default)]
    pub accepted_by: String,
    /// Seconds since the epoch.
    #[serde(default)]
    pub accepted_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Invalid {
    pub property: &'static str,
    pub reason: String,
}

fn invalid(property: &'static str, reason: impl Into<String>) -> Invalid {
    Invalid {
        property,
        reason: reason.into(),
    }
}

impl Acceptance {
    /// What an administrator sends is checked whole before it's kept.
    pub fn validate(&self) -> Result<(), Invalid> {
        let check_ok = self
            .check
            .strip_prefix("SS-")
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| (1..=MAX_CHECK).contains(&n));
        if !check_ok {
            return Err(invalid("check", "A check is named SS-1, SS-2 and so on."));
        }
        if self.subject.chars().count() > MAX_SUBJECT {
            return Err(invalid(
                "subject",
                format!("At most {MAX_SUBJECT} characters."),
            ));
        }
        let value_bytes = serde_json::to_vec(&self.accepted_value)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if value_bytes > MAX_VALUE_BYTES {
            return Err(invalid(
                "acceptedValue",
                format!("At most {MAX_VALUE_BYTES} bytes."),
            ));
        }
        let note = self.note.trim();
        if note.is_empty() {
            return Err(invalid("note", "Say why this is accepted."));
        }
        if note.chars().count() > MAX_NOTE {
            return Err(invalid("note", format!("At most {MAX_NOTE} characters.")));
        }
        Ok(())
    }
}

// --- Storage --------------------------------------------------------------

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize a security acceptance")
                .reason(err)
        })
    }
}

impl Deserialize for Json<Acceptance> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid security acceptance")
                .reason(err)
        })
    }
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_ACCEPTANCE);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(class(id))
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Acceptance>> {
    Ok(data
        .get_value::<Json<Acceptance>>(key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(acceptance)| acceptance))
}

/// Every acceptance, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Acceptance>> {
    let mut out = Vec::new();
    data.iterate(IterateParams::new(key(0), key(u32::MAX)), |_, value| {
        if let Ok(Json(acceptance)) = Json::<Acceptance>::deserialize(value) {
            out.push(acceptance);
        }
        Ok(true)
    })
    .await
    .caused_by(trc::location!())?;
    out.sort_by_key(|a| a.id);
    Ok(out)
}

pub enum Created {
    Id(u32),
    /// There are already [`MAX_ACCEPTANCES`].
    Full,
}

/// Keeps a new acceptance under the next free id. Two nodes creating at
/// once can't take the same id: the key must be absent.
pub async fn create(data: &Store, acceptance: &Acceptance) -> trc::Result<Created> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let existing = all(data).await?;
        if existing.len() >= MAX_ACCEPTANCES {
            return Ok(Created::Full);
        }
        let id = existing.iter().map(|a| a.id).max().unwrap_or(0) + 1;
        let stored = Acceptance {
            id,
            ..acceptance.clone()
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(Created::Id(id)),
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

pub async fn delete(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(id));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acceptance() -> Acceptance {
        Acceptance {
            id: 0,
            check: "SS-1".into(),
            subject: String::new(),
            accepted_value: serde_json::json!(true),
            note: "Old clients on the LAN; closed by 2027.".into(),
            accepted_by: String::new(),
            accepted_at: 0,
        }
    }

    #[test]
    fn a_note_is_required() {
        assert!(acceptance().validate().is_ok());
        let blank = Acceptance {
            note: "  ".into(),
            ..acceptance()
        };
        assert_eq!(blank.validate().unwrap_err().property, "note");
        let long = Acceptance {
            note: "x".repeat(501),
            ..acceptance()
        };
        assert_eq!(long.validate().unwrap_err().property, "note");
    }

    #[test]
    fn only_named_checks() {
        for bad in ["", "SS-0", "SS-41", "ss-1", "SS-x", "1"] {
            let a = Acceptance {
                check: bad.into(),
                ..acceptance()
            };
            assert_eq!(a.validate().unwrap_err().property, "check", "{bad}");
        }
    }

    #[test]
    fn subject_and_value_are_bounded() {
        let a = Acceptance {
            subject: "d".repeat(256),
            ..acceptance()
        };
        assert_eq!(a.validate().unwrap_err().property, "subject");
        let a = Acceptance {
            accepted_value: serde_json::json!("v".repeat(4096)),
            ..acceptance()
        };
        assert_eq!(a.validate().unwrap_err().property, "acceptedValue");
    }
}
