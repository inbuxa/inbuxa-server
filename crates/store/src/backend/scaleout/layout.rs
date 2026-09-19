/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The member lists of sharded stores, recorded in the data store (ST-20,
//! ST-26): each member's kind and location, never its secrets.

use crate::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};

/// The fork's feature byte for scale-out storage.
const FEATURE: u8 = b'S';

/// Where a member list is recorded: `b` the blob store, `m` the in-memory
/// store, `l` a lookup store by namespace.
pub fn key(kind: u8, name: &str) -> ValueClass {
    let mut key = vec![FEATURE, kind];
    key.extend_from_slice(name.as_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

struct Recorded(Vec<String>);

impl Deserialize for Recorded {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes)
            .map(Recorded)
            .map_err(|err| trc::StoreEvent::DeserializeError.reason(err))
    }
}

/// How the configured list compares with the recorded one.
#[derive(Debug, PartialEq, Eq)]
pub enum Comparison {
    /// No record yet, or the same list.
    Unchanged,
    /// Members added or reordered: the record was updated.
    Changed(String),
    /// A recorded member is gone.
    Missing(Vec<String>),
}

pub fn compare(recorded: &[String], current: &[String]) -> Comparison {
    let missing = recorded
        .iter()
        .filter(|member| !current.contains(member))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        Comparison::Missing(missing)
    } else if recorded == current {
        Comparison::Unchanged
    } else {
        let added = current
            .iter()
            .filter(|member| !recorded.contains(member))
            .cloned()
            .collect::<Vec<_>>();
        Comparison::Changed(if added.is_empty() {
            format!("members reordered, was {recorded:?}, now {current:?}")
        } else {
            format!("members added: {added:?}")
        })
    }
}

/// Compares `current` with the record, then records `current` unless a
/// member is missing and `keep_on_missing` is set.
pub async fn check(
    data: &Store,
    class: ValueClass,
    current: &[String],
    keep_on_missing: bool,
) -> trc::Result<Comparison> {
    if data.is_none() {
        return Ok(Comparison::Unchanged);
    }
    let recorded = data
        .get_value::<Recorded>(ValueKey::from(class.clone()))
        .await?
        .map(|r| r.0);
    let comparison = match &recorded {
        Some(recorded) => compare(recorded, current),
        None => Comparison::Unchanged,
    };
    let write = match &comparison {
        Comparison::Unchanged => recorded.is_none(),
        Comparison::Changed(_) => true,
        Comparison::Missing(_) => !keep_on_missing,
    };
    if write {
        let mut batch = BatchBuilder::new();
        batch.set(class, serde_json::to_vec(current).unwrap_or_default());
        data.write(batch.build_all()).await?;
    }
    Ok(comparison)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compares_lists() {
        assert_eq!(
            compare(&list(&["a", "b"]), &list(&["a", "b"])),
            Comparison::Unchanged
        );
        assert!(matches!(
            compare(&list(&["a", "b"]), &list(&["a", "b", "c"])),
            Comparison::Changed(_)
        ));
        assert!(matches!(
            compare(&list(&["a", "b"]), &list(&["b", "a"])),
            Comparison::Changed(_)
        ));
        assert_eq!(
            compare(&list(&["a", "b", "c"]), &list(&["a", "c"])),
            Comparison::Missing(list(&["b"]))
        );
    }
}
