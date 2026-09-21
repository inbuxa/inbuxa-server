/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:TenantProtocolPolicy`, one tenant's legacy mail protocols switch
//! (legacy-protocols spec, LP-9 to LP-14a). Stored as JSON under `P` `t` and
//! the tenant id in the fork's subspace; a tenant with nothing stored has
//! legacy protocols on.
//!
//! A tenant's switch closes no port -- other tenants share them (LP-13). It
//! refuses sign-in on the tenant's domains, and keeps client configuration
//! for them from offering what's refused. That is all it is: one fact per
//! tenant, easy to turn back, touching no listener, role or permission.

use crate::security::protocol_policy::{LegacyProtocols, ProtocolPolicy};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// One tenant's switch.
#[derive(Debug, Clone, PartialEq, Default, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TenantProtocolPolicy {
    /// The switch itself.
    pub legacy_protocols: LegacyProtocols,
    /// When it last changed, in milliseconds since the epoch.
    pub changed_at: Option<u64>,
    /// The account that last changed it.
    pub changed_by: Option<String>,
}

/// Why a tenant's switch can't be set this way, if it can't (LP-9).
///
/// A tenant can always turn legacy protocols off for itself. It can turn
/// them back on only while the server has them on: server off means off for
/// everyone.
pub fn refusal(server: &ProtocolPolicy, requested: LegacyProtocols) -> Option<&'static str> {
    (server.legacy_protocols.is_disabled() && !requested.is_disabled()).then_some(
        "Legacy mail protocols are off for the whole server (inbuxa:ProtocolPolicy), \
         so they can't be turned back on for one organization.",
    )
}

fn key(tenant_id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.extend_from_slice(b"Pt");
    key.extend_from_slice(&tenant_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

struct Json(TenantProtocolPolicy);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// The tenant's policy, or the default (on) when it has never been set.
pub async fn get(data: &Store, tenant_id: u32) -> trc::Result<TenantProtocolPolicy> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key(tenant_id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(policy)| policy)
        .unwrap_or_default())
}

/// Stores the tenant's policy.
pub async fn set(data: &Store, tenant_id: u32, policy: &TenantProtocolPolicy) -> trc::Result<()> {
    let bytes = serde_json::to_vec(policy).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(key(tenant_id), bytes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(legacy_protocols: LegacyProtocols) -> ProtocolPolicy {
        ProtocolPolicy {
            legacy_protocols,
            ..Default::default()
        }
    }

    #[test]
    fn a_tenant_starts_with_legacy_protocols_on() {
        assert!(
            !TenantProtocolPolicy::default()
                .legacy_protocols
                .is_disabled()
        );
    }

    #[test]
    fn a_tenant_can_always_turn_them_off() {
        for s in [LegacyProtocols::Enabled, LegacyProtocols::Disabled] {
            assert_eq!(refusal(&server(s), LegacyProtocols::Disabled), None);
        }
    }

    #[test]
    fn a_tenant_can_turn_them_on_only_while_the_server_has_them_on() {
        // LP-9, acceptance test 9.
        assert_eq!(
            refusal(&server(LegacyProtocols::Enabled), LegacyProtocols::Enabled),
            None
        );
        let why =
            refusal(&server(LegacyProtocols::Disabled), LegacyProtocols::Enabled).expect("refused");
        assert!(why.contains("inbuxa:ProtocolPolicy"), "{why}");
    }

    #[test]
    fn keys_are_per_tenant_and_clear_of_the_server_policy() {
        let ValueClass::Any(a) = key(1) else { panic!() };
        let ValueClass::Any(b) = key(2) else { panic!() };
        assert_ne!(a.key, b.key);
        assert_eq!(&a.key[..2], b"Pt");
        assert_ne!(a.key, b"Pp".to_vec());
    }

    #[test]
    fn stored_json_reads_back() {
        let policy = TenantProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            changed_at: Some(1),
            changed_by: Some("b".into()),
        };
        let Json(back) = Json::deserialize(&serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(back, policy);
        // Unknown and missing fields read as defaults.
        let Json(back) = Json::deserialize(br#"{"futureField":1}"#).unwrap();
        assert_eq!(back, TenantProtocolPolicy::default());
    }
}
