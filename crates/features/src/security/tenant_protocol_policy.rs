/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:TenantProtocolPolicy`, one tenant's legacy mail protocols switch
//! (legacy-protocols spec, LP-9 to LP-14a). Stored as JSON under `P` `t` and
//! the tenant id in the fork's subspace; a tenant with nothing stored has
//! legacy protocols on.
//!
//! A tenant has the same three switches as the server (IMAP, POP3,
//! ManageSieve) and the same kill-all; a protocol off server-wide is off for
//! every tenant whatever the tenant's own switch says.
//!
//! A tenant's switch closes no port -- other tenants share them (LP-13). It
//! refuses sign-in on the tenant's domains, and keeps client configuration
//! for them from offering what's refused. That is all it is: one fact per
//! tenant, easy to turn back, touching no listener, role or permission.

use crate::security::protocol_policy::{
    LegacyProtocols, ProtocolPolicy, SUBMISSION, SWITCHED, Switches, switches,
};
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
    /// The kill-all, as on the server's policy.
    pub legacy_protocols: LegacyProtocols,
    /// IMAP's switch. Unset reads as `legacy_protocols`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<LegacyProtocols>,
    /// POP3's switch. Unset reads as `legacy_protocols`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<LegacyProtocols>,
    /// ManageSieve's switch. Unset reads as `legacy_protocols`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manage_sieve: Option<LegacyProtocols>,
    /// When it last changed, in milliseconds since the epoch.
    pub changed_at: Option<u64>,
    /// The account that last changed it.
    pub changed_by: Option<String>,
}

switches!(TenantProtocolPolicy);

/// Why a tenant's switches can't be set this way, if they can't (LP-9).
///
/// A tenant can always turn a protocol off for itself. It can turn one on
/// only while the server has it on: server off means off for everyone.
/// `turned_on` is what the request sets to `enabled`, by protocol name.
pub fn refusal(server: &ProtocolPolicy, turned_on: &[&str]) -> Option<String> {
    let blocked: Vec<&str> = turned_on
        .iter()
        .copied()
        .filter(|protocol| server.is_off(protocol))
        .collect();
    (!blocked.is_empty()).then(|| {
        format!(
            "{} off for the whole server (inbuxa:ProtocolPolicy), so {} can't be turned \
             back on for one organization.",
            names(&blocked),
            if blocked.len() == 1 { "it" } else { "they" }
        )
    })
}

/// Protocol names as people read them: "IMAP and POP3 are", "POP3 is".
fn names(protocols: &[&str]) -> String {
    let named: Vec<&str> = protocols
        .iter()
        .map(|p| match *p {
            "imap" => "IMAP",
            "pop3" => "POP3",
            "manageSieve" => "ManageSieve",
            other => other,
        })
        .collect();
    let list = match named.as_slice() {
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => String::new(),
    };
    format!("{list} {}", if named.len() == 1 { "is" } else { "are" })
}

/// Whose switch turns a protocol off, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffBy {
    Server,
    Tenant,
}

/// Whether this protocol is off for an account or domain, and by whose
/// switch: the server's first (LP-6), then the tenant's (LP-10). Submission
/// is off when all three protocols are, counting both switches together.
pub fn off_by(
    server: &ProtocolPolicy,
    tenant: Option<&TenantProtocolPolicy>,
    protocol: &str,
) -> Option<OffBy> {
    if server.is_off(protocol) {
        return Some(OffBy::Server);
    }
    let tenant = tenant?;
    let off = if protocol == SUBMISSION {
        SWITCHED
            .iter()
            .all(|p| server.is_off(p) || tenant.is_off(p))
    } else {
        tenant.is_off(protocol)
    };
    off.then_some(OffBy::Tenant)
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

/// Forgets a tenant's switch, when the tenant is deleted. Otherwise a tenant
/// that came to have the same id would start with the old one's switch.
pub async fn remove(data: &Store, tenant_id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(key(tenant_id));
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

    fn tenant_off(protocols: &[&str]) -> TenantProtocolPolicy {
        let mut policy = TenantProtocolPolicy::default();
        for p in protocols {
            policy.set(p, LegacyProtocols::Disabled);
        }
        policy.normalize();
        policy
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
            assert_eq!(refusal(&server(s), &[]), None);
        }
    }

    #[test]
    fn a_tenant_can_turn_them_on_only_while_the_server_has_them_on() {
        // LP-9, acceptance test 9.
        assert_eq!(refusal(&server(LegacyProtocols::Enabled), SWITCHED), None);
        let why = refusal(&server(LegacyProtocols::Disabled), SWITCHED).expect("refused");
        assert!(why.contains("inbuxa:ProtocolPolicy"), "{why}");
        assert!(
            why.starts_with("IMAP, POP3 and ManageSieve are off"),
            "{why}"
        );
    }

    #[test]
    fn a_tenant_can_turn_on_what_the_server_allows() {
        // The server has only POP3 off: IMAP may come back, POP3 may not.
        let mut s = ProtocolPolicy::default();
        s.set("pop3", LegacyProtocols::Disabled);
        assert_eq!(refusal(&s, &["imap"]), None);
        let why = refusal(&s, &["imap", "pop3"]).expect("refused");
        assert!(why.starts_with("POP3 is off"), "{why}");
    }

    #[test]
    fn whose_switch_turns_a_protocol_off() {
        let mut s = ProtocolPolicy::default();
        s.set("pop3", LegacyProtocols::Disabled);
        let t = tenant_off(&["imap"]);
        assert_eq!(off_by(&s, Some(&t), "pop3"), Some(OffBy::Server));
        assert_eq!(off_by(&s, Some(&t), "imap"), Some(OffBy::Tenant));
        assert_eq!(off_by(&s, Some(&t), "manageSieve"), None);
        assert_eq!(off_by(&s, None, "imap"), None);
        // Sending goes on while any protocol is still allowed.
        assert_eq!(off_by(&s, Some(&t), SUBMISSION), None);
        // Between them, all three off: submission follows (LP-6, LP-10).
        let t = tenant_off(&["imap", "manageSieve"]);
        assert_eq!(off_by(&s, Some(&t), SUBMISSION), Some(OffBy::Tenant));
        assert_eq!(
            off_by(&server(LegacyProtocols::Disabled), None, SUBMISSION),
            Some(OffBy::Server)
        );
    }

    #[test]
    fn an_old_tenant_policy_reads_as_all_three() {
        let Json(old) = Json::deserialize(br#"{"legacyProtocols":"disabled"}"#).unwrap();
        for p in SWITCHED {
            assert!(old.is_off(p), "{p}");
        }
        assert!(old.is_off(SUBMISSION));
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
            ..Default::default()
        };
        let Json(back) = Json::deserialize(&serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(back, policy);
        // Unknown and missing fields read as defaults.
        let Json(back) = Json::deserialize(br#"{"futureField":1}"#).unwrap();
        assert_eq!(back, TenantProtocolPolicy::default());
    }
}
