/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SharingPolicy`, whether people may share their own mail and add
//! other accounts to the webmail (multi-account spec, MA-C, MA-10 to MA-14).
//!
//! Two levels, as the legacy-protocols switch has: the server's policy, and
//! one per tenant that can only be stricter. Stored as JSON in the fork's
//! subspace, `W` + `p` for the server and `W` + `t` + tenant for a tenant;
//! unset reads as the defaults, which are on, so a server keeps today's
//! behavior until someone turns it off.
//!
//! "Off" refuses new shares and stops honoring the ones already made, which
//! stay stored, so turning it back on restores them (John, 2026-10-05).
//! Group membership and shared mailboxes aren't users' shares and are never
//! affected.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// One level's switches. `None` on a tenant means "as the server says".
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingPolicy {
    /// People may share their own mail folders (MA-11). Default on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_sharing: Option<bool>,
    /// People may add their other accounts to the webmail (MA-B). Default on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_accounts: Option<bool>,
    /// Seconds since the epoch, and who: the console shows them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
}

/// What applies to one account: the server's switch, narrowed by its
/// tenant's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub mail_sharing: bool,
    pub add_accounts: bool,
}

impl Default for Effective {
    fn default() -> Self {
        Effective {
            mail_sharing: true,
            add_accounts: true,
        }
    }
}

/// A tenant can be stricter than the server, never looser (MA-C).
pub fn effective(server: &SharingPolicy, tenant: Option<&SharingPolicy>) -> Effective {
    let server_mail = server.mail_sharing.unwrap_or(true);
    let server_add = server.add_accounts.unwrap_or(true);
    Effective {
        mail_sharing: server_mail && tenant.and_then(|t| t.mail_sharing).unwrap_or(true),
        add_accounts: server_add && tenant.and_then(|t| t.add_accounts).unwrap_or(true),
    }
}

/// Why a tenant can't turn a switch on: the server has it off.
pub fn looser_than_server(server: &SharingPolicy, tenant: &SharingPolicy) -> Option<&'static str> {
    if tenant.mail_sharing == Some(true) && server.mail_sharing == Some(false) {
        return Some("The server has mail sharing off; a tenant can only be stricter.");
    }
    if tenant.add_accounts == Some(true) && server.add_accounts == Some(false) {
        return Some("The server has adding accounts off; a tenant can only be stricter.");
    }
    None
}

fn key(tenant_id: Option<u32>) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    match tenant_id {
        None => key.extend_from_slice(b"Wp"),
        Some(tenant_id) => {
            key.extend_from_slice(b"Wt");
            key.extend_from_slice(&tenant_id.to_be_bytes());
        }
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

struct Json(SharingPolicy);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// The server's policy (`None`) or a tenant's.
pub async fn get(data: &Store, tenant_id: Option<u32>) -> trc::Result<SharingPolicy> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key(tenant_id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(policy)| policy)
        .unwrap_or_default())
}

/// What applies to an account in `tenant_id`.
pub async fn effective_for(data: &Store, tenant_id: Option<u32>) -> trc::Result<Effective> {
    let server = get(data, None).await?;
    let tenant = match tenant_id {
        Some(tenant_id) => Some(get(data, Some(tenant_id)).await?),
        None => None,
    };
    Ok(effective(&server, tenant.as_ref()))
}

/// Stores a policy.
pub async fn set(data: &Store, tenant_id: Option<u32>, policy: &SharingPolicy) -> trc::Result<()> {
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

    fn on_off(mail: Option<bool>, add: Option<bool>) -> SharingPolicy {
        SharingPolicy {
            mail_sharing: mail,
            add_accounts: add,
            ..Default::default()
        }
    }

    #[test]
    fn unset_is_on() {
        assert_eq!(effective(&SharingPolicy::default(), None), Effective::default());
        assert_eq!(
            effective(&SharingPolicy::default(), Some(&SharingPolicy::default())),
            Effective::default()
        );
    }

    #[test]
    fn a_tenant_is_only_ever_stricter() {
        // The server off wins over a tenant on
        let server = on_off(Some(false), None);
        let tenant = on_off(Some(true), Some(false));
        let e = effective(&server, Some(&tenant));
        assert!(!e.mail_sharing);
        assert!(!e.add_accounts, "the tenant's own off holds");
        assert!(looser_than_server(&server, &tenant).is_some());
        // A tenant off under a server on
        let e = effective(&on_off(Some(true), Some(true)), Some(&on_off(Some(false), None)));
        assert!(!e.mail_sharing && e.add_accounts);
        assert!(looser_than_server(&on_off(None, None), &on_off(Some(true), Some(true))).is_none());
    }

    #[test]
    fn keys_stay_apart() {
        let ValueClass::Any(server) = key(None) else { panic!() };
        let ValueClass::Any(tenant) = key(Some(7)) else { panic!() };
        assert_eq!(server.key, b"Wp");
        assert_eq!(tenant.key, [b'W', b't', 0, 0, 0, 7]);
    }
}
