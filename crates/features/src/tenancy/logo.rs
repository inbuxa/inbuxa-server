/*
 * SPDX-FileCopyrightText: 2026 John Coffey
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The logo that applies to a signed-in principal (MT-22).
//!
//! Its domain's logo if set, else its tenant's. The value is returned as
//! stored, a URL or a data URL: the server never fetches a logo URL itself
//! (MT-23). Branding extends the chain past the tenant (BT-1).

use registry::schema::structs::{Account, Domain, Tenant};
use store::RegistryStore;
use types::id::Id;

/// The logo that applies to an account, read from the registry.
pub async fn for_account(registry: &RegistryStore, account_id: u32) -> trc::Result<Option<String>> {
    let Some(account) = registry.object::<Account>(Id::from(account_id)).await? else {
        return Ok(None);
    };
    let (domain_id, tenant_id) = match &account {
        Account::User(obj) => (obj.domain_id, obj.member_tenant_id),
        Account::Group(obj) => (obj.domain_id, obj.member_tenant_id),
    };
    let domain = registry.object::<Domain>(domain_id).await?;
    let tenant = match tenant_id {
        Some(tenant_id) => registry.object::<Tenant>(tenant_id).await?,
        None => None,
    };
    Ok(applicable(
        domain.as_ref().and_then(|d| d.logo.as_deref()),
        tenant.as_ref().and_then(|t| t.logo.as_deref()),
    )
    .map(str::to_string))
}

/// The logo that applies, from the principal's domain's and tenant's logos.
pub fn applicable<'x>(domain: Option<&'x str>, tenant: Option<&'x str>) -> Option<&'x str> {
    domain
        .filter(|logo| !logo.is_empty())
        .or(tenant.filter(|logo| !logo.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_then_tenant() {
        assert_eq!(applicable(Some("d"), Some("t")), Some("d"));
        assert_eq!(applicable(None, Some("t")), Some("t"));
        assert_eq!(applicable(Some(""), Some("t")), Some("t"));
        assert_eq!(applicable(None, None), None);
    }
}
