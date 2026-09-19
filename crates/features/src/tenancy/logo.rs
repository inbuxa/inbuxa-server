/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The logo that applies to a signed-in principal (MT-22).
//!
//! Its domain's logo if set, else its tenant's. The value is returned as
//! stored, a URL or a data URL: the server never fetches a logo URL itself
//! (MT-23). Branding extends the chain past the tenant to the server-wide
//! logo (BT-2); none means the client's built-in INBUXA logo.

use registry::schema::structs::{Account, Domain, Enterprise, Tenant};
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
    // BT-2: past the tenant, the server-wide logo; each value as stored, and
    // an unusable one skipped (BT-4)
    let server = registry
        .object::<Enterprise>(Id::singleton())
        .await?
        .and_then(|e| e.logo_url);
    Ok([
        domain.as_ref().and_then(|d| d.logo.as_deref()),
        tenant.as_ref().and_then(|t| t.logo.as_deref()),
        server.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|value| crate::branding::logo::read(value).is_some())
    .map(str::to_string))
}
