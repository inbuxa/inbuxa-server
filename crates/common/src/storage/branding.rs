/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Which logo applies to a domain name (branding spec BT-1, BT-2). The rules
//! live in `inbuxa_features::branding::logo`; this finds the domain through
//! the server's domain cache and reads the three levels from the registry
//! each time, so a change shows at once on every node (BT-10).

use crate::Server;
use inbuxa_features::branding::logo::{self, Logo, Source};
use registry::schema::structs::{Domain, Enterprise, Tenant};
use types::id::Id;

impl Server {
    /// The logos that apply to a domain name, most specific first. An unknown
    /// name gets what a known domain with no logo of its own gets (BT-6).
    pub async fn logos_for(&self, name: &str) -> trc::Result<Vec<Logo>> {
        let mut domain = None;
        for candidate in logo::lookup_names(name) {
            if let Some(found) = self.domain(&candidate).await? {
                domain = Some(found);
                break;
            }
        }
        let registry = self.registry();
        let domain_logo = match &domain {
            Some(domain) => registry
                .object::<Domain>(Id::from(domain.id))
                .await?
                .and_then(|d| d.logo),
            None => None,
        };
        let tenant_id = domain.as_ref().and_then(|d| d.id_tenant);
        let tenant_logo = match tenant_id {
            Some(tenant_id) => registry
                .object::<Tenant>(Id::from(tenant_id))
                .await?
                .and_then(|t| t.logo),
            None => None,
        };
        let server_logo = registry
            .object::<Enterprise>(Id::singleton())
            .await?
            .and_then(|e| e.logo_url);
        Ok(logo::chain([
            (
                Source::Domain(domain.as_ref().map_or(u32::MAX, |d| d.id)),
                domain_logo.as_deref(),
            ),
            (
                Source::Tenant(tenant_id.unwrap_or(u32::MAX)),
                tenant_logo.as_deref(),
            ),
            (Source::Server, server_logo.as_deref()),
        ]))
    }
}
