/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
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
    /// With `dark`, each level offers its dark-mode logo before its own
    /// logo (BT-27).
    pub async fn logos_for(&self, name: &str, dark: bool) -> trc::Result<Vec<Logo>> {
        let mut domain = None;
        for candidate in logo::lookup_names(name) {
            if let Some(found) = self.domain(&candidate).await? {
                domain = Some(found);
                break;
            }
        }
        let registry = self.registry();
        let (domain_logo, domain_dark) = match &domain {
            Some(domain) => registry
                .object::<Domain>(Id::from(domain.id))
                .await?
                .map_or((None, None), |d| (d.logo, d.logo_dark)),
            None => (None, None),
        };
        let tenant_id = domain.as_ref().and_then(|d| d.id_tenant);
        let (tenant_logo, tenant_dark) = match tenant_id {
            Some(tenant_id) => registry
                .object::<Tenant>(Id::from(tenant_id))
                .await?
                .map_or((None, None), |t| (t.logo, t.logo_dark)),
            None => (None, None),
        };
        let (server_logo, server_dark) = registry
            .object::<Enterprise>(Id::singleton())
            .await?
            .map_or((None, None), |e| (e.logo_url, e.logo_url_dark));
        let domain_source = Source::Domain(domain.as_ref().map_or(u32::MAX, |d| d.id));
        let tenant_source = Source::Tenant(tenant_id.unwrap_or(u32::MAX));
        Ok(logo::chain(logo::levels(
            [
                (
                    domain_source,
                    domain_logo.as_deref(),
                    domain_dark.as_deref(),
                ),
                (
                    tenant_source,
                    tenant_logo.as_deref(),
                    tenant_dark.as_deref(),
                ),
                (
                    Source::Server,
                    server_logo.as_deref(),
                    server_dark.as_deref(),
                ),
            ],
            dark,
        )))
    }
}
