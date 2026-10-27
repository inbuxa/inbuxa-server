/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Bind, LdapConnectionManager, LdapDirectory, LdapFilter, LdapFilterItem, LdapMappings,
    failover::LdapServers,
};
use crate::Directory;
use deadpool::{Runtime, managed::Pool};
use ldap3::LdapConnSettings;
use registry::schema::structs;
use std::sync::Arc;

impl LdapDirectory {
    pub async fn open(config: structs::LdapDirectory) -> Result<Directory, String> {
        let bind_dn = if let Some(dn) = config.bind_dn {
            Bind::new(
                dn,
                config
                    .bind_secret
                    .secret()
                    .await?
                    .map(|v| v.into_owned())
                    .ok_or_else(|| {
                        "LDAP bind password is required when bind DN is set".to_string()
                    })?,
            )
            .into()
        } else {
            None
        };

        let timeout = config.timeout.into_inner();
        let settings = LdapConnSettings::new()
            .set_conn_timeout(timeout)
            .set_starttls(config.use_tls)
            .set_no_tls_verify(config.allow_invalid_certs);
        #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
        let mut urls = vec![config.url];
        let servers = Arc::new(LdapServers::new(urls.into_boxed_slice()));
        let bind_manager = config
            .bind_authentication
            .then(|| LdapConnectionManager::new(servers.clone(), settings.clone(), None, timeout));
        let manager = LdapConnectionManager::new(servers.clone(), settings, bind_dn, timeout);

        let mut mappings = LdapMappings {
            base_dn: config.base_dn,
            filter_login: LdapFilter::new(&config.filter_login)?,
            filter_recipient: LdapFilter::new(&config.filter_recipient)?,
            filter_member_of: if let Some(filter) = config.filter_member_of {
                Some(LdapFilter::new(&filter)?)
            } else {
                None
            },
            attr_class: config
                .attr_class
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_groups: config
                .attr_member_of
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_description: config
                .attr_description
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_secret: config
                .attr_secret
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_secret_changed: config
                .attr_secret_changed
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_email: config
                .attr_email
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            attr_email_alias: config
                .attr_email_alias
                .into_inner()
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            group_class: config.group_class,
            attrs_principal: vec![],
        };

        let mut attrs_principal: Vec<String> = Vec::new();
        for attrs in [
            &mappings.attr_description,
            &mappings.attr_secret,
            &mappings.attr_secret_changed,
            &mappings.attr_groups,
            &mappings.attr_email_alias,
            &mappings.attr_email,
            &mappings.attr_class,
        ] {
            for attr in attrs.iter().filter(|a| !a.is_empty()) {
                if !attrs_principal.contains(attr) {
                    attrs_principal.push(attr.clone());
                }
            }
        }
        mappings.attrs_principal = attrs_principal;

        let create_timeout = if servers.server_count() > 1 {
            config
                .pool_timeout_create
                .into_inner()
                .max(timeout)
                .saturating_mul(u32::try_from(servers.server_count()).unwrap_or(u32::MAX))
        } else {
            config.pool_timeout_create.into_inner()
        };
        let build_pool = |manager: LdapConnectionManager| {
            Pool::builder(manager)
                .runtime(Runtime::Tokio1)
                .max_size(config.pool_max_connections as usize)
                .create_timeout(create_timeout.into())
                .wait_timeout(config.pool_timeout_wait.into_inner().into())
                .recycle_timeout(config.pool_timeout_recycle.into_inner().into())
                .build()
                .map_err(|err| format!("Failed to build LDAP pool: {err}"))
        };

        Ok(Directory::Ldap(LdapDirectory {
            mappings,
            pool: build_pool(manager)?,
            bind_pool: bind_manager.map(build_pool).transpose()?,
            servers,
            timeout,
        }))
    }
}

impl LdapFilter {
    pub(super) fn new(value: &str) -> Result<Self, String> {
        let mut filter = Vec::new();
        let mut token = String::new();
        let mut chars = value.chars();

        while let Some(ch) = chars.next() {
            match ch {
                '?' => {
                    // For backwards compatibility, we treat '?' as a placeholder for the full value.
                    if !token.is_empty() {
                        filter.push(LdapFilterItem::Static(token));
                        token = String::new();
                    }
                    filter.push(LdapFilterItem::Full);
                }
                '{' => {
                    if !token.is_empty() {
                        filter.push(LdapFilterItem::Static(token));
                        token = String::new();
                    }
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            break;
                        } else {
                            token.push(ch);
                        }
                    }
                    match token.as_str() {
                        "user" | "username" | "email" => filter.push(LdapFilterItem::Full),
                        "local" => filter.push(LdapFilterItem::LocalPart),
                        "domain" => filter.push(LdapFilterItem::DomainPart),
                        _ => {
                            return Err(format!("Unknown LDAP filter placeholder: {}", token));
                        }
                    }
                    token.clear();
                }
                _ => token.push(ch),
            }
        }

        if !token.is_empty() {
            filter.push(LdapFilterItem::Static(token));
        }

        if filter.len() >= 2 {
            Ok(LdapFilter { filter })
        } else {
            Err(format!(
                "Missing parameter placeholders in value {:?}",
                value
            ))
        }
    }
}
