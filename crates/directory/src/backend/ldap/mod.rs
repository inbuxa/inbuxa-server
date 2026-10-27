/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed::Pool;
use failover::LdapServers;
use ldap3::{Ldap, LdapConnSettings, ldap_escape};
use std::{sync::Arc, time::Duration};

pub mod config;
pub mod failover;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    bind_pool: Option<Pool<LdapConnectionManager>>,
    servers: Arc<LdapServers>,
    timeout: Duration,
}

impl LdapDirectory {
    pub fn has_failover(&self) -> bool {
        self.servers.has_failover()
    }

    pub fn disable_failover(&self) {
        self.servers.disable_failover();
    }
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_login: LdapFilter,
    filter_recipient: LdapFilter,
    filter_member_of: Option<LdapFilter>,
    attr_class: Vec<String>,
    attr_groups: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_secret_changed: Vec<String>,
    attr_email: Vec<String>,
    attr_email_alias: Vec<String>,
    attrs_principal: Vec<String>,
    group_class: String,
}

#[derive(Debug, Default)]
pub(crate) struct LdapFilter {
    filter: Vec<LdapFilterItem>,
}

#[derive(Debug)]
enum LdapFilterItem {
    Static(String),
    Full,
    LocalPart,
    DomainPart,
}

impl LdapFilter {
    pub fn build(&self, value: &str) -> String {
        let mut result = String::with_capacity(value.len() + 16);

        for item in &self.filter {
            match item {
                LdapFilterItem::Static(s) => result.push_str(s),
                LdapFilterItem::Full => result.push_str(ldap_escape(value).as_ref()),
                LdapFilterItem::LocalPart => {
                    result.push_str(
                        ldap_escape(
                            value
                                .rsplit_once('@')
                                .map(|(local, _)| local)
                                .unwrap_or(value),
                        )
                        .as_ref(),
                    );
                }
                LdapFilterItem::DomainPart => {
                    if let Some((_, domain)) = value.rsplit_once('@') {
                        result.push_str(ldap_escape(domain).as_ref());
                    }
                }
            }
        }

        result
    }
}

pub(crate) struct LdapConnectionManager {
    servers: Arc<LdapServers>,
    connector: Arc<LdapConnector>,
}

pub(crate) struct LdapConnector {
    settings: LdapConnSettings,
    bind_dn: Option<Bind>,
    timeout: Duration,
}

pub(crate) struct LdapConnection {
    ldap: Ldap,
    server: usize,
}

pub(crate) struct Bind {
    dn: String,
    password: String,
}

impl LdapConnectionManager {
    pub fn new(
        servers: Arc<LdapServers>,
        settings: LdapConnSettings,
        bind_dn: Option<Bind>,
        timeout: Duration,
    ) -> Self {
        Self {
            servers,
            connector: Arc::new(LdapConnector {
                settings,
                bind_dn,
                timeout,
            }),
        }
    }
}

impl Bind {
    pub fn new(dn: String, password: String) -> Self {
        Self { dn, password }
    }
}

