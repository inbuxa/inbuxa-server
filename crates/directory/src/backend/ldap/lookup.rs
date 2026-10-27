/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    LdapDirectory, LdapMappings,
    pool::{is_transport_error, with_conn},
};
use crate::{
    Account, Credentials, Group, IntoError, Recipient,
    core::{secret::verify_secret_hash, verifier::PasswordVerifier},
};
use compact_str::CompactString;
use deadpool::managed::Object;
use ldap3::{Ldap, ResultEntry, Scope, SearchEntry};
use std::time::Duration;
use store::xxhash_rust;
use utils::sanitize_email;

impl LdapDirectory {
    pub async fn authenticate(
        &self,
        credentials: &Credentials,
        verifier: &PasswordVerifier,
    ) -> trc::Result<Account> {
        let (username, secret) = match credentials {
            Credentials::Basic {
                username, secret, ..
            } => (username, secret),
            Credentials::Bearer { token, .. } => (token, token),
        };
        if secret.is_empty() {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .reason("Empty secret rejected"));
        }
        let filter = self.mappings.filter_login.build(username);
        let login = {
            let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;
            match self
                .authenticate_on(&mut conn.ldap, &filter, username, secret)
                .await
            {
                Err(err)
                | Ok(LdapLogin::VerifyHash {
                    groups: Err(err), ..
                }) if is_transport_error(&err) => {
                    trc::event!(
                        Store(trc::StoreEvent::LdapWarning),
                        Reason = "LDAP operation failed, retrying on a new connection",
                        CausedBy = err
                    );
                    drop(Object::take(conn));
                    let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;
                    self.authenticate_on(&mut conn.ldap, &filter, username, secret)
                        .await
                }
                login => login,
            }
        }?;

        match login {
            LdapLogin::Bound(account) => Ok(account),
            LdapLogin::VerifyHash {
                account,
                hash,
                groups,
            } => {
                let verified = verify_secret_hash(verifier, &hash, secret.as_bytes()).await?;
                hash_login(account, hash, groups, verified, filter)
            }
        }
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        with_conn!(&self.pool, |conn| self.recipient_on(conn, address))
    }

    async fn authenticate_on(
        &self,
        conn: &mut Ldap,
        filter: &str,
        username: &str,
        secret: &str,
    ) -> trc::Result<LdapLogin> {
        let Some(mut result) = self.find_object(conn, filter).await? else {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .reason(if self.bind_pool.is_some() {
                    "Auth bind lookup filter yielded no results"
                } else {
                    "Authentication filter yielded no results"
                })
                .ctx(trc::Key::Query, filter.to_string()));
        };

        let hash = if let Some(bind_pool) = &self.bind_pool {
            let is_bound: bool = with_conn!(bind_pool, |bind_conn| bind_on(
                bind_conn,
                &result.dn,
                secret,
                self.timeout
            ))?;
            if !is_bound {
                return Err(trc::AuthEvent::Failed
                    .into_err()
                    .reason("Secret rejected during auth bind using lookup filter")
                    .ctx(trc::Key::Name, result.dn)
                    .ctx(trc::Key::Query, filter.to_string()));
            }
            None
        } else {
            Some(result.account.secret.take().ok_or_else(|| {
                trc::AuthEvent::Failed
                    .into_err()
                    .reason("Account does not have a secret")
                    .ctx(trc::Key::Query, filter.to_string())
            })?)
        };

        if result.account.email.is_empty() {
            result.account.email =
                sanitize_email(username).unwrap_or_else(|| username.to_lowercase());
        }

        let groups = self.add_group_membership(conn, &mut result).await;

        match hash {
            Some(hash) => Ok(LdapLogin::VerifyHash {
                account: result.account,
                hash,
                groups,
            }),
            None => groups.map(|()| LdapLogin::Bound(result.account)),
        }
    }

    async fn recipient_on(&self, conn: &mut Ldap, address: &str) -> trc::Result<Recipient> {
        let filter = self.mappings.filter_recipient.build(address);
        if let Some(mut result) = self.find_object(conn, &filter).await? {
            if !result.is_group {
                self.add_group_membership(conn, &mut result).await?;
                Ok(Recipient::Account(result.account))
            } else {
                Ok(Recipient::Group(Group {
                    email: result.account.email,
                    email_aliases: result.account.email_aliases,
                    description: result.account.description,
                }))
            }
        } else {
            trc::event!(
                Store(trc::StoreEvent::LdapWarning),
                Reason = "Mailbox filter yielded no results",
                Query = filter
            );
            Ok(Recipient::Invalid)
        }
    }

    async fn add_group_membership(
        &self,
        conn: &mut Ldap,
        result: &mut LdapResult,
    ) -> trc::Result<()> {
        if let Some(group_dns) = result.account.groups.take() {
            let mut groups = Vec::new();
            for name in group_dns.into_iter().filter(|name| name.contains('=')) {
                let (rs, _res) = conn
                    .with_timeout(self.timeout)
                    .search(
                        &name,
                        Scope::Base,
                        "objectClass=*",
                        &self.mappings.attr_email,
                    )
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?
                    .success()
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?;
                for entry in rs {
                    'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                        if self.mappings.attr_email.contains(&attr.to_lowercase())
                            && let Some(email) =
                                value.first().map(|s| s.as_str()).and_then(sanitize_email)
                        {
                            groups.push(email);
                            break 'outer;
                        }
                    }
                }
            }
            result.account.groups = if groups.is_empty() {
                None
            } else {
                Some(groups)
            };
        } else if let Some(filter) = &self.mappings.filter_member_of {
            let filter = filter.build(&result.dn);
            let rs = conn
                .with_timeout(self.timeout)
                .search(
                    &self.mappings.base_dn,
                    Scope::Subtree,
                    &filter,
                    &self.mappings.attr_email,
                )
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .success()
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .0;
            let had_entries = !rs.is_empty();
            let mut groups = Vec::new();
            for entry in rs {
                for (attr, value) in SearchEntry::construct(entry).attrs {
                    if self.mappings.attr_email.contains(&attr.to_lowercase()) {
                        groups.extend(value.into_iter().filter_map(|v| {
                            sanitize_email(&v).or_else(|| {
                                trc::event!(
                                    Store(trc::StoreEvent::LdapWarning),
                                    Reason = "Group entry missing valid email attribute",
                                    Address = v
                                );
                                None
                            })
                        }));
                    }
                }
            }
            result.account.groups = if had_entries && groups.is_empty() {
                None
            } else {
                Some(groups)
            };
        } else {
            result.account.groups = (!self.mappings.attr_groups.is_empty()).then(Vec::new);
        }

        Ok(())
    }
}

impl LdapDirectory {
    async fn find_object(&self, conn: &mut Ldap, filter: &str) -> trc::Result<Option<LdapResult>> {
        conn.with_timeout(self.timeout)
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                filter,
                &self.mappings.attrs_principal,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .success()
            .map(|(rs, _)| {
                trc::event!(
                    Store(trc::StoreEvent::LdapQuery),
                    Query = CompactString::from(filter),
                    Result = rs.first().map(result_to_trace).unwrap_or_default()
                );

                rs.into_iter()
                    .next()
                    .map(|entry| self.mappings.map_entry(SearchEntry::construct(entry)))
            })
            .map_err(|err| err.into_error().caused_by(trc::location!()))
    }
}

enum LdapLogin {
    Bound(Account),
    VerifyHash {
        account: Account,
        hash: String,
        groups: trc::Result<()>,
    },
}

fn hash_login(
    mut account: Account,
    hash: String,
    groups: trc::Result<()>,
    verified: bool,
    filter: String,
) -> trc::Result<Account> {
    if verified {
        groups.map(|()| {
            account.secret = Some(hash);
            account
        })
    } else {
        Err(trc::AuthEvent::Failed
            .into_err()
            .reason("Invalid credentials")
            .ctx(trc::Key::Query, filter))
    }
}

struct LdapResult {
    dn: String,
    account: Account,
    is_group: bool,
}

impl LdapMappings {
    fn map_entry(&self, entry: SearchEntry) -> LdapResult {
        let mut account = Account::default();
        let mut is_group = false;

        for (attr, value) in entry.attrs {
            let attr = attr.to_lowercase();
            let is_email = self.attr_email.contains(&attr);
            let is_email_alias = self.attr_email_alias.contains(&attr);
            if is_email || is_email_alias {
                let mut values = value.into_iter().filter_map(|v| sanitize_email(&v));
                if is_email
                    && account.email.is_empty()
                    && let Some(email) = values.next()
                {
                    account.email = email;
                }
                if is_email_alias {
                    account.email_aliases.extend(values);
                }
            } else if self.attr_secret.contains(&attr) {
                account.secret = value.into_iter().find(|secret| !secret.is_empty());
            } else if self.attr_secret_changed.contains(&attr) {
                // Create a disabled AppPassword, used to indicate that the password has been changed
                // but cannot be used for authentication.
                if account.secret.is_none() {
                    account.secret = value.into_iter().find(|item| !item.is_empty()).map(|item| {
                        format!("$app${}$", xxhash_rust::xxh3::xxh3_64(item.as_bytes()))
                    });
                }
            } else if let Some(idx) = self.attr_description.iter().position(|a| a == &attr) {
                if (account.description.is_none() || idx == 0)
                    && let Some(desc) = value.into_iter().find(|desc| !desc.is_empty())
                {
                    account.description = Some(desc);
                }
            } else if self.attr_groups.contains(&attr) {
                account.groups.get_or_insert_default().extend(value);
            } else if self.attr_class.contains(&attr) {
                for value in value {
                    is_group |= value.eq_ignore_ascii_case(&self.group_class);
                }
            }
        }

        if !account.email_aliases.is_empty() {
            let mut aliases = Vec::with_capacity(account.email_aliases.len());
            for alias in std::mem::take(&mut account.email_aliases) {
                if alias != account.email && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
            account.email_aliases = aliases;
        }

        LdapResult {
            dn: entry.dn,
            account,
            is_group,
        }
    }
}

async fn bind_on(conn: &mut Ldap, dn: &str, secret: &str, timeout: Duration) -> trc::Result<bool> {
    Ok(conn
        .with_timeout(timeout)
        .simple_bind(dn, secret)
        .await
        .map_err(|err| err.into_error().caused_by(trc::location!()))?
        .success()
        .is_ok())
}

fn result_to_trace(rs: &ResultEntry) -> trc::Value {
    let se = SearchEntry::construct(rs.clone());
    se.attrs
        .into_iter()
        .map(|(k, v)| trc::Value::Array(vec![trc::Value::from(k), trc::Value::from(v.join(", "))]))
        .chain([trc::Value::from(se.dn)])
        .collect::<Vec<_>>()
        .into()
}

