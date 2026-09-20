/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{Server, auth::DomainCache, cache::invalidate::CacheInvalidationBuilder};
use registry::{
    schema::{
        prelude::{Object, ObjectType},
        structs::{
            Account, Credential, EmailAlias, GroupAccount, PasswordCredential, Roles, UserAccount,
            UserRoles,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId, list::List},
};
use std::sync::Arc;
use store::registry::write::{RegistryWrite, RegistryWriteResult};
use trc::AddContext;
use types::id::Id;

pub struct AccountWithId {
    pub id: u32,
    pub account: Account,
}

impl Server {
    pub async fn synchronize_account(
        &self,
        account: directory::Account,
    ) -> trc::Result<AccountWithId> {
        let (local, domain) = self.validate_address(&account.email).await?;

        match self
            .account_id_from_parts(local, domain.id)
            .await
            .caused_by(trc::location!())?
        {
            Some(account_id) => {
                let current_account = self
                    .registry()
                    .get(ObjectId::new(ObjectType::Account, account_id.into()))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Account ID from directory does not exist in registry")
                            .ctx(trc::Key::AccountName, account.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;

                // inbuxa: SCIM-58: SCIM is authoritative; sign-in changes nothing
                if domain.allows_scim() {
                    return Ok(AccountWithId {
                        id: account_id,
                        account: Account::from(current_account),
                    });
                }

                let mut updated_account = Account::from(current_account.clone())
                    .into_user()
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details(
                                "Account ID from directory does not correspond to a user account",
                            )
                            .ctx(trc::Key::AccountName, account.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;

                let mut has_changes = false;
                if let Some(secret) = account.secret
                    && secret != updated_account.password().unwrap_or_default()
                {
                    has_changes = true;
                    updated_account.set_password(secret);
                }
                if account.description.is_some()
                    && account.description != updated_account.description
                {
                    updated_account.description = account.description;
                    has_changes = true;
                }
                for alias in account.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self.same_directory(&domain, &alias).await?
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        updated_account.aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                        has_changes = true;
                    }
                }
                if let Some(groups) = account.groups {
                    let mut member_group_ids = Vec::with_capacity(groups.len());
                    for email in groups {
                        // inbuxa: SCIM-58: no group comes from a claim on a SCIM domain
                        if self.is_scim_address(&email).await?
                            || !self.same_directory(&domain, &email).await?
                        {
                            continue;
                        }
                        member_group_ids.push(
                            self.synchronize_group(directory::Group {
                                email,
                                ..Default::default()
                            })
                            .await
                            .caused_by(trc::location!())?
                            .into(),
                        );
                    }
                    if updated_account.member_group_ids.len() != member_group_ids.len()
                        || !updated_account
                            .member_group_ids
                            .iter()
                            .all(|id| member_group_ids.contains(id))
                    {
                        updated_account.member_group_ids = member_group_ids.into();
                        has_changes = true;
                    }
                }

                if has_changes {
                    let updated_account = Object::from(Account::User(updated_account));
                    match self
                        .registry()
                        .write(RegistryWrite::update(
                            Id::from(account_id),
                            &updated_account,
                            &current_account,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        RegistryWriteResult::Success(id) => {
                            let mut invalidator = CacheInvalidationBuilder::default();
                            invalidator.process_update(id, &current_account, &updated_account);
                            self.invalidate_caches(invalidator)
                                .await
                                .caused_by(trc::location!())?;

                            Ok(AccountWithId {
                                id: id.document_id(),
                                account: updated_account.into(),
                            })
                        }
                        failure => Err(trc::AuthEvent::Error
                            .into_err()
                            .caused_by(trc::location!())
                            .details("Failed to synchronize account with directory")
                            .reason(failure)),
                    }
                } else {
                    Ok(AccountWithId {
                        id: account_id,
                        account: Account::User(updated_account),
                    })
                }
            }
            None => {
                // inbuxa: SCIM-58: accounts on this domain come from SCIM only
                if domain.allows_scim() {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .details("The account isn't provisioned: its domain is managed by SCIM")
                        .ctx(trc::Key::AccountName, account.email));
                }

                let mut aliases = Vec::with_capacity(account.email_aliases.len());
                for alias in account.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self.same_directory(&domain, &alias).await?
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                    }
                }
                let mut member_group_ids = Vec::new();
                for email in account.groups.unwrap_or_default() {
                    // inbuxa: SCIM-58: no group comes from a claim on a SCIM domain
                    if self.is_scim_address(&email).await?
                        || !self.same_directory(&domain, &email).await?
                    {
                        continue;
                    }
                    member_group_ids.push(
                        self.synchronize_group(directory::Group {
                            email,
                            ..Default::default()
                        })
                        .await
                        .caused_by(trc::location!())?
                        .into(),
                    );
                }
                let account = Object::from(Account::User(UserAccount {
                    name: local.to_string(),
                    domain_id: Id::from(domain.id),
                    aliases: aliases.into(),
                    created_at: UTCDateTime::now(),
                    description: account.description,
                    member_group_ids: member_group_ids.into(),
                    member_tenant_id: domain.id_tenant.map(Id::from),
                    roles: UserRoles::User,
                    credentials: List::from_iter(account.secret.map(|secret| {
                        Credential::Password(PasswordCredential {
                            credential_id: 0u64.into(),
                            secret,
                            ..Default::default()
                        })
                    })),
                    ..Default::default()
                }));


                // inbuxa: DIR-15
                self.check_tenant_limits(&account).await?;
                match self
                    .registry()
                    .write(RegistryWrite::insert(&account))
                    .await
                    .caused_by(trc::location!())?
                {
                    RegistryWriteResult::Success(id) => {
                        let mut invalidator = CacheInvalidationBuilder::default();
                        invalidator.process_create(&account);
                        self.invalidate_caches(invalidator)
                            .await
                            .caused_by(trc::location!())?;

                        Ok(AccountWithId {
                            id: id.document_id(),
                            account: account.into(),
                        })
                    }
                    failure => Err(trc::AuthEvent::Error
                        .into_err()
                        .caused_by(trc::location!())
                        .details("Failed to create account from directory")
                        .reason(failure)),
                }
            }
        }
    }

    pub async fn synchronize_group(&self, group: directory::Group) -> trc::Result<u32> {
        let (local, domain) = self.validate_address(&group.email).await?;

        match self
            .account_id_from_parts(local, domain.id)
            .await
            .caused_by(trc::location!())?
        {
            Some(account_id) => {
                let current_account = self
                    .registry()
                    .get(ObjectId::new(ObjectType::Account, account_id.into()))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Account ID from directory does not exist in registry")
                            .ctx(trc::Key::AccountName, group.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;

                // inbuxa: SCIM-58: SCIM is authoritative; sign-in changes nothing
                if domain.allows_scim() {
                    return Ok(account_id);
                }

                let mut updated_account = Account::from(current_account.clone())
                    .into_group()
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details(
                                "Account ID from directory does not correspond to a group account",
                            )
                            .ctx(trc::Key::AccountName, group.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;

                let mut has_changes = false;
                if group.description.is_some() && group.description != updated_account.description {
                    updated_account.description = group.description;
                    has_changes = true;
                }
                for alias in group.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self.same_directory(&domain, &alias).await?
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        updated_account.aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                        has_changes = true;
                    }
                }

                if has_changes {
                    let updated_account = Object::from(Account::Group(updated_account));
                    match self
                        .registry()
                        .write(RegistryWrite::update(
                            Id::from(account_id),
                            &updated_account,
                            &current_account,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        RegistryWriteResult::Success(id) => {
                            let mut invalidator = CacheInvalidationBuilder::default();
                            invalidator.process_update(id, &current_account, &updated_account);
                            self.invalidate_caches(invalidator)
                                .await
                                .caused_by(trc::location!())?;

                            Ok(id.document_id())
                        }
                        failure => Err(trc::AuthEvent::Error
                            .into_err()
                            .caused_by(trc::location!())
                            .details("Failed to synchronize account with directory")
                            .reason(failure)),
                    }
                } else {
                    Ok(account_id)
                }
            }
            None => {
                // inbuxa: SCIM-58: groups on this domain come from SCIM only
                if domain.allows_scim() {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .details("The group isn't provisioned: its domain is managed by SCIM")
                        .ctx(trc::Key::AccountName, group.email));
                }

                let mut aliases = Vec::with_capacity(group.email_aliases.len());
                for alias in group.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self.same_directory(&domain, &alias).await?
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                    }
                }

                let account = Object::from(Account::Group(GroupAccount {
                    name: local.to_string(),
                    domain_id: Id::from(domain.id),
                    aliases: aliases.into(),
                    created_at: UTCDateTime::now(),
                    description: group.description,
                    member_tenant_id: domain.id_tenant.map(Id::from),
                    roles: Roles::Default,
                    ..Default::default()
                }));


                // inbuxa: DIR-15
                self.check_tenant_limits(&account).await?;
                match self
                    .registry()
                    .write(RegistryWrite::insert(&account))
                    .await
                    .caused_by(trc::location!())?
                {
                    RegistryWriteResult::Success(id) => {
                        let mut invalidator = CacheInvalidationBuilder::default();
                        invalidator.process_create(&account);
                        self.invalidate_caches(invalidator)
                            .await
                            .caused_by(trc::location!())?;

                        Ok(id.document_id())
                    }
                    failure => Err(trc::AuthEvent::Error
                        .into_err()
                        .caused_by(trc::location!())
                        .details("Failed to create account from directory")
                        .reason(failure)),
                }
            }
        }
    }

    /// inbuxa: DIR-6: whether an address is on a domain served by the same
    /// directory as `domain`; a warning when it isn't.
    async fn same_directory(&self, domain: &DomainCache, address: &str) -> trc::Result<bool> {
        let Some((_, other)) = address.rsplit_once('@') else {
            return Ok(true);
        };
        let Some(other) = self.domain(other).await? else {
            return Ok(true);
        };
        let same = match (
            self.get_directory_for_cached_domain(domain),
            self.get_directory_for_cached_domain(&other),
        ) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if !same {
            trc::event!(
                Auth(trc::AuthEvent::Warning),
                AccountName = address.to_string(),
                Domain = other.name().to_string(),
                Reason = "Dropped: the address is on a domain served by another directory",
            );
        }
        Ok(same)
    }

    /// inbuxa: DIR-15, MT-3, MT-17: an object created from a directory
    /// passes the same tenant checks as one created over JMAP.
    async fn check_tenant_limits(&self, object: &Object) -> trc::Result<()> {
        match inbuxa_features::tenancy::writes::check(self.registry(), None, None, object).await? {
            Ok(_) => Ok(()),
            Err(err) => Err(trc::AuthEvent::Failed
                .into_err()
                .details(err.description().unwrap_or("A tenant limit is reached").to_string())
                .reason("The directory's account can't be created")),
        }
    }

    /// inbuxa: SCIM-58: whether an address is on a domain SCIM manages.
    async fn is_scim_address(&self, address: &str) -> trc::Result<bool> {
        Ok(match address.rsplit_once('@') {
            Some((_, domain)) => self
                .domain(domain)
                .await?
                .is_some_and(|domain| domain.allows_scim()),
            None => false,
        })
    }

    async fn validate_address<'x>(
        &self,
        email: &'x str,
    ) -> trc::Result<(&'x str, Arc<DomainCache>)> {
        if email.is_empty() {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Account email cannot be empty"));
        }
        match email.rsplit_once('@') {
            Some((local, domain)) => self
                .domain(domain)
                .await
                .caused_by(trc::location!())?
                .map(|domain| (local, domain))
                .ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Account domain does not exist or has been disabled")
                        .ctx(trc::Key::Domain, domain.to_string())
                }),
            None => {
                trc::event!(
                    Auth(trc::AuthEvent::Warning),
                    AccountName = email.to_string().clone(),
                    Details = "Directory account is not an email, appended default domain",
                );
                self.domain_by_id(self.core.email.default_domain_id)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Default domain does not exist or has been disabled")
                            .ctx(trc::Key::Id, self.core.email.default_domain_id)
                    })
                    .map(|domain| (email, domain))
            }
        }
    }

    async fn validate_alias<'x>(
        &self,
        email: &'x str,
    ) -> trc::Result<Option<(&'x str, Arc<DomainCache>)>> {
        match email.rsplit_once('@') {
            Some((local, domain)) => self
                .domain(domain)
                .await
                .caused_by(trc::location!())
                .map(|domain| domain.map(|domain| (local, domain))),
            None => Ok(None),
        }
    }
}
