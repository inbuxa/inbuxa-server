/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use common::{
    Server,
    auth::{AccessToken, oauth::scope::OAuthScopes},
};
use jmap_proto::request::capability::{
    Account, BaseCapabilities, Capabilities, Capability, CapabilityIds, DelegationInfo,
    EmptyCapabilities, InbuxaAccountCapabilities, InbuxaDelegatedCapabilities,
    PrincipalOwnerCapabilities, Session,
};
use registry::schema::enums::Permission;
use std::future::Future;
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub trait SessionHandler: Sync + Send {
    fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Session>> + Send;
}

pub trait JmapAccount {
    fn jmap_account(&self, access_token: &AccessToken, account_id: u32, name: String) -> Account;

    fn jmap_account_capabilities(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Iterator<Item = (Capability, Capabilities)>;
}

impl JmapAccount for Server {
    fn jmap_account(&self, access_token: &AccessToken, account_id: u32, name: String) -> Account {
        let mut account_capabilities =
            VecMap::with_capacity(self.core.jmap.capabilities.account.len() + 1);
        account_capabilities.extend(self.jmap_account_capabilities(access_token, account_id));
        account_capabilities.append(
            Capability::PrincipalsOwner,
            Capabilities::PrincipalsOwner(PrincipalOwnerCapabilities {
                account_id_for_principal: Id::from(access_token.account_id()),
                principal_id: Id::from(account_id),
            }),
        );
        // inbuxa: AL-6, AL-7: a delegated locked account says so, and is
        // read-only at the read level
        let delegation = access_token.delegation(account_id).cloned();
        let is_read_only = access_token.is_read_only(account_id)
            || delegation
                .as_ref()
                .is_some_and(|d| d.access == inbuxa_features::lock::Access::Read);
        if let Some(delegation) = delegation {
            account_capabilities.append(
                Capability::Inbuxa,
                Capabilities::InbuxaDelegated(InbuxaDelegatedCapabilities {
                    delegation: DelegationInfo {
                        locked: true,
                        kind: delegation.kind.as_str(),
                        access: delegation.access.as_str(),
                        send_as: delegation.send_as,
                        until: delegation.until.map(|until| {
                            jmap_proto::types::date::UTCDate::from_timestamp(until as i64)
                                .to_string()
                        }),
                    },
                }),
            );
        }
        Account {
            name,
            is_personal: account_id == access_token.account_id(),
            is_read_only,
            account_capabilities,
        }
    }

    fn jmap_account_capabilities(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Iterator<Item = (Capability, Capabilities)> {
        let base_capabilities = &self.core.jmap.capabilities;
        // inbuxa: #186: reads in a sharing account go through the share
        let is_owner = access_token.reads_as_owner(account_id);
        let current_user_principal_id = Some(Id::from(access_token.account_id()));
        let supports_private = access_token.has_permission(Permission::JmapMetadataPrivate);
        let capability_ids = access_token
            .account_capabilities(base_capabilities)
            .filter(|capability| {
                is_owner
                    || !matches!(
                        capability,
                        Capability::Submission
                            | Capability::VacationResponse
                            | Capability::Sieve
                            | Capability::Quota
                            | Capability::EmailPush
                    )
            })
            .collect::<CapabilityIds>();

        Capability::all_capabilities()
            .iter()
            .copied()
            .filter(move |capability| capability_ids.contains(*capability))
            .filter_map(move |capability| {
                let capabilities = match base_capabilities.account.get(&capability) {
                    Some(Capabilities::Metadata(metadata)) => Capabilities::Metadata(
                        metadata.to_account_capabilities(capability_ids, supports_private)?,
                    ),
                    Some(capabilities) => {
                        capabilities.to_account_capabilities(current_user_principal_id, is_owner)
                    }
                    None => Capabilities::Empty(EmptyCapabilities::default()),
                };
                Some((capability, capabilities))
            })
    }
}

impl SessionHandler for Server {
    async fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> trc::Result<Session> {
        let mut session = Session::new(base_url, &self.core.jmap.capabilities);
        session.set_state(access_token.state());
        if access_token.oauth_scopes().is_some() {
            for capability in Capability::all_capabilities() {
                if !access_token.allows_oauth_scopes(capability_scopes(*capability)) {
                    session.capabilities.remove(capability);
                }
            }
        }

        // Set primary account
        let account = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        session.username = account.name().to_string();
        let account_id = Id::from(access_token.account_id());
        let mut primary_account = self.jmap_account(
            access_token,
            access_token.account_id(),
            account.name().to_string(),
        );
        // inbuxa: MT-22: the logo that applies to the signed-in principal
        let logo =
            inbuxa_features::tenancy::logo::for_account(self.registry(), access_token.account_id())
                .await
                .caused_by(trc::location!())?;
        session.capabilities.append(
            Capability::Inbuxa,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        // inbuxa: legacy-protocols, Interfaces: whichever switch is stricter,
        // per protocol. `legacyProtocols` stays for older webmail builds:
        // `disabled` only when every protocol is off.
        let legacy_off = self.legacy_off_for_account(access_token).await?;
        let legacy_protocols = if legacy_off.all() {
            "disabled"
        } else {
            "enabled"
        };
        let legacy_allowed = legacy_off.allowed();
        // inbuxa: ai-explain, EX-1 to EX-4: whether Explain can be offered
        let ai_explain = access_token.has_permission(Permission::SysAiExplain)
            && access_token.tenant_id().is_none()
            && self.ai_explain_model(&self.ai_limits().await).await.is_some();
        // inbuxa: MA-C: what the sharing switches leave this principal
        let sharing = inbuxa_features::security::sharing_policy::effective_for(
            self.store(),
            access_token.tenant_id(),
        )
        .await
        .caused_by(trc::location!())?;
        primary_account.account_capabilities.append(
            Capability::Inbuxa,
            Capabilities::Inbuxa(InbuxaAccountCapabilities {
                logo,
                legacy_protocols,
                legacy_allowed,
                ai_explain,
                mail_sharing: sharing.mail_sharing,
                add_accounts: sharing.add_accounts,
            }),
        );
        // inbuxa: Fastmail's Masked Email API, for accounts that may hold masks
        if access_token.has_permission(Permission::SysMaskedEmailGet)
            && access_token.allows_oauth_scopes(capability_scopes(Capability::FastmailMaskedEmail))
        {
            session.capabilities.append(
                Capability::FastmailMaskedEmail,
                Capabilities::Empty(EmptyCapabilities::default()),
            );
            primary_account.account_capabilities.append(
                Capability::FastmailMaskedEmail,
                Capabilities::Empty(EmptyCapabilities::default()),
            );
            session
                .primary_accounts
                .append(Capability::FastmailMaskedEmail, account_id);
        }
        for capability in access_token.account_capabilities(&self.core.jmap.capabilities) {
            if capability != Capability::Metadata
                || primary_account
                    .account_capabilities
                    .contains_key(&Capability::Metadata)
            {
                session.primary_accounts.append(capability, account_id);
            }
        }
        session.accounts.append(account_id, primary_account);

        // Add secondary accounts
        for &account_id in access_token.secondary_ids() {
            let Some(account) = self
                .try_account(account_id)
                .await
                .caused_by(trc::location!())?
            else {
                trc::event!(
                    Auth(trc::AuthEvent::Warning),
                    AccountId = account_id,
                    Reason = "Skipping orphan secondary account id in session",
                );
                continue;
            };
            session.accounts.append(
                Id::from(account_id),
                self.jmap_account(access_token, account_id, account.name().to_string()),
            );
        }

        if !session.accounts.values().any(|account| {
            account
                .account_capabilities
                .contains_key(&Capability::Metadata)
        }) {
            session.capabilities.remove(&Capability::Metadata);
        }

        Ok(session)
    }
}

trait AccountCapabilities {
    fn account_capabilities(
        &self,
        base_capabilities: &BaseCapabilities,
    ) -> impl Iterator<Item = Capability>;
}

impl AccountCapabilities for AccessToken {
    fn account_capabilities(
        &self,
        base_capabilities: &BaseCapabilities,
    ) -> impl Iterator<Item = Capability> {
        Capability::all_capabilities()
            .iter()
            .filter(move |capability| {
                let permission = match capability {
                    Capability::Mail | Capability::MailShare | Capability::EmailPush => {
                        Permission::JmapEmailGet
                    }
                    Capability::Submission => Permission::JmapEmailSubmissionCreate,
                    Capability::VacationResponse => Permission::JmapVacationResponseGet,
                    Capability::Contacts => Permission::JmapContactCardGet,
                    Capability::ContactsParse => Permission::JmapContactCardParse,
                    Capability::Calendars => Permission::JmapCalendarEventGet,
                    Capability::CalendarsParse => Permission::JmapCalendarEventParse,
                    Capability::Sieve => Permission::JmapSieveScriptGet,
                    Capability::Blob => Permission::JmapBlobGet,
                    Capability::Quota => Permission::JmapQuotaGet,
                    Capability::FileNode => Permission::JmapFileNodeGet,
                    Capability::Metadata
                        if base_capabilities
                            .account
                            .contains_key(&Capability::Metadata) =>
                    {
                        Permission::JmapMetadataGet
                    }
                    Capability::WebSocket
                    | Capability::Principals
                    | Capability::PrincipalsAvailability
                    | Capability::Stalwart => return true,
                    Capability::Core
                    | Capability::PrincipalsOwner
                    | Capability::WebPushVapid
                    | Capability::Metadata
                    | Capability::Inbuxa
                    | Capability::FastmailMaskedEmail => {
                        return false;
                    }
                };
                self.has_permission(permission)
            })
            .filter(|capability| self.allows_oauth_scopes(capability_scopes(**capability)))
            .copied()
    }
}

pub fn capability_scopes(capability: Capability) -> OAuthScopes {
    match capability {
        Capability::Core
        | Capability::Blob
        | Capability::Quota
        | Capability::Principals
        | Capability::PrincipalsOwner
        | Capability::WebSocket
        | Capability::WebPushVapid
        | Capability::Metadata => OAuthScopes::INTEROPERABLE,
        Capability::Mail
        | Capability::Submission
        | Capability::VacationResponse
        | Capability::Sieve
        | Capability::MailShare
        | Capability::EmailPush => OAuthScopes::MAIL,
        Capability::Contacts | Capability::ContactsParse => OAuthScopes::CONTACTS,
        Capability::Calendars | Capability::CalendarsParse | Capability::PrincipalsAvailability => {
            OAuthScopes::CALENDARS
        }
        Capability::FileNode => OAuthScopes::FILES,
        // inbuxa: the fork's own capability is like the vendor one above
        Capability::Stalwart | Capability::Inbuxa => OAuthScopes::NONE,
        // inbuxa: masks are mail addresses
        Capability::FastmailMaskedEmail => OAuthScopes::MAIL,
    }
}

pub fn allowed_capabilities(access_token: &AccessToken, using: CapabilityIds) -> CapabilityIds {
    if access_token.oauth_scopes().is_none() {
        return using;
    }
    Capability::all_capabilities()
        .iter()
        .copied()
        .filter(|capability| {
            using.contains(*capability)
                && access_token.allows_oauth_scopes(capability_scopes(*capability))
        })
        .collect()
}
