/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use common::{Server, auth::AccessToken};
use jmap_proto::request::capability::{
    Account, Capabilities, Capability, EmptyCapabilities, InbuxaAccountCapabilities, Session,
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

impl SessionHandler for Server {
    async fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> trc::Result<Session> {
        let mut session = Session::new(base_url, &self.core.jmap.capabilities);
        session.set_state(access_token.state());
        let account_capabilities = &self.core.jmap.capabilities.account;

        // Set primary account
        let account = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        session.username = account.name().to_string();
        let account_id = Id::from(access_token.account_id());
        let mut account = Account {
            name: account.name().to_string(),
            is_personal: true,
            is_read_only: false,
            account_capabilities: VecMap::with_capacity(account_capabilities.len()),
        };
        for capability in access_token.account_capabilities() {
            session.primary_accounts.append(capability, account_id);
            account.account_capabilities.append(
                capability,
                account_capabilities
                    .get(&capability)
                    .map(|v| v.to_account_capabilities(account_id.into(), true))
                    .unwrap_or_else(|| Capabilities::Empty(EmptyCapabilities::default())),
            );
        }
        // inbuxa: MT-22: the logo that applies to the signed-in principal
        let logo =
            inbuxa_features::tenancy::logo::for_account(self.registry(), access_token.account_id())
                .await
                .caused_by(trc::location!())?;
        session.capabilities.append(
            Capability::Inbuxa,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        // inbuxa: legacy-protocols, Interfaces: whichever switch is stricter
        let legacy_protocols = if self.legacy_protocols_off_for_account(access_token).await? {
            "disabled"
        } else {
            "enabled"
        };
        // inbuxa: ai-explain, EX-1 to EX-4: whether Explain can be offered
        let ai_explain = access_token.has_permission(Permission::SysAiExplain)
            && access_token.tenant_id().is_none()
            && self.ai_explain_model(&self.ai_limits().await).await.is_some();
        account.account_capabilities.append(
            Capability::Inbuxa,
            Capabilities::Inbuxa(InbuxaAccountCapabilities {
                logo,
                legacy_protocols,
                ai_explain,
            }),
        );
        // inbuxa: Fastmail's Masked Email API, for accounts that may hold masks
        if access_token.has_permission(Permission::SysMaskedEmailGet) {
            session.capabilities.append(
                Capability::FastmailMaskedEmail,
                Capabilities::Empty(EmptyCapabilities::default()),
            );
            account.account_capabilities.append(
                Capability::FastmailMaskedEmail,
                Capabilities::Empty(EmptyCapabilities::default()),
            );
            session
                .primary_accounts
                .append(Capability::FastmailMaskedEmail, account_id);
        }
        session.accounts.append(account_id, account);

        // Add secondary accounts
        for &account_id in access_token.secondary_ids() {
            let is_owner = access_token.is_member(account_id);
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

            let account_id = Id::from(account_id);
            let mut account = Account {
                name: account.name().to_string(),
                is_personal: false,
                is_read_only: false,
                account_capabilities: VecMap::with_capacity(account_capabilities.len()),
            };
            for capability in access_token.account_capabilities() {
                account.account_capabilities.append(
                    capability,
                    account_capabilities
                        .get(&capability)
                        .map(|v| v.to_account_capabilities(account_id.into(), is_owner))
                        .unwrap_or_else(|| Capabilities::Empty(EmptyCapabilities::default())),
                );
            }
            session.accounts.append(account_id, account);
        }

        Ok(session)
    }
}

trait AccountCapabilities {
    fn account_capabilities(&self) -> impl Iterator<Item = Capability>;
}

impl AccountCapabilities for AccessToken {
    fn account_capabilities(&self) -> impl Iterator<Item = Capability> {
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
                    Capability::WebSocket
                    | Capability::Principals
                    | Capability::PrincipalsAvailability
                    | Capability::Stalwart => return true,
                    Capability::Core
                    | Capability::PrincipalsOwner
                    | Capability::WebPushVapid
                    | Capability::Inbuxa
                    | Capability::FastmailMaskedEmail => {
                        return false;
                    }
                };
                self.has_permission(permission)
            })
            .copied()
    }
}
