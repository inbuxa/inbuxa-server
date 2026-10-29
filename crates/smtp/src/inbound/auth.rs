/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::core::Session;
use common::{
    auth::AuthRequest,
    config::smtp::session::Mechanism,
    network::{SessionStream, legacy::LegacyProtocol},
};
use directory::Credentials;
use mail_parser::{HeaderName, HeaderValue, decoders::base64::base64_decode};
use registry::schema::enums::Permission;
use smtp_proto::{AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH, AUTH_XOAUTH2, IntoString};
use trc::AuthEvent;

// inbuxa: mechanisms that send a bearer token, a credential on its own
pub const AUTH_BEARER: u64 = AUTH_OAUTHBEARER | AUTH_XOAUTH | AUTH_XOAUTH2;

pub struct SaslToken {
    mechanism: u64,
    credentials: Credentials,
}

impl SaslToken {
    pub fn from_mechanism(mechanism: u64) -> Option<SaslToken> {
        match mechanism {
            AUTH_PLAIN | AUTH_LOGIN => SaslToken {
                mechanism,
                credentials: Credentials::Basic {
                    username: String::new(),
                    secret: String::new(),
                    mfa_token: None,
                },
            }
            .into(),
            AUTH_OAUTHBEARER | AUTH_XOAUTH2 => SaslToken {
                mechanism,
                credentials: Credentials::Bearer {
                    username: None,
                    token: String::new(),
                },
            }
            .into(),
            _ => None,
        }
    }
}

impl<T: SessionStream> Session<T> {
    /// The mechanisms this session may use: the configured ones, less the
    /// bearer token ones on clear text whatever the configuration says.
    pub async fn sasl_mechanisms(&self) -> u64 {
        let mechanisms: u64 = self
            .server
            .eval_if::<Mechanism, _>(
                &self.server.core.smtp.session.auth.mechanisms,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or_default()
            .into();

        if self.stream.is_tls() {
            mechanisms
        } else {
            mechanisms & !AUTH_BEARER
        }
    }

    pub async fn handle_sasl_response(
        &mut self,
        token: &mut SaslToken,
        response: &[u8],
    ) -> Result<bool, ()> {
        if response.is_empty() {
            match (token.mechanism, &token.credentials) {
                (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER, _) => {
                    self.write(b"334 \r\n").await?;
                    return Ok(true);
                }
                (
                    AUTH_LOGIN,
                    Credentials::Basic {
                        username, secret, ..
                    },
                ) if username.is_empty() && secret.is_empty() => {
                    self.write(b"334 VXNlcm5hbWU6\r\n").await?;
                    return Ok(true);
                }
                _ => (),
            }
        } else if let Some(response) = base64_decode(response) {
            match (token.mechanism, &mut token.credentials) {
                (AUTH_PLAIN, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_plain(&response) {
                        return self.authenticate(credentials).await;
                    }
                }
                (
                    AUTH_LOGIN,
                    Credentials::Basic {
                        username, secret, ..
                    },
                ) => {
                    return if username.is_empty() {
                        *username = response.into_string();
                        self.write(b"334 UGFzc3dvcmQ6\r\n").await?;
                        Ok(true)
                    } else {
                        *secret = response.into_string();
                        self.authenticate(std::mem::replace(
                            &mut token.credentials,
                            Credentials::Basic {
                                username: String::new(),
                                secret: String::new(),
                                mfa_token: None,
                            },
                        ))
                        .await
                    };
                }
                (AUTH_OAUTHBEARER | AUTH_XOAUTH2, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_oauth(&response) {
                        return self.authenticate(credentials).await;
                    }
                }
                _ => (),
            }
        }

        self.auth_error(b"500 5.5.6 Invalid challenge.\r\n").await
    }

    pub async fn authenticate(&mut self, credentials: Credentials) -> Result<bool, ()> {
        // inbuxa: legacy-protocols LP-6. Refused before the password is looked
        // at, and not counted as an authentication error (LP-11). Only mail
        // apps authenticate, so this never touches inbound delivery (LP-3).
        if let Err(err) = self
            .server
            .refuse_legacy_sign_in(LegacyProtocol::Submission, &credentials)
            .await
        {
            return self.legacy_refusal(err).await;
        }

        // Authenticate
        let result = self
            .server
            .authenticate(&AuthRequest::from_credentials(
                credentials,
                self.data.session_id,
                self.data.remote_ip,
            ))
            .await
            .and_then(|access_token| access_token.assert_has_permission(Permission::EmailSend));

        // inbuxa: legacy-protocols LP-10, for a bearer token that named no
        // account and so couldn't be judged by its domain beforehand; and
        // LP-15, the sign-in is recorded for the impact panel.
        if let Ok(access_token) = &result
            && let Err(err) = self
                .server
                .admit_legacy_session(LegacyProtocol::Submission, access_token)
                .await
        {
            return self.legacy_refusal(err).await;
        }

        let result = match result {
            Ok(access_token) => self
                .server
                .account_info(access_token.account_id())
                .await
                .map(|account_info| (account_info, access_token)),
            Err(err) => Err(err),
        };

        match result {
            Ok((account_info, access_token)) => {
                self.data.authenticated_as = account_info.into();
                self.data.access_token = access_token.into();
                self.eval_post_auth_params().await;
                self.write(b"235 2.7.0 Authentication succeeded.\r\n")
                    .await?;
                return Ok(false);
            }
            Err(err) => {
                let reason = *err.as_ref();

                trc::error!(err.span_id(self.data.session_id));

                match reason {
                    trc::EventType::Auth(trc::AuthEvent::Failed) => {
                        return self
                            .auth_error(b"535 5.7.8 Authentication credentials invalid.\r\n")
                            .await;
                    }
                    trc::EventType::Auth(trc::AuthEvent::TokenExpired) => {
                        return self.auth_error(b"535 5.7.8 OAuth token expired.\r\n").await;
                    }
                    trc::EventType::Auth(trc::AuthEvent::MfaRequired) => {
                        return self
                            .auth_error(
                                concat!(
                                    "334 5.7.8 This account requires multi-factor authentication. ",
                                    "Alternatively, you can use an app password if your account has one.\r\n"
                                )
                                .as_bytes(),
                            )
                            .await;
                    }
                    trc::EventType::Security(trc::SecurityEvent::Unauthorized) => {
                        self.write(
                            concat!(
                                "550 5.7.1 Your account is not authorized ",
                                "to use this service.\r\n"
                            )
                            .as_bytes(),
                        )
                        .await?;
                        return Ok(false);
                    }
                    trc::EventType::Security(_) => {
                        return Err(());
                    }
                    _ => (),
                }
            }
        }

        self.write(b"454 4.7.0 Temporary authentication failure\r\n")
            .await?;

        Ok(false)
    }

    /// inbuxa: legacy-protocols LP-6, LP-10. A refusal is written with the
    /// words the error carries, which know whose switch refused; anything
    /// else that went wrong deciding is a temporary failure. Neither counts
    /// as an authentication error (LP-11).
    async fn legacy_refusal(&mut self, err: trc::Error) -> Result<bool, ()> {
        let reply = err
            .matches(trc::EventType::Auth(AuthEvent::LegacyProtocolRefused))
            .then(|| err.value_as_str(trc::Key::Details).map(str::to_string))
            .flatten();
        trc::error!(err.span_id(self.data.session_id));
        match reply {
            Some(reply) => self.write(reply.as_bytes()).await?,
            None => {
                self.write(b"454 4.7.0 Temporary authentication failure\r\n")
                    .await?
            }
        }
        Ok(false)
    }

    pub async fn auth_error(&mut self, response: &[u8]) -> Result<bool, ()> {
        tokio::time::sleep(self.params.auth_errors_wait).await;
        self.data.auth_errors += 1;
        self.write(response).await?;
        if self.data.auth_errors < self.params.auth_errors_max {
            Ok(false)
        } else {
            trc::event!(
                Auth(AuthEvent::TooManyAttempts),
                SpanId = self.data.session_id,
            );

            self.write(b"455 4.3.0 Too many authentication errors, disconnecting.\r\n")
                .await?;
            Err(())
        }
    }

    pub fn authenticated_as(&self) -> Option<&str> {
        self.data
            .authenticated_as
            .as_ref()
            .map(|authenticated_as| authenticated_as.name())
    }

    pub fn is_authenticated(&self) -> bool {
        self.data.authenticated_as.is_some()
    }

    pub fn authenticated_emails(&self) -> &[String] {
        self.data.authenticated_as.as_ref().unwrap().addresses()
    }

    /// inbuxa: MA-S, AL-8: whether the signed-in account holds a current
    /// delegation with sendAs into the account that owns `address`: a
    /// shared mailbox, or a locked account handed to it. The address must
    /// be the owner's own; a catch-all doesn't count.
    pub async fn delegate_sends_as(&self, address: &str) -> bool {
        let Some(access_token) = &self.data.access_token else {
            return false;
        };
        match self.server.account_id_from_email(address, false).await {
            Ok(Some(owner_id)) => access_token
                .delegation(owner_id)
                .is_some_and(|delegation| delegation.send_as),
            _ => false,
        }
    }

    /// inbuxa: MA-S3: when the message goes out as a shared mailbox the
    /// signed-in account was assigned to, the first From or Reply-To
    /// address that isn't the mailbox's own, as JMAP refuses it.
    pub async fn shared_mailbox_foreign_address(
        &self,
        message: &mail_parser::Message<'_>,
    ) -> Option<String> {
        let access_token = self.data.access_token.as_ref()?;
        let mail_from = self.data.mail_from.as_ref()?;
        let owner_id = self
            .server
            .account_id_from_email(&mail_from.address_lcase, false)
            .await
            .ok()??;
        if owner_id == access_token.account_id() || !access_token.delegated_shared_mailbox(owner_id)
        {
            return None;
        }
        let named = message
            .headers()
            .iter()
            .filter(|header| matches!(header.name, HeaderName::From | HeaderName::ReplyTo))
            .filter_map(|header| match &header.value {
                HeaderValue::Address(address) => Some(address),
                _ => None,
            })
            .flat_map(|address| address.iter())
            .filter_map(|addr| addr.address().map(str::to_string))
            .collect::<Vec<_>>();
        for address in named {
            if self
                .server
                .account_id_from_email(&address, true)
                .await
                .ok()
                .flatten()
                != Some(owner_id)
            {
                return Some(address);
            }
        }
        None
    }

    /// inbuxa: MA-D0a, AL-9: a message queued from an address that isn't the
    /// signed-in account's own is recorded: who sent it and as whom. A
    /// locked account's delegate's send is that delegation's record.
    pub async fn audit_queued_send_as(&self, queue_id: u64) {
        let (Some(access_token), Some(mail_from)) = (&self.data.access_token, &self.data.mail_from)
        else {
            return;
        };
        let address = mail_from.address_lcase.as_str();
        if address.is_empty() {
            return;
        }
        let Ok(Some(as_account_id)) = self.server.account_id_from_email(address, true).await else {
            return;
        };
        if as_account_id == access_token.account_id() {
            return;
        }
        match access_token.delegation(as_account_id) {
            Some(delegation) if delegation.kind.is_lock() => {
                self.server
                    .audit_delegate(
                        access_token,
                        as_account_id,
                        delegation.access.as_str(),
                        Some("SMTP submission"),
                        None,
                    )
                    .await;
            }
            _ => {
                self.server
                    .audit_send_as_queued(access_token, as_account_id, queue_id, address)
                    .await;
            }
        }
    }
}
