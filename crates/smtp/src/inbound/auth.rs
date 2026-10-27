/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::core::Session;
use common::{
    auth::{
        AuthRequest,
        oauth::scope::OAuthScopes,
        sasl::{BearerFailure, BearerMechanism, SASL_CANCEL, SASL_EMPTY},
    },
    config::smtp::session::Mechanism,
    network::{SessionStream, legacy::LegacyProtocol},
};
use directory::Credentials;
use encodify::base64::LENIENT;
use mail_parser::HeaderName;
use registry::schema::enums::Permission;
use smtp_proto::{AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, IntoString};
use trc::AuthEvent;

const AUTH_BEARER: u64 = AUTH_OAUTHBEARER | AUTH_XOAUTH2;
const CREDENTIALS_INVALID: &[u8] = b"535 5.7.8 Authentication credentials invalid.\r\n";
const TOKEN_EXPIRED: &[u8] = b"535 5.7.8 OAuth token expired.\r\n";
const INVALID_CHALLENGE: &[u8] = b"500 5.5.6 Invalid challenge.\r\n";
const NOT_AUTHORIZED: &[u8] = b"550 5.7.1 Your account is not authorized to use this service.\r\n";
const CANCELLED: &[u8] = b"501 5.7.0 Authentication cancelled.\r\n";

pub struct SaslToken {
    mechanism: u64,
    credentials: Credentials,
    pending_failure: Option<PendingFailure>,
}

#[derive(Clone, Copy)]
enum PendingFailure {
    Counted(&'static [u8]),
    Uncounted(&'static [u8]),
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
                pending_failure: None,
            }
            .into(),
            AUTH_OAUTHBEARER | AUTH_XOAUTH2 => SaslToken {
                mechanism,
                credentials: Credentials::Bearer {
                    username: None,
                    token: String::new(),
                },
                pending_failure: None,
            }
            .into(),
            _ => None,
        }
    }

    fn bearer_mechanism(&self) -> Option<BearerMechanism> {
        match self.mechanism {
            AUTH_OAUTHBEARER => Some(BearerMechanism::OAuthBearer),
            AUTH_XOAUTH2 => Some(BearerMechanism::XOAuth2),
            _ => None,
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn sasl_mechanisms(&self) -> u64 {
        let mechanisms: u64 = self
            .eval_if::<Mechanism>(&self.server.core.smtp.session.auth.mechanisms)
            .await
            .unwrap_or_default()
            .into();
        if self.server.accepts_bearer_tokens(self.stream.is_tls()) {
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
        match token.pending_failure.take() {
            Some(PendingFailure::Counted(failure)) => return self.auth_error(failure).await,
            Some(PendingFailure::Uncounted(failure)) => {
                self.write(failure).await?;
                return Ok(false);
            }
            None => {}
        }

        if response == SASL_CANCEL.as_bytes() {
            self.write(CANCELLED).await?;
            return Ok(false);
        }

        if response.is_empty() || response == SASL_EMPTY.as_bytes() {
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
        } else if let Ok(response) = LENIENT.decode(response) {
            match (token.mechanism, &mut token.credentials) {
                (AUTH_PLAIN, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_plain(&response) {
                        return self.authenticate(credentials, token).await;
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
                        let credentials = std::mem::replace(
                            &mut token.credentials,
                            Credentials::Basic {
                                username: String::new(),
                                secret: String::new(),
                                mfa_token: None,
                            },
                        );
                        self.authenticate(credentials, token).await
                    };
                }
                (AUTH_OAUTHBEARER | AUTH_XOAUTH2, _) => {
                    if let Some(credentials) = Credentials::decode_sasl_challenge_oauth(&response) {
                        return self.authenticate(credentials, token).await;
                    } else if let Some(mechanism) = token.bearer_mechanism() {
                        self.malformed_credentials().await?;
                        return self
                            .bearer_challenge(
                                token,
                                mechanism,
                                BearerFailure::InvalidToken,
                                None,
                                PendingFailure::Counted(INVALID_CHALLENGE),
                            )
                            .await;
                    }
                }
                _ => (),
            }
        }

        self.malformed_credentials().await?;
        self.auth_error(INVALID_CHALLENGE).await
    }

    async fn malformed_credentials(&mut self) -> Result<(), ()> {
        let err = self
            .server
            .auth_failure(
                AuthEvent::Failed
                    .into_err()
                    .details("Invalid SASL response."),
                self.data.remote_ip,
                None,
            )
            .await;
        if matches!(err.as_ref(), trc::EventType::Security(_)) {
            trc::error!(err.span_id(self.data.session_id));
            Err(())
        } else {
            Ok(())
        }
    }

    async fn bearer_challenge(
        &mut self,
        token: &mut SaslToken,
        mechanism: BearerMechanism,
        failure: BearerFailure,
        credentials: Option<&Credentials>,
        pending: PendingFailure,
    ) -> Result<bool, ()> {
        let challenge = self
            .server
            .bearer_failure_challenge(mechanism, failure, credentials)
            .await;
        token.pending_failure = Some(pending);
        self.write(format!("334 {challenge}\r\n").as_bytes())
            .await?;
        Ok(true)
    }

    pub async fn authenticate(
        &mut self,
        credentials: Credentials,
        token: &mut SaslToken,
    ) -> Result<bool, ()> {
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
        let request =
            AuthRequest::from_credentials(credentials, self.data.session_id, self.data.remote_ip);
        let result = match self.server.authenticate(&request).await {
            Ok(authenticated) => match token.bearer_mechanism() {
                Some(mechanism) => match authenticated
                    .access_token
                    .assert_allows_oauth_scopes(OAuthScopes::MAIL)
                {
                    Ok(access_token) => Ok(access_token),
                    Err(err) => {
                        trc::error!(err.span_id(self.data.session_id));
                        return self
                            .bearer_challenge(
                                token,
                                mechanism,
                                BearerFailure::InsufficientScope,
                                Some(&request.credentials),
                                PendingFailure::Uncounted(NOT_AUTHORIZED),
                            )
                            .await;
                    }
                },
                None => Ok(authenticated.access_token),
            }
            .and_then(|access_token| access_token.assert_has_permission(Permission::EmailSend)),
            Err(err) => Err(err),
        };

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
                self.data.access_token = access_token.into();
                self.data.authenticated_as = account_info.into();
                self.eval_post_auth_params().await;
                self.write(b"235 2.7.0 Authentication succeeded.\r\n")
                    .await?;
                return Ok(false);
            }
            Err(err) => {
                let reason = *err.as_ref();

                if let Some(mechanism) = token.bearer_mechanism()
                    && let Some(failure) = BearerFailure::from_error(&err)
                {
                    trc::error!(err.span_id(self.data.session_id));
                    return self
                        .bearer_challenge(
                            token,
                            mechanism,
                            failure,
                            Some(&request.credentials),
                            PendingFailure::Counted(match reason {
                                trc::EventType::Auth(trc::AuthEvent::TokenExpired) => TOKEN_EXPIRED,
                                _ => CREDENTIALS_INVALID,
                            }),
                        )
                        .await;
                }

                trc::error!(err.span_id(self.data.session_id));

                match reason {
                    trc::EventType::Auth(trc::AuthEvent::Failed) => {
                        return self.auth_error(CREDENTIALS_INVALID).await;
                    }
                    trc::EventType::Auth(trc::AuthEvent::TokenExpired) => {
                        return self.auth_error(TOKEN_EXPIRED).await;
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
                        self.write(NOT_AUTHORIZED).await?;
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
            .filter(|header| matches!(header.name(), HeaderName::From | HeaderName::ReplyTo))
            .filter_map(|header| header.value().as_address())
            .flat_map(|address| address.mailboxes().collect::<Vec<_>>())
            .filter_map(|mailbox| mailbox.address().map(str::to_string))
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
