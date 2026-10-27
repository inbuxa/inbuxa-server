/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::{
    auth::{
        AuthRequest,
        oauth::scope::OAuthScopes,
        sasl::{BearerFailure, BearerMechanism, SASL_CANCEL, SASL_EMPTY},
    },
    config::smtp::session::Mechanism,
    network::SessionStream,
};
use directory::Credentials;
use encodify::base64::LENIENT;
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

        let result = match result {
            Ok(access_token) => self.server.account_info(access_token.account_id()).await,
            Err(err) => Err(err),
        };

        match result {
            Ok(account_info) => {
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
}
