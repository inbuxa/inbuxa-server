/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Session, State,
    protocol::{Command, Mechanism, request},
};
use common::{
    auth::{
        AuthRequest,
        oauth::scope::OAuthScopes,
        sasl::{BearerFailure, BearerMechanism, SASL_CANCEL, SASL_EMPTY},
    },
    network::{SessionStream, limiter::LimiterResult},
};
use directory::Credentials;
use encodify::base64::LENIENT;
use registry::schema::enums::Permission;

impl<T: SessionStream> Session<T> {
    pub async fn handle_sasl(
        &mut self,
        mechanism: Mechanism,
        mut params: Vec<String>,
    ) -> trc::Result<()> {
        let bearer = match mechanism {
            Mechanism::Plain => None,
            Mechanism::OAuthBearer => Some(BearerMechanism::OAuthBearer),
            Mechanism::XOauth2 => Some(BearerMechanism::XOAuth2),
            _ => {
                return Err(trc::AuthEvent::Error
                    .into_err()
                    .details("Authentication mechanism not supported."));
            }
        };

        if bearer.is_some() && !self.server.accepts_bearer_tokens(self.stream.is_tls()) {
            return Err(trc::Pop3Event::Error
                .into_err()
                .details("OAUTHBEARER and XOAUTH2 require a TLS connection."));
        }

        match params.pop() {
            Some(param) if param == SASL_CANCEL => Err(trc::Pop3Event::Error
                .into_err()
                .details("Authentication cancelled.")),
            Some(param) if param != SASL_EMPTY => {
                let credentials = LENIENT.decode(param.as_bytes()).ok().map(|challenge| {
                    if bearer.is_none() {
                        Credentials::decode_sasl_challenge_plain(&challenge)
                    } else {
                        Credentials::decode_sasl_challenge_oauth(&challenge)
                    }
                });
                match (credentials, bearer) {
                    (Some(Some(credentials)), _) => self.authenticate(credentials, bearer).await,
                    (Some(None), Some(mechanism)) => {
                        let err = self.malformed_credentials().await;
                        match BearerFailure::from_error(&err) {
                            Some(failure) => {
                                self.bearer_challenge(mechanism, failure, None, err).await
                            }
                            None => Err(err),
                        }
                    }
                    _ => Err(self.malformed_credentials().await),
                }
            }
            _ => {
                self.expect_sasl_response(&mechanism);
                self.write_bytes("+\r\n").await
            }
        }
    }

    async fn bearer_challenge(
        &mut self,
        mechanism: BearerMechanism,
        failure: BearerFailure,
        credentials: Option<&Credentials>,
        err: trc::Error,
    ) -> trc::Result<()> {
        let challenge = self
            .server
            .bearer_failure_challenge(mechanism, failure, credentials)
            .await;
        if let State::NotAuthenticated { sasl_failure, .. } = &mut self.state {
            *sasl_failure = Some(err);
        }
        self.expect_sasl_response(match mechanism {
            BearerMechanism::OAuthBearer => &Mechanism::OAuthBearer,
            BearerMechanism::XOAuth2 => &Mechanism::XOauth2,
        });
        self.write_bytes(format!("+ {challenge}\r\n")).await
    }

    fn expect_sasl_response(&mut self, mechanism: &Mechanism) {
        self.receiver.state = request::State::Argument {
            request: Command::Auth {
                mechanism: mechanism.as_str().as_bytes().to_vec(),
                params: vec![],
            },
            num: 1,
            last_is_space: true,
        };
    }

    pub async fn authenticate(
        &mut self,
        credentials: Credentials,
        bearer: Option<BearerMechanism>,
    ) -> trc::Result<()> {
        // Authenticate
        let request = AuthRequest::from_credentials(credentials, self.session_id, self.remote_addr);
        let access_token = match self.server.authenticate(&request).await {
            Ok(authenticated) => match bearer {
                Some(mechanism) => {
                    match authenticated
                        .access_token
                        .assert_allows_oauth_scopes(OAuthScopes::MAIL)
                    {
                        Ok(access_token) => access_token,
                        Err(err) => {
                            return self
                                .bearer_challenge(
                                    mechanism,
                                    BearerFailure::InsufficientScope,
                                    Some(&request.credentials),
                                    BearerFailure::insufficient_scope(err),
                                )
                                .await;
                        }
                    }
                }
                None => authenticated.access_token,
            }
            .assert_has_permission(Permission::Pop3Authenticate)?,
            Err(err) => {
                let err = self.register_auth_failure(err);
                return match (bearer, BearerFailure::from_error(&err)) {
                    (Some(mechanism), Some(failure)) => {
                        self.bearer_challenge(mechanism, failure, Some(&request.credentials), err)
                            .await
                    }
                    _ => Err(err),
                };
            }
        };

        // Enforce concurrency limits
        let in_flight = match access_token.is_imap_request_allowed() {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => {
                return Err(trc::LimitEvent::ConcurrentRequest.into_err());
            }
            LimiterResult::Disabled => None,
        };

        // Fetch mailbox
        let mailbox = self.fetch_mailbox(access_token.account_id()).await?;

        // Create session
        self.state = State::Authenticated {
            in_flight,
            mailbox,
            access_token,
        };
        self.write_ok("Authentication successful").await
    }

    async fn malformed_credentials(&mut self) -> trc::Error {
        let err = self
            .server
            .auth_failure(
                trc::AuthEvent::Failed
                    .into_err()
                    .details("Invalid SASL response."),
                self.remote_addr,
                None,
            )
            .await;
        self.register_auth_failure(err)
    }

    fn register_auth_failure(&mut self, err: trc::Error) -> trc::Error {
        if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
            match &mut self.state {
                State::NotAuthenticated { auth_failures, .. }
                    if *auth_failures < self.server.core.imap.max_auth_failures =>
                {
                    *auth_failures += 1;
                }
                _ => {
                    return trc::AuthEvent::TooManyAttempts.into_err().caused_by(err);
                }
            }
        }

        err
    }
}
