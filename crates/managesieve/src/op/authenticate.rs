/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

use crate::core::{Command, ResponseCode, Session, State, StatusResponse};
use common::{
    auth::{
        AuthRequest,
        oauth::scope::OAuthScopes,
        sasl::{BearerFailure, BearerMechanism, SASL_CANCEL},
    },
    network::{SessionStream, limiter::LimiterResult},
};
use directory::Credentials;
use encodify::base64::LENIENT;
use imap_proto::{
    protocol::authenticate::Mechanism,
    receiver::{self, MAX_UNAUTHENTICATED_REQUEST_SIZE, Request},
};
use registry::schema::enums::Permission;

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        if request.tokens.is_empty() {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Authentication mechanism missing."));
        }

        let mut tokens = request.tokens.into_iter();
        let mechanism = Mechanism::parse(&tokens.next().unwrap().unwrap_bytes())
            .map_err(|err| trc::AuthEvent::Error.into_err().details(err))?;
        let mut params: Vec<CompactString> = tokens
            .filter_map(|token| token.unwrap_string().ok())
            .collect();

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
            return Err(trc::ManageSieveEvent::Error
                .into_err()
                .code(ResponseCode::EncryptNeeded)
                .details("OAUTHBEARER and XOAUTH2 require a TLS connection."));
        }

        let param = match params.pop() {
            Some(param) if param == SASL_CANCEL => {
                return Err(trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Authentication cancelled."));
            }
            Some(param) if !param.is_empty() => param,
            _ => {
                self.expect_sasl_response(&mechanism);
                return Ok(b"{0}\r\n".to_vec());
            }
        };
        let credentials = LENIENT.decode(param.as_bytes()).ok().map(|challenge| {
            if bearer.is_none() {
                Credentials::decode_sasl_challenge_plain(&challenge)
            } else {
                Credentials::decode_sasl_challenge_oauth(&challenge)
            }
        });
        let credentials = match (credentials, bearer) {
            (Some(Some(credentials)), _) => credentials,
            (Some(None), Some(bearer)) => {
                let err = self.malformed_credentials().await;
                return match BearerFailure::from_error(&err) {
                    Some(failure) => Ok(self
                        .bearer_challenge(bearer, failure, None, err, &mechanism)
                        .await),
                    None => Err(err),
                };
            }
            _ => return Err(self.malformed_credentials().await),
        };

        // Authenticate
        let request = AuthRequest::from_credentials(credentials, self.session_id, self.remote_addr);
        let access_token = match self.server.authenticate(&request).await {
            Ok(authenticated) => match bearer {
                Some(bearer) => {
                    match authenticated
                        .access_token
                        .assert_allows_oauth_scopes(OAuthScopes::MAIL)
                    {
                        Ok(access_token) => access_token,
                        Err(err) => {
                            return Ok(self
                                .bearer_challenge(
                                    bearer,
                                    BearerFailure::InsufficientScope,
                                    Some(&request.credentials),
                                    BearerFailure::insufficient_scope(err),
                                    &mechanism,
                                )
                                .await);
                        }
                    }
                }
                None => authenticated.access_token,
            }
            .assert_has_permission(Permission::SieveAuthenticate)?,
            Err(err) => {
                let err = self.register_auth_failure(err);
                return match (bearer, BearerFailure::from_error(&err)) {
                    (Some(bearer), Some(failure)) => Ok(self
                        .bearer_challenge(
                            bearer,
                            failure,
                            Some(&request.credentials),
                            err,
                            &mechanism,
                        )
                        .await),
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

        // Create session
        self.state = State::Authenticated {
            access_token,
            in_flight,
        };
        self.receiver.max_request_size = self.server.core.imap.max_request_size;

        Ok(StatusResponse::ok("Authentication successful").into_bytes())
    }

    async fn bearer_challenge(
        &mut self,
        bearer: BearerMechanism,
        failure: BearerFailure,
        credentials: Option<&Credentials>,
        err: trc::Error,
        mechanism: &Mechanism,
    ) -> Vec<u8> {
        let challenge = self
            .server
            .bearer_failure_challenge(bearer, failure, credentials)
            .await;
        if let State::NotAuthenticated { sasl_failure, .. } = &mut self.state {
            *sasl_failure = Some(err);
        }
        self.expect_sasl_response(mechanism);
        format!("\"{challenge}\"\r\n").into_bytes()
    }

    fn expect_sasl_response(&mut self, mechanism: &Mechanism) {
        self.receiver.request = receiver::Request {
            tag: "".into(),
            command: Command::Authenticate,
            tokens: vec![receiver::Token::Argument(
                receiver::ArgumentBytes::from_slice(mechanism.as_bytes()),
            )],
        };
        self.receiver.state = receiver::State::Argument { last_ch: b' ' };
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

    pub async fn handle_unauthenticate(&mut self) -> trc::Result<Vec<u8>> {
        self.state = State::NotAuthenticated {
            auth_failures: 0,
            sasl_failure: None,
        };
        self.receiver.max_request_size = MAX_UNAUTHENTICATED_REQUEST_SIZE;

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::Unauthenticate),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        Ok(StatusResponse::ok("Unauthenticate successful.").into_bytes())
    }
}
