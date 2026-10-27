/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, SessionData, State};
use common::{
    auth::{
        AuthRequest,
        oauth::scope::OAuthScopes,
        sasl::{BearerFailure, BearerMechanism, SASL_CANCEL, SASL_EMPTY},
    },
    network::{SessionStream, limiter::LimiterResult},
};
use compact_str::CompactString;
use directory::Credentials;
use encodify::base64::LENIENT;
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::authenticate::Mechanism,
    receiver::{self, MAX_UNAUTHENTICATED_REQUEST_SIZE, Request},
};
use registry::schema::enums::Permission;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        let mut args = request.parse_authenticate()?;

        let bearer = match args.mechanism {
            Mechanism::Plain => None,
            Mechanism::OAuthBearer => Some(BearerMechanism::OAuthBearer),
            Mechanism::XOauth2 => Some(BearerMechanism::XOAuth2),
            _ => {
                return Err(trc::AuthEvent::Error
                    .into_err()
                    .details("Authentication mechanism not supported.")
                    .id(args.tag)
                    .code(ResponseCode::Cannot));
            }
        };

        if bearer.is_some() && !self.server.accepts_bearer_tokens(self.is_tls) {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("OAUTHBEARER and XOAUTH2 require a TLS connection.")
                .code(ResponseCode::PrivacyRequired)
                .id(args.tag));
        }

        match args.params.pop() {
            Some(param) if param == SASL_CANCEL => Err(trc::ImapEvent::Error
                .into_err()
                .details("Authentication cancelled.")
                .ctx(trc::Key::Type, ResponseType::Bad)
                .id(args.tag)),
            Some(param) if param != SASL_EMPTY => {
                let Ok(challenge) = LENIENT.decode(param.as_bytes()) else {
                    return Err(self
                        .malformed_credentials(&args.tag)
                        .await
                        .ctx(trc::Key::Type, ResponseType::Bad));
                };
                let credentials = if bearer.is_none() {
                    Credentials::decode_sasl_challenge_plain(&challenge)
                } else {
                    Credentials::decode_sasl_challenge_oauth(&challenge)
                };
                match (credentials, bearer) {
                    (Some(credentials), _) => {
                        self.authenticate(credentials, args.tag, bearer).await
                    }
                    (None, Some(mechanism)) => {
                        let err = self.malformed_credentials(&args.tag).await;
                        match BearerFailure::from_error(&err) {
                            Some(failure) => {
                                self.bearer_challenge(mechanism, failure, None, err, args.tag)
                                    .await
                            }
                            None => Err(err),
                        }
                    }
                    (None, None) => Err(self.malformed_credentials(&args.tag).await),
                }
            }
            _ => {
                self.expect_sasl_response(args.tag, args.mechanism);
                self.write_bytes(b"+ \r\n".to_vec()).await
            }
        }
    }

    async fn bearer_challenge(
        &mut self,
        mechanism: BearerMechanism,
        failure: BearerFailure,
        credentials: Option<&Credentials>,
        err: trc::Error,
        tag: CompactString,
    ) -> trc::Result<()> {
        let challenge = self
            .server
            .bearer_failure_challenge(mechanism, failure, credentials)
            .await;
        if let State::NotAuthenticated { sasl_failure, .. } = &mut self.state {
            *sasl_failure = Some(err);
        }
        self.expect_sasl_response(
            tag,
            match mechanism {
                BearerMechanism::OAuthBearer => Mechanism::OAuthBearer,
                BearerMechanism::XOAuth2 => Mechanism::XOauth2,
            },
        );
        self.write_bytes(format!("+ {challenge}\r\n").into_bytes())
            .await
    }

    fn expect_sasl_response(&mut self, tag: CompactString, mechanism: Mechanism) {
        self.receiver.request = receiver::Request {
            tag,
            command: Command::Authenticate,
            tokens: vec![receiver::Token::Argument(
                receiver::ArgumentBytes::from_slice(mechanism.as_bytes()),
            )],
        };
        self.receiver.state = receiver::State::Argument { last_ch: b' ' };
    }

    pub async fn authenticate(
        &mut self,
        credentials: Credentials,
        tag: CompactString,
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
                                    BearerFailure::insufficient_scope(err).id(tag.clone()),
                                    tag,
                                )
                                .await;
                        }
                    }
                }
                None => authenticated.access_token,
            }
            .assert_has_permission(Permission::ImapAuthenticate)
            .map_err(|err| err.id(tag.clone()))?,
            Err(err) => {
                let err = self.register_auth_failure(err, &tag);
                return match (bearer, BearerFailure::from_error(&err)) {
                    (Some(mechanism), Some(failure)) => {
                        self.bearer_challenge(
                            mechanism,
                            failure,
                            Some(&request.credentials),
                            err,
                            tag,
                        )
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
                return Err(trc::LimitEvent::ConcurrentRequest
                    .into_err()
                    .id(tag.clone()));
            }
            LimiterResult::Disabled => None,
        };

        // Create session
        self.state = State::Authenticated {
            data: Arc::new(
                SessionData::new(self, access_token, in_flight)
                    .await
                    .map_err(|err| err.id(tag.clone()))?,
            ),
        };
        self.receiver.max_request_size = self.server.core.imap.max_request_size;
        self.write_bytes(
            StatusResponse::ok("Authentication successful")
                .with_code(ResponseCode::Capability {
                    capabilities: self.capabilities(),
                })
                .with_tag(tag)
                .into_bytes(),
        )
        .await
    }

    async fn malformed_credentials(&mut self, tag: &CompactString) -> trc::Error {
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
        self.register_auth_failure(err, tag)
    }

    fn register_auth_failure(&mut self, err: trc::Error, tag: &CompactString) -> trc::Error {
        if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
            let auth_failures = self.state.auth_failures();
            if auth_failures < self.server.core.imap.max_auth_failures {
                self.state = State::NotAuthenticated {
                    auth_failures: auth_failures + 1,
                    sasl_failure: None,
                };
            } else {
                return trc::AuthEvent::TooManyAttempts
                    .into_err()
                    .caused_by(err)
                    .id(tag.clone());
            }
        }

        err.id(tag.clone())
    }

    pub async fn handle_unauthenticate(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        self.state = State::NotAuthenticated {
            auth_failures: 0,
            sasl_failure: None,
        };
        self.receiver.max_request_size = MAX_UNAUTHENTICATED_REQUEST_SIZE;
        self.is_condstore = false;
        self.is_qresync = false;
        self.is_utf8 = false;
        self.is_objectid = false;
        self.is_uidonly = false;

        self.write_bytes(
            StatusResponse::completed(Command::Unauthenticate)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
