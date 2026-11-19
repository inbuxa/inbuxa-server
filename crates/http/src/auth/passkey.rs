/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: passkey registration (passkeys spec, PK-6 to PK-8).
//!
//! `inbuxa:Passkey/set` create hands back a URL to `/passkey/register` with
//! a single-use ticket. That page posts here twice:
//!
//! 1. `start`, with the ticket and the account's password (and TOTP code
//!    when it has one). The answer is the options for the browser's
//!    `navigator.credentials.create`. A stolen session token can start a
//!    registration, but without the password it can't get this far (PK-8).
//! 2. `finish`, with the ticket and what the browser made. The passkey
//!    turns active (PK-7).
//!
//! What `start` began waits in the in-memory store under the ticket, so any
//! node can answer `finish`, and it's deleted as it's read: it's good once.

use common::{
    KV_PASSKEY_CEREMONY, Server,
    auth::{AccessToken, AuthRequest},
};
use directory::Credentials;
use http_proto::{HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse};
use inbuxa_features::passkey::{self, Activated, HANDLE_LEN, Passkey};
use serde::{Deserialize, Serialize};
use store::{
    dispatch::lookup::KeyValue,
    rand::{RngExt, rng},
    write::now,
};
use trc::AddContext;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Credential, CredentialID, PasskeyRegistration,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

/// How long the browser has between `start` and `finish`.
const CEREMONY_SECONDS: u64 = 300;

#[derive(Debug, Deserialize)]
#[serde(tag = "step", rename_all = "camelCase")]
pub enum RegisterRequest {
    #[serde(rename_all = "camelCase")]
    Start {
        ticket: String,
        password: String,
        #[serde(default)]
        mfa_token: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Finish {
        ticket: String,
        credential: Box<RegisterPublicKeyCredential>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RegisterResponse {
    /// The options for `navigator.credentials.create`.
    #[serde(rename_all = "camelCase")]
    Options {
        name: String,
        account_name: String,
        options: Box<CreationChallengeResponse>,
    },
    #[serde(rename_all = "camelCase")]
    Registered {
        name: String,
    },
    /// The ticket is unknown, used or out of time.
    Expired,
    MfaRequired,
    /// The password or code was wrong.
    Failure,
    /// The authenticator's answer didn't check out, or that passkey is
    /// already registered.
    #[serde(rename_all = "camelCase")]
    Refused {
        reason: String,
    },
}

/// What waits between `start` and `finish`.
#[derive(Serialize, Deserialize)]
struct Ceremony {
    account_id: u32,
    number: u32,
    rp_id: String,
    state: PasskeyRegistration,
}

/// The WebAuthn relying party for this server (PK-3): the host of its public
/// HTTPS URL, which is also the only origin it accepts.
pub fn relying_party(server: &Server) -> trc::Result<(Webauthn, String)> {
    let rp_id = jmap::inbuxa::passkey::current_rp_id(server);
    let origin = Url::parse(&server.core.network.http.url_https).map_err(|err| {
        trc::AuthEvent::Error
            .into_err()
            .details("The server's public URL isn't a URL.")
            .reason(err)
    })?;
    let webauthn = WebauthnBuilder::new(&rp_id, &origin)
        .and_then(|builder| builder.rp_name("inbuxa").build())
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .details("Passkeys need the server's public URL to name a host.")
                .reason(err)
        })?;
    Ok((webauthn, rp_id))
}

fn ceremony_key(ticket: &str) -> Vec<u8> {
    KeyValue::<()>::build_key(KV_PASSKEY_CEREMONY, passkey::ticket_hash(ticket))
}

pub trait PasskeyRegistrationHandler: Sync + Send {
    fn handle_passkey_registration(
        &self,
        session: &HttpSessionData,
        body: Vec<u8>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl PasskeyRegistrationHandler for Server {
    async fn handle_passkey_registration(
        &self,
        session: &HttpSessionData,
        body: Vec<u8>,
    ) -> trc::Result<HttpResponse> {
        let request = serde_json::from_slice::<RegisterRequest>(&body).map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;
        let response = match request {
            RegisterRequest::Start {
                ticket,
                password,
                mfa_token,
            } => start(self, session, &ticket, password, mfa_token).await?,
            RegisterRequest::Finish { ticket, credential } => {
                finish(self, &ticket, &credential).await?
            }
        };
        Ok(JsonResponse::new(response).no_cache().into_http_response())
    }
}

async fn start(
    server: &Server,
    session: &HttpSessionData,
    ticket: &str,
    password: String,
    mfa_token: Option<String>,
) -> trc::Result<RegisterResponse> {
    let Some(pending) = passkey::by_ticket(server.store(), ticket, now()).await? else {
        return Ok(RegisterResponse::Expired);
    };
    let account = server
        .account(pending.account_id)
        .await
        .caused_by(trc::location!())?;

    // PK-8: the password (and code) first. The sign-in limits and the
    // failure counting are the ones every sign-in goes through.
    let access_token: AccessToken = match server
        .authenticate(&AuthRequest {
            credentials: Credentials::Basic {
                username: account.name.to_string(),
                secret: password,
                mfa_token,
            },
            session_id: session.session_id,
            remote_ip: session.remote_ip,
        })
        .await
    {
        Ok(access_token) => access_token,
        Err(err) => {
            return match *err.as_ref() {
                trc::EventType::Auth(trc::AuthEvent::MfaRequired) => {
                    trc::error!(err.span_id(session.session_id));
                    Ok(RegisterResponse::MfaRequired)
                }
                trc::EventType::Auth(_) | trc::EventType::Security(_) => {
                    trc::error!(err.span_id(session.session_id));
                    Ok(RegisterResponse::Failure)
                }
                _ => Err(err),
            };
        }
    };
    if access_token.account_id() != pending.account_id {
        return Ok(RegisterResponse::Failure);
    }

    let (webauthn, rp_id) = relying_party(server)?;
    let fresh = rng().random::<[u8; HANDLE_LEN]>();
    let handle = passkey::ensure_user_handle(server.store(), pending.account_id, fresh).await?;
    let user_id = Uuid::from_slice(&handle).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .details("Invalid passkey user handle")
            .reason(err)
    })?;
    // Registering the same authenticator twice is refused by the browser
    let exclude = passkey::all(server.store(), pending.account_id)
        .await?
        .into_iter()
        .filter(|p| !p.credential_id.is_empty())
        .map(|p| CredentialID::from(p.credential_id))
        .collect::<Vec<_>>();
    let display_name = account
        .description
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&account.name);
    let (mut options, state) = webauthn
        .start_passkey_registration(
            user_id,
            &account.name,
            display_name,
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .details("Failed to start a passkey registration")
                .reason(err)
        })?;

    // PK-1: discoverable, so the login page can offer it before anyone
    // types a name. The library leaves it optional.
    let selection = options
        .public_key
        .authenticator_selection
        .get_or_insert_with(Default::default);
    selection.resident_key = Some(ResidentKeyRequirement::Required);
    selection.require_resident_key = true;

    let ceremony = serde_json::to_string(&Ceremony {
        account_id: pending.account_id,
        number: pending.number,
        rp_id,
        state,
    })
    .map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to serialize a passkey registration")
            .reason(err)
    })?;
    let left = pending.ticket_expires.saturating_sub(now()).max(1);
    server
        .in_memory_store()
        .key_set(
            KeyValue::new(ceremony_key(ticket), ceremony.into_bytes())
                .expires(left.min(CEREMONY_SECONDS)),
        )
        .await?;

    Ok(RegisterResponse::Options {
        name: pending.name,
        account_name: account.name.to_string(),
        options: Box::new(options),
    })
}

async fn finish(
    server: &Server,
    ticket: &str,
    credential: &RegisterPublicKeyCredential,
) -> trc::Result<RegisterResponse> {
    // Good once: read and deleted
    let key = ceremony_key(ticket);
    let Some(ceremony) = server
        .in_memory_store()
        .key_get::<String>(key.clone())
        .await?
    else {
        return Ok(RegisterResponse::Expired);
    };
    server.in_memory_store().key_delete(key).await?;
    let ceremony = serde_json::from_str::<Ceremony>(&ceremony).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .details("Invalid passkey registration")
            .reason(err)
    })?;
    let Some(pending) = passkey::by_ticket(server.store(), ticket, now())
        .await?
        .filter(|p| p.account_id == ceremony.account_id && p.number == ceremony.number)
    else {
        return Ok(RegisterResponse::Expired);
    };

    let (webauthn, rp_id) = relying_party(server)?;
    if rp_id != ceremony.rp_id {
        return Ok(RegisterResponse::Expired);
    }
    let made = match webauthn.finish_passkey_registration(credential, &ceremony.state) {
        Ok(made) => made,
        Err(err) => {
            trc::event!(
                Auth(trc::AuthEvent::Failed),
                AccountId = pending.account_id,
                Details = "Passkey registration refused",
                Reason = err.to_string(),
            );
            return Ok(RegisterResponse::Refused {
                reason: "The passkey couldn't be checked. Try again.".to_string(),
            });
        }
    };
    let public_key = serde_json::to_vec(&made).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to serialize a passkey")
            .reason(err)
    })?;
    // The attestation isn't asked for (PK-2), so there's no AAGUID to keep
    let backed_up = Credential::from(made.clone()).backup_state;
    let transports = credential
        .response
        .transports
        .iter()
        .flatten()
        .filter_map(|t| serde_json::to_value(t).ok())
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect();

    let name = pending.name.clone();
    let active = Passkey {
        state: passkey::State::Active,
        ticket_expires: 0,
        rp_id,
        credential_id: made.cred_id().to_vec(),
        public_key,
        sign_count: 0,
        transports,
        backed_up,
        aaguid: Vec::new(),
        ..pending
    };
    match passkey::activate(server.store(), ticket, active).await? {
        Activated::Done(_) => Ok(RegisterResponse::Registered { name }),
        Activated::Taken => Ok(RegisterResponse::Refused {
            reason: "That passkey is already registered.".to_string(),
        }),
    }
}
