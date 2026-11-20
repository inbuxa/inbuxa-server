/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: passkeys (passkeys spec): registration (PK-6 to PK-8) and
//! sign-in (PK-9 to PK-12).
//!
//! Registration:
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
//! Instead of the password, `start` takes one of the account's active
//! passkeys.
//!
//! Sign-in: `POST /api/auth/passkey` hands out a challenge (PK-10), kept in
//! the in-memory store for two minutes and good once; the login request then
//! carries the browser's assertion in place of a name and password (PK-11).

use common::{
    KV_PASSKEY_CEREMONY, Server,
    auth::{AccessToken, AuthRequest},
};
use directory::Credentials;
use http_proto::{HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse};
use inbuxa_features::audit::Via;
use inbuxa_features::passkey::{self, Activated, HANDLE_LEN, Passkey};
use jmap::inbuxa::passkey::{allowed_for, settings};
use registry::schema::{enums::Permission, structs::Authentication};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use store::{
    InMemoryStore,
    dispatch::lookup::KeyValue,
    rand::{RngExt, distr::Alphanumeric, rng},
    write::now,
};
use trc::AddContext;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Credential, CredentialID, DiscoverableAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_proto::ResidentKeyRequirement;

/// How long the browser has between `start` and `finish`.
const CEREMONY_SECONDS: u64 = 300;
/// How long a sign-in challenge lasts (PK-10).
const CHALLENGE_SECONDS: u64 = 120;
const CHALLENGE_ID_LEN: usize = 32;

/// What the browser answered a sign-in challenge with.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertion {
    pub challenge_id: String,
    pub credential: Box<PublicKeyCredential>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "step", rename_all = "camelCase")]
pub enum RegisterRequest {
    #[serde(rename_all = "camelCase")]
    Start {
        ticket: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        mfa_token: Option<String>,
        /// One of the account's passkeys, in place of the password (PK-8).
        #[serde(default)]
        passkey: Option<PasskeyAssertion>,
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

/// The WebAuthn relying party for this server (PK-3): `passkeyRpId` or the
/// host of its public HTTPS URL. That URL is the only origin it accepts
/// (PK-2).
pub fn relying_party(
    server: &Server,
    settings: &Authentication,
) -> trc::Result<(Webauthn, String)> {
    let rp_id = jmap::inbuxa::passkey::current_rp_id(server, settings);
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
                .details("Passkeys need the server's public URL to name a host within the relying-party id.")
                .reason(err)
        })?;
    Ok((webauthn, rp_id))
}

fn turned_off() -> RegisterResponse {
    RegisterResponse::Refused {
        reason: "Passkeys are turned off for this account.".to_string(),
    }
}

fn ceremony_key(ticket: &str) -> Vec<u8> {
    let mut key = vec![b'r'];
    key.extend_from_slice(&passkey::ticket_hash(ticket));
    KeyValue::<()>::build_key(KV_PASSKEY_CEREMONY, key)
}

fn challenge_key(id: &str) -> Vec<u8> {
    let mut key = vec![b'a'];
    key.extend_from_slice(id.as_bytes());
    KeyValue::<()>::build_key(KV_PASSKEY_CEREMONY, key)
}

/// Reads a challenge or ceremony and makes sure only one request gets it.
///
/// Reading and then deleting is two steps, so two requests sent together
/// could both read it before either deleted it. Each reader also counts
/// itself on a claim counter for what it read, which every in-memory store
/// increments atomically (Redis, SQL, the key-value stores, sharded or not),
/// and only the first one is handed the value. The counter is named after
/// the value as well as the key: a registration ticket starts a new ceremony
/// under the same key after a failed try, and that one gets its own claim.
/// The counter expires with the challenge, so it needs no cleanup.
async fn take_once(server: &Server, key: Vec<u8>, ttl: u64) -> trc::Result<Option<String>> {
    let store = server.in_memory_store();
    let Some(value) = store.key_get::<String>(key.clone()).await? else {
        return Ok(None);
    };
    let first = claim_once(store, &key, &value, ttl).await?;
    store.key_delete(key).await?;
    Ok(first.then_some(value))
}

/// Counts a reader of `value` under `key`; true only for the first one.
/// Public for the race test, which calls it directly: two sign-ins rarely
/// land between a read and a delete over HTTP, but here they all do.
pub async fn claim_once(
    store: &InMemoryStore,
    key: &[u8],
    value: &str,
    ttl: u64,
) -> trc::Result<bool> {
    let mut claim = key.to_vec();
    claim.push(b'!');
    claim.extend_from_slice(&Sha256::digest(value.as_bytes())[..16]);
    store
        .counter_incr(KeyValue::new(claim, 1).expires(ttl), true)
        .await
        .map(|claims| claims == 1)
}

/// A sign-in challenge between the two requests.
#[derive(Serialize, Deserialize)]
struct SignInCeremony {
    rp_id: String,
    state: DiscoverableAuthentication,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge_id: String,
    options: Box<RequestChallengeResponse>,
}

/// PK-10: a challenge for the login page or the registration page. The
/// options name no credentials: the browser offers the passkeys it holds for
/// this relying party.
pub async fn challenge(server: &Server) -> trc::Result<HttpResponse> {
    // PK-9: offered when they're allowed server-wide
    let settings = settings(server).await?;
    if !settings.passkeys_allowed {
        return Err(trc::ResourceEvent::NotFound.into_err());
    }
    let (webauthn, rp_id) = relying_party(server, &settings)?;
    let (options, state) = webauthn
        .start_discoverable_authentication()
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .details("Failed to start a passkey sign-in")
                .reason(err)
        })?;
    let challenge_id = rng()
        .sample_iter(Alphanumeric)
        .take(CHALLENGE_ID_LEN)
        .map(char::from)
        .collect::<String>();
    let ceremony = serde_json::to_string(&SignInCeremony { rp_id, state }).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to serialize a passkey sign-in")
            .reason(err)
    })?;
    server
        .in_memory_store()
        .key_set(
            KeyValue::new(challenge_key(&challenge_id), ceremony.into_bytes())
                .expires(CHALLENGE_SECONDS),
        )
        .await?;
    Ok(JsonResponse::new(ChallengeResponse {
        challenge_id,
        options: Box::new(options),
    })
    .no_cache()
    .into_http_response())
}

fn refused(reason: &'static str) -> trc::Error {
    trc::AuthEvent::Failed
        .into_err()
        .details("Passkey sign-in refused")
        .reason(reason)
}

/// PK-11, PK-12: signs in with a passkey. Failures count toward the same
/// limits and blocking as a wrong password, and a passkey needs no TOTP code.
pub async fn sign_in(
    server: &Server,
    session: &HttpSessionData,
    assertion: &PasskeyAssertion,
) -> trc::Result<AccessToken> {
    let result = check_assertion(server, session, assertion)
        .await
        .and_then(|token| {
            // AL-2: a locked account fails as a wrong passkey does
            if token.is_locked() {
                Err(refused("Account is locked").ctx(trc::Key::AccountId, token.account_id()))
            } else {
                token.assert_has_permission(Permission::Authenticate)
            }
        });
    let request = AuthRequest {
        credentials: Credentials::Bearer {
            username: None,
            token: String::new(),
        },
        session_id: session.session_id,
        remote_ip: session.remote_ip,
    };
    match result {
        Ok(token) => {
            trc::event!(
                Auth(trc::AuthEvent::Success),
                AccountId = token.account_id(),
                SpanId = session.session_id,
                Type = "passkey",
            );
            // AU-1.4, AU-1.5
            server.audit_sign_in(&request, &token).await;
            Ok(token)
        }
        Err(err) => {
            if matches!(err.as_ref(), trc::EventType::Auth(trc::AuthEvent::Failed))
                && server.has_auth_fail2ban()
                && server.is_auth_fail2banned(session.remote_ip, None).await?
            {
                Err(trc::SecurityEvent::AuthenticationBan
                    .into_err()
                    .ctx(trc::Key::RemoteIp, session.remote_ip))
            } else {
                // PK-18: auth.failed, told apart from a password by its type
                Err(err
                    .ctx(trc::Key::RemoteIp, session.remote_ip)
                    .ctx(trc::Key::Type, "passkey"))
            }
        }
    }
}

async fn check_assertion(
    server: &Server,
    session: &HttpSessionData,
    assertion: &PasskeyAssertion,
) -> trc::Result<AccessToken> {
    // PK-10: good once
    if assertion.challenge_id.len() != CHALLENGE_ID_LEN {
        return Err(refused("Unknown passkey challenge"));
    }
    let key = challenge_key(&assertion.challenge_id);
    let Some(ceremony) = take_once(server, key, CHALLENGE_SECONDS).await? else {
        return Err(refused("Unknown, used or expired passkey challenge"));
    };
    let ceremony = serde_json::from_str::<SignInCeremony>(&ceremony).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .details("Invalid passkey sign-in")
            .reason(err)
    })?;
    let settings = settings(server).await?;
    let (webauthn, rp_id) = relying_party(server, &settings)?;
    if rp_id != ceremony.rp_id {
        return Err(refused("The relying-party id changed during sign-in"));
    }

    // The account by user handle, the passkey by credential id: both must agree
    let credential = &assertion.credential;
    let (handle, credential_id) = webauthn
        .identify_discoverable_authentication(credential)
        .map_err(|_| refused("No user handle in the passkey's answer"))?;
    let Some(mut record) = passkey::by_credential(server.store(), credential_id)
        .await?
        .filter(|p| p.state == passkey::State::Active)
    else {
        return Err(refused("Unknown passkey"));
    };
    if passkey::account_of_handle(server.store(), handle.as_bytes()).await?
        != Some(record.account_id)
    {
        return Err(refused("The passkey belongs to another account")
            .ctx(trc::Key::AccountId, record.account_id));
    }
    // PK-12, PK-13: switched off for the account, or its directory signs it in
    if !allowed_for(server, &settings, record.account_id).await? {
        return Err(refused("Passkeys are turned off for this account")
            .ctx(trc::Key::AccountId, record.account_id));
    }
    // PK-4: a passkey works only for the relying-party id it was made for
    if record.rp_id != rp_id {
        return Err(
            refused("The passkey was registered for another relying-party id")
                .ctx(trc::Key::AccountId, record.account_id),
        );
    }
    let mut stored = serde_json::from_slice::<webauthn_rs::prelude::Passkey>(&record.public_key)
        .map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid stored passkey")
                .reason(err)
        })?;

    // The signature, the origin (PK-2), user verification and the counter
    let result = match webauthn.finish_discoverable_authentication_v2(
        credential,
        ceremony.state,
        Credential::from(stored.clone()),
    ) {
        Ok(result) => result,
        Err(WebauthnError::CredentialPossibleCompromise) => {
            // PK-18
            trc::event!(
                Auth(trc::AuthEvent::PasskeyCounter),
                AccountId = record.account_id,
                Id = passkey::passkey_id(record.account_id, record.number),
                SpanId = session.session_id,
                Details = "The passkey may have been copied",
            );
            return Err(refused("Passkey counter went backwards")
                .ctx(trc::Key::AccountId, record.account_id));
        }
        Err(err) => {
            return Err(refused("The passkey's answer didn't check out")
                .ctx(trc::Key::AccountId, record.account_id)
                .details(err.to_string()));
        }
    };

    // Keep the new counter and flags, and when it was last used
    stored.update_credential(&result);
    record.sign_count = result.counter();
    record.backed_up = result.backup_state();
    record.last_used_at = Some(now());
    record.public_key = serde_json::to_vec(&stored).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to serialize a passkey")
            .reason(err)
    })?;
    passkey::save(server.store(), &record).await?;

    server
        .access_token(record.account_id)
        .await
        .and_then(|token| AccessToken::new(token, session.remote_ip))
        .map(|token| token.with_origin(Via::Passkey))
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
                passkey,
            } => start(self, session, &ticket, password, mfa_token, passkey).await?,
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
    assertion: Option<PasskeyAssertion>,
) -> trc::Result<RegisterResponse> {
    let Some(pending) = passkey::by_ticket(server.store(), ticket, now()).await? else {
        return Ok(RegisterResponse::Expired);
    };
    // PK-12, PK-13
    let settings = settings(server).await?;
    if !allowed_for(server, &settings, pending.account_id).await? {
        return Ok(turned_off());
    }
    let account = server
        .account(pending.account_id)
        .await
        .caused_by(trc::location!())?;

    // PK-8: the password (and code), or an active passkey, first. The
    // sign-in limits and the failure counting are the ones every sign-in
    // goes through.
    let signed_in = match &assertion {
        Some(assertion) => sign_in(server, session, assertion).await,
        None => {
            server
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
        }
    };
    let access_token: AccessToken = match signed_in {
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
    // An app password is for one app, not for adding ways to sign in
    if access_token.account_id() != pending.account_id
        || matches!(access_token.origin(), Some(Via::AppPassword { .. }))
    {
        return Ok(RegisterResponse::Failure);
    }

    let (webauthn, rp_id) = relying_party(server, &settings)?;
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
    // Good once: claimed, then deleted
    let key = ceremony_key(ticket);
    let Some(ceremony) = take_once(server, key, CEREMONY_SECONDS).await? else {
        return Ok(RegisterResponse::Expired);
    };
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

    let settings = settings(server).await?;
    if !allowed_for(server, &settings, pending.account_id).await? {
        return Ok(turned_off());
    }
    let (webauthn, rp_id) = relying_party(server, &settings)?;
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
