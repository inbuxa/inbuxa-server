/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{GrantType, crypto::SymmetricEncrypt};
use crate::Server;
use compact_str::CompactString;
use encodify::base64::URL_SAFE_NO_PAD;
use std::time::SystemTime;
use store::{
    blake3,
    rand::{RngExt, rng},
};
use utils::codec::leb128::{Leb128Reader, Leb128Writer};

pub const FAILED_TO_DECODE_TOKEN: &str = concat!(
    "Failed to decode token. If you are using an ",
    "external OIDC provider, make sure it is configured as the default directory under ",
    "the Authentication object."
);

pub(crate) const TOKEN_HEADER: &str = "sw1.";
pub(super) const TOKEN_KEY_CONTEXT: &str = "stalwart-oauth-token-sw1";
const OAUTH_EPOCH: u64 = 946684800; // Jan 1, 2000

pub struct TokenInfo {
    pub grant_type: GrantType,
    pub account_id: u32,
    pub claims: Option<String>,
    pub expiry: u64,
    pub issued_at: u64,
    pub expires_in: u64,
    pub credential_version: u64,
    pub credential_expired: bool,
    pub grant: Option<TokenGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenGrant {
    pub id: u64,
    pub generation: u64,
}

struct RawToken {
    grant_type: GrantType,
    account_id: u32,
    claims: Option<String>,
    issued_at: u64,
    expiry: u64,
    credential_version: u64,
    grant: Option<TokenGrant>,
}

pub struct RefreshTokenParams<'x> {
    pub account_id: u32,
    pub account_name: &'x str,
    pub grant: TokenGrant,
    pub rotated_at: u64,
    pub credential_version: u64,
    pub scope: Option<&'x str>,
}

impl Server {
    pub async fn encode_access_token(
        &self,
        grant_type: GrantType,
        account_id: u32,
        account_name: &str,
        expiry_in: u64,
        claims: Option<&str>,
        credential_version: Option<u64>,
    ) -> trc::Result<String> {
        let issued_at = seconds_since_oauth_epoch();
        self.seal_token(
            &RawToken {
                grant_type,
                account_id,
                claims: claims.map(|claims| claims.to_string()),
                issued_at,
                expiry: issued_at + expiry_in,
                credential_version: credential_version
                    .filter(|_| !matches!(grant_type, GrantType::Rsvp))
                    .unwrap_or_default(),
                grant: None,
            },
            account_name,
            &rng().random::<[u8; SymmetricEncrypt::NONCE_LEN]>(),
        )
    }

    pub fn encode_grant_access_token(
        &self,
        account_id: u32,
        account_name: &str,
        grant_id: u64,
        credential_version: u64,
    ) -> trc::Result<String> {
        let issued_at = seconds_since_oauth_epoch();
        self.seal_token(
            &RawToken {
                grant_type: GrantType::AccessToken,
                account_id,
                claims: None,
                issued_at,
                expiry: issued_at + self.core.oauth.oauth_expiry_token,
                credential_version,
                grant: Some(TokenGrant {
                    id: grant_id,
                    generation: 0,
                }),
            },
            account_name,
            &rng().random::<[u8; SymmetricEncrypt::NONCE_LEN]>(),
        )
    }

    pub fn encode_refresh_token(&self, params: RefreshTokenParams<'_>) -> trc::Result<String> {
        let issued_at = params.rotated_at.saturating_sub(OAUTH_EPOCH);
        let mut hasher = blake3::Hasher::new_keyed(&self.core.oauth.refresh_nonce_key);
        hasher.update(&params.grant.id.to_le_bytes());
        hasher.update(&params.grant.generation.to_le_bytes());
        let mut nonce = [0u8; SymmetricEncrypt::NONCE_LEN];
        hasher.finalize_xof().fill(&mut nonce);

        self.seal_token(
            &RawToken {
                grant_type: GrantType::RefreshToken,
                account_id: params.account_id,
                claims: params.scope.map(|scope| scope.to_string()),
                issued_at,
                expiry: issued_at + self.core.oauth.oauth_expiry_refresh_token,
                credential_version: params.credential_version,
                grant: Some(params.grant),
            },
            params.account_name,
            &nonce,
        )
    }

    fn seal_token(
        &self,
        raw: &RawToken,
        account_name: &str,
        nonce: &[u8; SymmetricEncrypt::NONCE_LEN],
    ) -> trc::Result<String> {
        seal_token(
            &self.core.oauth.token_cipher,
            raw,
            account_name.as_bytes(),
            nonce,
        )
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, "Failed to encrypt token")
                .reason(err)
                .caused_by(trc::location!())
        })
    }

    pub fn decode_access_token(
        &self,
        expected_grant_type: Option<GrantType>,
        token_: &str,
    ) -> trc::Result<TokenInfo> {
        let token = open_token(&self.core.oauth.token_cipher, token_).map_err(|_| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, FAILED_TO_DECODE_TOKEN)
                .caused_by(trc::location!())
                .details(CompactString::from(token_))
        })?;

        let now = seconds_since_oauth_epoch();
        if token.expiry <= now || token.issued_at > now {
            return Err(trc::AuthEvent::TokenExpired.into_err());
        }

        if expected_grant_type.is_some_and(|g| g != token.grant_type) {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Invalid grant type"));
        }

        Ok(TokenInfo {
            grant_type: token.grant_type,
            account_id: token.account_id,
            claims: token.claims,
            expiry: token.expiry + OAUTH_EPOCH,
            issued_at: token.issued_at + OAUTH_EPOCH,
            expires_in: token.expiry - now,
            credential_version: token.credential_version,
            credential_expired: false,
            grant: token.grant,
        })
    }

    pub async fn validate_access_token(
        &self,
        expected_grant_type: Option<GrantType>,
        token: &str,
    ) -> trc::Result<TokenInfo> {
        let mut token = self.decode_access_token(expected_grant_type, token)?;

        if token.credential_version != 0 {
            let inner = self
                .access_token(token.account_id)
                .await
                .map_err(|err| trc::AuthEvent::Error.into_err().ctx(trc::Key::Details, err))?;
            assert_credential_version(token.credential_version, inner.credential_version())?;
            token.credential_expired = inner.is_main_credential_expired();
        }

        Ok(token)
    }
}

pub fn assert_credential_version(token_version: u64, current_version: u64) -> trc::Result<()> {
    if token_version == 0 || token_version == current_version {
        Ok(())
    } else {
        Err(trc::AuthEvent::TokenExpired
            .into_err()
            .details("Token revoked"))
    }
}

fn seal_token(
    cipher: &SymmetricEncrypt,
    token: &RawToken,
    footer: &[u8],
    nonce: &[u8; SymmetricEncrypt::NONCE_LEN],
) -> Result<String, String> {
    let mut payload = Vec::with_capacity(32);
    payload.push_leb128(token.account_id);
    payload.push(token.grant_type.id());
    payload.push_leb128(token.issued_at);
    payload.push_leb128(token.expiry);
    payload.push_leb128(token.credential_version);
    match token.grant {
        Some(grant) => {
            payload.push_leb128(grant.id.saturating_add(1));
            payload.push_leb128(grant.generation);
        }
        None => payload.push(0),
    }
    if let Some(claims) = token.claims.as_deref().filter(|claims| !claims.is_empty()) {
        payload.extend_from_slice(claims.as_bytes());
    }

    let ciphertext = cipher.encrypt_with_aad(&payload, nonce, footer)?;

    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ciphertext);

    let mut out = String::with_capacity(TOKEN_HEADER.len() + (body.len() + footer.len()) * 2);
    out.push_str(TOKEN_HEADER);
    URL_SAFE_NO_PAD.encode_append(&body, &mut out);
    if !footer.is_empty() {
        out.push('.');
        URL_SAFE_NO_PAD.encode_append(footer, &mut out);
    }

    Ok(out)
}

fn open_token(cipher: &SymmetricEncrypt, token: &str) -> Result<RawToken, ()> {
    let rest = token.strip_prefix(TOKEN_HEADER).ok_or(())?;
    let (body, footer) = match rest.split_once('.') {
        Some((body, footer)) => (
            body,
            URL_SAFE_NO_PAD.decode(footer.as_bytes()).map_err(|_| ())?,
        ),
        None => (rest, Vec::new()),
    };
    let body = URL_SAFE_NO_PAD.decode(body.as_bytes()).map_err(|_| ())?;
    if body.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return Err(());
    }
    let (nonce, ciphertext) = body.split_at(SymmetricEncrypt::NONCE_LEN);

    let payload = cipher
        .decrypt_with_aad(ciphertext, nonce, &footer)
        .map_err(|_| ())?;

    let mut bytes = payload.as_slice();
    let account_id: u32 = bytes.read_leb128().ok_or(())?;
    let (&grant_type, rest) = bytes.split_first().ok_or(())?;
    let grant_type = GrantType::from_id(grant_type).ok_or(())?;
    bytes = rest;
    let issued_at: u64 = bytes.read_leb128().ok_or(())?;
    let expiry: u64 = bytes.read_leb128().ok_or(())?;
    let credential_version: u64 = bytes.read_leb128().ok_or(())?;
    let grant = match bytes.read_leb128::<u64>().ok_or(())? {
        0 => None,
        id => Some(TokenGrant {
            id: id - 1,
            generation: bytes.read_leb128().ok_or(())?,
        }),
    };
    let claims = if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8(bytes.to_vec()).map_err(|_| ())?)
    };

    Ok(RawToken {
        grant_type,
        account_id,
        claims,
        issued_at,
        expiry,
        credential_version,
        grant,
    })
}

#[inline(always)]
fn seconds_since_oauth_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_sub(OAUTH_EPOCH)
}

