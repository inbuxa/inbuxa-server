/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Joining (spec "Joining and reset", RL-8).
//!
//! inbuxa-admin shows the join token once. The relay keeps the downstream's
//! CA pin and the secret from it; on the first link the downstream sends a
//! nonce, and the relay proves it holds the token with
//! `HMAC-SHA256(secret, nonce || relay link pin)`. The downstream then pins
//! the relay's link key.

use crate::{b64, pin::Pin};
use aws_lc_rs::{hmac, rand::SecureRandom};
use serde::{Deserialize, Serialize};

/// How long a join token is good for.
pub const TOKEN_LIFETIME_SECS: u64 = 24 * 3600;

/// The only token version so far.
pub const TOKEN_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinToken {
    pub v: u32,
    /// The `inbuxa:Relay` id on the downstream.
    pub relay_id: String,
    /// The downstream link CA's key pin (RL-6).
    #[serde(with = "b64")]
    pub ca_spki: Pin,
    /// Single use; deleted on both sides once the join succeeds.
    #[serde(with = "b64")]
    pub secret: [u8; 32],
    /// Unix seconds.
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    UnknownVersion,
    Expired,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Malformed => "the join token is malformed",
            TokenError::UnknownVersion => "the join token is from a newer release",
            TokenError::Expired => "the join token has expired",
        })
    }
}

impl std::error::Error for TokenError {}

impl JoinToken {
    /// A new token for `relay_id`, valid from `now` for a day.
    pub fn issue(relay_id: impl Into<String>, ca_spki: Pin, now: u64) -> Self {
        let mut secret = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut secret)
            .expect("system random source");
        JoinToken {
            v: TOKEN_VERSION,
            relay_id: relay_id.into(),
            ca_spki,
            secret,
            expires_at: now + TOKEN_LIFETIME_SECS,
        }
    }

    /// The text an administrator copies: base64url of the JSON.
    pub fn encode(&self) -> String {
        b64::encode(&serde_json::to_vec(self).expect("token serializes"))
    }

    /// Reads a token, and checks its version and expiry against `now`.
    pub fn decode(text: &str, now: u64) -> Result<Self, TokenError> {
        let bytes = b64::decode(text.trim()).ok_or(TokenError::Malformed)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| TokenError::Malformed)?;
        if value.get("v").and_then(|v| v.as_u64()) != Some(u64::from(TOKEN_VERSION)) {
            return Err(if value.get("v").is_some_and(|v| v.is_u64()) {
                TokenError::UnknownVersion
            } else {
                TokenError::Malformed
            });
        }
        let token: JoinToken = serde_json::from_value(value).map_err(|_| TokenError::Malformed)?;
        if token.relay_id.is_empty() {
            return Err(TokenError::Malformed);
        }
        if now >= token.expires_at {
            return Err(TokenError::Expired);
        }
        Ok(token)
    }
}

/// The relay's answer to `Relay/join`.
pub fn join_proof(secret: &[u8; 32], nonce: &[u8], relay_pin: &Pin) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(nonce);
    ctx.update(relay_pin);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(ctx.sign().as_ref());
    proof
}

/// The downstream's check of that answer, in constant time.
pub fn verify_join_proof(secret: &[u8; 32], nonce: &[u8], relay_pin: &Pin, proof: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut data = Vec::with_capacity(nonce.len() + relay_pin.len());
    data.extend_from_slice(nonce);
    data.extend_from_slice(relay_pin);
    hmac::verify(&key, &data, proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_expiry() {
        let token = JoinToken::issue("r1", [7; 32], 1000);
        let text = token.encode();
        assert_eq!(JoinToken::decode(&text, 1000), Ok(token.clone()));
        assert_eq!(
            JoinToken::decode(&text, 1000 + TOKEN_LIFETIME_SECS),
            Err(TokenError::Expired)
        );
        assert_eq!(
            JoinToken::decode("not a token", 1000),
            Err(TokenError::Malformed)
        );
    }

    #[test]
    fn newer_versions_are_named() {
        let text = b64::encode(br#"{"v":2,"relayId":"r1"}"#);
        assert_eq!(JoinToken::decode(&text, 0), Err(TokenError::UnknownVersion));
        let text = b64::encode(br#"{"v":"1"}"#);
        assert_eq!(JoinToken::decode(&text, 0), Err(TokenError::Malformed));
    }

    #[test]
    fn extra_fields_are_refused() {
        let token = JoinToken::issue("r1", [7; 32], 0);
        let mut value = serde_json::to_value(&token).unwrap();
        value["extra"] = serde_json::Value::Bool(true);
        let text = b64::encode(&serde_json::to_vec(&value).unwrap());
        assert_eq!(JoinToken::decode(&text, 0), Err(TokenError::Malformed));
    }

    #[test]
    fn proof_binds_secret_nonce_and_pin() {
        let secret = [1u8; 32];
        let proof = join_proof(&secret, b"nonce", &[2; 32]);
        assert!(verify_join_proof(&secret, b"nonce", &[2; 32], &proof));
        assert!(!verify_join_proof(&[9; 32], b"nonce", &[2; 32], &proof));
        assert!(!verify_join_proof(&secret, b"other", &[2; 32], &proof));
        assert!(!verify_join_proof(&secret, b"nonce", &[3; 32], &proof));
        assert!(!verify_join_proof(
            &secret,
            b"nonce",
            &[2; 32],
            &proof[..31]
        ));
    }
}
