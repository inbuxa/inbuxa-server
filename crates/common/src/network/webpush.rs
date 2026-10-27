/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use encodify::base64::URL_SAFE_NO_PAD;
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, PrivateKeyInfoRef, der::SecretDocument},
};
use parking_lot::Mutex;
use reqwest::{Url, header::HeaderValue};
use std::sync::Arc;

const VAPID_TOKEN_TTL: u64 = 12 * 60 * 60;
const VAPID_PREFIX: &str = "vapid t=";
const VAPID_JWT_HEADER: &[u8] = br#"{"typ":"JWT","alg":"ES256"}"#;
const VAPID_TOKEN_REFRESH: u64 = VAPID_TOKEN_TTL / 2;

#[derive(Clone)]
pub struct Vapid {
    key: VapidKey,
    contact: Option<String>,
    tokens: Arc<Mutex<AHashMap<String, VapidToken>>>,
}

struct VapidToken {
    authorization: HeaderValue,
    issued_at: u64,
}

impl Vapid {
    pub fn new(key: VapidKey, contact: Option<String>) -> Self {
        Self {
            key,
            contact,
            tokens: Arc::default(),
        }
    }

    pub fn public_key(&self) -> &str {
        self.key.public_key()
    }

    pub fn authorization(&self, endpoint: &str, now: u64) -> Option<HeaderValue> {
        let origin = endpoint_origin(endpoint)?;
        if let Some(token) = self
            .tokens
            .lock()
            .get(&origin)
            .filter(|token| token.is_fresh(now))
        {
            return Some(token.authorization.clone());
        }

        let authorization = HeaderValue::try_from(self.key.authorization_for_origin(
            &origin,
            self.contact.as_deref(),
            now,
        )?)
        .ok()?;
        let mut tokens = self.tokens.lock();
        tokens.retain(|_, token| token.is_fresh(now));
        tokens.insert(
            origin,
            VapidToken {
                authorization: authorization.clone(),
                issued_at: now,
            },
        );
        Some(authorization)
    }
}

impl VapidToken {
    fn is_fresh(&self, now: u64) -> bool {
        now.checked_sub(self.issued_at)
            .is_some_and(|age| age < VAPID_TOKEN_REFRESH)
    }
}

#[derive(Clone)]
pub struct VapidKey {
    signing_key: SigningKey,
    public_key: String,
}

impl VapidKey {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, String> {
        let pem = pem.trim_start_matches('\u{feff}').trim();

        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::from_signing_key(key));
        }
        if let Ok(secret) = SecretKey::from_sec1_pem(pem) {
            return Ok(Self::from_signing_key(secret.into()));
        }
        if let Some(secret) = secret_key_from_explicit_params(pem) {
            return Ok(Self::from_signing_key(secret.into()));
        }

        Err(SigningKey::from_pkcs8_pem(pem)
            .err()
            .map(|err| {
                format!(
                    "{err}. Re-encode the key as named-curve PKCS#8, \
                     e.g. `openssl pkey -in key.pem -out key_pkcs8.pem`."
                )
            })
            .unwrap_or_else(|| "unsupported VAPID key encoding".to_string()))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key =
            URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_sec1_point(false).as_bytes());
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn authorization(&self, endpoint: &str, contact: Option<&str>, now: u64) -> Option<String> {
        self.authorization_for_origin(&endpoint_origin(endpoint)?, contact, now)
    }

    fn authorization_for_origin(
        &self,
        origin: &str,
        contact: Option<&str>,
        now: u64,
    ) -> Option<String> {
        let mut claims = serde_json::Map::new();
        claims.insert("aud".into(), origin.into());
        claims.insert("exp".into(), (now + VAPID_TOKEN_TTL).into());
        if let Some(sub) = contact {
            claims.insert("sub".into(), sub.into());
        }

        let mut authorization = String::from(VAPID_PREFIX);
        URL_SAFE_NO_PAD.encode_append(VAPID_JWT_HEADER, &mut authorization);
        authorization.push('.');
        URL_SAFE_NO_PAD.encode_append(serde_json::to_vec(&claims).ok()?, &mut authorization);
        let signature: Signature = self
            .signing_key
            .sign(authorization.get(VAPID_PREFIX.len()..)?.as_bytes());
        authorization.push('.');
        URL_SAFE_NO_PAD.encode_append(signature.to_bytes(), &mut authorization);
        authorization.push_str(", k=");
        authorization.push_str(&self.public_key);

        Some(authorization)
    }
}

fn endpoint_origin(url: &str) -> Option<String> {
    let origin = Url::parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

pub fn normalize_contact(contact: &str) -> Option<String> {
    let contact = contact.trim();

    match contact.split_once(':') {
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("mailto") => Some(contact.to_string()),
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => Some(contact.to_string()),
        Some(_) => None,
        None if contact.contains('@') => Some(format!("mailto:{contact}")),
        None => None,
    }
}

pub fn generate_pkcs8_pem() -> Result<String, String> {
    use p256::elliptic_curve::Generate;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    SigningKey::try_generate()
        .map_err(|err| err.to_string())?
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|err| err.to_string())
}

fn secret_key_from_explicit_params(pem: &str) -> Option<SecretKey> {
    let (_, document) = SecretDocument::from_pem(pem).ok()?;
    let private_key_info = PrivateKeyInfoRef::try_from(document.as_bytes()).ok()?;
    SecretKey::from_sec1_der(private_key_info.private_key.as_bytes()).ok()
}

