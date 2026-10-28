/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    config::{EcKeyCurve, build_ecdsa_pem, build_rsa_keypair},
    manager::application::Resource,
};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, RSAKeyParameters,
        RSAKeyType,
    },
};
use registry::schema::{enums::JwtSignatureAlgorithm, prelude::ObjectType, structs::OidcProvider};
use std::borrow::Cow;
use store::{
    rand::{RngExt, distr::Alphanumeric, rng},
    registry::bootstrap::Bootstrap,
};

#[derive(Clone)]
pub struct OAuthConfig {
    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,

    pub allow_anonymous_client_registration: bool,
    pub require_client_authentication: bool,

    pub oidc_expiry_id_token: u64,
    pub oidc_signing_secret: EncodingKey,
    pub oidc_signature_algorithm: Algorithm,
    pub oidc_jwks: Resource<Vec<u8>>,
}

impl OAuthConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let auth = bp.setting_infallible::<OidcProvider>().await;

        let oidc_signature_algorithm = match auth.signature_algorithm {
            JwtSignatureAlgorithm::Es256 => Algorithm::ES256,
            JwtSignatureAlgorithm::Es384 => Algorithm::ES384,
            JwtSignatureAlgorithm::Ps256 => Algorithm::PS256,
            JwtSignatureAlgorithm::Ps384 => Algorithm::PS384,
            JwtSignatureAlgorithm::Ps512 => Algorithm::PS512,
            JwtSignatureAlgorithm::Rs256 => Algorithm::RS256,
            JwtSignatureAlgorithm::Rs384 => Algorithm::RS384,
            JwtSignatureAlgorithm::Rs512 => Algorithm::RS512,
            JwtSignatureAlgorithm::Hs256 => Algorithm::HS256,
            JwtSignatureAlgorithm::Hs384 => Algorithm::HS384,
            JwtSignatureAlgorithm::Hs512 => Algorithm::HS512,
        };

        // inbuxa: every fallback key is its own random value, and an empty
        // secret counts as missing.
        let random_key = || {
            rng()
                .sample_iter(Alphanumeric)
                .take(64)
                .map(char::from)
                .collect::<String>()
        };

        let signature_key = match auth.signature_key.secret().await {
            Ok(key) if !key.is_empty() => key,
            Ok(_) => {
                bp.build_error(
                    ObjectType::OidcProvider.singleton(),
                    "The OIDC signature key is empty",
                );
                Cow::Owned(random_key())
            }
            Err(err) => {
                bp.build_error(ObjectType::OidcProvider.singleton(), err);
                Cow::Owned(random_key())
            }
        };

        let configured = match oidc_signature_algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Ok((EncodingKey::from_secret(signature_key.as_bytes()), None))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => parse_rsa_key(&auth)
                .await
                .map(|(secret, alg)| (secret, Some(alg))),
            Algorithm::ES256 | Algorithm::ES384 => parse_ecdsa_key(&auth, oidc_signature_algorithm)
                .await
                .map(|(secret, alg)| (secret, Some(alg))),
            _ => Err(format!(
                "Unsupported OIDC signature algorithm {oidc_signature_algorithm:?}"
            )),
        };

        // inbuxa: when the configured key can't be used, sign with a fresh
        // ES256 key and publish only its public half. The old fallback was a
        // random HMAC secret published as an "oct" key in the public JWKS,
        // where anyone could take it and sign ID tokens.
        let (oidc_signing_secret, algorithm, oidc_signature_algorithm) = match configured {
            Ok((secret, algorithm)) => (secret, algorithm, oidc_signature_algorithm),
            Err(err) => {
                bp.build_error(ObjectType::OidcProvider.singleton(), err);
                match ephemeral_es256_key() {
                    Ok((secret, algorithm)) => (secret, Some(algorithm), Algorithm::ES256),
                    Err(err) => {
                        // Nothing is published, so no relying party accepts
                        // what this key signs.
                        bp.build_error(ObjectType::OidcProvider.singleton(), err);
                        (
                            EncodingKey::from_secret(random_key().as_bytes()),
                            None,
                            oidc_signature_algorithm,
                        )
                    }
                }
            }
        };

        let oidc_jwks = Resource {
            content_type: "application/json".into(),
            contents: serde_json::to_string(&JwkSet {
                keys: algorithm
                    .into_iter()
                    .map(|algorithm| Jwk {
                        common: CommonParameters {
                            public_key_use: PublicKeyUse::Signature.into(),
                            key_algorithm: KeyAlgorithm::from(oidc_signature_algorithm).into(),
                            key_id: "default".to_string().into(),
                            ..Default::default()
                        },
                        algorithm,
                    })
                    .collect(),
            })
            .unwrap_or_default()
            .into_bytes(),
        };

        OAuthConfig {
            oauth_key: match auth.encryption_key.secret().await {
                Ok(key) if !key.is_empty() => key.into_owned(),
                Ok(_) => {
                    bp.build_error(
                        ObjectType::OidcProvider.singleton(),
                        "The OAuth encryption key is empty",
                    );
                    random_key()
                }
                Err(err) => {
                    bp.build_error(ObjectType::OidcProvider.singleton(), err);
                    random_key()
                }
            },
            oauth_expiry_user_code: auth.user_code_expiry.as_secs(),
            oauth_expiry_auth_code: auth.auth_code_expiry.as_secs(),
            oauth_expiry_token: auth.access_token_expiry.as_secs(),
            oauth_expiry_refresh_token: auth.refresh_token_expiry.as_secs(),
            oauth_expiry_refresh_token_renew: auth.refresh_token_renewal.as_secs(),
            oauth_max_auth_attempts: auth.auth_code_max_attempts as u32,
            oidc_expiry_id_token: auth.id_token_expiry.as_secs(),
            allow_anonymous_client_registration: auth.anonymous_client_registration,
            require_client_authentication: auth.require_client_registration,
            oidc_signing_secret,
            oidc_signature_algorithm,
            oidc_jwks,
        }
    }
}

fn ephemeral_es256_key() -> Result<(EncodingKey, AlgorithmParameters), String> {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|err| format!("Failed to generate a fallback OIDC key: {err}"))?;
    let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref()));
    let ecdsa_key = build_ecdsa_pem(EcKeyCurve::P256, &pem)?;

    Ok((
        EncodingKey::from_ec_der(&ecdsa_key.pkcs8_der),
        AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(&ecdsa_key.x),
            y: URL_SAFE_NO_PAD.encode(&ecdsa_key.y),
        }),
    ))
}

async fn parse_rsa_key(auth: &OidcProvider) -> Result<(EncodingKey, AlgorithmParameters), String> {
    let rsa_key = build_rsa_keypair(auth.signature_key.secret().await?.as_ref())?;

    let rsa_key_params = RSAKeyParameters {
        key_type: RSAKeyType::RSA,
        n: URL_SAFE_NO_PAD.encode(&rsa_key.modulus),
        e: URL_SAFE_NO_PAD.encode(&rsa_key.exponent),
    };

    Ok((
        EncodingKey::from_rsa_der(&rsa_key.pkcs1_der),
        AlgorithmParameters::RSA(rsa_key_params),
    ))
}

async fn parse_ecdsa_key(
    auth: &OidcProvider,
    oidc_signature_algorithm: Algorithm,
) -> Result<(EncodingKey, AlgorithmParameters), String> {
    let (curve, ec_curve) = match oidc_signature_algorithm {
        Algorithm::ES256 => (EllipticCurve::P256, EcKeyCurve::P256),
        Algorithm::ES384 => (EllipticCurve::P384, EcKeyCurve::P384),
        _ => unreachable!(),
    };

    let ecdsa_key = build_ecdsa_pem(ec_curve, auth.signature_key.secret().await?.as_ref())?;

    let ecdsa_key_params = EllipticCurveKeyParameters {
        key_type: EllipticCurveKeyType::EC,
        curve,
        x: URL_SAFE_NO_PAD.encode(&ecdsa_key.x),
        y: URL_SAFE_NO_PAD.encode(&ecdsa_key.y),
    };

    Ok((
        EncodingKey::from_ec_der(&ecdsa_key.pkcs8_der),
        AlgorithmParameters::EllipticCurve(ecdsa_key_params),
    ))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::AlgorithmParameters;

    #[test]
    fn fallback_signing_key_is_asymmetric() {
        // What the JWKS publishes for the fallback must be a public key only.
        let (_, params) = super::ephemeral_es256_key().unwrap();
        assert!(matches!(params, AlgorithmParameters::EllipticCurve(_)));
        let json = serde_json::to_string(&params).unwrap();
        assert!(!json.contains("\"oct\""), "{json}");
        assert!(!json.contains("\"d\""), "{json}");
    }
}
