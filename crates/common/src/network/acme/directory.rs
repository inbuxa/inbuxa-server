/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use super::jose::{
    decode_account_key, key_authorization, key_authorization_sha256,
    key_authorization_sha256_base64, sign,
};
use crate::network::acme::http::{
    acme_client, get_header, https, parse_alternate_links, parse_retry_after, read_body,
};
use crate::network::acme::{
    AcmeError, AcmeResult, Auth, AuthStatus, Challenge, ChallengeType, Directory, Identifier,
    Order, SerializedCert,
};
use aws_lc_rs::signature::EcdsaKeyPair;
use encodify::base64::URL_SAFE_NO_PAD;
use rcgen::{CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use registry::schema::structs::AcmeProvider;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::time::Duration;
use store::Serialize;
use store::write::Archiver;
use utils::outbound::OutboundClient;

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug)]
pub struct AcmeRequestBuilder {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub kid: String,
    pub challenge: ChallengeType,
    pub preferred_chain: Option<String>,
    client: OutboundClient,
}

pub struct AcmeResponse<L, B> {
    pub location: L,
    pub body: B,
    pub retry_after: Option<Duration>,
    pub alternates: Vec<String>,
}

impl AcmeRequestBuilder {
    pub async fn new(provider: AcmeProvider) -> AcmeResult<Self> {
        let client = acme_client(&provider);
        let directory = Directory::discover(&client, &provider.directory).await?;
        let key_pair = decode_account_key(&provider.account_key)?;

        Ok(Self {
            key_pair,
            directory,
            kid: provider.account_uri,
            challenge: provider.challenge_type.into(),
            preferred_chain: provider.preferred_chain,
            client,
        })
    }

    async fn request(
        &self,
        url: impl AsRef<str>,
        payload: &str,
    ) -> AcmeResult<AcmeResponse<Option<String>, String>> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce(&self.client).await?,
            url.as_ref(),
            payload,
        )?;
        let response = https(&self.client, url.as_ref(), Method::POST, Some(body)).await?;

        Ok(AcmeResponse {
            location: get_header(&response, "Location").ok(),
            retry_after: parse_retry_after(&response),
            alternates: parse_alternate_links(&response),
            body: read_body(response).await?,
        })
    }

    pub async fn new_order(&self, domains: Vec<String>) -> AcmeResult<AcmeResponse<String, Order>> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = json!({
            "identifiers": domains,
        })
        .to_string();
        let response = self.request(&self.directory.new_order, &payload).await?;
        Ok(AcmeResponse {
            location: response.location.ok_or(AcmeError::Invalid(format!(
                "Missing Location header in new order response from {}",
                self.directory.new_order
            )))?,
            body: serde_json::from_str(&response.body).map_err(AcmeError::Json)?,
            retry_after: response.retry_after,
            alternates: response.alternates,
        })
    }

    pub async fn auth(
        &self,
        url: impl AsRef<str>,
    ) -> AcmeResult<AcmeResponse<Option<String>, Auth>> {
        AcmeResponse::parse(self.request(url, "").await?)
    }

    pub async fn challenge(&self, url: impl AsRef<str>) -> AcmeResult<()> {
        self.request(&url, "{}").await.map(|_| ())
    }

    pub async fn order(
        &self,
        url: impl AsRef<str>,
    ) -> AcmeResult<AcmeResponse<Option<String>, Order>> {
        AcmeResponse::parse(self.request(&url, "").await?)
    }

    pub async fn finalize(
        &self,
        url: impl AsRef<str>,
        csr: Vec<u8>,
    ) -> AcmeResult<AcmeResponse<Option<String>, Order>> {
        let mut payload = String::from("{\"csr\":\"");
        URL_SAFE_NO_PAD.encode_append(csr, &mut payload);
        payload.push_str("\"}");
        AcmeResponse::parse(self.request(&url, &payload).await?)
    }

    pub async fn certificate(
        &self,
        url: impl AsRef<str>,
    ) -> AcmeResult<AcmeResponse<Option<String>, String>> {
        self.request(&url, "").await
    }

    pub fn http_proof(&self, challenge: &Challenge) -> AcmeResult<Vec<u8>> {
        let challenge_token = challenge.token.as_deref().ok_or_else(|| {
            AcmeError::Invalid("Missing http-01 challenge token in response".to_string())
        })?;
        key_authorization(&self.key_pair, challenge_token).map(|key| key.into_bytes())
    }

    pub fn dns_proof(&self, challenge: &Challenge) -> AcmeResult<String> {
        let challenge_token = challenge.token.as_deref().ok_or_else(|| {
            AcmeError::Invalid("Missing dns-01 challenge token in response".to_string())
        })?;
        key_authorization_sha256_base64(&self.key_pair, challenge_token)
    }

    pub fn tls_alpn_key(&self, challenge: &Challenge, domain: String) -> AcmeResult<Vec<u8>> {
        let challenge_token = challenge.token.as_deref().ok_or_else(|| {
            AcmeError::Invalid("Missing tls-alpn-01 challenge token in response".to_string())
        })?;
        let mut params = rcgen::CertificateParams::new(vec![domain]).map_err(|err| {
            AcmeError::Crypto(format!("Failed to create certificate params: {}", err))
        })?;
        let key_auth = key_authorization_sha256(&self.key_pair, challenge_token)?;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| AcmeError::Crypto(format!("Failed to generate key pair: {}", err)))?;
        let cert = params.self_signed(&key_pair).map_err(|err| {
            AcmeError::Crypto(format!(
                "Failed to generate TLS-ALPN-01 certificate: {}",
                err
            ))
        })?;

        Archiver::new(SerializedCert {
            certificate: cert.der().to_vec(),
            private_key: key_pair.serialize_der(),
        })
        .untrusted()
        .serialize()
        .map_err(|_| AcmeError::Crypto("Failed to serialize certificate".to_string()))
    }
}

impl Directory {
    pub async fn discover(client: &OutboundClient, url: impl AsRef<str>) -> AcmeResult<Self> {
        let mut directory: Directory = serde_json::from_str(
            &read_body(https(client, url.as_ref(), Method::GET, None).await?).await?,
        )?;
        directory.meta.normalize();
        Ok(directory)
    }

    pub async fn nonce(&self, client: &OutboundClient) -> AcmeResult<String> {
        get_header(
            &https(client, &self.new_nonce, Method::HEAD, None).await?,
            "replay-nonce",
        )
    }
}

impl<L, T: DeserializeOwned> AcmeResponse<L, T> {
    pub fn parse(input: AcmeResponse<L, String>) -> AcmeResult<AcmeResponse<L, T>> {
        serde_json::from_str(&input.body)
            .map_err(|err| {
                AcmeError::Invalid(format!(
                    "ACME response parsing error: {}, body: {}",
                    err, input.body
                ))
            })
            .map(|body| AcmeResponse {
                location: input.location,
                body,
                retry_after: input.retry_after,
                alternates: input.alternates,
            })
    }
}

impl<L, T> AcmeResponse<L, T> {
    pub fn assert_reasonable_retry_after(self) -> AcmeResult<Self> {
        if let Some(retry_after) = self.retry_after
            && retry_after > Duration::from_secs(10 * 60)
        {
            trc::event!(
                Acme(trc::AcmeEvent::RenewBackoff),
                Elapsed = retry_after,
                Reason = "ACME server requested an excessively long Retry-After",
            );

            return Err(AcmeError::Backoff {
                wait: retry_after.into(),
            });
        }

        Ok(self)
    }
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::DnsPersist01 => "dns-persist-01",
            Self::Unknown => "unknown",
        }
    }
}

impl AuthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Deactivated => "deactivated",
        }
    }
}
