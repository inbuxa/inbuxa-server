/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! STARTTLS for outbound mail: DANE (RFC 7672) where the destination's
//! TLSA records are signed, WebPKI checks where its MTA-STS policy
//! enforces (RFC 8461), and otherwise encryption without a certificate
//! check (spec "Outbound").

use inbuxa_outbound_tls::{Tlsa, dane};
use inbuxa_relay_proto::types::TlsInfo;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

/// What a delivery to one MX host asks of TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// In the clear: an opportunistic session whose TLS didn't set up.
    None,
    /// STARTTLS when offered, certificate unchecked.
    Opportunistic,
    /// STARTTLS required (`outboundTls: required`), certificate unchecked.
    Required,
    /// The host's zone is signed but its TLSA records are unusable: RFC
    /// 7672 §2.2 still asks for encryption.
    DaneEncrypt,
    /// The chain must match these TLSA records.
    Dane(Arc<Tlsa>),
    /// MTA-STS enforce: a WebPKI chain valid for the MX host's name.
    Verified,
}

impl TlsMode {
    pub fn is_required(&self) -> bool {
        !matches!(self, TlsMode::None | TlsMode::Opportunistic)
    }

    /// The TLS-RPT policy type (RFC 8460 §4.4).
    pub fn policy_type(&self) -> &'static str {
        match self {
            TlsMode::Dane(_) | TlsMode::DaneEncrypt => "tlsa",
            TlsMode::Verified => "sts",
            _ => "no-policy-found",
        }
    }
}

/// A TLS failure, with its TLS-RPT result type (RFC 8460 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFailure {
    pub reason: String,
    pub result_type: &'static str,
    /// The handshake itself failed, as opposed to a policy check after it.
    pub handshake: bool,
}

impl TlsFailure {
    pub fn starttls_not_supported() -> Self {
        TlsFailure {
            reason: "STARTTLS isn't offered".into(),
            result_type: "starttls-not-supported",
            handshake: false,
        }
    }
}

pub struct TlsOutcome {
    pub stream: TlsStream<TcpStream>,
    pub info: TlsInfo,
}

pub async fn handshake(
    tcp: TcpStream,
    mx: &str,
    domain: &str,
    mode: &TlsMode,
    timeout: Duration,
) -> Result<TlsOutcome, TlsFailure> {
    let failure = |reason: String, result_type| TlsFailure {
        reason,
        result_type,
        handshake: true,
    };
    let name = ServerName::try_from(mx.to_string())
        .map_err(|_| failure(format!("{mx} isn't a host name"), "validation-failure"))?;
    let config = match mode {
        TlsMode::Verified => verified(),
        _ => unverified(),
    };
    let stream = tokio::time::timeout(timeout, TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| failure("the handshake timed out".into(), "validation-failure"))?
        .map_err(|e| {
            let result_type = match e.get_ref().and_then(|inner| inner.downcast_ref::<Error>()) {
                Some(Error::InvalidCertificate(CertificateError::NotValidForName))
                | Some(Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                    ..
                })) => "certificate-host-mismatch",
                Some(Error::InvalidCertificate(
                    CertificateError::Expired | CertificateError::ExpiredContext { .. },
                )) => "certificate-expired",
                Some(Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
                    "certificate-not-trusted"
                }
                _ => "validation-failure",
            };
            failure(e.to_string(), result_type)
        })?;
    let (_, conn) = stream.get_ref();
    if let TlsMode::Dane(tlsa) = mode {
        let certificates = conn.peer_certificates();
        if let Err(e) = dane::verify(tlsa, &[mx, domain], certificates) {
            return Err(TlsFailure {
                reason: e.description().into(),
                result_type: "validation-failure",
                handshake: false,
            });
        }
    }
    let info = TlsInfo {
        version: conn
            .protocol_version()
            .map_or("unknown".into(), |v| format!("{v:?}")),
        cipher: conn
            .negotiated_cipher_suite()
            .map_or("unknown".into(), |c| format!("{:?}", c.suite())),
    };
    Ok(TlsOutcome { stream, info })
}

/// WebPKI against the system's roots: the container image carries them.
pub(super) fn verified() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = crate::link::tls::provider();
            let mut roots = rustls::RootCertStore::empty();
            let found = rustls_native_certs::load_native_certs();
            let (added, _) = roots.add_parsable_certificates(found.certs);
            if added == 0 {
                eprintln!(
                    "inbuxa-relay: no CA roots found; MTA-STS destinations can't be delivered to"
                );
            }
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build();
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("default TLS versions");
            Arc::new(match verifier {
                Ok(verifier) => config.with_webpki_verifier(verifier).with_no_client_auth(),
                // No roots: nothing verifies, so nothing is delivered.
                Err(_) => config
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(Refuse))
                    .with_no_client_auth(),
            })
        })
        .clone()
}

/// Any certificate: opportunistic TLS, and DANE, which checks the chain
/// itself after the handshake.
fn unverified() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder_with_provider(crate::link::tls::provider())
                    .with_safe_default_protocol_versions()
                    .expect("default TLS versions")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AnyCertificate))
                    .with_no_client_auth(),
            )
        })
        .clone()
}

#[derive(Debug)]
struct AnyCertificate;

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    // The signatures still have to be right: the server must hold the key
    // of the certificate it sent, or DANE would check a stolen chain.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &crate::link::tls::provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &crate::link::tls::provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crate::link::tls::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct Refuse;

impl ServerCertVerifier for Refuse {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crate::link::tls::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
