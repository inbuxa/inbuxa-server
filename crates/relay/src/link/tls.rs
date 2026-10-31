/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! TLS on the link (RL-5, RL-6, RL-7): TLS 1.3 only, and a client
//! certificate required, chained to the downstream link CA whose key is
//! pinned. A client without one gets a TLS alert and nothing else.

use inbuxa_relay_proto::pin::{Pin, pins_match, spki_pin};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject};
use std::sync::Arc;
use tokio::sync::watch;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The pin of a certificate's key.
pub fn cert_pin(cert: &[u8]) -> Option<Pin> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).ok()?;
    Some(spki_pin(parsed.tbs_certificate.subject_pki.raw))
}

/// A new link key and its self-signed certificate, as PEM.
pub fn new_link_identity(relay_id: &str) -> Result<(String, String), rcgen::Error> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec![format!("{relay_id}.relay.invalid")])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("inbuxa-relay {relay_id}"),
    );
    // The pin is the identity; the dates only have to cover its life.
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2126, 1, 1);
    let cert = params.self_signed(&key)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// The link's server config.
pub fn server_config(
    key_pem: &str,
    cert_pem: &str,
    ca_pins: watch::Receiver<Vec<Pin>>,
) -> Result<rustls::ServerConfig, String> {
    let provider = provider();
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .map_err(|e| format!("link certificate: {e}"))?;
    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| format!("link key: {e}"))?;
    let verifier = Arc::new(PinnedCaVerifier {
        ca_pins,
        algorithms: provider.signature_verification_algorithms,
    });
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("link certificate: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The pinned CA among the certificates a client sent with its own, if one
/// is there.
pub fn client_ca<'a>(
    intermediates: &'a [CertificateDer<'a>],
    pins: &[Pin],
) -> Option<(&'a CertificateDer<'a>, Pin)> {
    intermediates.iter().find_map(|c| {
        let pin = cert_pin(c)?;
        pins.iter()
            .any(|trusted| pins_match(&pin, trusted))
            .then_some((c, pin))
    })
}

/// Accepts a client certificate only if one of the certificates the client
/// sent has a pinned CA key and signed the client's own certificate,
/// which must be valid now and for client authentication. The pins are the
/// relay's CA and, while the downstream replaces it, the next one (RL-34).
#[derive(Debug)]
pub struct PinnedCaVerifier {
    ca_pins: watch::Receiver<Vec<Pin>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedCaVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let pins = self.ca_pins.borrow().clone();
        let (ca, _) = client_ca(intermediates, &pins).ok_or(Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))?;
        let anchor = webpki::anchor_from_trusted_cert(ca)
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let ee = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        ee.verify_for_usage(
            self.algorithms.all,
            &[anchor],
            &[],
            now,
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|e| {
            Error::InvalidCertificate(match e {
                webpki::Error::CertExpired { .. } => rustls::CertificateError::Expired,
                webpki::Error::CertNotValidYet { .. } => rustls::CertificateError::NotValidYet,
                _ => rustls::CertificateError::BadSignature,
            })
        })?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // The link is TLS 1.3 only.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A test downstream: a CA and a node certificate it issued.
    pub struct TestCa {
        pub ca_der: Vec<u8>,
        pub node_cert_der: Vec<u8>,
        pub node_key_der: Vec<u8>,
    }

    pub fn test_ca(eku_client: bool) -> TestCa {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test link CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let node_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut node_params = rcgen::CertificateParams::new(vec!["node1.invalid".into()]).unwrap();
        if eku_client {
            node_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        }
        let node = node_params.signed_by(&node_key, &issuer).unwrap();
        TestCa {
            ca_der: ca.der().to_vec(),
            node_cert_der: node.der().to_vec(),
            node_key_der: node_key.serialize_der(),
        }
    }

    fn verifier(pin: Pin) -> PinnedCaVerifier {
        PinnedCaVerifier {
            ca_pins: watch::channel(vec![pin]).1,
            algorithms: provider().signature_verification_algorithms,
        }
    }

    #[test]
    fn accepts_only_the_pinned_ca() {
        let ca = test_ca(true);
        let pin = cert_pin(&ca.ca_der).unwrap();
        let ee = CertificateDer::from(ca.node_cert_der.clone());
        let chain = [CertificateDer::from(ca.ca_der.clone())];
        let now = UnixTime::now();
        assert!(verifier(pin).verify_client_cert(&ee, &chain, now).is_ok());
        assert!(
            verifier([0; 32])
                .verify_client_cert(&ee, &chain, now)
                .is_err()
        );
        assert!(verifier(pin).verify_client_cert(&ee, &[], now).is_err());

        // A certificate from another CA, sent with the pinned CA's cert.
        let other = test_ca(true);
        let other_ee = CertificateDer::from(other.node_cert_der);
        assert!(
            verifier(pin)
                .verify_client_cert(&other_ee, &chain, now)
                .is_err()
        );
    }

    #[test]
    fn link_identity_pins() {
        let (key, cert) = new_link_identity("r1").unwrap();
        let der = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        assert!(cert_pin(&der).is_some());
        assert!(server_config(&key, &cert, watch::channel(vec![[1; 32]]).1).is_ok());
    }
}
