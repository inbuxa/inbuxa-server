/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

//! DANE (RFC 7672): a server's certificate chain against its TLSA records.

use crate::{Tlsa, TlsaEntry, TlsaMatching};
use rustls_pki_types::{CertificateDer, Der, ServerName, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256, Sha512};
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_parser::asn1_rs::Any;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Which kind of TLSA record matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaneMatch {
    EndEntity,
    TrustAnchor,
}

impl DaneMatch {
    pub fn as_str(&self) -> &'static str {
        match self {
            DaneMatch::EndEntity => "end-entity",
            DaneMatch::TrustAnchor => "trust-anchor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaneFailure {
    /// The host sent no certificates.
    NoCertificates,
    /// One of them didn't parse; the parser's reason.
    CertificateParse(String),
    /// None matched a TLSA record.
    NoMatch,
}

impl DaneFailure {
    pub fn description(&self) -> &'static str {
        match self {
            DaneFailure::NoCertificates => "No certificates were provided by host",
            DaneFailure::CertificateParse(_) => "Failed to parse X.509 certificate",
            DaneFailure::NoMatch => "No matching certificates found in TLSA records",
        }
    }
}

/// Checks the chain a host presented against its TLSA records: a DANE-EE
/// record matching the end entity, or a DANE-TA record anchoring a chain
/// that is valid for one of `reference_ids`.
pub fn verify(
    tlsa: &Tlsa,
    reference_ids: &[&str],
    certificates: Option<&[CertificateDer<'_>]>,
) -> Result<DaneMatch, DaneFailure> {
    let certificates = match certificates {
        Some(certificates) if !certificates.is_empty() => certificates,
        _ => return Err(DaneFailure::NoCertificates),
    };

    let mut parsed = Vec::with_capacity(certificates.len());
    for der_certificate in certificates {
        match X509Certificate::from_der(der_certificate.as_ref()) {
            Ok((_, cert)) => parsed.push(cert),
            Err(err) => return Err(DaneFailure::CertificateParse(err.to_string())),
        }
    }

    if verify_end_entity(tlsa, certificates, &parsed) {
        Ok(DaneMatch::EndEntity)
    } else if verify_trust_anchor(tlsa, reference_ids, certificates, &parsed) {
        Ok(DaneMatch::TrustAnchor)
    } else {
        Err(DaneFailure::NoMatch)
    }
}

fn verify_end_entity(
    tlsa: &Tlsa,
    certificates: &[CertificateDer<'_>],
    parsed: &[X509Certificate<'_>],
) -> bool {
    tlsa.has_end_entities
        && tlsa
            .entries
            .iter()
            .filter(|record| record.is_end_entity)
            .any(|record| record_matches(record, &parsed[0], certificates[0].as_ref()))
}

fn verify_trust_anchor(
    tlsa: &Tlsa,
    reference_ids: &[&str],
    certificates: &[CertificateDer<'_>],
    parsed: &[X509Certificate<'_>],
) -> bool {
    if !tlsa.has_intermediates {
        return false;
    }

    let end_entity = match EndEntityCert::try_from(&certificates[0]) {
        Ok(end_entity) => end_entity,
        Err(_) => return false,
    };

    let mut anchors: Vec<TrustAnchor<'static>> = Vec::new();

    for record in tlsa.entries.iter().filter(|record| !record.is_end_entity) {
        match (record.is_spki, record.matching) {
            (false, TlsaMatching::Full) => {
                let der = CertificateDer::from(record.data.clone());
                if let Ok(anchor) = anchor_from_trusted_cert(&der) {
                    anchors.push(anchor.to_owned());
                }
            }
            (true, TlsaMatching::Full) => {
                if let Some(depth) = (1..certificates.len())
                    .find(|&depth| parsed[depth].public_key().raw == record.data.as_slice())
                {
                    if let Ok(anchor) = anchor_from_trusted_cert(&certificates[depth]) {
                        anchors.push(anchor.to_owned());
                    }
                } else if let Some(spki) = der_value(&record.data) {
                    for depth in 1..certificates.len() {
                        if is_chain_top(parsed, depth)
                            && let Some(subject) = der_value(parsed[depth].issuer().as_raw())
                        {
                            anchors.push(TrustAnchor {
                                subject: Der::from(subject.to_vec()),
                                subject_public_key_info: Der::from(spki.to_vec()),
                                name_constraints: None,
                            });
                        }
                    }
                }
            }
            _ => {
                for depth in 1..certificates.len() {
                    if record_matches(record, &parsed[depth], certificates[depth].as_ref())
                        && let Ok(anchor) = anchor_from_trusted_cert(&certificates[depth])
                    {
                        anchors.push(anchor.to_owned());
                    }
                }
            }
        }
    }

    !anchors.is_empty()
        && end_entity
            .verify_for_usage(
                ALL_VERIFICATION_ALGS,
                &anchors,
                &certificates[1..],
                UnixTime::now(),
                KeyUsage::server_auth(),
                None,
                None,
            )
            .is_ok()
        && reference_ids.iter().any(|reference| {
            ServerName::try_from(*reference)
                .map(|name| end_entity.verify_is_valid_for_subject_name(&name).is_ok())
                .unwrap_or(false)
        })
}

fn is_chain_top(parsed: &[X509Certificate<'_>], depth: usize) -> bool {
    let issuer = parsed[depth].issuer().as_raw();
    !parsed
        .iter()
        .enumerate()
        .any(|(other, cert)| other != depth && cert.subject().as_raw() == issuer)
}

fn record_matches(record: &TlsaEntry, cert: &X509Certificate<'_>, raw: &[u8]) -> bool {
    let selected: &[u8] = if record.is_spki {
        cert.public_key().raw
    } else {
        raw
    };

    match record.matching {
        TlsaMatching::Full => selected == record.data.as_slice(),
        TlsaMatching::Sha256 => Sha256::digest(selected).as_slice() == record.data.as_slice(),
        TlsaMatching::Sha512 => Sha512::digest(selected).as_slice() == record.data.as_slice(),
    }
}

#[inline(always)]
fn der_value(der: &[u8]) -> Option<&[u8]> {
    Any::from_der(der).ok().map(|(_, any)| any.data)
}
