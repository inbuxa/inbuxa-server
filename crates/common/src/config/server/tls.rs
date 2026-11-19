/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::network::acme::ParsedCert;
use ahash::{AHashMap, AHashSet};
use rcgen::generate_simple_self_signed;
use registry::{
    schema::{
        prelude::{Object, ObjectType},
        structs::{Certificate, PublicText, SecretText, SystemSettings},
    },
    types::{datetime::UTCDateTime, map::Map},
};
use rustls::{
    SupportedProtocolVersion,
    crypto::aws_lc_rs::sign::any_supported_type,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};
use rustls_pemfile::{Item, certs, read_all};
use rustls_pki_types::PrivateKeyDer;
use std::{io::Cursor, path::PathBuf, sync::Arc};
use store::{
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::now,
};

/// inbuxa: K-C8. Directories, each holding tls.crt and tls.key as a
/// Kubernetes TLS Secret mounts them, whose certificates the server uses
/// without storing them: cert-manager renews them in place, and every node
/// reads its own copy. Separated by commas or whitespace.
pub const CERTIFICATE_DIRS_VAR: &str = "TLS_CERTIFICATE_DIRS";

/// The files of each directory in INBUXA_TLS_CERTIFICATE_DIRS: (certificate,
/// private key)
pub fn certificate_dir_files() -> Vec<(PathBuf, PathBuf)> {
    types::branding::env_var(CERTIFICATE_DIRS_VAR)
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|dir| !dir.is_empty())
        .map(|dir| {
            let dir = PathBuf::from(dir);
            (dir.join("tls.crt"), dir.join("tls.key"))
        })
        .collect()
}

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

pub(crate) async fn parse_certificates(
    bp: &mut Bootstrap,
    certificates: &mut AHashMap<Box<str>, Arc<CertifiedKey>>,
    subject_names: &mut AHashSet<Box<str>>,
) {
    let system = bp.setting_infallible::<SystemSettings>().await;

    // Parse certificates
    let now = now() as i64;
    let mut certs_expired = Vec::new();
    let mut certs_expirations = AHashMap::new();
    for cert_obj in bp.list_infallible::<Certificate>().await {
        let obj_id = cert_obj.id;
        let revision = cert_obj.revision;
        let mut cert = cert_obj.object;

        let is_file_backed = matches!(cert.certificate, PublicText::File(_))
            || matches!(cert.private_key, SecretText::File(_));
        let mut public = None;
        let mut refreshed_meta = None;
        if is_file_backed {
            let pem = match cert.certificate.value().await {
                Ok(value) => value.into_owned().into_bytes(),
                Err(err) => {
                    bp.build_error(obj_id, format!("Failed to obtain certificate value: {err}"));
                    continue;
                }
            };
            match ParsedCert::parse(&pem) {
                Ok(parsed) => {
                    let not_valid_after =
                        UTCDateTime::from_timestamp(parsed.valid_not_after.timestamp());
                    let not_valid_before =
                        UTCDateTime::from_timestamp(parsed.valid_not_before.timestamp());
                    let sans = Map::new(parsed.sans);
                    if cert.not_valid_after != not_valid_after
                        || cert.not_valid_before != not_valid_before
                        || cert.issuer != parsed.issuer
                        || cert.subject_alternative_names != sans
                    {
                        refreshed_meta =
                            Some((not_valid_after, not_valid_before, parsed.issuer, sans));
                    }
                    public = Some(pem);
                }
                Err(err) => {
                    bp.build_error(obj_id, format!("Invalid certificate: {err}"));
                    continue;
                }
            }
        }

        let (not_valid_after, not_valid_before) = match refreshed_meta.as_ref() {
            Some((after, before, _, _)) => (after.timestamp(), before.timestamp()),
            None => (
                cert.not_valid_after.timestamp(),
                cert.not_valid_before.timestamp(),
            ),
        };

        if not_valid_after <= now {
            certs_expired.push((
                obj_id,
                cert.subject_alternative_names.clone().into_inner(),
                Object {
                    inner: cert.into(),
                    revision,
                },
            ));
            continue;
        } else if not_valid_before > now {
            continue; // Skip certificates that are not yet valid
        }

        let secret = match cert.private_key.secret().await {
            Ok(secret) => secret.into_owned().into_bytes(),
            Err(err) => {
                bp.build_error(
                    obj_id,
                    format!("Failed to obtain private key secret: {err}"),
                );
                continue;
            }
        };
        let public = match public {
            Some(public) => public,
            None => match cert.certificate.value().await {
                Ok(value) => value.into_owned().into_bytes(),
                Err(err) => {
                    bp.build_error(obj_id, format!("Failed to obtain certificate value: {err}"));
                    continue;
                }
            },
        };

        if let Some((not_valid_after, not_valid_before, issuer, sans)) = refreshed_meta {
            let old = Object {
                inner: cert.clone().into(),
                revision,
            };
            cert.not_valid_after = not_valid_after;
            cert.not_valid_before = not_valid_before;
            cert.issuer = issuer;
            cert.subject_alternative_names = sans;
            let new = Object {
                inner: cert.clone().into(),
                revision,
            };
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::update(obj_id.id(), &new, &old))
                .await
            {
                trc::error!(
                    err.details("Failed to refresh TLS certificate metadata in registry.")
                        .caused_by(trc::location!())
                );
            }
        }

        // Add default certificate
        if system
            .default_certificate_id
            .as_ref()
            .is_some_and(|id| *id == obj_id.id())
        {
            cert.subject_alternative_names
                .push_unchecked("*".to_string());
        }

        // Ensure that the most up-to-date certificate is used
        cert.subject_alternative_names.inner_mut().retain(|name| {
            if certs_expirations
                .get(name)
                .is_none_or(|expires| *expires < not_valid_after)
            {
                certs_expirations.insert(name.clone(), not_valid_after);
                true
            } else {
                false
            }
        });

        match build_certified_key(public, secret) {
            Ok(key) => {
                // Add certificates
                let key = Arc::new(key);
                for name in cert.subject_alternative_names.into_inner() {
                    subject_names.insert(name.as_str().into());
                    certificates.insert(
                        name.strip_prefix("*.")
                            .map(Into::into)
                            .unwrap_or_else(|| name.into_boxed_str()),
                        key.clone(),
                    );
                }
            }
            Err(err) => {
                bp.build_error(obj_id, format!("Invalid certificate: {err}"));
            }
        }
    }

    // inbuxa: K-C8, certificates kept in mounted directories, not in the store
    for (cert_path, key_path) in certificate_dir_files() {
        let read = async {
            let public = tokio::fs::read(&cert_path)
                .await
                .map_err(|err| format!("{}: {err}", cert_path.display()))?;
            let secret = tokio::fs::read(&key_path)
                .await
                .map_err(|err| format!("{}: {err}", key_path.display()))?;
            let parsed = ParsedCert::parse(&public)
                .map_err(|err| format!("{}: {err}", cert_path.display()))?;
            Ok::<_, String>((public, secret, parsed))
        };
        let (public, secret, parsed) = match read.await {
            Ok(read) => read,
            Err(err) => {
                bp.build_error(
                    ObjectType::Certificate.singleton(),
                    format!(
                        "Failed to read the certificate in INBUXA_{CERTIFICATE_DIRS_VAR}: {err}"
                    ),
                );
                continue;
            }
        };
        let not_valid_after = parsed.valid_not_after.timestamp();
        if not_valid_after <= now || parsed.valid_not_before.timestamp() > now {
            bp.build_error(
                ObjectType::Certificate.singleton(),
                format!(
                    "The certificate in {} is not valid now (from {} to {})",
                    cert_path.display(),
                    parsed.valid_not_before,
                    parsed.valid_not_after
                ),
            );
            continue;
        }
        let mut names = parsed.sans;
        names.retain(|name| {
            if certs_expirations
                .get(name)
                .is_none_or(|expires| *expires < not_valid_after)
            {
                certs_expirations.insert(name.clone(), not_valid_after);
                true
            } else {
                false
            }
        });
        match build_certified_key(public, secret) {
            Ok(key) => {
                let key = Arc::new(key);
                for name in names {
                    subject_names.insert(name.as_str().into());
                    certificates.insert(
                        name.strip_prefix("*.")
                            .map(Into::into)
                            .unwrap_or_else(|| name.into_boxed_str()),
                        key.clone(),
                    );
                }
            }
            Err(err) => {
                bp.build_error(
                    ObjectType::Certificate.singleton(),
                    format!("Invalid certificate in {}: {err}", cert_path.display()),
                );
            }
        }
    }

    // inbuxa: K-C10: when the first name served runs out, for an alert that
    // warns before a renewal that isn't happening matters
    trc::Collector::update_gauge(
        trc::MetricType::TlsEarliestExpiry,
        certs_expirations
            .iter()
            .filter(|(name, _)| name.as_str() != "*")
            .map(|(_, expires)| (*expires).max(0) as u64)
            .min()
            .unwrap_or_default(),
    );

    // No default certificate set: pick one now, once per load, so handshakes
    // without SNI or for an unknown name get a predictable certificate.
    if !certificates.contains_key("*") && certificates.len() > 1 {
        let (key, covers_hostname) =
            fallback_default_certificate(certificates, &system.default_hostname);
        if !covers_hostname {
            trc::event!(
                Tls(trc::TlsEvent::MultipleCertificatesAvailable),
                Total = certificates.len(),
                Hostname = system.default_hostname.clone(),
            );
        }
        if let Some(key) = key {
            certificates.insert("*".into(), key);
        }
    }

    // Remove expired certificates
    if !certs_expired.is_empty() {
        for (id, sans, object) in certs_expired {
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::delete_object(id, &object))
                .await
            {
                trc::error!(
                    err.details("Failed to delete expired TLS certificate from registry.")
                        .caused_by(trc::location!())
                );
            } else {
                trc::event!(
                    Tls(trc::TlsEvent::ExpiredCertificateRemoved),
                    Details = sans
                );
            }
        }
    }
}

/// The certificate to use when no default is set: the one for the server's
/// hostname (exact, then a wildcard on its parent domain), otherwise the one
/// whose name sorts first, so the choice doesn't depend on hash-map order.
/// The flag says whether the hostname was covered.
pub(crate) fn fallback_default_certificate<T: Clone>(
    certificates: &AHashMap<Box<str>, T>,
    hostname: &str,
) -> (Option<T>, bool) {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if !hostname.is_empty()
        && let Some(cert) = certificates.get(hostname.as_str()).or_else(|| {
            hostname
                .split_once('.')
                .and_then(|(_, domain)| certificates.get(domain))
        })
    {
        return (Some(cert.clone()), true);
    }
    (
        certificates
            .iter()
            .filter(|(name, _)| name.as_ref() != "*")
            .min_by(|a, b| a.0.cmp(b.0))
            .map(|(_, cert)| cert.clone()),
        false,
    )
}

pub(crate) fn build_certified_key(
    cert: Vec<u8>,
    pk_bytes: Vec<u8>,
) -> Result<CertifiedKey, String> {
    let mut pk = None;
    for item in read_all(&mut Cursor::new(pk_bytes)) {
        match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            Item::Pkcs8Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs8(key));
                break;
            }
            Item::Pkcs1Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs1(key));
                break;
            }
            Item::Sec1Key(key) => {
                pk = Some(PrivateKeyDer::Sec1(key));
                break;
            }
            _ => continue, // Skip certificates, DH params, etc.
        }
    }
    let pk = pk.ok_or_else(|| "No private keys found.".to_string())?;
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates: {err}"))?;

    if !cert.is_empty() {
        Ok(CertifiedKey {
            cert,
            key: any_supported_type(&pk)
                .map_err(|err| format!("Failed to sign certificate: {err}",))?,
            ocsp: None,
        })
    } else {
        Err("No certificates found.".to_string())
    }
}

pub(crate) fn build_self_signed_cert(
    domains: impl Into<Vec<String>>,
) -> Result<CertifiedKey, String> {
    let domains = domains
        .into()
        .into_iter()
        .map(|domain| {
            if domain.is_ascii() {
                domain
            } else {
                idna::domain_to_ascii(&domain).unwrap_or(domain)
            }
        })
        .collect::<Vec<_>>();
    let rcgen::CertifiedKey { cert, signing_key } = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.pem().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::fallback_default_certificate;
    use ahash::AHashMap;

    fn certs(names: &[(&str, u32)]) -> AHashMap<Box<str>, u32> {
        names
            .iter()
            .map(|(name, id)| (Box::<str>::from(*name), *id))
            .collect()
    }

    #[test]
    fn fallback_prefers_the_server_hostname() {
        let map = certs(&[("a.example.org", 1), ("mail.example.com", 2), ("z.test", 3)]);
        assert_eq!(
            fallback_default_certificate(&map, "mail.example.com"),
            (Some(2), true)
        );
        assert_eq!(
            fallback_default_certificate(&map, "MAIL.example.com."),
            (Some(2), true)
        );
    }

    #[test]
    fn fallback_uses_a_wildcard_on_the_hostname_domain() {
        // A "*.example.com" SAN is stored under "example.com".
        let map = certs(&[("a.example.org", 1), ("example.com", 2)]);
        assert_eq!(
            fallback_default_certificate(&map, "mail.example.com"),
            (Some(2), true)
        );
    }

    #[test]
    fn fallback_without_a_match_is_the_same_every_time() {
        let names: Vec<(String, u32)> = (0..64).map(|i| (format!("d{i:02}.test"), i)).collect();
        for _ in 0..20 {
            let map: AHashMap<Box<str>, u32> = names
                .iter()
                .map(|(n, i)| (Box::<str>::from(n.as_str()), *i))
                .collect();
            assert_eq!(
                fallback_default_certificate(&map, "mail.other.net"),
                (Some(0), false)
            );
            assert_eq!(fallback_default_certificate(&map, ""), (Some(0), false));
        }
    }
}
