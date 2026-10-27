/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::jose::{account_thumbprint, decode_account_key};
use super::order::qualify_hostname;
use crate::network::acme::{AcmeError, AcmeResult, Challenge, DirectoryMeta};
use aws_lc_rs::digest::{Context, SHA256};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::schema::structs::AcmeProvider;
use reqwest::Url;
use std::collections::BTreeMap;

pub const MAX_ISSUER_DOMAIN_NAMES: usize = 10;
const MAX_CAA_IDENTITIES: usize = 32;
const MAX_DOMAIN_NAME_LEN: usize = 253;
const HASH_ALGORITHM: &str = "sha-256";
const WILDCARD_POLICY: &str = "; policy=wildcard";

pub struct PersistRecordBuilder<'x> {
    issuer: &'x str,
    prefix: &'x str,
    thumbprint: String,
    account_url: &'x str,
}

pub fn normalize_domain_name(name: &str) -> Option<String> {
    let name = name.trim();
    let name = name.strip_suffix('.').unwrap_or(name);
    idna::domain_to_ascii(name)
        .ok()
        .filter(|name| !name.is_empty() && name.len() <= MAX_DOMAIN_NAME_LEN)
}

fn normalize_domain_names(names: &mut Vec<String>, max_names: usize) {
    let is_valid = names.len() <= max_names
        && names
            .iter_mut()
            .all(|name| match normalize_domain_name(name) {
                Some(normalized) => {
                    *name = normalized;
                    true
                }
                None => false,
            });
    if !is_valid {
        names.clear();
    }
}

impl DirectoryMeta {
    pub(crate) fn normalize(&mut self) {
        normalize_domain_names(&mut self.issuer_domain_names, MAX_ISSUER_DOMAIN_NAMES);
        normalize_domain_names(&mut self.caa_identities, MAX_CAA_IDENTITIES);
        self.account_hash_prefix = self
            .account_hash_prefix
            .take()
            .filter(|prefix| !prefix.trim().is_empty() && Url::parse(prefix.trim()).is_ok())
            .map(|prefix| prefix.trim().to_string());
    }

    pub fn require_persist_support(&self) -> AcmeResult<()> {
        if self.account_hash_prefix.is_none() || self.issuer_domain_names.is_empty() {
            Err(AcmeError::Invalid(
                "The ACME server does not support DNS-PERSIST-01: its directory does not advertise both accountHashPrefix and issuerDomainNames".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn verify_persist_challenge(&self, challenge: &Challenge) -> AcmeResult<()> {
        self.require_persist_support()?;
        let offered = &challenge.issuer_domain_names;
        if offered.is_empty() || offered.len() > MAX_ISSUER_DOMAIN_NAMES {
            return Err(AcmeError::Invalid(format!(
                "Malformed dns-persist-01 challenge: expected between 1 and {MAX_ISSUER_DOMAIN_NAMES} issuer domain names, found {}",
                offered.len()
            )));
        }
        let mut normalized = Vec::with_capacity(offered.len());
        for name in offered {
            normalized.push(normalize_domain_name(name).ok_or_else(|| {
                AcmeError::Invalid(format!(
                    "Malformed dns-persist-01 challenge: invalid issuer domain name {name:?}"
                ))
            })?);
        }
        if let Some(missing) = self
            .issuer_domain_names
            .iter()
            .find(|name| !normalized.contains(name))
        {
            return Err(AcmeError::Invalid(format!(
                "Malformed dns-persist-01 challenge: directory issuer domain name {missing:?} is not offered by the challenge"
            )));
        }
        if !self.caa_identities.is_empty()
            && let Some(undisclosed) = normalized
                .iter()
                .find(|name| !self.caa_identities.contains(name))
        {
            return Err(AcmeError::Invalid(format!(
                "Malformed dns-persist-01 challenge: issuer domain name {undisclosed:?} is not listed in the directory CAA identities"
            )));
        }
        Ok(())
    }
}

impl<'x> PersistRecordBuilder<'x> {
    pub fn new(provider: &'x AcmeProvider) -> AcmeResult<Self> {
        let (Some(issuer), Some(prefix)) = (
            provider.issuer_domain_names.as_slice().first(),
            provider.account_hash_prefix.as_deref(),
        ) else {
            return Err(AcmeError::Invalid(format!(
                "ACME provider {} does not advertise both accountHashPrefix and issuerDomainNames, DNS-PERSIST-01 records cannot be built",
                provider.directory
            )));
        };
        Ok(Self {
            issuer,
            prefix,
            thumbprint: account_thumbprint(&decode_account_key(&provider.account_key)?)?,
            account_url: &provider.account_uri,
        })
    }

    pub fn build(&self, fqdn: &str, wildcard: bool) -> Option<String> {
        let mut record = String::with_capacity(160);
        record.push_str(self.issuer);
        record.push_str("; accounturi=");
        record.push_str(self.prefix);
        record.push_str(HASH_ALGORITHM);
        record.push('/');
        URL_SAFE_NO_PAD.encode_append(
            account_hash(
                &normalize_domain_name(fqdn)?,
                &self.thumbprint,
                self.account_url,
            )?,
            &mut record,
        );
        if wildcard {
            record.push_str(WILDCARD_POLICY);
        }
        Some(record)
    }
}

fn account_hash(domain: &str, thumbprint: &str, account_url: &str) -> Option<impl AsRef<[u8]>> {
    let domain_len = u8::try_from(domain.len()).ok()?;
    let mut context = Context::new(&SHA256);
    context.update(&[domain_len]);
    context.update(domain.as_bytes());
    context.update(thumbprint.as_bytes());
    context.update(account_url.as_bytes());
    Some(context.finish())
}

pub fn persist_validation_names(
    domain: &str,
    subject_alternative_names: &[String],
) -> BTreeMap<String, bool> {
    let mut names = BTreeMap::new();
    let Some(domain) = normalize_domain_name(domain) else {
        return names;
    };
    if subject_alternative_names.is_empty() {
        names.insert(domain, true);
        return names;
    }
    for name in subject_alternative_names {
        let name = qualify_hostname(name, &domain);
        let (base, wildcard) = match name.strip_prefix("*.") {
            Some(base) => (base, true),
            None => (name.as_str(), false),
        };
        let Some(base) = normalize_domain_name(base) else {
            continue;
        };
        if base == domain
            || base
                .strip_suffix(domain.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
        {
            *names.entry(base).or_insert(false) |= wildcard;
        }
    }
    names
}

