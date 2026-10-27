/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Email, Hostname};
use std::net::IpAddr;

const MAX_IP_ADDR_LEN: usize = 45;

#[inline]
pub(crate) fn can_be_ip_addr(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_IP_ADDR_LEN {
        return false;
    }
    match bytes.first() {
        Some(b':') => true,
        Some(byte) if byte.is_ascii_digit() => true,
        Some(byte) if byte.is_ascii_hexdigit() => bytes.contains(&b':'),
        _ => false,
    }
}

#[inline]
fn ip_candidate(fqdn: &str) -> Option<&str> {
    let text = fqdn
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(fqdn);

    can_be_ip_addr(text).then_some(text)
}

fn decode_punycode(fqdn: &str) -> String {
    let mut decoded = String::with_capacity(fqdn.len());

    for part in fqdn.split('.') {
        if !decoded.is_empty() {
            decoded.push('.');
        }

        if let Some(puny) = part
            .strip_prefix("xn--")
            .and_then(idna::punycode::decode_to_string)
            .filter(|puny| idna::domain_to_ascii(puny).is_ok_and(|reencoded| reencoded == part))
        {
            decoded.push_str(&puny);
        } else {
            decoded.push_str(part);
        }
    }

    decoded
}

fn second_level_domain(fqdn: &str) -> Option<String> {
    psl::domain(fqdn.as_bytes()).and_then(|domain| {
        if domain.suffix().typ().is_some() {
            std::str::from_utf8(domain.as_bytes()).ok().map(Into::into)
        } else {
            None
        }
    })
}

impl Hostname {
    pub fn new(host: &str) -> Self {
        Hostname::from_lowercase(host.trim_end_matches('.').to_lowercase())
    }

    fn from_lowercase(mut fqdn: String) -> Self {
        if fqdn.contains("xn--") {
            fqdn = decode_punycode(&fqdn);
        }

        let ip = ip_candidate(&fqdn).and_then(|text| text.parse::<IpAddr>().ok());

        Hostname {
            sld: if ip.is_none() {
                second_level_domain(&fqdn)
            } else {
                None
            },
            ip,
            fqdn,
        }
    }

    pub fn sld_or_default(&self) -> &str {
        self.sld.as_deref().unwrap_or(self.fqdn.as_str())
    }
}

impl Email {
    pub fn new(address: &str) -> Self {
        let address = address.to_lowercase();
        let (local_part, domain) = address.rsplit_once('@').unwrap_or((address.as_str(), ""));

        Email {
            local_part: local_part.into(),
            domain_part: Hostname::from_lowercase(domain.trim_end_matches('.').into()),
            address,
        }
    }
}

