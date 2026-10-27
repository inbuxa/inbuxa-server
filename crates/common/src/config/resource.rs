/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::{enums::ServiceProtocol, structs::Service};
use reqwest::Url;
use utils::map::vec_map::VecMap;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ResourceIdentifiers {
    pub identifiers: Box<[Box<str>]>,
    pub trusted_hosts: Box<[Box<str>]>,
    pub registrable_domain: Option<Box<str>>,
    pub serves_files: bool,
}

impl ResourceIdentifiers {
    pub fn build(
        url_https: &str,
        services: &VecMap<ServiceProtocol, Service>,
        default_hostname: &str,
    ) -> Self {
        let mut trusted_hosts: Vec<Box<str>> = Vec::with_capacity(services.len() + 1);
        let mut bare_hosts: Vec<Box<str>> = Vec::with_capacity(services.len());
        let mut registrable_domain = None;
        let mut serves_files = false;

        if let Ok(url) = Url::parse(url_https)
            && let Some(host) = url.host_str().filter(|host| !host.is_empty())
        {
            let authority: Box<str> = match url.port() {
                Some(port) => format!("{host}:{port}").into_boxed_str(),
                None => host.into(),
            };
            registrable_domain = url.domain().and_then(psl::domain_str).map(Box::from);
            push_unique(&mut trusted_hosts, authority);
        }

        for (service, details) in services {
            let Some(host) =
                normalize_host(details.hostname.as_deref().unwrap_or(default_hostname))
            else {
                continue;
            };
            serves_files |= matches!(service, ServiceProtocol::Jmap | ServiceProtocol::Webdav);
            match service {
                ServiceProtocol::Jmap
                | ServiceProtocol::Caldav
                | ServiceProtocol::Carddav
                | ServiceProtocol::Webdav => push_unique(&mut trusted_hosts, host),
                ServiceProtocol::Imap
                | ServiceProtocol::Pop3
                | ServiceProtocol::Smtp
                | ServiceProtocol::Managesieve => push_unique(&mut bare_hosts, host),
            }
        }

        let mut identifiers = Vec::with_capacity(trusted_hosts.len() + bare_hosts.len());
        identifiers.extend(
            trusted_hosts
                .iter()
                .map(|host| format!("https://{host}").into_boxed_str()),
        );
        identifiers.extend(bare_hosts);

        ResourceIdentifiers {
            identifiers: identifiers.into_boxed_slice(),
            trusted_hosts: trusted_hosts.into_boxed_slice(),
            registrable_domain,
            serves_files,
        }
    }

    pub fn is_known_resource(&self, resource: &str) -> bool {
        if resource.contains([':', '/']) {
            let Ok(url) = Url::parse(resource) else {
                return false;
            };
            url.scheme() == "https"
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.host_str().is_some_and(|host| {
                    self.trusted_hosts
                        .iter()
                        .any(|trusted| authority_matches(trusted, host, url.port()))
                })
        } else {
            normalize_host(resource).is_some_and(|host| {
                self.identifiers
                    .iter()
                    .filter(|identifier| !identifier.starts_with("https://"))
                    .any(|identifier| identifier.as_ref() == host.as_ref())
            })
        }
    }

    pub fn is_trusted_host(&self, authority: &str) -> bool {
        self.trusted_hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(authority))
    }
}

fn normalize_host(host: &str) -> Option<Box<str>> {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        None
    } else if host.is_ascii() {
        Some(host.to_ascii_lowercase().into_boxed_str())
    } else {
        idna::domain_to_ascii(host).ok().map(String::into_boxed_str)
    }
}

fn authority_matches(trusted: &str, host: &str, port: Option<u16>) -> bool {
    let (Some(trusted_host), Some(trusted_port)) =
        (trusted.get(..host.len()), trusted.get(host.len()..))
    else {
        return false;
    };
    trusted_host.eq_ignore_ascii_case(host)
        && match port {
            Some(port) => trusted_port
                .strip_prefix(':')
                .is_some_and(|trusted_port| trusted_port.parse::<u16>().ok() == Some(port)),
            None => trusted_port.is_empty(),
        }
}

fn push_unique(list: &mut Vec<Box<str>>, value: Box<str>) {
    if !list.contains(&value) {
        list.push(value);
    }
}

