/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A tenant's own DNS provider may only talk to public addresses.
//!
//! Some providers take an endpoint (cPanel, Plesk, PowerDNS, Infoblox, ...)
//! and RFC 2136 takes a server address, so a tenant administrator could aim
//! the server's DNS updates at a loopback or private service and read
//! something back in the error. Others build their URL from a region or zone
//! name, where a crafted value (`x@10.0.0.1/`) could move the host. For a
//! provider owned by a tenant, endpoints must be HTTPS to names that resolve
//! only to public addresses, an RFC 2136 server must be a public address, and
//! names that go into URLs must be plain names. The server's own providers,
//! which only a server administrator can create, keep any destination:
//! private DNS servers are a normal setup there.
//!
//! This runs each time a provider is saved and each time an updater is built
//! from it, so a name that later moves to a private address is caught at the
//! next use.

use super::super::is_global_ip;
use registry::schema::{prelude::ObjectInner, structs::DnsServer};
use reqwest::Url;
use std::net::IpAddr;

/// The endpoint and URL-name fields of a tenant's provider, or `Ok(())` for
/// a provider the server owns.
pub async fn check_tenant_dns_server(server: &DnsServer) -> Result<(), String> {
    if ObjectInner::DnsServer(server.clone())
        .member_tenant_id()
        .is_none()
    {
        return Ok(());
    }
    let fields = TenantFields::of(server);
    if fields.plain_http {
        return Err("A tenant's DNS provider must use HTTPS (scheme)".to_string());
    }

    for (field, name) in fields.names {
        if !is_plain_name(name) {
            return Err(format!(
                "{field} may only contain letters, digits, '-', '_' and '.'"
            ));
        }
    }
    if let Some(ip) = fields.rfc2136 {
        if !is_global_ip(&ip) {
            return Err(format!(
                "A tenant's DNS server must have a public address, not {ip}"
            ));
        }
    }
    for (field, endpoint) in fields.endpoints {
        check_endpoint(field, endpoint).await?;
    }
    Ok(())
}

#[derive(Default)]
struct TenantFields<'x> {
    endpoints: Vec<(&'static str, &'x str)>,
    names: Vec<(&'static str, &'x str)>,
    rfc2136: Option<IpAddr>,
    plain_http: bool,
}

impl<'x> TenantFields<'x> {
    fn of(server: &'x DnsServer) -> Self {
        let mut fields = TenantFields::default();
        match server {
            DnsServer::Tsig(server) => fields.rfc2136 = Some(server.host.0),
            DnsServer::BluecatV2(server) => fields.endpoints.push(("baseUrl", &server.base_url)),
            DnsServer::Cpanel(server) => fields.endpoints.push(("baseUrl", &server.base_url)),
            DnsServer::Plesk(server) => fields.endpoints.push(("baseUrl", &server.base_url)),
            DnsServer::EdgeDns(server) => fields.endpoints.push(("host", &server.host)),
            DnsServer::Infoblox(server) => fields.endpoints.push(("host", &server.host)),
            DnsServer::PowerDns(server) => {
                fields
                    .endpoints
                    .extend(server.endpoint.as_deref().map(|e| ("endpoint", e)));
                fields
                    .names
                    .extend(server.server_id.as_deref().map(|e| ("serverId", e)));
            }
            DnsServer::UltraDns(server) => {
                fields
                    .endpoints
                    .extend(server.endpoint.as_deref().map(|e| ("endpoint", e)));
            }
            DnsServer::Volcengine(server) => {
                if let Some(host) = server.host.as_deref() {
                    fields.endpoints.push(("host", host));
                }
                fields
                    .names
                    .extend(server.region.as_deref().map(|e| ("region", e)));
                if server
                    .scheme
                    .as_deref()
                    .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("https"))
                {
                    fields.plain_http = true;
                }
            }
            DnsServer::Route53(server) => {
                fields.names.push(("region", &server.region));
                fields.names.extend(
                    server
                        .hosted_zone_id
                        .as_deref()
                        .map(|e| ("hostedZoneId", e)),
                );
            }
            DnsServer::Lightsail(server) => {
                fields
                    .names
                    .extend(server.region.as_deref().map(|e| ("region", e)));
                fields
                    .names
                    .extend(server.domain.as_deref().map(|e| ("domain", e)));
            }
            DnsServer::Alidns(server) => {
                fields
                    .names
                    .extend(server.region.as_deref().map(|e| ("region", e)));
            }
            DnsServer::TencentCloud(server) => {
                fields
                    .names
                    .extend(server.region.as_deref().map(|e| ("region", e)));
            }
            DnsServer::HuaweiCloud(server) => fields.names.push(("region", &server.region)),
            DnsServer::OracleCloud(server) => fields.names.push(("region", &server.region)),
            _ => {}
        }
        fields
    }
}

/// A value that can sit inside a host name or a path segment and not move
/// the host: no '@', ':', '/', '?', '#', '%' or spaces.
fn is_plain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// An endpoint, given as a URL or a bare `host[:port]` (which providers
/// reach over HTTPS), must be HTTPS to a name whose every address is public.
async fn check_endpoint(field: &str, endpoint: &str) -> Result<(), String> {
    let endpoint = endpoint.trim();
    let url = if endpoint.contains("://") {
        Url::parse(endpoint)
    } else {
        Url::parse(&format!("https://{endpoint}"))
    }
    .map_err(|_| format!("{field} is not a valid address"))?;

    if url.scheme() != "https" {
        return Err(format!("A tenant's DNS provider must use HTTPS ({field})"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{field} may not contain credentials"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("{field} has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_global_ip(&ip) {
            Ok(())
        } else {
            Err(format!(
                "A tenant's DNS provider must use a public address ({field})"
            ))
        };
    }

    let addrs =
        tokio::net::lookup_host((host.as_str(), url.port_or_known_default().unwrap_or(443)))
            .await
            .map_err(|_| format!("{field}: {host} does not resolve"))?
            .collect::<Vec<_>>();
    if addrs.is_empty() || addrs.iter().any(|addr| !is_global_ip(&addr.ip())) {
        return Err(format!(
            "A tenant's DNS provider must use a public address ({field}: {host})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names() {
        for ok in [
            "eu-west-1",
            "cn-hangzhou",
            "Z123ABC",
            "example.com",
            "localhost_1",
        ] {
            assert!(is_plain_name(ok), "{ok}");
        }
        for bad in ["", "x@10.0.0.1/", "a/b", "a:1", "a?b", "a#b", "a%2f", "a b"] {
            assert!(!is_plain_name(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn endpoints() {
        for bad in [
            "http://dns.example.com/api",
            "https://127.0.0.1/api",
            "https://10.1.2.3:2083",
            "10.1.2.3:2083",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://169.254.169.254/",
            "https://user:pw@8.8.8.8/",
            "https://localhost/",
            "localhost:8081",
            "ftp://8.8.8.8/",
        ] {
            assert!(check_endpoint("endpoint", bad).await.is_err(), "{bad}");
        }
        for ok in [
            "https://8.8.8.8/api",
            "8.8.8.8:2083",
            "https://[2606:4700::1111]/",
        ] {
            assert!(check_endpoint("endpoint", ok).await.is_ok(), "{ok}");
        }
    }
}
