/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! HTTP requests to URLs that outsiders choose (push subscription endpoints,
//! TLS-RPT `rua=` URIs, MTA-STS policy hosts, URL shorteners found in mail)
//! may only reach public addresses. A host name is checked when it resolves,
//! so a name that answers with a loopback, private or link-local address
//! can't reach inside the network, and neither can a redirect or a later
//! re-resolution. IP literals don't resolve, so callers check them with
//! [`has_public_host`] before sending.

use super::is_global_ip;
use reqwest::{
    ClientBuilder, Url,
    dns::{Addrs, Name, Resolve, Resolving},
};
use std::net::IpAddr;

pub trait PublicOnly {
    /// Connect only to public addresses, and never through a proxy (which
    /// would resolve the name itself, out of our sight).
    fn public_only(self) -> Self;
}

impl PublicOnly for ClientBuilder {
    fn public_only(self) -> Self {
        self.no_proxy().dns_resolver(PublicResolver)
    }
}

struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|addr| is_global_ip(&addr.ip()))
                .collect::<Vec<_>>();

            if !addrs.is_empty() {
                Ok(Box::new(addrs.into_iter()) as Addrs)
            } else {
                Err(format!("{} has no public address", name.as_str()).into())
            }
        })
    }
}

/// False when the URL's host is an IP literal that isn't public, or is
/// missing. Host names pass here and are checked when they resolve.
pub fn has_public_host(url: &str) -> bool {
    let Some(host) = Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
    else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&host);

    match host.parse::<IpAddr>() {
        // The test harness serves push and reports on 127.0.0.1;
        // loopback host names are still refused when they resolve.
        #[cfg(feature = "test_mode")]
        Ok(ip) if ip.is_loopback() => true,
        Ok(ip) => is_global_ip(&ip),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicOnly, has_public_host};
    use std::time::Duration;

    #[test]
    fn ip_literal_hosts() {
        for url in [
            "https://127.0.0.1/push",
            "https://10.1.2.3:8443/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[::ffff:192.168.0.1]/",
            "https://[fd00::1]/",
            "not a url",
        ] {
            assert!(!has_public_host(url), "{url}");
        }

        for url in [
            "https://8.8.8.8/",
            "https://[2606:4700::1111]/",
            "https://push.example.com/",
            "https://localhost/",
        ] {
            assert!(has_public_host(url), "{url}");
        }
    }

    #[tokio::test]
    async fn names_resolving_to_local_addresses_are_not_reached() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = reqwest::Client::builder().public_only().build().unwrap();

        let result = client
            .get(format!("http://localhost:{port}/"))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        assert!(result.is_err(), "{result:?}");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "a connection reached the loopback listener"
        );
    }
}
