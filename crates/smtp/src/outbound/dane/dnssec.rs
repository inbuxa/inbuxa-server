/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: the lookups themselves are in inbuxa-outbound-tls, shared with
// inbuxa-relay (RL-30); this adds the server's caches and test mocks.

use common::Server;
use inbuxa_outbound_tls::dnssec::{self, Resolvers};
pub use inbuxa_outbound_tls::dnssec::{DnssecStatus, TlsaResult, least_secure};
use mail_auth::{MX, RecordSet, common::resolver::ToFqdn};
use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
};

pub trait TlsaLookup: Sync + Send {
    fn mx_lookup(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<RecordSet<MX>>> + Send;

    fn tlsa_lookup(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<TlsaResult>> + Send;

    fn ipv4_lookup_dnssec(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<RecordSet<Ipv4Addr>>> + Send;

    fn ipv6_lookup_dnssec(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<RecordSet<Ipv6Addr>>> + Send;
}

fn resolvers(server: &Server) -> Resolvers<'_> {
    Resolvers {
        dnssec: &server.core.smtp.resolvers.dnssec.resolver,
        plain: server.core.smtp.resolvers.dns.resolver(),
    }
}

impl TlsaLookup for Server {
    async fn mx_lookup(&self, key: impl ToFqdn + Sync + Send) -> mail_auth::Result<RecordSet<MX>> {
        if !self.core.smtp.resolvers.dnssec_available {
            return self
                .core
                .smtp
                .resolvers
                .dns
                .mx_lookup(key, Some(&self.inner.cache.dns_mx))
                .await;
        }

        let key = key.to_fqdn().into_owned().into_boxed_str();
        if let Some(value) = self.inner.cache.dns_mx.get::<str>(key.as_ref())
            && value.dnssec_status != DnssecStatus::Indeterminate
        {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let (records, valid_until) = dnssec::mx(&resolvers(self), key.as_ref()).await?;
        if let Some(valid_until) = valid_until {
            self.inner
                .cache
                .dns_mx
                .insert_with_expiry(key, records.clone(), valid_until);
        }

        Ok(records)
    }

    async fn tlsa_lookup(&self, key: impl ToFqdn + Sync + Send) -> mail_auth::Result<TlsaResult> {
        let key = key.to_fqdn().into_owned().into_boxed_str();
        if let Some(value) = self.inner.cache.dns_tlsa.get(key.as_ref()) {
            return Ok(TlsaResult::Secure(value));
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            if key.as_ref().contains("_dnssec_bogus.") {
                return Ok(TlsaResult::Bogus);
            }
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let (result, valid_until) = dnssec::tlsa(&resolvers(self), key.as_ref()).await?;
        if let (TlsaResult::Secure(tlsa), Some(valid_until)) = (&result, valid_until) {
            self.inner
                .cache
                .dns_tlsa
                .insert_with_expiry(key, tlsa.clone(), valid_until);
        }

        Ok(result)
    }

    async fn ipv4_lookup_dnssec(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> mail_auth::Result<RecordSet<Ipv4Addr>> {
        if !self.core.smtp.resolvers.dnssec_available {
            return self
                .core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup(key, Some(&self.inner.cache.dns_ipv4))
                .await;
        }

        let key = key.to_fqdn().into_owned().into_boxed_str();
        if let Some(value) = self.inner.cache.dns_ipv4.get::<str>(key.as_ref())
            && value.dnssec_status != DnssecStatus::Indeterminate
        {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let (records, valid_until) = dnssec::ipv4(&resolvers(self), key.as_ref()).await?;
        if let Some(valid_until) = valid_until {
            self.inner
                .cache
                .dns_ipv4
                .insert_with_expiry(key, records.clone(), valid_until);
        }

        Ok(records)
    }

    async fn ipv6_lookup_dnssec(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> mail_auth::Result<RecordSet<Ipv6Addr>> {
        if !self.core.smtp.resolvers.dnssec_available {
            return self
                .core
                .smtp
                .resolvers
                .dns
                .ipv6_lookup(key, Some(&self.inner.cache.dns_ipv6))
                .await;
        }

        let key = key.to_fqdn().into_owned().into_boxed_str();
        if let Some(value) = self.inner.cache.dns_ipv6.get::<str>(key.as_ref())
            && value.dnssec_status != DnssecStatus::Indeterminate
        {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let (records, valid_until) = dnssec::ipv6(&resolvers(self), key.as_ref()).await?;
        if let Some(valid_until) = valid_until {
            self.inner
                .cache
                .dns_ipv6
                .insert_with_expiry(key, records.clone(), valid_until);
        }

        Ok(records)
    }
}
