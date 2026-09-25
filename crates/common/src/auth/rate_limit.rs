/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::auth::AccessToken;
use crate::network::ip_to_bytes;
use crate::network::limiter::{InFlight, LimiterResult};
use crate::{KV_RATE_LIMIT_HTTP_ANONYMOUS, KV_RATE_LIMIT_HTTP_AUTHENTICATED, Server};
use registry::schema::enums::Permission;
use std::net::IpAddr;
use trc::AddContext;

impl Server {
    pub async fn is_http_authenticated_request_allowed(
        &self,
        access_token: &AccessToken,
        addr: IpAddr,
    ) -> trc::Result<Option<InFlight>> {
        // inbuxa: an account with unlimited requests passes both limits
        // below anyway, so don't count its requests. The count is a write to
        // one counter per account in the in-memory store, and concurrent
        // requests from one account queue on that key (a row lock on SQL,
        // conflict retries on RocksDB): in a cluster rehearsal ten parallel
        // admin writes were accepted one after another, about 33 ms apart.
        if access_token.has_permission(Permission::UnlimitedRequests) {
            return Ok(None);
        }

        let rate_reset = if let Some(rate) = &self.core.network.http.rate_authenticated {
            if self.is_ip_allowed(addr) {
                None
            } else {
                self.core
                    .storage
                    .memory
                    .is_rate_allowed(
                        KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                        &access_token.account_id().to_be_bytes(),
                        rate,
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?
                    .map(|reset| (reset, rate.count))
            }
        } else {
            None
        };

        if let Some((reset, count)) = rate_reset {
            if access_token.has_permission(Permission::UnlimitedRequests) {
                Ok(None)
            } else {
                Err(trc::LimitEvent::TooManyRequests
                    .into_err()
                    .ctx(trc::Key::Expires, reset)
                    .ctx(trc::Key::Limit, count))
            }
        } else {
            match access_token.is_http_request_allowed() {
                LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
                LimiterResult::Forbidden => {
                    if access_token.has_permission(Permission::UnlimitedRequests) {
                        Ok(None)
                    } else {
                        Err(trc::LimitEvent::ConcurrentRequest
                            .into_err()
                            .ctx(trc::Key::Limit, access_token.concurrent_http_requests()))
                    }
                }
                LimiterResult::Disabled => Ok(None),
            }
        }
    }

    pub async fn is_http_anonymous_request_allowed(&self, addr: IpAddr) -> trc::Result<()> {
        if let Some(rate) = &self.core.network.http.rate_anonymous
            && !self.is_ip_allowed(addr)
            && let Some(reset) = self
                .core
                .storage
                .memory
                .is_rate_allowed(
                    KV_RATE_LIMIT_HTTP_ANONYMOUS,
                    &ip_to_bytes(&addr),
                    rate,
                    false,
                )
                .await
                .caused_by(trc::location!())?
        {
            return Err(trc::LimitEvent::TooManyRequests
                .into_err()
                .ctx(trc::Key::Expires, reset)
                .ctx(trc::Key::Limit, rate.count));
        }
        Ok(())
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> trc::Result<Option<InFlight>> {
        match access_token.is_upload_allowed() {
            LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
            LimiterResult::Forbidden => {
                if access_token.has_permission(Permission::UnlimitedRequests) {
                    Ok(None)
                } else {
                    Err(trc::LimitEvent::ConcurrentUpload
                        .into_err()
                        .ctx(trc::Key::Limit, access_token.concurrent_uploads()))
                }
            }
            LimiterResult::Disabled => Ok(None),
        }
    }
}
