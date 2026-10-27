/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(stalwart_tests)]
pub static STS_TEST_POLICY: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

use common::{
    Server,
    config::smtp::resolver::{CachedPolicy, MtaStsEntry, MtaStsFailure, MtaStsFailureKind, Policy},
};
use compact_str::CompactString;
use mail_auth::mta_sts::MtaStsRecord;
use smtp_report::tlsrpt::FailureType;
use trc::MtaStsEvent;
use utils::outbound::OutboundError;

use super::{Error, parse::ParsePolicy};

#[cfg(not(stalwart_tests))]
use reqwest::Method;
#[cfg(not(stalwart_tests))]
use utils::HttpLimitResponse;

const FETCH_RETRY_INTERVAL: Duration = Duration::from_secs(300);
const FETCH_IN_PROGRESS: &str = "Policy fetch in progress.";
const MAX_REASON_LEN: usize = 256;

#[cfg(not(stalwart_tests))]
const MAX_POLICY_SIZE: usize = 1024 * 1024;

pub trait MtaStsLookup: Sync + Send {
    fn lookup_mta_sts_policy(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Arc<Policy>, Error>> + Send;
}

#[allow(unused_variables)]
impl MtaStsLookup for Server {
    async fn lookup_mta_sts_policy(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> Result<Arc<Policy>, Error> {
        let cache = &self.inner.cache.dns_mta_sts;

        // Lookup MTA-STS TXT record
        let record = match self
            .core
            .smtp
            .resolvers
            .dns
            .txt_lookup::<MtaStsRecord>(
                format!("_mta-sts.{domain}."),
                Some(&self.inner.cache.dns_txt),
            )
            .await
        {
            Ok(record) => record,
            Err(err) => {
                // Return the cached policy in case of failure
                return cache
                    .get(domain)
                    .and_then(|entry| {
                        entry
                            .fallback(Instant::now())
                            .map(|cached| cached.policy.clone())
                    })
                    .ok_or_else(|| err.into());
            }
        };

        // Check if the policy or a failed fetch has been cached
        let entry = match cache.get(domain) {
            Some(entry) => Ok(entry),
            None => {
                cache
                    .get_value_or_guard_async(&Box::<str>::from(domain))
                    .await
            }
        };
        let (fallback, guard) = match entry {
            Ok(entry) => {
                let now = Instant::now();
                match entry.policy_for(&record.id, now) {
                    Some(Ok(policy)) => return Ok(policy),
                    Some(Err(failure)) => return Err(Error::Backoff(failure)),
                    None => {
                        let fallback = entry.fallback(now).cloned();
                        if let Some(cached) = &fallback {
                            let retry_after = now + FETCH_RETRY_INTERVAL;
                            cache.insert_with_expiry(
                                domain.into(),
                                MtaStsEntry::Failed(Arc::new(MtaStsFailure {
                                    id: record.id.as_str().into(),
                                    kind: MtaStsFailureKind::TemporaryFetchError,
                                    reason: FETCH_IN_PROGRESS.into(),
                                    retry_after,
                                    fallback: Some(cached.clone()),
                                })),
                                cached.expires.max(retry_after),
                            );
                        }
                        (fallback, None)
                    }
                }
            }
            Err(guard) => (None, Some(guard)),
        };

        // Fetch policy
        let result: Result<Policy, Error> = async {
            #[cfg(not(stalwart_tests))]
            let bytes = self
                .core
                .smtp
                .mta_sts_client
                .request(
                    Method::GET,
                    &format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"),
                )?
                .timeout(timeout)
                .send()
                .await?
                .bytes_with_limit(MAX_POLICY_SIZE)
                .await?
                .ok_or_else(|| Error::InvalidPolicy("Policy too large".to_string()))?;
            #[cfg(stalwart_tests)]
            let bytes = STS_TEST_POLICY.lock().clone();

            Ok(Policy::parse(
                std::str::from_utf8(&bytes).map_err(|err| Error::InvalidPolicy(err.to_string()))?,
                record.id.clone(),
            )?)
        }
        .await;

        let (entry, expires, result) = match result {
            Ok(policy) => {
                let policy = Arc::new(policy);
                let expires = Instant::now()
                    + Duration::from_secs(if (3600..31557600).contains(&policy.max_age) {
                        policy.max_age
                    } else {
                        86400
                    });
                (
                    MtaStsEntry::Policy(CachedPolicy {
                        policy: policy.clone(),
                        expires,
                    }),
                    expires,
                    Ok(policy),
                )
            }
            Err(err) => {
                let retry_after = Instant::now() + FETCH_RETRY_INTERVAL;
                let expires = fallback
                    .as_ref()
                    .map_or(retry_after, |cached| cached.expires.max(retry_after));
                let kind = err.failure_kind();
                let mut reason = err.to_string();
                reason.truncate(reason.floor_char_boundary(MAX_REASON_LEN));
                let cached = fallback.as_ref().map(|cached| cached.policy.clone());
                if cached.is_some() {
                    trc::event!(
                        MtaSts(if kind == MtaStsFailureKind::InvalidPolicy {
                            MtaStsEvent::InvalidPolicy
                        } else {
                            MtaStsEvent::PolicyFetchError
                        }),
                        Domain = CompactString::from(domain),
                        Reason = reason.clone(),
                        Details = "Applying the cached policy",
                    );
                }
                let entry = MtaStsEntry::Failed(Arc::new(MtaStsFailure {
                    id: record.id.as_str().into(),
                    kind,
                    reason: reason.into_boxed_str(),
                    retry_after,
                    fallback,
                }));
                (entry, expires, cached.ok_or(err))
            }
        };

        match guard {
            Some(guard) => guard.insert_with_expiry(entry, expires),
            None if matches!(entry, MtaStsEntry::Failed(_))
                && matches!(
                    cache.get(domain),
                    Some(MtaStsEntry::Policy(cached)) if cached.policy.id == record.id
                ) => {}
            None => cache.insert_with_expiry(domain.into(), entry, expires),
        }

        result
    }
}

impl Error {
    fn failure_kind(&self) -> MtaStsFailureKind {
        match self {
            Error::InvalidPolicy(_) => MtaStsFailureKind::InvalidPolicy,
            Error::Destination(_) => MtaStsFailureKind::PermanentFetchError,
            Error::Http(err)
                if err.is_status() && err.status() == Some(reqwest::StatusCode::NOT_FOUND) =>
            {
                MtaStsFailureKind::PermanentFetchError
            }
            Error::Backoff(failure) => failure.kind,
            Error::Http(_) | Error::Dns(_) => MtaStsFailureKind::TemporaryFetchError,
        }
    }
}

impl From<&Error> for FailureType {
    fn from(err: &Error) -> Self {
        match err.failure_kind() {
            MtaStsFailureKind::InvalidPolicy => FailureType::StsPolicyInvalid,
            MtaStsFailureKind::TemporaryFetchError | MtaStsFailureKind::PermanentFetchError => {
                FailureType::StsPolicyFetchError
            }
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Dns(err) => match err {
                mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code)) => {
                    write!(f, "Record not found: {code:?}")
                }
                mail_auth::Error::Dns(mail_auth::DnsError::InvalidRecordType) => {
                    f.write_str("Failed to parse MTA-STS DNS record.")
                }
                _ => write!(f, "DNS lookup error: {err}"),
            },
            Error::Http(err) => {
                if err.is_timeout() {
                    f.write_str("Timeout fetching policy.")
                } else if err.is_connect() {
                    f.write_str("Could not reach policy host.")
                } else if err.is_status() && (err.status() == Some(reqwest::StatusCode::NOT_FOUND))
                {
                    f.write_str("Policy not found.")
                } else {
                    f.write_str("Failed to fetch policy.")
                }
            }
            Error::Destination(err) => write!(f, "Policy host rejected: {err}"),
            Error::InvalidPolicy(err) => write!(f, "Failed to parse policy: {err}"),
            Error::Backoff(failure) => f.write_str(&failure.reason),
        }
    }
}

impl From<mail_auth::Error> for Error {
    fn from(value: mail_auth::Error) -> Self {
        Error::Dns(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Http(value)
    }
}

impl From<OutboundError> for Error {
    fn from(value: OutboundError) -> Self {
        Error::Destination(value)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::InvalidPolicy(value)
    }
}
