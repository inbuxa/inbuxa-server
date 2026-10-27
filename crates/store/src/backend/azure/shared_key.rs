/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::hmac;
use azure_core::{
    error::{Error, ErrorKind},
    http::{
        Context, Request,
        headers::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, IF_MATCH, MS_DATE},
        policies::{Policy, PolicyResult},
    },
    time::{OffsetDateTime, to_rfc7231},
};
use encodify::base64::STANDARD;
use std::{borrow::Cow, fmt, fmt::Write, future::Future, pin::Pin, sync::Arc};
use tinyvec::TinyVec;

const CANONICAL_HEADER_PREFIX: &str = "x-ms-";
const SIGNED_HEADERS_BEFORE_LENGTH: [HeaderName; 2] = [
    HeaderName::from_static("content-encoding"),
    HeaderName::from_static("content-language"),
];
const SIGNED_HEADERS_AFTER_LENGTH: [HeaderName; 8] = [
    HeaderName::from_static("content-md5"),
    CONTENT_TYPE,
    HeaderName::from_static("date"),
    HeaderName::from_static("if-modified-since"),
    IF_MATCH,
    HeaderName::from_static("if-none-match"),
    HeaderName::from_static("if-unmodified-since"),
    HeaderName::from_static("range"),
];

pub(super) struct SharedKeyPolicy {
    account: Box<str>,
    key: hmac::Key,
}

impl SharedKeyPolicy {
    pub(super) fn new(account: &str, account_key: &str) -> Result<Self, String> {
        let key = STANDARD
            .decode(account_key.trim())
            .map_err(|err| format!("Invalid Azure storage account key: {err}"))?;
        Ok(Self {
            account: account.into(),
            key: hmac::Key::new(hmac::HMAC_SHA256, &key),
        })
    }

    fn string_to_sign(&self, request: &Request) -> String {
        let headers = request.headers();
        let url = request.url();
        let mut out = String::with_capacity(256 + url.path().len());

        out.push_str(request.method().as_str());
        out.push('\n');
        for name in &SIGNED_HEADERS_BEFORE_LENGTH {
            out.push_str(headers.get_optional_str(name).unwrap_or_default());
            out.push('\n');
        }
        match headers.get_optional_str(&CONTENT_LENGTH) {
            Some("0") | None => {
                if let Some(len) = request.body().len().filter(|len| *len > 0) {
                    let _ = write!(out, "{len}");
                }
            }
            Some(len) => out.push_str(len),
        }
        out.push('\n');
        for name in &SIGNED_HEADERS_AFTER_LENGTH {
            out.push_str(headers.get_optional_str(name).unwrap_or_default());
            out.push('\n');
        }

        let mut ms_headers: TinyVec<[(&str, &str); 16]> = headers
            .iter()
            .filter(|(name, _)| name.as_str().starts_with(CANONICAL_HEADER_PREFIX))
            .map(|(name, value)| (name.as_str(), value.as_str().trim()))
            .collect();
        ms_headers.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (name, value) in ms_headers {
            out.push_str(name);
            out.push(':');
            out.push_str(value);
            out.push('\n');
        }

        out.push('/');
        out.push_str(&self.account);
        out.push_str(url.path());

        if url.query().is_some_and(|query| !query.is_empty()) {
            let mut params: TinyVec<[(Cow<'_, str>, Cow<'_, str>); 4]> = url
                .query_pairs()
                .map(|(name, value)| {
                    if name.bytes().any(|ch| ch.is_ascii_uppercase()) {
                        (Cow::Owned(name.to_ascii_lowercase()), value)
                    } else {
                        (name, value)
                    }
                })
                .collect();
            params.sort_unstable();
            let mut last_name = None;
            for (name, value) in &params {
                if last_name == Some(name.as_ref()) {
                    out.push(',');
                } else {
                    out.push('\n');
                    out.push_str(name);
                    out.push(':');
                    last_name = Some(name.as_ref());
                }
                out.push_str(value);
            }
        }

        out
    }

    fn authorization(&self, request: &Request) -> String {
        let signature = hmac::sign(&self.key, self.string_to_sign(request).as_bytes());
        let mut out = String::with_capacity(self.account.len() + 56);
        out.push_str("SharedKey ");
        out.push_str(&self.account);
        out.push(':');
        STANDARD.encode_append(signature.as_ref(), &mut out);
        out
    }
}

impl fmt::Debug for SharedKeyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedKeyPolicy")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl Policy for SharedKeyPolicy {
    fn send<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        ctx: &'life1 Context,
        request: &'life2 mut Request,
        next: &'life3 [Arc<dyn Policy>],
    ) -> Pin<Box<dyn Future<Output = PolicyResult> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let [next_policy, rest @ ..] = next else {
                return Err(Error::with_message(
                    ErrorKind::Other,
                    "Shared Key policy must not be the last policy in the pipeline",
                ));
            };
            request.insert_header(MS_DATE, to_rfc7231(&OffsetDateTime::now_utc()));
            let authorization = self.authorization(request);
            request.insert_header(AUTHORIZATION, authorization);
            next_policy.send(ctx, request, rest).await
        })
    }
}

