/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Credentials;
use aws_lc_rs::{
    digest::{SHA256, digest},
    hmac::{HMAC_SHA256, Key, sign},
};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE_SCOPE: &str = "/s3/aws4_request";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

pub struct Signer {
    access_key: Box<str>,
    secret_key: Box<[u8]>,
    region: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmzDate([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Hex([u8; 64]);

pub struct CanonicalRequest<'x> {
    pub method: &'x str,
    pub uri: &'x str,
    pub query: &'x str,
    pub headers: &'x [(&'x str, &'x str)],
    pub payload_hash: &'x str,
}

impl Signer {
    pub fn new(credentials: &Credentials, region: &str) -> Self {
        let secret = credentials.secret_key();
        let mut secret_key = Vec::with_capacity(4 + secret.len());
        secret_key.extend_from_slice(b"AWS4");
        secret_key.extend_from_slice(secret.as_bytes());
        Signer {
            access_key: credentials.access_key().into(),
            secret_key: secret_key.into_boxed_slice(),
            region: region.into(),
        }
    }

    pub fn authorization(&self, request: &CanonicalRequest<'_>, date: &AmzDate) -> String {
        let canonical_hash = Sha256Hex::of(request.build().as_bytes());

        let mut string_to_sign = String::with_capacity(
            ALGORITHM.len() + 18 + 9 + self.region.len() + SERVICE_SCOPE.len() + 1 + 64,
        );
        string_to_sign.push_str(ALGORITHM);
        string_to_sign.push('\n');
        string_to_sign.push_str(date.as_str());
        string_to_sign.push('\n');
        self.push_scope(&mut string_to_sign, date);
        string_to_sign.push('\n');
        string_to_sign.push_str(canonical_hash.as_str());

        let signing_key = self.signing_key(date);
        let signature = Sha256Hex::from_bytes(
            sign(&signing_key, string_to_sign.as_bytes())
                .as_ref()
                .first_chunk::<32>()
                .copied()
                .unwrap_or_default(),
        );

        let signed_headers_len = request
            .headers
            .iter()
            .map(|(name, _)| name.len() + 1)
            .sum::<usize>();
        let mut authorization = String::with_capacity(
            ALGORITHM.len()
                + 12
                + self.access_key.len()
                + 10
                + self.region.len()
                + SERVICE_SCOPE.len()
                + 15
                + signed_headers_len
                + 11
                + 64,
        );
        authorization.push_str(ALGORITHM);
        authorization.push_str(" Credential=");
        authorization.push_str(&self.access_key);
        authorization.push('/');
        self.push_scope(&mut authorization, date);
        authorization.push_str(",SignedHeaders=");
        request.push_signed_headers(&mut authorization);
        authorization.push_str(",Signature=");
        authorization.push_str(signature.as_str());
        authorization
    }

    fn push_scope(&self, out: &mut String, date: &AmzDate) {
        out.push_str(date.day());
        out.push('/');
        out.push_str(&self.region);
        out.push_str(SERVICE_SCOPE);
    }

    fn signing_key(&self, date: &AmzDate) -> Key {
        let step = |key: &[u8], data: &[u8]| sign(&Key::new(HMAC_SHA256, key), data);
        let date_key = step(&self.secret_key, date.day().as_bytes());
        let region_key = step(date_key.as_ref(), self.region.as_bytes());
        let service_key = step(region_key.as_ref(), b"s3");
        let signing_key = step(service_key.as_ref(), b"aws4_request");
        Key::new(HMAC_SHA256, signing_key.as_ref())
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl CanonicalRequest<'_> {
    pub fn build(&self) -> String {
        let headers_len = self
            .headers
            .iter()
            .map(|(name, value)| (name.len() + value.len()) * 2 + 3)
            .sum::<usize>();
        let mut out = String::with_capacity(
            self.method.len()
                + self.uri.len()
                + self.query.len()
                + headers_len
                + self.payload_hash.len()
                + 5,
        );
        out.push_str(self.method);
        out.push('\n');
        out.push_str(self.uri);
        out.push('\n');
        out.push_str(self.query);
        out.push('\n');
        for (name, value) in self.headers {
            out.push_str(name);
            out.push(':');
            out.push_str(value.trim());
            out.push('\n');
        }
        out.push('\n');
        self.push_signed_headers(&mut out);
        out.push('\n');
        out.push_str(self.payload_hash);
        out
    }

    fn push_signed_headers(&self, out: &mut String) {
        let mut headers = self.headers.iter();
        if let Some((name, _)) = headers.next() {
            out.push_str(name);
        }
        for (name, _) in headers {
            out.push(';');
            out.push_str(name);
        }
    }
}

impl AmzDate {
    pub fn now() -> Self {
        Self::from_unix(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        )
    }

    pub fn from_unix(timestamp: u64) -> Self {
        let days = timestamp / 86_400;
        let seconds = timestamp % 86_400;
        let (year, month, day) = civil_from_days(days);
        let mut out = *b"00000000T000000Z";
        write_digits(&mut out[0..4], year);
        write_digits(&mut out[4..6], month);
        write_digits(&mut out[6..8], day);
        write_digits(&mut out[9..11], seconds / 3600);
        write_digits(&mut out[11..13], (seconds / 60) % 60);
        write_digits(&mut out[13..15], seconds % 60);
        AmzDate(out)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    pub fn day(&self) -> &str {
        self.as_str().get(..8).unwrap_or_default()
    }
}

fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn write_digits(out: &mut [u8], mut value: u64) {
    for digit in out.iter_mut().rev() {
        *digit = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

impl Sha256Hex {
    pub fn of(data: &[u8]) -> Self {
        Self::from_bytes(
            digest(&SHA256, data)
                .as_ref()
                .first_chunk::<32>()
                .copied()
                .unwrap_or_default(),
        )
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut out = [0u8; 64];
        for ([high, low], byte) in out.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
            *high = HEX_LOWER[usize::from(byte >> 4)];
            *low = HEX_LOWER[usize::from(byte & 0x0f)];
        }
        Sha256Hex(out)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

