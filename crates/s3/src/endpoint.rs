/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlStyle {
    Path,
    VirtualHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    scheme: Scheme,
    authority: Box<str>,
    base_path: Box<str>,
}

#[derive(Debug)]
pub(crate) struct Location {
    url_prefix: Box<str>,
    path_offset: usize,
    host: Box<str>,
}

impl Scheme {
    fn parse(scheme: &str) -> Result<Self> {
        hashify::map_ignore_case!(scheme.as_bytes(), Scheme,
            "http" => Scheme::Http,
            "https" => Scheme::Https,
        )
        .copied()
        .ok_or_else(|| Error::InvalidConfig(format!("unsupported URL scheme {scheme:?}").into()))
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    fn default_port(&self) -> &'static str {
        match self {
            Scheme::Http => "80",
            Scheme::Https => "443",
        }
    }
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self> {
        let url = url.trim();
        let (scheme, rest) = match url.split_once("://") {
            Some((scheme, rest)) => (Scheme::parse(scheme)?, rest),
            None => (Scheme::Https, url),
        };
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty()
            || !authority.bytes().all(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'-' | b'_' | b':' | b'[' | b']')
            })
        {
            return Err(Error::InvalidConfig(
                format!("invalid S3 endpoint host {authority:?}").into(),
            ));
        }
        let mut authority = authority.to_ascii_lowercase();
        if let Some((host, port)) = authority.rsplit_once(':')
            && !host.ends_with(':')
            && !port.ends_with(']')
            && port == scheme.default_port()
        {
            authority.truncate(host.len());
        }

        let mut base_path = String::with_capacity(path.len() + 1);
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            base_path.push('/');
            push_segment(&mut base_path, segment)?;
        }

        Ok(Endpoint {
            scheme,
            authority: authority.into_boxed_str(),
            base_path: base_path.into_boxed_str(),
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn locate(&self, bucket: &str, style: UrlStyle) -> Result<Location> {
        if bucket.is_empty() || bucket.contains('/') {
            return Err(Error::InvalidConfig(
                format!("invalid bucket name {bucket:?}").into(),
            ));
        }
        let scheme = self.scheme.as_str();
        match style {
            UrlStyle::Path => {
                let mut url = String::with_capacity(
                    scheme.len()
                        + 3
                        + self.authority.len()
                        + self.base_path.len()
                        + bucket.len()
                        + 1,
                );
                url.push_str(scheme);
                url.push_str("://");
                url.push_str(&self.authority);
                let path_offset = url.len();
                url.push_str(&self.base_path);
                url.push('/');
                push_segment(&mut url, bucket)?;
                Ok(Location {
                    url_prefix: url.into_boxed_str(),
                    path_offset,
                    host: self.authority.clone(),
                })
            }
            UrlStyle::VirtualHost => {
                if !bucket.bytes().all(|ch| {
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, b'-' | b'.')
                }) {
                    return Err(Error::InvalidConfig(
                        format!("bucket {bucket:?} is not a valid host name").into(),
                    ));
                }
                let mut host = String::with_capacity(bucket.len() + 1 + self.authority.len());
                host.push_str(bucket);
                host.push('.');
                host.push_str(&self.authority);
                let mut url =
                    String::with_capacity(scheme.len() + 3 + host.len() + self.base_path.len());
                url.push_str(scheme);
                url.push_str("://");
                url.push_str(&host);
                let path_offset = url.len();
                url.push_str(&self.base_path);
                Ok(Location {
                    url_prefix: url.into_boxed_str(),
                    path_offset,
                    host: host.into_boxed_str(),
                })
            }
        }
    }
}

impl Location {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn object_url(&self, key: &str) -> Result<RequestUrl> {
        let mut url = String::with_capacity(self.url_prefix.len() + 1 + key.len() + key.len() / 2);
        url.push_str(&self.url_prefix);
        url.push('/');
        push_key(&mut url, key)?;
        Ok(RequestUrl {
            url,
            path_offset: self.path_offset,
            query_offset: None,
        })
    }

    pub(crate) fn bucket_url(&self, query: &str) -> RequestUrl {
        let mut url = String::with_capacity(self.url_prefix.len() + 2 + query.len());
        url.push_str(&self.url_prefix);
        url.push('/');
        let query_offset = url.len();
        url.push('?');
        url.push_str(query);
        RequestUrl {
            url,
            path_offset: self.path_offset,
            query_offset: Some(query_offset),
        }
    }
}

#[derive(Debug)]
pub(crate) struct RequestUrl {
    url: String,
    path_offset: usize,
    query_offset: Option<usize>,
}

impl RequestUrl {
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }

    pub(crate) fn canonical_uri(&self) -> &str {
        self.url
            .get(self.path_offset..self.query_offset.unwrap_or(self.url.len()))
            .unwrap_or("/")
    }
}

const fn is_unreserved(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b'~')
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn push_encoded(out: &mut String, segment: &str) {
    for &ch in segment.as_bytes() {
        if is_unreserved(ch) {
            out.push(char::from(ch));
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[usize::from(ch >> 4)]));
            out.push(char::from(HEX_UPPER[usize::from(ch & 0x0f)]));
        }
    }
}

fn push_segment(out: &mut String, segment: &str) -> Result<()> {
    if matches!(segment, "." | "..") {
        return Err(Error::InvalidKey(segment.into()));
    }
    push_encoded(out, segment);
    Ok(())
}

pub(crate) fn push_key(out: &mut String, key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidKey(key.into()));
    }
    let mut segments = key.split('/');
    if let Some(first) = segments.next() {
        push_segment(out, first).map_err(|_| Error::InvalidKey(key.into()))?;
    }
    for segment in segments {
        out.push('/');
        push_segment(out, segment).map_err(|_| Error::InvalidKey(key.into()))?;
    }
    Ok(())
}

