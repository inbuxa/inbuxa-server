/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ByteRange, Condition, Depth, If, RequestHeaders, ResourceState, Return, Timeout};
use calcard::vcard::VCardVersion;
use std::ops::Range;

impl<'x> RequestHeaders<'x> {
    pub fn new(uri: &'x str) -> Self {
        RequestHeaders {
            uri,
            raw_uri: uri,
            ..Default::default()
        }
    }

    pub fn parse(&mut self, key: &str, value: &'x str) -> bool {
        hashify::fnc_map_ignore_case!(key.as_bytes(),
            "Depth" => {
                if let Some(depth) = Depth::parse(value.as_bytes()) {
                    self.depth = depth;
                    return true;
                }
            },
            "Destination" => {
                let value = strip_query_and_fragment(value);
                self.destination = Some(value);
                return true;
            },
            "Lock-Token" => {
                self.lock_token = Some(try_unwrap_coded_url(value));
                return true;
            },
            "If" => {
                let num = self.if_.len();
                self.parse_if(value);
                return self.if_.len() != num;
            },
            "If-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, false);
                return self.if_.len() != num;
            },
            "If-None-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, true);
                return self.if_.len() != num;
            },
            "Timeout" => {
                let value = value.split_once(',').map(|(first, _)| first).unwrap_or(value).trim();
                if let Some(seconds) = value.strip_prefix("Second-") {
                    if let Ok(seconds) = seconds.parse() {
                        self.timeout = Timeout::Second(seconds);
                        return true;
                    }
                } else if value == "Infinite" {
                    self.timeout = Timeout::Infinite;
                    return true;
                }
            },
            "Overwrite" => {
                self.overwrite_fail = value == "F";
                return true;
            },
            "CalDAV-Timezones" => {
                self.no_timezones = value == "F";
                return true;
            },
            "Prefer" => {
                for value in value.split(&[',', ';']) {
                    match value.trim() {
                        "return=minimal" => self.ret = Return::Minimal,
                        "return=representation" => self.ret = Return::Representation,
                        "depth-noroot" => self.depth_no_root = true,
                        _ => {}
                    }
                }
            },
            "Content-Type" => {
                let value = value.trim();
                if (2..=127).contains(&value.len()) {
                    self.content_type = Some(value);
                }
                return true;
            },
            "Accept" => {
                let mut preferred: Option<(f32, VCardVersion)> = None;

                for entry in value.split(',') {
                    let mut parts = entry.split(';');
                    if !parts.next().is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/vcard")) {
                        continue;
                    }

                    let mut version = None;
                    let mut quality = 1.0;

                    for param in parts {
                        let Some((name, param_value)) = param.split_once('=') else {
                            continue;
                        };
                        let param_value = param_value.trim().trim_matches('"');

                        if name.trim().eq_ignore_ascii_case("version") {
                            version = VCardVersion::try_parse(param_value);
                        } else if name.trim().eq_ignore_ascii_case("q") {
                            quality = param_value.parse().unwrap_or(1.0);
                        }
                    }

                    if let Some(version) = version
                        && quality > 0.0
                        && preferred.is_none_or(|(preferred_quality, _)| quality > preferred_quality) {
                        preferred = Some((quality, version));
                    }
                }

                if let Some((_, version)) = preferred {
                    self.vcard_version = Some(version);
                }
                return true;
            },
            "If-Schedule-Tag-Match" => {
                self.if_schedule_tag = value.trim().trim_matches('"').parse().ok();
                return true;
            },
            "Schedule-Reply" => {
                self.no_schedule_reply = value == "F";
                return true;
            },
            "Range" => {
                self.range = ByteRange::parse(value);
                return self.range.is_some();
            },
            "If-Range" => {
                self.if_range = Some(value.trim());
                return true;
            },
            _ => {}
        );

        false
    }

    pub fn has_if(&self) -> bool {
        !self.if_.is_empty()
    }

    pub fn eval_if_resources(&self) -> impl Iterator<Item = &str> {
        self.if_.iter().filter_map(|if_| if_.resource)
    }

    pub fn eval_if<T>(&self, resources: &[ResourceState<T>]) -> bool
    where
        T: AsRef<str>,
    {
        if self.if_.is_empty() {
            return true;
        }

        'outer: for if_ in &self.if_ {
            if if_.list.is_empty() {
                continue;
            }

            let (current_token, current_etag) = resources
                .iter()
                .find_map(|r| {
                    if if_.resource == r.resource.as_ref().map(|v| v.as_ref()) {
                        Some((r.state_token.as_ref(), r.etag.as_ref()))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            for cond in if_.list.iter() {
                match cond {
                    Condition::StateToken { is_not, token } => {
                        if !((current_token == *token) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::ETag { is_not, tag } => {
                        if !((current_etag == *tag) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::Exists { is_not } => {
                        if !((current_etag.is_empty()) ^ is_not) {
                            continue 'outer;
                        }
                    }
                }
            }

            return true;
        }

        false
    }

    fn parse_if(&mut self, value: &'x str) {
        let value = value.as_bytes();
        let mut iter = value.iter().enumerate();
        let mut resource = None;

        while let Some((idx, ch)) = iter.next() {
            match ch {
                b'<' if resource.is_none() => {
                    for (to_idx, ch) in iter.by_ref() {
                        if *ch == b'>' {
                            resource = Some(std::str::from_utf8(&value[idx + 1..to_idx]).unwrap());
                            break;
                        }
                    }
                }
                b'(' => {
                    let mut is_not = false;
                    let mut conditions = Vec::new();
                    while let Some((idx, ch)) = iter.next() {
                        match ch {
                            b'N' => {
                                if matches!(iter.next(), Some((_, b'o')))
                                    && matches!(iter.next(), Some((_, b't')))
                                {
                                    is_not = true;
                                } else {
                                    return;
                                }
                            }
                            b'<' | b'[' => {
                                let (stop_char, is_etag) = match ch {
                                    b'<' => (b'>', false),
                                    b'[' => (b']', true),
                                    _ => unreachable!(),
                                };

                                for (to_idx, ch) in iter.by_ref() {
                                    if *ch == stop_char {
                                        let value =
                                            std::str::from_utf8(&value[idx + 1..to_idx]).unwrap();
                                        let condition = if is_etag {
                                            Condition::ETag { is_not, tag: value }
                                        } else {
                                            Condition::StateToken {
                                                is_not,
                                                token: value,
                                            }
                                        };
                                        conditions.push(condition);
                                        is_not = false;
                                        break;
                                    }
                                }
                            }
                            b')' => {
                                self.if_.push(If {
                                    resource: resource.take(),
                                    list: conditions,
                                });
                                break;
                            }
                            _ => {
                                if !ch.is_ascii_whitespace() {
                                    return;
                                }
                            }
                        }
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return;
                    }
                }
            }
        }
    }

    pub fn parse_if_match(&mut self, value: &'x str, is_not: bool) {
        if value == "*" {
            self.if_.push(If {
                resource: None,
                list: vec![Condition::Exists { is_not }],
            });
        } else if !is_not {
            for etag in value.split(',') {
                self.if_.push(If {
                    resource: None,
                    list: vec![Condition::ETag {
                        is_not,
                        tag: etag.trim(),
                    }],
                });
            }
        } else {
            let mut etags = Vec::new();
            for etag in value.split(',') {
                etags.push(Condition::ETag {
                    is_not,
                    tag: etag.trim(),
                });
            }
            self.if_.push(If {
                resource: None,
                list: etags,
            });
        }
    }

    pub fn eval_if_range(&self, etag: &str, last_modified: Option<&str>) -> bool {
        match self.if_range {
            Some(validator) => {
                !validator.starts_with("W/")
                    && (validator == etag
                        || last_modified.is_some_and(|last_modified| validator == last_modified))
            }
            None => true,
        }
    }

    pub fn base_uri(&self) -> Option<&str> {
        dav_base_uri(self.uri)
    }
}

impl ByteRange {
    pub fn parse(value: &str) -> Option<Self> {
        let (unit, spec) = value.split_once('=')?;
        if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
            return None;
        }

        let (start, end) = spec.split_once('-')?;
        let (start, end) = (start.trim(), end.trim());

        if !start.is_empty() {
            let start = start.parse::<u64>().ok()?;
            let end = if !end.is_empty() {
                let end = end.parse::<u64>().ok()?;
                if end < start {
                    return None;
                }
                Some(end)
            } else {
                None
            };

            Some(ByteRange::Offset { start, end })
        } else {
            end.parse::<u64>().ok().map(ByteRange::Suffix)
        }
    }

    pub fn resolve(&self, size: u64) -> Option<Range<u64>> {
        match self {
            ByteRange::Offset { start, end } if *start < size => {
                Some(*start..end.map_or(size, |end| std::cmp::min(end.saturating_add(1), size)))
            }
            ByteRange::Suffix(length) if *length > 0 && size > 0 => {
                Some(size.saturating_sub(*length)..size)
            }
            _ => None,
        }
    }
}

pub fn dav_base_uri(uri: &str) -> Option<&str> {
    // From a path ../dav/collection/account/..
    // returns ../dav/collection/account without the trailing slash

    let uri = uri.as_bytes();
    let mut found_dav = false;
    let mut last_idx = 0;
    let mut sep_count = 0;

    for (idx, ch) in uri.iter().enumerate() {
        if *ch == b'/' {
            if !found_dav {
                found_dav = uri.get(idx + 1..idx + 5).is_some_and(|s| s == b"dav/");
            } else if found_dav {
                if sep_count == 2 {
                    break;
                }
                sep_count += 1;
            }
        }
        last_idx = idx;
    }

    if sep_count == 2 {
        uri.get(..last_idx + 1)
            .map(|uri| std::str::from_utf8(uri).unwrap())
    } else {
        None
    }
}

impl Depth {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::map!(value, Depth,
            "0" => Depth::Zero,
            "1" => Depth::One,
            "infinity" => Depth::Infinity,
            "infinite" => Depth::Infinity,
        )
        .copied()
    }
}

pub fn strip_query_and_fragment(uri: &str) -> &str {
    uri.split_once(['?', '#']).map_or(uri, |(path, _)| path)
}

fn try_unwrap_coded_url(url: &str) -> &str {
    url.strip_prefix("<")
        .and_then(|url| url.strip_suffix(">"))
        .unwrap_or(url)
}

