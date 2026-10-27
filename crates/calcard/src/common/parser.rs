/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Data, Encoding, PartialDateTime, tokenizer::Token};
use crate::{
    Parser,
    common::{IanaParse, IanaString, IanaType},
    icalendar::Uri,
};
use encodify::hex;
use mail_parser::DateTime;
use std::{borrow::Cow, iter::Peekable, slice::Iter, str::FromStr};

impl<'x> Parser<'x> {
    pub(crate) fn raw_token(&mut self) -> Option<Cow<'x, str>> {
        let (first, last) = (self.token_buf.first()?, self.token_buf.last()?);
        self.source.get(first.start..=last.end).map(unfold)
    }

    pub(crate) fn buf_parse_one<T: From<Token<'x>>>(&mut self) -> Option<T> {
        let result = self.token_buf.pop().map(T::from);
        self.token_buf.clear();
        result
    }
}

impl Token<'_> {
    pub(crate) fn into_uri_bytes(self) -> std::result::Result<Data, String> {
        match Data::try_parse(self.text.as_ref()) {
            Some(data) => Ok(data),
            None => Err(self.into_string()),
        }
    }

    pub(crate) fn into_timestamp(
        self,
        require_time: bool,
    ) -> std::result::Result<PartialDateTime, String> {
        match PartialDateTime::from_timestamp_bytes(&self.text, require_time) {
            (dt, true) => Ok(dt),
            (_, false) => Err(self.into_string()),
        }
    }

    pub(crate) fn into_offset(self) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        dt.parse_zone(&mut self.text.iter().peekable());
        if !dt.is_null() {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_float(self) -> std::result::Result<f64, String> {
        if let Ok(float) = self.text.as_str().parse::<f64>()
            && float.is_finite()
        {
            return Ok(float);
        }

        Err(self.into_string())
    }

    pub(crate) fn into_integer(self) -> std::result::Result<i64, String> {
        if let Ok(integer) = self.text.as_str().parse::<i64>() {
            return Ok(integer);
        }

        Err(self.into_string())
    }

    pub(crate) fn into_boolean(self) -> bool {
        self.text.as_ref().eq_ignore_ascii_case(b"true")
    }
}

impl Data {
    pub fn try_parse(text: &[u8]) -> Option<Self> {
        const BASE64: &[u8] = b"base64";

        let (scheme, text) = text.split_at_checked(5)?;
        if !scheme.eq_ignore_ascii_case(b"data:") {
            return None;
        }
        let mut parts = text.splitn(2, |ch| *ch == b',');
        let header = parts.next()?;
        let data = parts.next().filter(|data| !data.is_empty())?;
        let header = header.strip_suffix(b"\\").unwrap_or(header);
        let mut segments = header.rsplitn(2, |ch| *ch == b';');
        let (media_type, is_base64) = match (segments.next(), segments.next()) {
            (Some(last), media_type) if last.eq_ignore_ascii_case(BASE64) => {
                (media_type.unwrap_or_default(), true)
            }
            _ => (header, false),
        };

        Some(Data {
            content_type: std::str::from_utf8(media_type)
                .ok()
                .filter(|media_type| !media_type.is_empty())
                .map(str::to_string),
            data: if is_base64 {
                Encoding::Base64.decode(data)?.into_owned()
            } else {
                hex::PERCENT.decode(data).ok()?.into_owned()
            },
        })
    }
}

impl PartialDateTime {
    pub(crate) fn from_timestamp_bytes(bytes: &[u8], require_time: bool) -> (Self, bool) {
        if let Some(dt) = Self::from_basic_format(bytes) {
            let valid = !require_time || dt.has_time();
            (dt, valid)
        } else {
            let mut dt = Self::default();
            let valid = dt.parse_timestamp(&mut bytes.iter().peekable(), require_time);
            (dt, valid)
        }
    }

    fn from_basic_format(bytes: &[u8]) -> Option<Self> {
        let (date, time) = bytes.split_first_chunk::<8>()?;
        let mut dt = Self::from_basic_date(date)?;
        match time {
            [] => {}
            [b'T' | b't', h0, h1, m0, m1, s0, s1, zone @ ..] => {
                dt.hour = Some(Self::two_digits(*h0, *h1)?);
                dt.minute = Some(Self::two_digits(*m0, *m1)?);
                dt.second = Some(Self::two_digits(*s0, *s1)?);
                match zone {
                    [] => {}
                    [b'Z' | b'z'] => {
                        dt.tz_hour = Some(0);
                        dt.tz_minute = Some(0);
                    }
                    _ => return None,
                }
            }
            _ => return None,
        }
        Some(dt)
    }

    pub(crate) fn from_basic_date(&[y0, y1, y2, y3, m0, m1, d0, d1]: &[u8; 8]) -> Option<Self> {
        Some(PartialDateTime {
            year: Some(
                u16::from(Self::two_digits(y0, y1)?) * 100 + u16::from(Self::two_digits(y2, y3)?),
            ),
            month: Some(Self::two_digits(m0, m1)?),
            day: Some(Self::two_digits(d0, d1)?),
            ..Default::default()
        })
    }

    #[inline(always)]
    fn two_digits(tens: u8, ones: u8) -> Option<u8> {
        let (tens, ones) = (tens.wrapping_sub(b'0'), ones.wrapping_sub(b'0'));
        (tens < 10 && ones < 10).then(|| tens * 10 + ones)
    }

    pub fn parse_timestamp(
        &mut self,
        iter: &mut Peekable<Iter<'_, u8>>,
        require_time: bool,
    ) -> bool {
        let mut idx = 0;
        for ch in iter {
            match ch {
                b'0'..=b'9' => {
                    let value = match idx {
                        0..=3 => {
                            if let Some(value) = &mut self.year {
                                *value =
                                    value.saturating_mul(10).saturating_add((ch - b'0') as u16);
                            } else {
                                self.year = Some((ch - b'0') as u16);
                            }
                            idx += 1;
                            continue;
                        }
                        4..=5 => &mut self.month,
                        6..=7 => &mut self.day,
                        9..=10 => &mut self.hour,
                        11..=12 => &mut self.minute,
                        13..=14 => &mut self.second,
                        16..=17 => &mut self.tz_hour,
                        18..=19 => &mut self.tz_minute,
                        _ => return false,
                    };

                    if let Some(value) = value {
                        *value = value.saturating_mul(10).saturating_add(ch - b'0');
                    } else {
                        *value = Some(ch - b'0');
                    }
                }
                b'T' | b't' if idx == 8 => {}
                b'+' if idx == 15 => {}
                b'Z' | b'z' if idx == 15 => {
                    self.tz_hour = Some(0);
                    self.tz_minute = Some(0);
                }
                b'-' if idx == 15 => {
                    self.tz_minus = true;
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    continue;
                }
                _ => break,
            }
            idx += 1;
        }

        if self.hour.is_some() {
            self.minute.get_or_insert(0);
            self.second.get_or_insert(0);
        }

        self.has_date() && (!require_time || self.has_time())
    }

    pub(crate) fn parse_zone(&mut self, iter: &mut Peekable<Iter<'_, u8>>) -> bool {
        self.tz_minus = match iter.peek() {
            Some(b'-') => true,
            Some(b'+') => false,
            Some(b'Z') | Some(b'z') => {
                self.tz_hour = Some(0);
                self.tz_minute = Some(0);
                iter.next();
                return true;
            }
            _ => return false,
        };

        iter.next();
        let mut idx = 0;
        for ch in iter {
            match ch {
                b'0'..=b'9' => {
                    idx += 1;
                    let value = match idx {
                        1 | 2 => &mut self.tz_hour,
                        3 | 4 => &mut self.tz_minute,
                        _ => return false,
                    };

                    if let Some(value) = value {
                        *value = value.saturating_mul(10).saturating_add(ch - b'0');
                    } else {
                        *value = Some(ch - b'0');
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return false;
                    }
                }
            }
        }

        self.tz_hour.is_some()
    }

    pub fn is_null(&self) -> bool {
        self.year.is_none()
            && self.month.is_none()
            && self.day.is_none()
            && self.hour.is_none()
            && self.minute.is_none()
            && self.second.is_none()
            && self.tz_hour.is_none()
            && self.tz_minute.is_none()
    }

    #[inline(always)]
    pub fn has_date(&self) -> bool {
        self.year.is_some() && self.month.is_some() && self.day.is_some()
    }

    #[inline(always)]
    pub fn has_time(&self) -> bool {
        self.hour.is_some() && self.minute.is_some()
    }

    #[inline(always)]
    pub fn has_zone(&self) -> bool {
        self.tz_hour.is_some()
    }

    #[inline(always)]
    pub fn has_date_and_time(&self) -> bool {
        self.has_date() && self.has_time()
    }

    fn to_datetime(&self) -> Option<DateTime> {
        if self.has_date() && self.has_time() {
            DateTime {
                year: self.year.unwrap(),
                month: self.month.unwrap(),
                day: self.day.unwrap(),
                hour: self.hour.unwrap(),
                minute: self.minute.unwrap(),
                second: self.second.unwrap_or_default(),
                tz_before_gmt: self.tz_minus,
                tz_hour: self.tz_hour.unwrap_or_default(),
                tz_minute: self.tz_minute.unwrap_or_default(),
            }
            .into()
        } else {
            None
        }
    }

    pub fn to_rfc3339(&self) -> Option<String> {
        self.to_datetime().map(|dt| dt.to_rfc3339())
    }

    pub fn to_timestamp(&self) -> Option<i64> {
        self.to_datetime().map(|dt| dt.to_timestamp())
    }
}

pub(crate) fn parse_digits(
    iter: &mut Peekable<Iter<'_, u8>>,
    target: &mut Option<u16>,
    num: usize,
    nullable: bool,
) -> bool {
    let mut idx = 0;
    while let Some(ch) = iter.peek() {
        match ch {
            b'0'..=b'9' => {
                let ch = (*ch - b'0') as u16;
                idx += 1;
                iter.next();

                if let Some(target) = target {
                    *target = target.saturating_mul(10).saturating_add(ch);

                    if idx == num {
                        return true;
                    }
                } else {
                    *target = Some(ch);
                }
            }
            b'-' if nullable => {
                idx += 1;
                iter.next();
                if idx == num / 2 {
                    return true;
                }
            }
            _ => {
                if !ch.is_ascii_whitespace() {
                    return false;
                } else {
                    iter.next();
                }
            }
        };
    }

    false
}

pub(crate) fn parse_small_digits(
    iter: &mut Peekable<Iter<'_, u8>>,
    target: &mut Option<u8>,
    num: usize,
    nullable: bool,
) -> bool {
    let mut idx = 0;
    while let Some(ch) = iter.peek() {
        match ch {
            b'0'..=b'9' => {
                let ch = *ch - b'0';
                idx += 1;
                iter.next();

                if let Some(target) = target {
                    *target = target.saturating_mul(10).saturating_add(ch);

                    if idx == num {
                        return true;
                    }
                } else {
                    *target = Some(ch);
                }
            }
            b'-' if nullable => {
                idx += 1;
                iter.next();
                if idx == num / 2 {
                    return true;
                }
            }
            _ => {
                if !ch.is_ascii_whitespace() {
                    return false;
                } else {
                    iter.next();
                }
            }
        };
    }

    false
}

pub(crate) fn unfold(text: &str) -> Cow<'_, str> {
    if !text.as_bytes().contains(&b'\n') {
        return Cow::Borrowed(text);
    }

    let mut unfolded = String::with_capacity(text.len());

    for (pos, chunk) in text.split('\n').enumerate() {
        let chunk = if pos == 0 {
            chunk
        } else {
            chunk.strip_prefix([' ', '\t']).unwrap_or(chunk)
        };
        unfolded.push_str(chunk.strip_suffix('\r').unwrap_or(chunk));
    }

    Cow::Owned(unfolded)
}

#[derive(Default)]
pub(crate) struct Timestamp(pub i64);

impl FromStr for Timestamp {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Timestamp::parse(s.as_bytes()).ok_or(())
    }
}

impl IanaParse for Timestamp {
    fn parse(value: &[u8]) -> Option<Self> {
        PartialDateTime::from_timestamp_bytes(value, true)
            .0
            .to_timestamp()
            .map(Timestamp)
    }
}

pub(crate) struct Integer(pub i64);

impl IanaParse for Integer {
    fn parse(value: &[u8]) -> Option<Self> {
        let mut num: i64 = 0;
        let mut is_negative = false;

        for (pos, ch) in value.iter().enumerate() {
            match ch {
                b'-' if pos == 0 => {
                    is_negative = true;
                }
                b'+' if pos == 0 => {}
                b'0'..=b'9' => {
                    num = num.saturating_mul(10).saturating_add((*ch - b'0') as i64);
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return None;
                    }
                }
            }
        }

        Some(Integer(if is_negative { -num } else { num }))
    }
}

pub(crate) struct Boolean(pub bool);

impl IanaParse for Boolean {
    fn parse(value: &[u8]) -> Option<Self> {
        if value.eq_ignore_ascii_case(b"true") {
            Some(Boolean(true))
        } else if value.eq_ignore_ascii_case(b"false") {
            Some(Boolean(false))
        } else {
            None
        }
    }
}

impl<I> From<Token<'_>> for IanaType<I, String>
where
    I: IanaParse,
{
    fn from(value: Token<'_>) -> Self {
        I::parse(value.text.as_ref())
            .map(IanaType::Iana)
            .unwrap_or_else(|| IanaType::Other(value.into_string()))
    }
}

impl<I> From<Token<'_>> for IanaType<I, Uri>
where
    I: IanaString
        + IanaParse
        + std::fmt::Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + std::hash::Hash,
{
    fn from(value: Token<'_>) -> Self {
        I::parse(value.text.as_ref())
            .map(IanaType::Iana)
            .unwrap_or_else(|| {
                IanaType::Other(
                    value
                        .into_uri_bytes()
                        .map(Uri::from)
                        .unwrap_or_else(Uri::Location),
                )
            })
    }
}

