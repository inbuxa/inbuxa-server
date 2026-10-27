/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        CalendarScale, IanaParse, IanaString, IdReference, LinkRelation,
        format::AsciiPush,
        jsprop::text::{DisplayEq, Expect, IdReferenceText, PointerText, PointerTextExt},
    },
    icalendar::{
        ICalendarDuration, ICalendarFrequency, ICalendarMethod, ICalendarMonth, ICalendarSkip,
        ICalendarWeekday,
    },
    jscalendar::{
        JSCalendar, JSCalendarAlertAction, JSCalendarDateTime, JSCalendarEventStatus,
        JSCalendarFreeBusyStatus, JSCalendarId, JSCalendarLinkDisplay, JSCalendarParticipantKind,
        JSCalendarParticipantRole, JSCalendarParticipationStatus, JSCalendarPrivacy,
        JSCalendarProgress, JSCalendarProperty, JSCalendarRelation, JSCalendarRelativeTo,
        JSCalendarScheduleAgent, JSCalendarType, JSCalendarValue, JSCalendarVirtualLocationFeature,
    },
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, PointerDepth, Property as _, Value};
use mail_parser::DateTime;
use serde::Serializer;
use std::{
    borrow::Cow,
    fmt::{self, Write},
    mem::discriminant,
    ops::RangeInclusive,
    str::{FromStr, from_utf8},
};

const FOUR_DIGIT_YEARS: RangeInclusive<i64> = -62_167_219_200..=253_402_300_799;
pub(crate) const VALUE_TEXT: usize = 64;
pub(crate) const KEY_TEXT: usize = 128;

impl<'x, I: JSCalendarId, B: JSCalendarId> JSCalendar<'x, I, B> {
    pub fn parse(json: &'x str) -> Result<Self, String> {
        Value::parse_json(json).map(JSCalendar)
    }

    pub fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.0).unwrap_or_default()
    }
}

impl<I: JSCalendarId, B: JSCalendarId> Element for JSCalendarValue<I, B> {
    type Property = JSCalendarProperty<I>;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                JSCalendarProperty::Type => JSCalendarType::from_str(value)
                    .ok()
                    .map(JSCalendarValue::Type),
                JSCalendarProperty::Created
                | JSCalendarProperty::Updated
                | JSCalendarProperty::Acknowledged
                | JSCalendarProperty::ScheduleUpdated
                | JSCalendarProperty::When
                | JSCalendarProperty::UtcStart
                | JSCalendarProperty::UtcEnd => {
                    JSCalendarDateTime::from_rfc3339(value, false).map(JSCalendarValue::DateTime)
                }
                JSCalendarProperty::Due
                | JSCalendarProperty::RecurrenceId
                | JSCalendarProperty::Start
                | JSCalendarProperty::Until => {
                    JSCalendarDateTime::from_rfc3339(value, true).map(JSCalendarValue::DateTime)
                }
                JSCalendarProperty::Duration
                | JSCalendarProperty::EstimatedDuration
                | JSCalendarProperty::Offset => {
                    ICalendarDuration::parse(value.as_bytes()).map(JSCalendarValue::Duration)
                }
                JSCalendarProperty::Action => JSCalendarAlertAction::from_str(value)
                    .ok()
                    .map(JSCalendarValue::AlertAction),
                JSCalendarProperty::FreeBusyStatus => JSCalendarFreeBusyStatus::from_str(value)
                    .ok()
                    .map(JSCalendarValue::FreeBusyStatus),
                JSCalendarProperty::Kind => JSCalendarParticipantKind::from_str(value)
                    .ok()
                    .map(JSCalendarValue::ParticipantKind),
                JSCalendarProperty::ParticipationStatus => {
                    JSCalendarParticipationStatus::from_str(value)
                        .ok()
                        .map(JSCalendarValue::ParticipationStatus)
                }
                JSCalendarProperty::Privacy => JSCalendarPrivacy::from_str(value)
                    .ok()
                    .map(JSCalendarValue::Privacy),
                JSCalendarProperty::Progress => JSCalendarProgress::from_str(value)
                    .ok()
                    .map(JSCalendarValue::Progress),
                JSCalendarProperty::RelativeTo => JSCalendarRelativeTo::from_str(value)
                    .ok()
                    .map(JSCalendarValue::RelativeTo),
                JSCalendarProperty::ScheduleAgent => JSCalendarScheduleAgent::from_str(value)
                    .ok()
                    .map(JSCalendarValue::ScheduleAgent),
                JSCalendarProperty::Status => JSCalendarEventStatus::from_str(value)
                    .ok()
                    .map(JSCalendarValue::EventStatus),
                JSCalendarProperty::Rel => {
                    LinkRelation::parse(value.as_bytes()).map(JSCalendarValue::LinkRelation)
                }
                JSCalendarProperty::Frequency => {
                    ICalendarFrequency::parse(value.as_bytes()).map(JSCalendarValue::Frequency)
                }
                JSCalendarProperty::FirstDayOfWeek | JSCalendarProperty::Day => {
                    ICalendarWeekday::parse(value.as_bytes()).map(JSCalendarValue::Weekday)
                }
                JSCalendarProperty::Skip => {
                    ICalendarSkip::parse(value.as_bytes()).map(JSCalendarValue::Skip)
                }
                JSCalendarProperty::Rscale => {
                    CalendarScale::parse(value.as_bytes()).map(JSCalendarValue::CalendarScale)
                }
                JSCalendarProperty::ByMonth => {
                    ICalendarMonth::parse(value.as_bytes()).map(JSCalendarValue::Month)
                }
                JSCalendarProperty::Method => {
                    ICalendarMethod::parse(value.as_bytes()).map(JSCalendarValue::Method)
                }
                JSCalendarProperty::Id | JSCalendarProperty::BaseEventId => {
                    match IdReference::parse(value) {
                        IdReference::Value(value) => JSCalendarValue::Id(value).into(),
                        IdReference::Reference(value) => JSCalendarValue::IdReference(value).into(),
                        IdReference::Error => None,
                    }
                }
                JSCalendarProperty::BlobId => match IdReference::parse(value) {
                    IdReference::Value(value) => JSCalendarValue::BlobId(value).into(),
                    IdReference::Reference(value) => JSCalendarValue::IdReference(value).into(),
                    IdReference::Error => None,
                },
                _ => None,
            }
        } else if key
            .as_string_key()
            .is_some_and(|name| name.ends_with(BLOB_ID_SUFFIX))
        {
            match IdReference::parse(value) {
                IdReference::Value(value) => JSCalendarValue::BlobId(value).into(),
                IdReference::Reference(value) => JSCalendarValue::IdReference(value).into(),
                IdReference::Error => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JSCalendarValue::Type(v) => v.as_str().into(),
            JSCalendarValue::DateTime(v) => v.to_rfc3339().into(),
            JSCalendarValue::Duration(v) => v.to_string().into(),
            JSCalendarValue::AlertAction(v) => v.as_str().into(),
            JSCalendarValue::FreeBusyStatus(v) => v.as_str().into(),
            JSCalendarValue::ParticipantKind(v) => v.as_str().into(),
            JSCalendarValue::ParticipationStatus(v) => v.as_str().into(),
            JSCalendarValue::Privacy(v) => v.as_str().into(),
            JSCalendarValue::Progress(v) => v.as_str().into(),
            JSCalendarValue::RelativeTo(v) => v.as_str().into(),
            JSCalendarValue::ScheduleAgent(v) => v.as_str().into(),
            JSCalendarValue::EventStatus(v) => v.as_str().into(),
            JSCalendarValue::LinkRelation(v) => v.as_str().into(),
            JSCalendarValue::Frequency(v) => v.as_js_str().into(),
            JSCalendarValue::CalendarScale(v) => v.as_js_str().into(),
            JSCalendarValue::Skip(v) => v.as_js_str().into(),
            JSCalendarValue::Weekday(v) => v.as_js_str().into(),
            JSCalendarValue::Month(v) => v.to_string().into(),
            JSCalendarValue::Method(v) => v.as_js_str().into(),
            JSCalendarValue::Id(v) => v.to_string().into(),
            JSCalendarValue::BlobId(v) => v.to_string().into(),
            JSCalendarValue::IdReference(s) => s.to_id_reference().into(),
        }
    }

    #[inline]
    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JSCalendarValue::DateTime(_)
            | JSCalendarValue::Duration(_)
            | JSCalendarValue::Month(_)
            | JSCalendarValue::Id(_)
            | JSCalendarValue::BlobId(_)
            | JSCalendarValue::IdReference(_) => self.serialize_data_text(serializer),
            _ => serializer.serialize_str(&self.to_cow()),
        }
    }
}

impl<I: JSCalendarId, B: JSCalendarId> JSCalendarValue<I, B> {
    #[inline(never)]
    fn serialize_data_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StackText::<VALUE_TEXT>::serialize(
            serializer,
            |text| match self {
                JSCalendarValue::DateTime(date_time) => date_time.push_rfc3339(text),
                JSCalendarValue::Duration(duration) => text.push_duration(duration.parts()),
                JSCalendarValue::Month(month) => write!(text, "{month}"),
                JSCalendarValue::Id(id) => write!(text, "{id}"),
                JSCalendarValue::BlobId(id) => write!(text, "{id}"),
                JSCalendarValue::IdReference(id) => text.push_id_reference(id),
                _ => Err(fmt::Error),
            },
            || self.to_cow(),
        )
    }
}

impl<I: JSCalendarId> jmap_tools::Property for JSCalendarProperty<I> {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        Self::try_parse_nested(key, value, PointerDepth::default())
    }

    fn try_parse_nested(
        key: Option<&Key<'_, Self>>,
        value: &str,
        depth: PointerDepth,
    ) -> Option<Self> {
        match key {
            Some(Key::Property(key)) if key.is_metadata() => None,
            Some(Key::Property(key)) => match key.patch_or_prop() {
                JSCalendarProperty::RecurrenceOverrides => {
                    JSCalendarDateTime::from_rfc3339(value, true).map(JSCalendarProperty::DateTime)
                }
                JSCalendarProperty::Display => JSCalendarLinkDisplay::from_str(value)
                    .ok()
                    .map(JSCalendarProperty::LinkDisplay),
                JSCalendarProperty::Features => JSCalendarVirtualLocationFeature::from_str(value)
                    .ok()
                    .map(JSCalendarProperty::VirtualLocationFeature),
                JSCalendarProperty::Roles => JSCalendarParticipantRole::from_str(value)
                    .ok()
                    .map(JSCalendarProperty::ParticipantRole),
                JSCalendarProperty::Relation => JSCalendarRelation::from_str(value)
                    .ok()
                    .map(JSCalendarProperty::RelationValue),
                JSCalendarProperty::ConvertedProperties => {
                    JsonPointer::parse_nested(value, depth).map(JSCalendarProperty::Pointer)
                }
                JSCalendarProperty::DateTime(_) if value.contains('/') => {
                    JsonPointer::parse_nested(value, depth).map(JSCalendarProperty::Pointer)
                }
                JSCalendarProperty::DateTime(_) | JSCalendarProperty::Entries => {
                    JSCalendarProperty::parse_name(value)
                }
                JSCalendarProperty::CalendarIds => match IdReference::parse(value) {
                    IdReference::Value(value) => JSCalendarProperty::IdValue(value).into(),
                    IdReference::Reference(value) => JSCalendarProperty::IdReference(value).into(),
                    IdReference::Error => None,
                },
                _ => JSCalendarProperty::parse_nested_name(value),
            },
            None if value.contains('/') => {
                JsonPointer::parse_nested(value, depth).map(JSCalendarProperty::Pointer)
            }
            None => JSCalendarProperty::parse_name(value),
            Some(_) => JSCalendarProperty::parse_nested_name(value),
        }
    }

    fn is_opaque(&self) -> bool {
        self.is_metadata()
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JSCalendarProperty::DateTime(dt) => dt.to_rfc3339().into(),
            JSCalendarProperty::Pointer(pointer) => pointer.to_text().into(),
            JSCalendarProperty::IdReference(id) => id.to_id_reference().into(),
            _ => self.to_string(),
        }
    }

    #[inline]
    fn key_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (a, b) if !a.has_data() && !b.has_data() => discriminant(a) == discriminant(b),
            (JSCalendarProperty::DateTime(a), JSCalendarProperty::DateTime(b)) => a.same_rfc3339(b),
            _ => self.data_key_eq(other),
        }
    }

    #[inline]
    fn key_eq_str(&self, other: &str) -> bool {
        if !self.has_data() {
            self.to_string() == other
        } else {
            self.data_key_eq_str(other)
        }
    }

    #[inline]
    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JSCalendarProperty::DateTime(_)
            | JSCalendarProperty::Pointer(_)
            | JSCalendarProperty::IdValue(_)
            | JSCalendarProperty::IdReference(_) => self.serialize_data_text(serializer),
            _ => serializer.serialize_str(&self.to_cow()),
        }
    }
}

pub(crate) const BLOB_ID_SUFFIX: &str = "/blobId";

impl<I: JSCalendarId> JSCalendarProperty<I> {
    #[inline(never)]
    fn data_key_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JSCalendarProperty::Pointer(a), JSCalendarProperty::Pointer(b)) if a == b => true,
            _ => match (self.static_name(), other.static_name()) {
                (Some(a), Some(b)) => a == b,
                (Some(a), None) => other.data_key_eq_str(a),
                (None, Some(b)) => self.data_key_eq_str(b),
                (None, None) => other.data_key_eq_str(&self.to_string()),
            },
        }
    }

    #[inline(never)]
    fn data_key_eq_str(&self, other: &str) -> bool {
        match self {
            JSCalendarProperty::DateTime(date_time) => date_time.rfc3339_eq(other),
            JSCalendarProperty::IdValue(id) => id.display_eq(other),
            JSCalendarProperty::Pointer(pointer) => pointer.text_eq(other),
            JSCalendarProperty::IdReference(reference) => {
                other.strip_prefix('#') == Some(reference.as_str())
            }
            JSCalendarProperty::LinkRelation(relation) => relation.as_str() == other,
            _ => self.to_string() == other,
        }
    }

    #[inline(never)]
    fn serialize_data_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StackText::<KEY_TEXT>::serialize(
            serializer,
            |text| match self {
                JSCalendarProperty::DateTime(date_time) => date_time.push_rfc3339(text),
                JSCalendarProperty::Pointer(pointer) => {
                    text.push_pointer(pointer, Self::push_pointer_key)
                }
                JSCalendarProperty::IdValue(id) => write!(text, "{id}"),
                JSCalendarProperty::IdReference(id) => text.push_id_reference(id),
                _ => Err(fmt::Error),
            },
            || self.to_cow(),
        )
    }

    fn push_pointer_key<const N: usize>(&self, text: &mut StackText<N>) -> fmt::Result {
        match self {
            JSCalendarProperty::DateTime(date_time) => date_time.push_rfc3339(text),
            property => text.push_pointer_token(&property.to_cow()),
        }
    }

    fn patch_or_prop(&self) -> &JSCalendarProperty<I> {
        let mut property = self;
        while let JSCalendarProperty::Pointer(ptr) = property {
            match ptr.last() {
                Some(JsonPointerItem::Key(Key::Property(inner))) => property = inner,
                _ => break,
            }
        }
        property
    }
}

impl JSCalendarDateTime {
    pub(crate) fn from_rfc3339(value: &str, is_local: bool) -> Option<Self> {
        let timestamp = match value.as_bytes() {
            [
                y0,
                y1,
                y2,
                y3,
                b'-',
                m0,
                m1,
                b'-',
                d0,
                d1,
                b'T',
                h0,
                h1,
                b':',
                i0,
                i1,
                b':',
                s0,
                s1,
                rest @ ..,
            ] if matches!(rest, [] | [b'Z'])
                && [y0, y1, y2, y3, m0, m1, d0, d1, h0, h1, i0, i1, s0, s1]
                    .iter()
                    .all(|digit| digit.is_ascii_digit()) =>
            {
                let pair = |high: &u8, low: &u8| (high - b'0') * 10 + (low - b'0');
                DateTime {
                    year: u16::from(pair(y0, y1)) * 100 + u16::from(pair(y2, y3)),
                    month: pair(m0, m1),
                    day: pair(d0, d1),
                    hour: pair(h0, h1),
                    minute: pair(i0, i1),
                    second: pair(s0, s1),
                    tz_before_gmt: false,
                    tz_hour: 0,
                    tz_minute: 0,
                }
                .to_timestamp_local()
            }
            _ => DateTime::parse_rfc3339(value)?.to_timestamp_local(),
        };
        Some(JSCalendarDateTime {
            timestamp,
            is_local,
        })
    }

    #[inline]
    fn same_rfc3339(&self, other: &Self) -> bool {
        self.is_local == other.is_local
            && (self.timestamp == other.timestamp
                || (!FOUR_DIGIT_YEARS.contains(&self.timestamp)
                    || !FOUR_DIGIT_YEARS.contains(&other.timestamp))
                    && self.same_wide_rfc3339(other))
    }

    #[inline(never)]
    fn same_wide_rfc3339(&self, other: &Self) -> bool {
        self.to_rfc3339() == other.to_rfc3339()
    }

    fn rfc3339_eq(&self, text: &str) -> bool {
        let mut expect = Expect::new(text);
        self.push_rfc3339(&mut expect).is_ok() && expect.is_complete()
    }

    pub(crate) fn push_rfc3339(&self, text: &mut impl AsciiPush) -> fmt::Result {
        let dt = DateTime::from_timestamp(self.timestamp);
        text.push_4_digits(dt.year)?;
        text.push_byte(b'-')?;
        text.push_2_digits(dt.month)?;
        text.push_byte(b'-')?;
        text.push_2_digits(dt.day)?;
        text.push_byte(b'T')?;
        text.push_2_digits(dt.hour)?;
        text.push_byte(b':')?;
        text.push_2_digits(dt.minute)?;
        text.push_byte(b':')?;
        text.push_2_digits(dt.second)?;
        if self.is_local {
            Ok(())
        } else {
            text.push_byte(b'Z')
        }
    }
}

pub(crate) struct StackText<const N: usize> {
    len: usize,
    bytes: [u8; N],
}

impl<const N: usize> StackText<N> {
    pub(crate) fn serialize<S: Serializer>(
        serializer: S,
        push: impl FnOnce(&mut Self) -> fmt::Result,
        fallback: impl FnOnce() -> Cow<'static, str>,
    ) -> Result<S::Ok, S::Error> {
        let mut text = StackText {
            len: 0,
            bytes: [0; N],
        };
        match push(&mut text).ok().and_then(|()| text.as_str()) {
            Some(text) => serializer.serialize_str(text),
            None => serializer.serialize_str(&fallback()),
        }
    }

    fn as_str(&self) -> Option<&str> {
        self.bytes
            .get(..self.len)
            .and_then(|bytes| from_utf8(bytes).ok())
    }

    pub(crate) fn push_pointer<P: jmap_tools::Property>(
        &mut self,
        pointer: &JsonPointer<P>,
        push_key: impl Fn(&P, &mut Self) -> fmt::Result,
    ) -> fmt::Result {
        for (pos, item) in pointer.as_slice().iter().enumerate() {
            if pos > 0 {
                self.push_byte(b'/')?;
            }
            match item {
                JsonPointerItem::Root => {}
                JsonPointerItem::Wildcard => self.push_byte(b'*')?,
                JsonPointerItem::Invalid(invalid) => self.write_str(invalid)?,
                JsonPointerItem::Key(Key::Property(property)) => push_key(property, self)?,
                JsonPointerItem::Key(Key::Borrowed(key)) => self.push_pointer_token(key)?,
                JsonPointerItem::Key(Key::Owned(key)) => self.push_pointer_token(key)?,
                JsonPointerItem::Number(number) => self.push_u64(*number)?,
            }
        }
        Ok(())
    }

    pub(crate) fn push_id_reference(&mut self, id: &str) -> fmt::Result {
        self.push_byte(b'#')?;
        self.write_str(id)
    }

    #[inline(always)]
    fn push_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        let end = self.len + bytes.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl<const N: usize> PointerText for StackText<N> {}

impl<const N: usize> AsciiPush for StackText<N> {
    #[inline(always)]
    fn push_ascii(&mut self, bytes: &[u8]) -> fmt::Result {
        self.push_bytes(bytes)
    }
}

impl<const N: usize> Write for StackText<N> {
    #[inline(always)]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_bytes(text.as_bytes())
    }
}

