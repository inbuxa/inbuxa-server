/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    Entry, Parser, StopChar, Token,
    common::{
        CalendarScale, Encoding, PartialDateTime,
        decode::{Decoded, ValueDecoder},
        parser::{Boolean, Integer, parse_digits, parse_small_digits},
        stack::ComponentStack,
        tokenizer::Mode,
    },
    icalendar::{ICalendarDay, ICalendarWeekday},
};
use smallvec::{SmallVec, smallvec};
use std::{iter::Peekable, mem::take, slice::Iter};

const EMPTY_CALENDAR_LINE: &str = "BEGIN:VCALENDAR";
const COMPONENT_CAPACITY: usize = 4;

impl ICalendar {
    fn into_entry(self, strict: bool) -> Entry {
        if strict
            && self
                .calendar_root()
                .is_some_and(|root| root.component_ids.is_empty())
        {
            Entry::InvalidLine(EMPTY_CALENDAR_LINE.to_string())
        } else {
            Entry::ICalendar(self)
        }
    }
}

struct Params {
    params: Vec<ICalendarParameter>,
    stop_char: StopChar,
    data_type: Option<IanaType<ICalendarValueType, String>>,
    charset: Option<String>,
    encoding: Option<Encoding>,
}

impl Params {
    fn decode_value(
        &self,
        token: &mut Token<'_>,
        payload: Option<Vec<u8>>,
        encoding: Encoding,
        name: &ICalendarProperty,
    ) -> Option<Vec<u8>> {
        let binary = match &self.data_type {
            Some(data_type) => data_type == &IanaType::Iana(ICalendarValueType::Binary),
            None => {
                encoding == Encoding::Base64
                    && matches!(name, ICalendarProperty::Attach | ICalendarProperty::Image)
            }
        };
        let decoder = ValueDecoder {
            encoding,
            charset: self.charset.as_deref(),
            binary,
        };
        match decoder.decode(&token.text, token.stop_char, payload) {
            Decoded::Text(text) => {
                token.text = text.into();
                None
            }
            Decoded::Binary(bytes) => Some(bytes),
            Decoded::Undecodable => None,
        }
    }

    fn value(&mut self, token: Token<'_>, default_type: &ValueType) -> ICalendarValue {
        let value_type = match default_type {
            ValueType::Ical(default_type) => self
                .data_type
                .as_ref()
                .map(|v| v.iana().unwrap_or(&ICalendarValueType::Text))
                .unwrap_or(default_type),
            ValueType::CalendarScale => {
                return IanaType::from(token).map_or_text(ICalendarValue::CalendarScale);
            }
            ValueType::Method => return IanaType::from(token).map_or_text(ICalendarValue::Method),
            ValueType::Classification => {
                return IanaType::from(token).map_or_text(ICalendarValue::Classification);
            }
            ValueType::Status => return IanaType::from(token).map_or_text(ICalendarValue::Status),
            ValueType::Transparency => {
                return IanaType::from(token).map_or_text(ICalendarValue::Transparency);
            }
            ValueType::Action => return IanaType::from(token).map_or_text(ICalendarValue::Action),
            ValueType::BusyType => {
                return IanaType::from(token).map_or_text(ICalendarValue::BusyType);
            }
            ValueType::ParticipantType => {
                return IanaType::from(token).map_or_text(ICalendarValue::ParticipantType);
            }
            ValueType::ResourceType => {
                return IanaType::from(token).map_or_text(ICalendarValue::ResourceType);
            }
            ValueType::Proximity => {
                return IanaType::from(token).map_or_text(ICalendarValue::Proximity);
            }
        };
        match value_type {
            ICalendarValueType::Date => token
                .into_ical_date()
                .map(ICalendarValue::PartialDateTime)
                .unwrap_or_else(ICalendarValue::Text),
            ICalendarValueType::DateTime => match token.into_timestamp(false) {
                Ok(timestamp) => {
                    if !timestamp.has_time() {
                        self.data_type = Some(IanaType::Iana(ICalendarValueType::Date));
                    }
                    ICalendarValue::PartialDateTime(timestamp)
                }
                Err(other) => ICalendarValue::Text(other),
            },
            ICalendarValueType::Time => token
                .into_ical_time()
                .map(ICalendarValue::PartialDateTime)
                .unwrap_or_else(ICalendarValue::Text),
            ICalendarValueType::UtcOffset => token
                .into_offset()
                .map(ICalendarValue::PartialDateTime)
                .unwrap_or_else(ICalendarValue::Text),
            ICalendarValueType::Boolean => ICalendarValue::Boolean(token.into_boolean()),
            ICalendarValueType::Float => token
                .into_float()
                .map(ICalendarValue::Float)
                .unwrap_or_else(ICalendarValue::Text),
            ICalendarValueType::Integer => token
                .into_integer()
                .map(ICalendarValue::Integer)
                .unwrap_or_else(ICalendarValue::Text),
            ICalendarValueType::Uri | ICalendarValueType::CalAddress => token
                .into_uri_bytes()
                .map(|data| ICalendarValue::Uri(Uri::from(data)))
                .unwrap_or_else(|uri| ICalendarValue::Uri(Uri::Location(uri))),
            ICalendarValueType::Duration => match ICalendarDuration::parse(token.text.as_ref()) {
                Some(duration) => ICalendarValue::Duration(duration),
                None => ICalendarValue::Text(token.into_string()),
            },
            ICalendarValueType::Period => match ICalendarPeriod::parse(token.text.as_ref()) {
                Some(period) => ICalendarValue::Period(Box::new(period)),
                None => ICalendarValue::Text(token.into_string()),
            },
            ICalendarValueType::Text
            | ICalendarValueType::Binary
            | ICalendarValueType::Unknown
            | ICalendarValueType::XmlReference
            | ICalendarValueType::Uid
            | ICalendarValueType::Recur => ICalendarValue::Text(token.into_string()),
        }
    }

    fn push_known(&mut self, name: &ICalendarParameterName, token: Token<'_>) {
        let value = match name {
            ICalendarParameterName::Altrep
            | ICalendarParameterName::DelegatedFrom
            | ICalendarParameterName::DelegatedTo
            | ICalendarParameterName::Dir
            | ICalendarParameterName::Member
            | ICalendarParameterName::SentBy
            | ICalendarParameterName::Schema => ICalendarParameterValue::Uri(Uri::from(token)),
            ICalendarParameterName::Rsvp | ICalendarParameterName::Derived => {
                IanaType::<Boolean, String>::from(token).into()
            }
            ICalendarParameterName::Range => {
                if token.text.as_ref().eq_ignore_ascii_case(b"THISANDFUTURE") {
                    ICalendarParameterValue::Bool(true)
                } else {
                    return;
                }
            }
            ICalendarParameterName::Size | ICalendarParameterName::Order => {
                IanaType::<Integer, String>::from(token).into()
            }
            ICalendarParameterName::Gap => {
                IanaType::<ICalendarDuration, String>::from(token).into()
            }
            ICalendarParameterName::Cutype => {
                IanaType::<ICalendarUserTypes, String>::from(token).into()
            }
            ICalendarParameterName::Fbtype => {
                IanaType::<ICalendarFreeBusyType, String>::from(token).into()
            }
            ICalendarParameterName::Partstat => {
                IanaType::<ICalendarParticipationStatus, String>::from(token).into()
            }
            ICalendarParameterName::Related => {
                IanaType::<ICalendarRelated, String>::from(token).into()
            }
            ICalendarParameterName::Reltype => {
                IanaType::<ICalendarRelationshipType, String>::from(token).into()
            }
            ICalendarParameterName::Role => {
                IanaType::<ICalendarParticipationRole, String>::from(token).into()
            }
            ICalendarParameterName::ScheduleAgent => {
                IanaType::<ICalendarScheduleAgentValue, String>::from(token).into()
            }
            ICalendarParameterName::ScheduleForceSend => {
                IanaType::<ICalendarScheduleForceSendValue, String>::from(token).into()
            }
            ICalendarParameterName::Value => {
                self.data_type = Some(token.into());
                return;
            }
            ICalendarParameterName::Display => {
                IanaType::<ICalendarDisplayType, String>::from(token).into()
            }
            ICalendarParameterName::Feature => {
                IanaType::<ICalendarFeatureType, String>::from(token).into()
            }
            ICalendarParameterName::Linkrel => IanaType::<LinkRelation, String>::from(token).into(),
            _ => ICalendarParameterValue::Text(token.into_string()),
        };
        self.params
            .push(ICalendarParameter::new(name.clone(), value));
    }
}

trait IntoValue<I> {
    fn map_or_text(self, iana: impl FnOnce(I) -> ICalendarValue) -> ICalendarValue;
}

impl<I> IntoValue<I> for IanaType<I, String> {
    fn map_or_text(self, iana: impl FnOnce(I) -> ICalendarValue) -> ICalendarValue {
        match self {
            IanaType::Iana(value) => iana(value),
            IanaType::Other(value) => ICalendarValue::Text(value),
        }
    }
}

enum ParamKind {
    Known(ICalendarParameterName),
    Charset,
    Encoding,
    Other(ICalendarParameterName),
    Pending,
}

impl ParamKind {
    fn classify(token: Token<'_>, params: &mut Params) -> Self {
        let name = token.text.as_ref();
        if let Some(name) = ICalendarParameterName::try_parse(name) {
            return ParamKind::Known(name);
        }
        match name.first() {
            None => ParamKind::Pending,
            Some(b'c' | b'C') if name.eq_ignore_ascii_case(b"charset") => ParamKind::Charset,
            Some(b'e' | b'E') if name.eq_ignore_ascii_case(b"encoding") => ParamKind::Encoding,
            _ if params.encoding.is_none() && name.eq_ignore_ascii_case(b"base64") => {
                params.encoding = Some(Encoding::Base64);
                ParamKind::Pending
            }
            _ => ParamKind::Other(ICalendarParameterName::Other(token.into_string())),
        }
    }
}

#[derive(Default)]
struct ParamValues {
    count: usize,
    last_other: Option<String>,
}

impl ParamValues {
    fn push(&mut self, kind: &ParamKind, token: Token<'_>, params: &mut Params) {
        self.count += 1;
        match kind {
            ParamKind::Known(name) => params.push_known(name, token),
            ParamKind::Charset => params.charset = Some(token.into_string()),
            ParamKind::Encoding => params.encoding = Encoding::parse(token.text.as_ref()),
            ParamKind::Other(name) => {
                if let Some(value) = self.last_other.replace(token.into_string()) {
                    params.params.push(ICalendarParameter::new(
                        name.clone(),
                        ICalendarParameterValue::Text(value),
                    ));
                }
            }
            ParamKind::Pending => {}
        }
    }

    fn finish(self, kind: ParamKind, params: &mut Params) {
        match kind {
            ParamKind::Known(name) if self.count == 0 => {
                params
                    .params
                    .push(ICalendarParameter::new(name, ICalendarParameterValue::Null));
            }
            ParamKind::Other(name) => params.params.push(ICalendarParameter::new(
                name,
                self.last_other
                    .map_or(ICalendarParameterValue::Null, ICalendarParameterValue::Text),
            )),
            _ => {}
        }
    }
}

impl Parser<'_> {
    pub fn icalendar(&mut self, component_type: ICalendarComponentType) -> Entry {
        let mut components = Vec::with_capacity(COMPONENT_CAPACITY);
        components.push(ICalendarComponent {
            component_type,
            ..Default::default()
        });
        let mut parents = ComponentStack::new();
        let mut current = 0;
        let mut next_component_id: u32 = 1;

        loop {
            self.expect_iana_token();
            let Some(name) = self.token() else {
                break;
            };
            let property = ICalendarProperty::parse(name.text.as_ref());

            let mut params = Params {
                params: Vec::new(),
                stop_char: name.stop_char,
                data_type: None,
                encoding: None,
                charset: None,
            };

            match params.stop_char {
                StopChar::Semicolon => {
                    params.params = Vec::with_capacity(
                        property
                            .as_ref()
                            .map_or(0, ICalendarProperty::parameter_capacity),
                    );
                    self.ical_parameters(&mut params);
                }
                StopChar::Colon => {}
                StopChar::Lf => {
                    if name.text.is_empty() || !self.strict {
                        continue;
                    } else {
                        return Entry::InvalidLine(name.into_string());
                    }
                }
                StopChar::Comma | StopChar::Equal | StopChar::Dot => {
                    params.stop_char = self.seek_value_or_eol();
                }
            }

            let name = match property {
                Some(ICalendarProperty::Begin) => {
                    if params.stop_char == StopChar::Colon
                        && let Some(component_type) = self.component_type()
                    {
                        if let Some(parent) = components.get_mut(current) {
                            parent.component_ids.push(next_component_id);
                        }
                        components.push(ICalendarComponent {
                            component_type,
                            ..Default::default()
                        });
                        parents.push(current);
                        current = next_component_id as usize;
                        let Some(id) = next_component_id.checked_add(1) else {
                            return Entry::TooManyComponents;
                        };
                        next_component_id = id;
                        continue;
                    }

                    if !self.strict {
                        continue;
                    } else {
                        return Entry::InvalidLine("BEGIN".to_string());
                    }
                }
                Some(ICalendarProperty::End) => {
                    if params.stop_char == StopChar::Colon
                        && let Some(component_type) = self.component_type()
                    {
                        let open_type = components
                            .get(current)
                            .map(|component| &component.component_type);
                        if open_type == Some(&component_type) || !self.strict {
                            if let Some(parent) = parents.pop() {
                                current = parent;
                                continue;
                            } else {
                                break;
                            }
                        } else {
                            return Entry::UnexpectedComponentEnd {
                                expected: open_type.cloned().unwrap_or_default(),
                                found: component_type,
                            };
                        }
                    }

                    if !self.strict {
                        continue;
                    } else {
                        return Entry::InvalidLine("END".to_string());
                    }
                }
                Some(name) => name,
                None => {
                    if !name.text.is_empty() {
                        ICalendarProperty::Other(name.into_string())
                    } else {
                        if params.stop_char != StopChar::Lf {
                            self.seek_lf();
                        }
                        continue;
                    }
                }
            };

            let entry = self.ical_entry(name, params);
            if let Some(component) = components.get_mut(current) {
                if component.entries.capacity() == 0 {
                    self.presize(
                        &mut component.entries,
                        component.component_type.entry_capacity(),
                    );
                }
                component.entries.push(entry);
            }
        }

        if !parents.is_empty() && self.strict {
            return Entry::UnterminatedComponent(
                components
                    .get(current)
                    .map_or("", |component| component.component_type.as_str())
                    .to_string()
                    .into(),
            );
        }

        ICalendar { components }.into_entry(self.strict)
    }

    fn component_type(&mut self) -> Option<ICalendarComponentType> {
        self.expect_single_value();
        self.token().map(|token| {
            ICalendarComponentType::parse(token.text.as_ref())
                .unwrap_or_else(|| ICalendarComponentType::Other(token.into_string()))
        })
    }

    fn ical_entry(&mut self, name: ICalendarProperty, mut params: Params) -> ICalendarEntry {
        let mut entry = ICalendarEntry {
            name,
            params: take(&mut params.params),
            values: SmallVec::new(),
        };

        if params.stop_char != StopChar::Lf {
            let (default_type, multi_value) = entry.name.default_types();
            match multi_value {
                ValueSeparator::None => {
                    self.expect_single_value();
                }
                ValueSeparator::Comma => {
                    self.expect_multi_value_comma();
                }
                ValueSeparator::Semicolon => {
                    self.expect_multi_value_semicolon();
                }
            }

            match params.encoding {
                Some(Encoding::Base64) if multi_value != ValueSeparator::None => {
                    self.expect_single_value();
                }
                Some(Encoding::QuotedPrintable) => {
                    self.mode.set(Mode::UNFOLD_QP, true);
                }
                _ => {}
            }

            self.mode.set(
                Mode::UNESCAPE_BACKSLASH,
                !matches!(
                    params
                        .data_type
                        .as_ref()
                        .map(|data_type| data_type.iana().unwrap_or(&ICalendarValueType::Text))
                        .or(match &default_type {
                            ValueType::Ical(default_type) => Some(default_type),
                            _ => None,
                        }),
                    Some(ICalendarValueType::Uri | ICalendarValueType::CalAddress)
                ),
            );

            if matches!(
                (&params.data_type, &default_type),
                (Some(IanaType::Iana(ICalendarValueType::Recur)), _)
                    | (None, ValueType::Ical(ICalendarValueType::Recur))
            ) {
                entry.values = smallvec![match self.rrule() {
                    Ok(rrule) => ICalendarValue::RecurrenceRule(Box::new(rrule)),
                    Err(other) => ICalendarValue::Text(other),
                }];
            } else {
                let mut payload = None;
                while let Some(mut token) = self.value_token(params.encoding, &mut payload) {
                    let eol = token.stop_char == StopChar::Lf;

                    if token.text.is_empty()
                        && (matches!(multi_value, ValueSeparator::None)
                            || matches!(entry.name, ICalendarProperty::Other(_))
                                && entry.values.is_empty())
                    {
                        if eol {
                            break;
                        } else {
                            continue;
                        }
                    }

                    let value = if let Some(encoding) = params.encoding
                        && let Some(binary) =
                            params.decode_value(&mut token, payload.take(), encoding, &entry.name)
                    {
                        params.data_type = Some(IanaType::Iana(ICalendarValueType::Binary));
                        ICalendarValue::Binary(binary)
                    } else {
                        params.value(token, &default_type)
                    };
                    entry.values.push(value);

                    if eol {
                        break;
                    }
                }
            }
        }

        if let Some(data_type) = params.data_type {
            entry.params.push(ICalendarParameter {
                name: ICalendarParameterName::Value,
                value: match data_type {
                    IanaType::Iana(value) => ICalendarParameterValue::Value(value),
                    IanaType::Other(value) => ICalendarParameterValue::Text(value),
                },
            });
        }

        entry
    }

    fn ical_parameters(&mut self, params: &mut Params) {
        while params.stop_char == StopChar::Semicolon {
            self.expect_iana_token();
            let Some(token) = self.token() else {
                params.stop_char = StopChar::Lf;
                break;
            };
            params.stop_char = token.stop_char;
            let kind = ParamKind::classify(token, params);
            let buffered = matches!(kind, ParamKind::Pending) || !self.token_buf.is_empty();
            let mut values = ParamValues::default();

            if !matches!(
                params.stop_char,
                StopChar::Lf | StopChar::Colon | StopChar::Semicolon
            ) {
                if params.stop_char != StopChar::Equal {
                    params.stop_char = self.seek_param_value_or_eol();
                }
                if params.stop_char == StopChar::Equal {
                    self.expect_param_value();
                    while !matches!(
                        params.stop_char,
                        StopChar::Lf | StopChar::Colon | StopChar::Semicolon
                    ) {
                        match self.token() {
                            Some(token) => {
                                params.stop_char = token.stop_char;
                                if buffered {
                                    self.token_buf.push(token);
                                } else {
                                    values.push(&kind, token, params);
                                }
                            }
                            None => {
                                params.stop_char = StopChar::Lf;
                                break;
                            }
                        }
                    }
                }
            }

            if buffered {
                self.buffered_param(kind, params);
            } else {
                values.finish(kind, params);
            }
        }
    }

    fn buffered_param(&mut self, kind: ParamKind, params: &mut Params) {
        match kind {
            ParamKind::Known(name) => {
                if self.token_buf.is_empty() {
                    params
                        .params
                        .push(ICalendarParameter::new(name, ICalendarParameterValue::Null));
                } else {
                    for token in self.token_buf.drain(..) {
                        params.push_known(&name, token);
                    }
                }
            }
            ParamKind::Charset => {
                for token in self.token_buf.drain(..) {
                    params.charset = token.into_string().into();
                }
            }
            ParamKind::Encoding => {
                for token in self.token_buf.drain(..) {
                    params.encoding = Encoding::parse(token.text.as_ref());
                }
            }
            ParamKind::Other(name) => {
                if self.token_buf.is_empty() {
                    params
                        .params
                        .push(ICalendarParameter::new(name, ICalendarParameterValue::Null));
                } else {
                    params.params.extend(self.token_buf.drain(..).map(|token| {
                        ICalendarParameter::new(
                            name.clone(),
                            ICalendarParameterValue::Text(token.into_string()),
                        )
                    }));
                }
            }
            ParamKind::Pending => {}
        }
    }

    pub(crate) fn rrule(&mut self) -> Result<ICalendarRecurrenceRule, String> {
        self.expect_rrule_value();

        let mut last_stop_char = StopChar::Equal;
        let mut is_valid = true;
        let mut has_freq = false;
        let mut rrule = ICalendarRecurrenceRule::default();

        let mut token_start = usize::MAX;

        while let Some(mut token) = self.token_until_lf(&mut last_stop_char) {
            if token_start == usize::MAX && !token.text.is_empty() {
                token_start = token.start;
            }
            if !is_valid {
                continue;
            }
            if token.text.is_empty() && token.stop_char != StopChar::Equal {
                continue;
            }
            if token.stop_char != StopChar::Equal {
                if !self.strict {
                    // Ignore unknown tokens
                    while let Some(token_) = self.token_until_lf(&mut last_stop_char) {
                        if token_.stop_char == StopChar::Equal {
                            token = token_;
                            break;
                        }
                    }
                    if token.stop_char != StopChar::Equal {
                        is_valid = false;
                        continue;
                    }
                } else {
                    is_valid = false;
                    continue;
                }
            }

            hashify::fnc_map_ignore_case!(token.text.as_ref(),
                b"FREQ" => {
                    while let Some(value) = self.parse_value_until_lf(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.freq = value;
                            has_freq = true;
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"UNTIL" => {
                    while let Some(value) = self.parse_value_until_lf::<ICalendarDateOrTime>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.until = Some(value.0);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"COUNT" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            let count = value.0.unsigned_abs() as u32;
                            if count > 0 {
                                rrule.count = Some(count);
                            }
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"INTERVAL" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            let interval = value.0.unsigned_abs() as u16;
                            if interval > 0 {
                                rrule.interval = Some(interval);
                            }
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYSECOND" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.bysecond.push(value.0.unsigned_abs() as u8);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYMINUTE" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.byminute.push(value.0.unsigned_abs() as u8);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYHOUR" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.byhour.push(value.0.unsigned_abs() as u8);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYDAY" => {
                    while let Some(value) = self.parse_value_until_lf::<ICalendarDay>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.byday.push(value);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYMONTHDAY" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.bymonthday.push(value.0 as i8);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYYEARDAY" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.byyearday.push(value.0 as i16);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYWEEKNO" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.byweekno.push(value.0 as i8);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYMONTH" => {
                    while let Some(value) = self.parse_value_until_lf::<ICalendarMonth>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.bymonth.push(value);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"BYSETPOS" => {
                    while let Some(value) = self.parse_value_until_lf::<Integer>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.bysetpos.push(value.0 as i32);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"WKST" => {
                    while let Some(value) = self.parse_value_until_lf::<ICalendarWeekday>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.wkst = Some(value);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"RSCALE" => {
                    while let Some(value) = self.parse_value_until_lf::<CalendarScale>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.rscale = Some(value);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                b"SKIP" => {
                    while let Some(value) = self.parse_value_until_lf::<ICalendarSkip>(StopChar::Semicolon, &mut last_stop_char) {                        if let Some(value)= value {
                            rrule.skip = Some(value);
                        } else if !self.strict {
                            is_valid = false;
                        }
                    }
                },
                _ => {
                    if !self.strict {
                        // Ignore unknown tokens
                        while let Some(token) = self.token_until_lf(&mut last_stop_char) {                            if token.stop_char == StopChar::Semicolon{
                                break;
                            }
                        }
                    } else {
                        is_valid = false;
                    }
                }
            );
        }

        if has_freq && is_valid {
            Ok(rrule)
        } else if token_start != usize::MAX && self.last_token_end >= token_start {
            Err(self
                .input
                .get(token_start..=self.last_token_end)
                .map(|slice| {
                    let mut buf = Vec::with_capacity(slice.len());
                    let mut iter = slice.iter().peekable();

                    while let Some(ch) = iter.next() {
                        match ch {
                            b'\r' => {}
                            b'\n' => {
                                iter.next_if(|ch| matches!(ch, b' ' | b'\t'));
                            }
                            _ => buf.push(*ch),
                        }
                    }

                    String::from_utf8(buf)
                        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
                })
                .unwrap_or_default())
        } else {
            Err("".to_string())
        }
    }
}

impl Token<'_> {
    pub(crate) fn into_ical_date(self) -> std::result::Result<PartialDateTime, String> {
        if let Some(dt) = self
            .text
            .first_chunk::<8>()
            .and_then(PartialDateTime::from_basic_date)
        {
            return Ok(dt);
        }
        let mut dt = PartialDateTime::default();
        if dt.parse_ical_date(&mut self.text.iter().peekable()) {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_ical_time(self) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        if dt.parse_ical_time(&mut self.text.iter().peekable()) {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }
}

impl PartialDateTime {
    pub fn parse_ical_date(&mut self, iter: &mut Peekable<Iter<'_, u8>>) -> bool {
        parse_digits(iter, &mut self.year, 4, false)
            && parse_small_digits(iter, &mut self.month, 2, false)
            && parse_small_digits(iter, &mut self.day, 2, false)
    }

    pub fn parse_ical_time(&mut self, iter: &mut Peekable<Iter<'_, u8>>) -> bool {
        if parse_small_digits(iter, &mut self.hour, 2, false)
            && parse_small_digits(iter, &mut self.minute, 2, false)
            && parse_small_digits(iter, &mut self.second, 2, false)
        {
            self.parse_zone(iter);
            true
        } else {
            false
        }
    }
}

struct ICalendarDateOrTime(PartialDateTime);

impl IanaParse for ICalendarDateOrTime {
    fn parse(value: &[u8]) -> Option<Self> {
        match PartialDateTime::from_timestamp_bytes(value, false) {
            (dt, true) => Some(ICalendarDateOrTime(dt)),
            (_, false) => None,
        }
    }
}

impl IanaParse for ICalendarPeriod {
    fn parse(value: &[u8]) -> Option<Self> {
        let mut iter = value.iter().peekable();
        let mut start = PartialDateTime::default();
        if start.parse_timestamp(&mut iter, true) {
            if let Some(duration) = ICalendarDuration::try_parse(&mut iter) {
                Some(ICalendarPeriod::Duration { start, duration })
            } else {
                let mut end = PartialDateTime::default();
                if end.parse_timestamp(&mut iter, true) {
                    Some(ICalendarPeriod::Range { start, end })
                } else {
                    None
                }
            }
        } else {
            None
        }
    }
}

impl IanaParse for ICalendarMonth {
    fn parse(value: &[u8]) -> Option<Self> {
        let mut num: i8 = 0;
        let mut is_leap = false;

        for (pos, ch) in value.iter().enumerate() {
            match ch {
                b'L' | b'l' if pos > 0 => {
                    is_leap = true;
                }
                b'0'..=b'9' => {
                    num = num.saturating_mul(10).saturating_add((*ch - b'0') as i8);
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return None;
                    }
                }
            }
        }

        Some(ICalendarMonth(if is_leap { -num } else { num }))
    }
}

impl ICalendarMonth {
    pub fn new(month: u8, is_leap: bool) -> Self {
        let month = i8::try_from(month).unwrap_or(i8::MAX);
        ICalendarMonth(if is_leap { -month } else { month })
    }

    pub fn is_leap(&self) -> bool {
        self.0 < 0
    }

    pub fn month(&self) -> u8 {
        self.0.unsigned_abs()
    }
}

impl From<ICalendarMonth> for u8 {
    fn from(value: ICalendarMonth) -> Self {
        value.month()
    }
}

impl ICalendarDuration {
    fn try_parse(iter: &mut Peekable<Iter<'_, u8>>) -> Option<Self> {
        let mut dur = ICalendarDuration::default();
        loop {
            match iter.peek() {
                Some(b'P' | b'p') => {
                    iter.next();
                    break;
                }
                Some(b'+') => {
                    iter.next();
                }
                Some(b'-') if !dur.neg => {
                    iter.next();
                    dur.neg = true;
                }
                Some(b' ' | b'\t') => {
                    iter.next();
                }
                _ => {
                    return None;
                }
            }
        }

        let mut num: u32 = 0;
        let mut saw_component = false;
        for ch in iter {
            match ch {
                b'0'..=b'9' => {
                    num = num.saturating_mul(10).saturating_add((ch - b'0') as u32);
                }
                b'T' | b't' => {}
                b'W' | b'w' => {
                    dur.weeks = num;
                    num = 0;
                    saw_component = true;
                }
                b'D' | b'd' => {
                    dur.days = num;
                    num = 0;
                    saw_component = true;
                }
                b'H' | b'h' => {
                    dur.hours = num;
                    num = 0;
                    saw_component = true;
                }
                b'M' | b'm' => {
                    dur.minutes = num;
                    num = 0;
                    saw_component = true;
                }
                b'S' | b's' => {
                    dur.seconds = num;
                    num = 0;
                    saw_component = true;
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return None;
                    }
                }
            }
        }

        if saw_component { Some(dur) } else { None }
    }
}

impl IanaParse for ICalendarDuration {
    fn parse(value: &[u8]) -> Option<Self> {
        ICalendarDuration::try_parse(&mut value.iter().peekable())
    }
}

impl From<Token<'_>> for Uri {
    fn from(token: Token<'_>) -> Self {
        token
            .into_uri_bytes()
            .map(Uri::from)
            .unwrap_or_else(Uri::Location)
    }
}

impl IanaParse for ICalendarDay {
    fn parse(value: &[u8]) -> Option<Self> {
        let mut iter = value.iter().enumerate();
        let mut is_negative = false;
        let mut has_ordwk = false;
        let mut ordwk: i16 = 0;

        loop {
            let (pos, ch) = iter.next()?;

            match ch {
                b'0'..=b'9' => {
                    ordwk = ordwk.saturating_mul(10).saturating_add((ch - b'0') as i16);
                    has_ordwk = true;
                }
                b'-' if pos == 0 => {
                    is_negative = true;
                }
                b'+' if pos == 0 => {}
                b'A'..=b'Z' | b'a'..=b'z' => {
                    return ICalendarWeekday::parse(value.get(pos..).unwrap_or_default()).map(
                        |weekday| ICalendarDay {
                            ordwk: has_ordwk.then_some(if is_negative { -ordwk } else { ordwk }),
                            weekday,
                        },
                    );
                }
                _ => return None,
            }
        }
    }
}

impl Uri {
    pub fn parse(value: impl Into<String>) -> Self {
        let uri = value.into();
        Data::try_parse(uri.as_bytes())
            .map(Uri::from)
            .unwrap_or_else(|| Uri::Location(uri))
    }
}

