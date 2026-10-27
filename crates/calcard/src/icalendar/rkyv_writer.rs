/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    common::{
        ArchivedPartialDateTime, CalendarScale, PartialDateTime,
        format::{AsciiPush, BufferedWrite, DurationParts},
        stack::ComponentStack,
        writer::{
            DOCUMENT_BUFFER, ENTRY_BUFFER, FoldingWriter, LineWriter, VisitedComponents,
            write_param_text, write_param_value, write_quoted_param_value, write_text, write_uri,
        },
    },
    icalendar::{
        ValueSeparator,
        writer::{DATE_BUFFER, DURATION_BUFFER, PERIOD_BUFFER, RRULE_BUFFER},
    },
};
use std::{
    fmt::{self, Display, Write},
    slice::Iter,
};

impl ArchivedICalendar {
    pub fn write_to(&self, out: &mut impl Write) -> fmt::Result {
        out.write_buffered::<DOCUMENT_BUFFER>(|buf| {
            self.write_components(&mut FoldingWriter::new(buf))
        })
    }

    fn write_components<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
    ) -> fmt::Result {
        let _v = [0.into()];
        let mut component_iter: Iter<'_, rkyv::primitive::ArchivedU32> = _v.iter();
        let mut component_stack = ComponentStack::new();
        let mut visited = VisitedComponents::new(self.components.len());

        loop {
            if let Some(component_id) = component_iter.next() {
                let component_id = component_id.to_native() as usize;
                let Some(component) = self
                    .components
                    .get(component_id)
                    .filter(|_| visited.insert(component_id))
                else {
                    continue;
                };
                out.write_boundary("BEGIN:", component.component_type.as_str())?;

                for entry in component.entries.iter() {
                    if !matches!(
                        entry.name,
                        ArchivedICalendarProperty::Begin | ArchivedICalendarProperty::End
                    ) {
                        entry.write_line(out, true)?;
                    }
                }

                if !component.component_ids.is_empty() {
                    component_stack.push((component, component_iter));
                    component_iter = component.component_ids.iter();
                } else {
                    out.write_boundary("END:", component.component_type.as_str())?;
                }
            } else if let Some((component, iter)) = component_stack.pop() {
                out.write_boundary("END:", component.component_type.as_str())?;
                component_iter = iter;
            } else {
                break;
            }
        }

        Ok(())
    }
}

impl ArchivedICalendarEntry {
    pub fn write_to(&self, out: &mut impl Write, with_value: bool) -> fmt::Result {
        out.write_buffered::<ENTRY_BUFFER>(|buf| {
            self.write_line(&mut FoldingWriter::new(buf), with_value)
        })
    }

    pub(crate) fn write_line<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
        with_value: bool,
    ) -> fmt::Result {
        out.write_atomic(self.name.as_str())?;

        if matches!(
            self.values.first().as_ref(),
            Some(ArchivedICalendarValue::Binary(_))
        ) {
            out.write_atomic(";ENCODING=BASE64")?;
            if !self
                .params
                .iter()
                .any(|param| param.name == ArchivedICalendarParameterName::Value)
            {
                out.write_atomic(";VALUE=BINARY")?;
            }
        }

        let mut types = None;
        let mut last_param: Option<&ArchivedICalendarParameterName> = None;

        for param in self.params.iter() {
            if last_param.is_some_and(|last_param| last_param == &param.name) {
                out.write_atomic(",")?;
            } else {
                out.write_atomic(";")?;
                out.write_atomic(param.name.as_str())?;
                if !matches!(param.value, ArchivedICalendarParameterValue::Null) {
                    out.write_atomic("=")?;
                }
                last_param = Some(&param.name);
            }

            match &param.value {
                ArchivedICalendarParameterValue::Text(v)
                    if matches!(param.name, ArchivedICalendarParameterName::Jsptr) =>
                {
                    write_quoted_param_value(out, v, true)?;
                }
                ArchivedICalendarParameterValue::Text(v) => {
                    write_param_value(out, v, true)?;
                }
                ArchivedICalendarParameterValue::Integer(i) => {
                    out.push_u64(i.to_native())?;
                }
                ArchivedICalendarParameterValue::Bool(v) => {
                    let v = if !matches!(param.name, ArchivedICalendarParameterName::Range) {
                        if *v { "TRUE" } else { "FALSE" }
                    } else {
                        "THISANDFUTURE"
                    };
                    out.write_atomic(v)?;
                }
                ArchivedICalendarParameterValue::Uri(uri) => {
                    out.write_atomic("\"")?;
                    uri.write_param_text(out)?;
                    out.write_atomic("\"")?;
                }
                ArchivedICalendarParameterValue::Cutype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Fbtype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Partstat(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Related(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Reltype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Role(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::ScheduleAgent(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::ScheduleForceSend(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Value(v) => {
                    types = Some(v);
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Display(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Feature(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Duration(v) => {
                    out.push_duration(v.parts())?;
                }
                ArchivedICalendarParameterValue::Linkrel(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ArchivedICalendarParameterValue::Null => {
                    last_param = None;
                }
            }
        }

        out.write_atomic(":")?;

        if with_value {
            let (default_type, separator) = self.name.default_types();
            let separator = if !matches!(separator, ValueSeparator::Comma) {
                ";"
            } else {
                ","
            };
            let default_type = default_type.unwrap_ical();

            for (pos, value) in self.values.iter().enumerate() {
                if pos > 0 {
                    out.write_atomic(separator)?;
                }

                let text = match value {
                    ArchivedICalendarValue::Binary(v) => {
                        out.write_base64(v)?;
                        continue;
                    }
                    ArchivedICalendarValue::Boolean(v) => {
                        out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                        continue;
                    }
                    ArchivedICalendarValue::Uri(v) => {
                        v.write_value(out)?;
                        continue;
                    }
                    ArchivedICalendarValue::PartialDateTime(v) => {
                        PartialDateTime::from(v).push_ical(
                            out,
                            &ICalendarValueType::from(types.unwrap_or(&default_type)),
                        )?;
                        continue;
                    }
                    ArchivedICalendarValue::Duration(v) => {
                        out.push_duration(v.parts())?;
                        continue;
                    }
                    ArchivedICalendarValue::RecurrenceRule(v) => {
                        v.push_to(out)?;
                        continue;
                    }
                    ArchivedICalendarValue::Period(v) => {
                        v.push_to(out)?;
                        continue;
                    }
                    ArchivedICalendarValue::Float(v) => {
                        write!(out, "{v}")?;
                        continue;
                    }
                    ArchivedICalendarValue::Integer(v) => {
                        out.push_i64(v.to_native())?;
                        continue;
                    }
                    ArchivedICalendarValue::Text(v) => {
                        match types.unwrap_or(&default_type) {
                            ArchivedICalendarValueType::Uri
                            | ArchivedICalendarValueType::CalAddress => {
                                write_uri(out, v)?;
                            }
                            ArchivedICalendarValueType::Recur => write_text(out, v, false, false)?,
                            _ => write_text(out, v, true, true)?,
                        }
                        continue;
                    }
                    ArchivedICalendarValue::CalendarScale(v) => v.as_str(),
                    ArchivedICalendarValue::Method(v) => v.as_str(),
                    ArchivedICalendarValue::Classification(v) => v.as_str(),
                    ArchivedICalendarValue::Status(v) => v.as_str(),
                    ArchivedICalendarValue::Transparency(v) => v.as_str(),
                    ArchivedICalendarValue::Action(v) => v.as_str(),
                    ArchivedICalendarValue::BusyType(v) => v.as_str(),
                    ArchivedICalendarValue::ParticipantType(v) => v.as_str(),
                    ArchivedICalendarValue::ResourceType(v) => v.as_str(),
                    ArchivedICalendarValue::Proximity(v) => v.as_str(),
                };

                out.write_atomic(text)?;
            }
        }
        out.end_line()
    }
}

impl ArchivedUri {
    fn write_value(&self, out: &mut impl LineWriter) -> fmt::Result {
        match self {
            ArchivedUri::Data(v) => {
                out.write_str("data:")?;
                out.write_str(v.content_type.as_deref().unwrap_or_default())?;
                out.write_str(";")?;
                out.write_atomic("base64,")?;
                out.write_base64(&v.data)
            }
            ArchivedUri::Location(v) => write_uri(out, v),
        }
    }

    fn write_param_text(&self, out: &mut impl LineWriter) -> fmt::Result {
        match self {
            ArchivedUri::Data(v) => {
                out.write_str("data:")?;
                write_param_text(out, v.content_type.as_deref().unwrap_or_default(), true)?;
                out.write_str(";")?;
                out.write_atomic("base64,")?;
                out.write_base64(&v.data)
            }
            ArchivedUri::Location(v) => write_param_text(out, v, true),
        }
    }
}

impl ArchivedICalendarRecurrenceRule {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        buf.push_ascii_str("FREQ=")?;
        buf.push_ascii_str(self.freq.as_str())?;
        if let Some(until) = self.until.as_ref() {
            buf.push_ascii_str(";UNTIL=")?;
            PartialDateTime::from(until).push_ical(
                buf,
                if until.has_date_and_time() {
                    &ICalendarValueType::DateTime
                } else {
                    &ICalendarValueType::Date
                },
            )?;
        }
        if let Some(count) = self.count.as_ref().filter(|c| **c > 0) {
            buf.push_ascii_str(";COUNT=")?;
            buf.push_u64(count.to_native().into())?;
        }
        if let Some(interval) = self.interval.as_ref() {
            buf.push_ascii_str(";INTERVAL=")?;
            buf.push_u64(interval.to_native().into())?;
        }
        buf.push_list(";BYSECOND=", &self.bysecond, |buf, item| {
            buf.push_u64((*item).into())
        })?;
        buf.push_list(";BYMINUTE=", &self.byminute, |buf, item| {
            buf.push_u64((*item).into())
        })?;
        buf.push_list(";BYHOUR=", &self.byhour, |buf, item| {
            buf.push_u64((*item).into())
        })?;
        buf.push_list(";BYDAY=", &self.byday, |buf, item| item.push_to(buf))?;
        buf.push_list(";BYMONTHDAY=", &self.bymonthday, |buf, item| {
            buf.push_i64((*item).into())
        })?;
        buf.push_list(";BYYEARDAY=", &self.byyearday, |buf, item| {
            buf.push_i64(item.to_native().into())
        })?;
        buf.push_list(";BYWEEKNO=", &self.byweekno, |buf, item| {
            buf.push_i64((*item).into())
        })?;
        buf.push_list(";BYMONTH=", &self.bymonth, |buf, item| item.push_to(buf))?;
        buf.push_list(";BYSETPOS=", &self.bysetpos, |buf, item| {
            buf.push_i64(item.to_native().into())
        })?;
        if let Some(wkst) = self.wkst.as_ref() {
            buf.push_ascii_str(";WKST=")?;
            buf.push_ascii_str(wkst.as_str())?;
        }
        if let Some(rscale) = self.rscale.as_ref() {
            buf.push_ascii_str(";RSCALE=")?;
            buf.push_ascii_str(rscale.as_str())?;
        } else if self.skip.is_some() {
            buf.push_ascii_str(";RSCALE=")?;
            buf.push_ascii_str(CalendarScale::Gregorian.as_str())?;
        }
        if let Some(skip) = self.skip.as_ref() {
            buf.push_ascii_str(";SKIP=")?;
            buf.push_ascii_str(skip.as_str())?;
        }

        Ok(())
    }
}

impl Display for ArchivedICalendarRecurrenceRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<RRULE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ArchivedICalendarDay {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        if let Some(ordwk) = self.ordwk.as_ref() {
            buf.push_i64(ordwk.to_native().into())?;
        }
        buf.push_ascii_str(self.weekday.as_str())
    }
}

impl Display for ArchivedICalendarDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DATE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ArchivedICalendarMonth {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        buf.push_u64(self.month().into())?;
        if self.is_leap() {
            buf.push_byte(b'L')?;
        }
        Ok(())
    }
}

impl Display for ArchivedICalendarMonth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DATE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ArchivedICalendarPeriod {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        match self {
            ArchivedICalendarPeriod::Range { start, end } => {
                PartialDateTime::from(start).push_ical(buf, &ICalendarValueType::DateTime)?;
                buf.push_byte(b'/')?;
                PartialDateTime::from(end).push_ical(buf, &ICalendarValueType::DateTime)
            }
            ArchivedICalendarPeriod::Duration { start, duration } => {
                PartialDateTime::from(start).push_ical(buf, &ICalendarValueType::DateTime)?;
                buf.push_byte(b'/')?;
                buf.push_duration(duration.parts())
            }
        }
    }
}

impl Display for ArchivedICalendarPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<PERIOD_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ArchivedICalendarDuration {
    fn parts(&self) -> DurationParts {
        DurationParts {
            neg: self.neg,
            weeks: self.weeks.to_native(),
            days: self.days.to_native(),
            hours: self.hours.to_native(),
            minutes: self.minutes.to_native(),
            seconds: self.seconds.to_native(),
        }
    }
}

impl Display for ArchivedICalendarDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DURATION_BUFFER>(|buf| buf.push_duration(self.parts()))
    }
}

impl ArchivedPartialDateTime {
    pub fn format_as_ical(
        &self,
        out: &mut impl Write,
        fmt: &ArchivedICalendarValueType,
    ) -> fmt::Result {
        PartialDateTime::from(self).format_as_ical(out, &ICalendarValueType::from(fmt))
    }
}

impl From<&ArchivedICalendarValueType> for ICalendarValueType {
    fn from(value_type: &ArchivedICalendarValueType) -> Self {
        match value_type {
            ArchivedICalendarValueType::Binary => ICalendarValueType::Binary,
            ArchivedICalendarValueType::Boolean => ICalendarValueType::Boolean,
            ArchivedICalendarValueType::CalAddress => ICalendarValueType::CalAddress,
            ArchivedICalendarValueType::Date => ICalendarValueType::Date,
            ArchivedICalendarValueType::DateTime => ICalendarValueType::DateTime,
            ArchivedICalendarValueType::Duration => ICalendarValueType::Duration,
            ArchivedICalendarValueType::Float => ICalendarValueType::Float,
            ArchivedICalendarValueType::Integer => ICalendarValueType::Integer,
            ArchivedICalendarValueType::Period => ICalendarValueType::Period,
            ArchivedICalendarValueType::Recur => ICalendarValueType::Recur,
            ArchivedICalendarValueType::Text => ICalendarValueType::Text,
            ArchivedICalendarValueType::Time => ICalendarValueType::Time,
            ArchivedICalendarValueType::Unknown => ICalendarValueType::Unknown,
            ArchivedICalendarValueType::Uri => ICalendarValueType::Uri,
            ArchivedICalendarValueType::UtcOffset => ICalendarValueType::UtcOffset,
            ArchivedICalendarValueType::XmlReference => ICalendarValueType::XmlReference,
            ArchivedICalendarValueType::Uid => ICalendarValueType::Uid,
        }
    }
}

impl Display for ArchivedICalendar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}
