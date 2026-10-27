/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ICalendar, ICalendarDay, ICalendarDuration, ICalendarEntry, ICalendarPeriod,
    ICalendarRecurrenceRule, ICalendarValueType,
};
use crate::{
    common::{
        CalendarScale, IanaString, PartialDateTime,
        format::{AsciiPush, BufferedWrite, DurationParts},
        stack::ComponentStack,
        writer::{
            DOCUMENT_BUFFER, ENTRY_BUFFER, FoldingWriter, LineWriter, VisitedComponents,
            write_param_text, write_param_value, write_quoted_param_value, write_text, write_uri,
        },
    },
    icalendar::{
        ICalendarMonth, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarValue, Uri, ValueSeparator,
    },
};
use std::{
    fmt::{self, Display, Write},
    slice::Iter,
};

pub(crate) const RRULE_BUFFER: usize = 256;
pub(crate) const DURATION_BUFFER: usize = 64;
pub(crate) const DATE_BUFFER: usize = 32;
pub(crate) const PERIOD_BUFFER: usize = 96;

impl ICalendar {
    pub fn write_to(&self, out: &mut impl Write) -> fmt::Result {
        out.write_buffered::<DOCUMENT_BUFFER>(|buf| {
            self.write_components(&mut FoldingWriter::new(buf))
        })
    }

    fn write_components<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
    ) -> fmt::Result {
        let mut component_iter: Iter<'_, u32> = [0].iter();
        let mut component_stack = ComponentStack::new();
        let mut visited = VisitedComponents::new(self.components.len());

        loop {
            if let Some(component_id) = component_iter.next() {
                let component_id = *component_id as usize;
                let Some(component) = self
                    .components
                    .get(component_id)
                    .filter(|_| visited.insert(component_id))
                else {
                    continue;
                };
                out.write_boundary("BEGIN:", component.component_type.as_str())?;

                for entry in &component.entries {
                    if !matches!(
                        entry.name,
                        ICalendarProperty::Begin | ICalendarProperty::End
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

impl ICalendarEntry {
    pub fn write_to(&self, out: &mut impl Write) -> fmt::Result {
        self.write_with_value(out, true)
    }

    pub fn write_with_value(&self, out: &mut impl Write, with_value: bool) -> fmt::Result {
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

        if matches!(self.values.first(), Some(ICalendarValue::Binary(_))) {
            out.write_atomic(";ENCODING=BASE64")?;
            if !self
                .params
                .iter()
                .any(|param| param.name == ICalendarParameterName::Value)
            {
                out.write_atomic(";VALUE=BINARY")?;
            }
        }

        let mut types = None;
        let mut last_param: Option<&ICalendarParameterName> = None;

        for param in &self.params {
            if last_param.is_some_and(|last_param| last_param == &param.name) {
                out.write_atomic(",")?;
            } else {
                out.write_atomic(";")?;
                out.write_atomic(param.name.as_str())?;
                if !matches!(param.value, ICalendarParameterValue::Null) {
                    out.write_atomic("=")?;
                }
                last_param = Some(&param.name);
            }

            match &param.value {
                ICalendarParameterValue::Text(v)
                    if matches!(param.name, ICalendarParameterName::Jsptr) =>
                {
                    write_quoted_param_value(out, v, true)?;
                }
                ICalendarParameterValue::Text(v) => {
                    write_param_value(out, v, true)?;
                }
                ICalendarParameterValue::Integer(i) => {
                    out.push_u64(*i)?;
                }
                ICalendarParameterValue::Bool(v) => {
                    let v = if !matches!(param.name, ICalendarParameterName::Range) {
                        if *v { "TRUE" } else { "FALSE" }
                    } else {
                        "THISANDFUTURE"
                    };
                    out.write_atomic(v)?;
                }
                ICalendarParameterValue::Uri(uri) => {
                    out.write_atomic("\"")?;
                    uri.write_param_text(out)?;
                    out.write_atomic("\"")?;
                }
                ICalendarParameterValue::Cutype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Fbtype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Partstat(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Related(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Reltype(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Role(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::ScheduleAgent(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::ScheduleForceSend(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Value(v) => {
                    types = Some(v);
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Display(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Feature(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Duration(v) => {
                    out.push_duration(v.parts())?;
                }
                ICalendarParameterValue::Linkrel(v) => {
                    write_param_value(out, v.as_str(), true)?;
                }
                ICalendarParameterValue::Null => {
                    last_param = None;
                }
            }
        }

        out.write_atomic(":")?;

        if !with_value {
            return out.end_line();
        }

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
                ICalendarValue::Binary(v) => {
                    out.write_base64(v)?;
                    continue;
                }
                ICalendarValue::Boolean(v) => {
                    out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                    continue;
                }
                ICalendarValue::Uri(v) => {
                    v.write_value(out)?;
                    continue;
                }
                ICalendarValue::PartialDateTime(v) => {
                    v.push_ical(out, types.unwrap_or(&default_type))?;
                    continue;
                }
                ICalendarValue::Duration(v) => {
                    out.push_duration(v.parts())?;
                    continue;
                }
                ICalendarValue::RecurrenceRule(v) => {
                    v.push_to(out)?;
                    continue;
                }
                ICalendarValue::Period(v) => {
                    v.push_to(out)?;
                    continue;
                }
                ICalendarValue::Float(v) => {
                    write!(out, "{v}")?;
                    continue;
                }
                ICalendarValue::Integer(v) => {
                    out.push_i64(*v)?;
                    continue;
                }
                ICalendarValue::Text(v) => {
                    match types.unwrap_or(&default_type) {
                        ICalendarValueType::Uri | ICalendarValueType::CalAddress => {
                            write_uri(out, v)?;
                        }
                        ICalendarValueType::Recur => write_text(out, v, false, false)?,
                        _ => write_text(out, v, true, true)?,
                    }
                    continue;
                }
                ICalendarValue::CalendarScale(v) => v.as_str(),
                ICalendarValue::Method(v) => v.as_str(),
                ICalendarValue::Classification(v) => v.as_str(),
                ICalendarValue::Status(v) => v.as_str(),
                ICalendarValue::Transparency(v) => v.as_str(),
                ICalendarValue::Action(v) => v.as_str(),
                ICalendarValue::BusyType(v) => v.as_str(),
                ICalendarValue::ParticipantType(v) => v.as_str(),
                ICalendarValue::ResourceType(v) => v.as_str(),
                ICalendarValue::Proximity(v) => v.as_str(),
            };

            out.write_atomic(text)?;
        }

        out.end_line()
    }
}

impl Uri {
    fn write_value(&self, out: &mut impl LineWriter) -> fmt::Result {
        match self {
            Uri::Data(v) => {
                out.write_str("data:")?;
                out.write_str(v.content_type.as_deref().unwrap_or_default())?;
                out.write_str(";")?;
                out.write_atomic("base64,")?;
                out.write_base64(&v.data)
            }
            Uri::Location(v) => write_uri(out, v),
        }
    }

    fn write_param_text(&self, out: &mut impl LineWriter) -> fmt::Result {
        match self {
            Uri::Data(v) => {
                out.write_str("data:")?;
                write_param_text(out, v.content_type.as_deref().unwrap_or_default(), true)?;
                out.write_str(";")?;
                out.write_atomic("base64,")?;
                out.write_base64(&v.data)
            }
            Uri::Location(v) => write_param_text(out, v, true),
        }
    }
}

impl Uri {
    pub fn to_unwrapped_string(&self) -> String {
        match self {
            Uri::Data(v) => v.to_unwrapped_string(),
            Uri::Location(v) => v.to_string(),
        }
    }

    pub fn into_unwrapped_string(self) -> String {
        match self {
            Uri::Data(v) => v.to_unwrapped_string(),
            Uri::Location(v) => v,
        }
    }
}

impl ICalendarRecurrenceRule {
    pub(crate) fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        buf.push_ascii_str("FREQ=")?;
        buf.push_ascii_str(self.freq.as_str())?;
        if let Some(until) = &self.until {
            buf.push_ascii_str(";UNTIL=")?;
            until.push_ical(
                buf,
                if until.has_date_and_time() {
                    &ICalendarValueType::DateTime
                } else {
                    &ICalendarValueType::Date
                },
            )?;
        }
        if let Some(count) = self.count.filter(|c| *c > 0) {
            buf.push_ascii_str(";COUNT=")?;
            buf.push_u64(count.into())?;
        }
        if let Some(interval) = self.interval {
            buf.push_ascii_str(";INTERVAL=")?;
            buf.push_u64(interval.into())?;
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
            buf.push_i64((*item).into())
        })?;
        buf.push_list(";BYWEEKNO=", &self.byweekno, |buf, item| {
            buf.push_i64((*item).into())
        })?;
        buf.push_list(";BYMONTH=", &self.bymonth, |buf, item| item.push_to(buf))?;
        buf.push_list(";BYSETPOS=", &self.bysetpos, |buf, item| {
            buf.push_i64((*item).into())
        })?;
        if let Some(wkst) = self.wkst {
            buf.push_ascii_str(";WKST=")?;
            buf.push_ascii_str(wkst.as_str())?;
        }
        if let Some(rscale) = &self.rscale {
            buf.push_ascii_str(";RSCALE=")?;
            buf.push_ascii_str(rscale.as_str())?;
        } else if self.skip.is_some() {
            buf.push_ascii_str(";RSCALE=")?;
            buf.push_ascii_str(CalendarScale::Gregorian.as_str())?;
        }
        if let Some(skip) = &self.skip {
            buf.push_ascii_str(";SKIP=")?;
            buf.push_ascii_str(skip.as_str())?;
        }

        Ok(())
    }
}

impl Display for ICalendarRecurrenceRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<RRULE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ICalendarDay {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        if let Some(ordwk) = self.ordwk {
            buf.push_i64(ordwk.into())?;
        }
        buf.push_ascii_str(self.weekday.as_str())
    }
}

impl Display for ICalendarDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DATE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ICalendarMonth {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        buf.push_u64(self.month().into())?;
        if self.is_leap() {
            buf.push_byte(b'L')?;
        }
        Ok(())
    }
}

impl Display for ICalendarMonth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DATE_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ICalendarPeriod {
    fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        match self {
            ICalendarPeriod::Range { start, end } => {
                start.push_ical(buf, &ICalendarValueType::DateTime)?;
                buf.push_byte(b'/')?;
                end.push_ical(buf, &ICalendarValueType::DateTime)
            }
            ICalendarPeriod::Duration { start, duration } => {
                start.push_ical(buf, &ICalendarValueType::DateTime)?;
                buf.push_byte(b'/')?;
                buf.push_duration(duration.parts())
            }
        }
    }
}

impl Display for ICalendarPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<PERIOD_BUFFER>(|buf| self.push_to(buf))
    }
}

impl ICalendarDuration {
    pub(crate) fn parts(&self) -> DurationParts {
        DurationParts {
            neg: self.neg,
            weeks: self.weeks,
            days: self.days,
            hours: self.hours,
            minutes: self.minutes,
            seconds: self.seconds,
        }
    }
}

impl Display for ICalendarDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<DURATION_BUFFER>(|buf| buf.push_duration(self.parts()))
    }
}

impl PartialDateTime {
    pub fn format_as_ical(&self, out: &mut impl Write, fmt: &ICalendarValueType) -> fmt::Result {
        out.write_buffered::<DATE_BUFFER>(|buf| self.push_ical(buf, fmt))
    }

    pub(crate) fn push_ical(
        &self,
        buf: &mut impl AsciiPush,
        fmt: &ICalendarValueType,
    ) -> fmt::Result {
        if matches!(fmt, ICalendarValueType::Date | ICalendarValueType::DateTime) {
            buf.push_4_digits(self.year.unwrap_or_default())?;
            buf.push_2_digits(self.month.unwrap_or_default())?;
            buf.push_2_digits(self.day.unwrap_or_default())?;
        }

        if matches!(fmt, ICalendarValueType::DateTime) {
            buf.push_byte(b'T')?;
        }

        if matches!(fmt, ICalendarValueType::DateTime | ICalendarValueType::Time) {
            buf.push_2_digits(self.hour.unwrap_or_default())?;
            buf.push_2_digits(self.minute.unwrap_or_default())?;
            buf.push_2_digits(self.second.unwrap_or_default())?;

            if matches!((self.tz_hour, self.tz_minute), (Some(0), Some(0))) {
                buf.push_byte(b'Z')?;
            }
        }

        if matches!(fmt, ICalendarValueType::UtcOffset) {
            buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
            buf.push_2_digits(self.tz_hour.unwrap_or_default())?;
            buf.push_2_digits(self.tz_minute.unwrap_or_default())?;
        }

        Ok(())
    }
}

impl Display for ICalendar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

