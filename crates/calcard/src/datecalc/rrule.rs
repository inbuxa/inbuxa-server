/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Turns a parsed `RRULE` property into an expandable recurrence rule.

use super::{
    error::{RRuleError, ValidationError},
    recurrence::{ByWeekday, RecurrenceIter, RecurrenceRule},
};
use crate::{
    common::{
        CalendarScale,
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::{ICalendarFrequency, ICalendarRecurrenceRule},
};
use jiff::{Unit, civil::Time};

const END_OF_DAY: Time = Time::constant(23, 59, 0, 0);

/// A recurrence rule bound to the start of its series.
#[derive(Clone, Debug)]
pub struct RRule {
    rule: RecurrenceRule,
}

impl RRule {
    /// Builds a rule from a parsed `RRULE` and the start of its series.
    pub fn from_ical(
        rule: &ICalendarRecurrenceRule,
        dt_start: ZonedDateTime,
        is_date: bool,
    ) -> Result<Self, RRuleError> {
        // A non-Gregorian calendar scale puts instances on entirely different
        // dates, so expanding the rule as though the scale were absent would
        // silently produce the wrong ones.
        if let Some(rscale) = rule
            .rscale
            .as_ref()
            .filter(|rscale| **rscale != CalendarScale::Gregorian)
        {
            return Err(ValidationError::UnsupportedCalendarScale(rscale.clone()).into());
        }

        let mut builder = RecurrenceRule::builder(rule.freq, dt_start);

        if let Some(interval) = rule.interval.filter(|interval| *interval > 0) {
            builder.interval(i32::from(interval));
        }
        if let Some(count) = rule.count {
            builder.count(count);
        }
        if let Some(until) = rule.until.as_ref().and_then(|until| until.to_date_time()) {
            let tz = dt_start.timezone();
            let until = if is_date && until.offset.is_some() {
                let written = until.date_time;
                let last_day = if written.time() >= END_OF_DAY {
                    Some(written.date())
                } else {
                    written.round(Unit::Day).ok().map(|day| day.date())
                };
                last_day.and_then(|day| tz.from_local(day.to_datetime(Time::MAX)))
            } else {
                until.to_date_time_with_tz(tz)
            };
            if let Some(until) = until {
                builder.until(until);
            }
        }
        if let Some(wkst) = rule.wkst {
            builder.week_start(wkst.into());
        }

        builder.by_month(
            rule.bymonth
                .iter()
                .map(|month| month.month() as i8)
                .collect::<Vec<_>>(),
        );
        let by_week: &[i8] = if rule.freq == ICalendarFrequency::Yearly {
            &rule.byweekno
        } else {
            &[]
        };
        let by_year_day: &[i16] = if matches!(
            rule.freq,
            ICalendarFrequency::Monthly | ICalendarFrequency::Weekly | ICalendarFrequency::Daily
        ) {
            &[]
        } else {
            &rule.byyearday
        };
        let by_month_day: &[i8] = if rule.freq == ICalendarFrequency::Weekly {
            &[]
        } else {
            &rule.bymonthday
        };
        let numbered_weekdays = rule.freq == ICalendarFrequency::Monthly
            || (rule.freq == ICalendarFrequency::Yearly && by_week.is_empty());

        builder.by_week(by_week);
        builder.by_year_day(by_year_day);
        builder.by_month_day(by_month_day);
        builder.by_week_day(
            rule.byday
                .iter()
                .map(|day| match day.ordwk.filter(|_| numbered_weekdays) {
                    Some(nth) => ByWeekday::Numbered {
                        nth: i8::try_from(nth).unwrap_or(i8::MAX),
                        weekday: day.weekday.into(),
                    },
                    None => ByWeekday::Any(day.weekday.into()),
                })
                .collect::<Vec<_>>(),
        );
        builder.by_hour(rule.byhour.iter().map(|v| *v as i8).collect::<Vec<_>>());
        builder.by_minute(rule.byminute.iter().map(|v| *v as i8).collect::<Vec<_>>());
        builder.by_second(rule.bysecond.iter().map(|v| *v as i8).collect::<Vec<_>>());
        let set_position_alone = rule.bymonth.is_empty()
            && by_week.is_empty()
            && by_year_day.is_empty()
            && by_month_day.is_empty()
            && rule.byday.is_empty()
            && rule.byhour.is_empty()
            && rule.byminute.is_empty()
            && rule.bysecond.is_empty();
        if !set_position_alone {
            builder.by_set_position(rule.bysetpos.as_slice());
        } else if !rule.bysetpos.is_empty()
            && !rule.bysetpos.iter().any(|position| position.abs() == 1)
        {
            builder.count(0);
        }

        Ok(RRule {
            rule: builder.build()?,
        })
    }

    /// Returns an iterator over the instances this rule generates.
    pub fn iter(&self) -> RecurrenceIter<'_> {
        self.rule.iter()
    }

    /// Returns the time zone instances are generated in.
    pub fn tz(&self) -> Tz {
        self.rule.tz()
    }
}
