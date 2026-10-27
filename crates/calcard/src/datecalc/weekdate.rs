/*
 * SPDX-FileCopyrightText: 2025 Andrew Gallant <jamslam@gmail.com> (https://github.com/BurntSushi/bttf)
 *
 * SPDX-License-Identifier: Unlicense OR MIT
 */

//! Week dates under an arbitrary week start.
//!
//! RFC 5545 lets a rule choose the day a week starts on (WKST), so BYWEEKNO
//! cannot use [`jiff::civil::ISOWeekDate`], which always starts on Monday.
//!
//! Ported from `bttf`, with the `anyhow` errors replaced by `Option`: every
//! failure here means a date outside the supported range, which a recurrence
//! rule skips rather than reports.

use jiff::{
    ToSpan,
    civil::{Date, Weekday},
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct WeekDate {
    // The weekday on which this week date calendar starts weeks. This is the
    // key difference from `jiff::civil::ISOWeekDate`, which always starts on
    // Monday.
    start: Weekday,
    year: i16,
    week: i8,
    weekday: Weekday,
}

impl WeekDate {
    /// Create a new week date.
    ///
    /// `year` must be in the range `-9999..=9999`. `week` must be in the range
    /// `1..=53`, although `53` is only valid for "long" years.
    ///
    /// `start` corresponds to how the week numbering scheme determines the
    /// start of a week.
    pub(crate) fn new(start: Weekday, year: i16, week: i8, weekday: Weekday) -> Option<WeekDate> {
        if !(1..=53).contains(&week) || (week == 53 && !is_long_year(start, year)) {
            return None;
        }
        if year == -9999 || year == 9999 {
            let start_of_year = week_start_of_year(start, year)?;
            let mut days = i32::from(week - 1) * 7;
            days += i32::from(weekday.since(start));
            if start_of_year.checked_add(days.days()).is_err() {
                return None;
            }
        }
        Some(WeekDate {
            start,
            year,
            week,
            weekday,
        })
    }

    /// Returns a new week date for the given Gregorian date.
    ///
    /// The week date uses a week numbering scheme where the given weekday
    /// is the first day in the week. That is, the first week date of a year
    /// starts on the given weekday and is the first week whose majority of
    /// days (>= 4) falls in the same Gregorian year.
    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn from_date(start: Weekday, date: Date) -> Option<WeekDate> {
        let mut start_of_year = week_start_of_year(start, date.year())?;
        if date < start_of_year {
            start_of_year = week_start_of_year(start, date.year() - 1)?;
        } else {
            let next = date.year() + 1;
            // This fails when `date` is in year 9999, which is Jiff's maximum.
            // But by the same token, in that case, `date` will never be
            // greater than or equal to the start of that year. So we can just
            // ignore it.
            if let Some(next_start_of_year) = week_start_of_year(start, next)
                && date >= next_start_of_year
            {
                start_of_year = next_start_of_year;
            }
        }

        debug_assert!(date >= start_of_year);
        let diff_days = start_of_year.until(date).ok()?.get_days();
        // +1 because weeks are one-indexed. `date` cannot be more than 53
        // weeks after `start_of_year`, so the conversion always fits.
        let week = i8::try_from(diff_days / 7).ok()? + 1;
        // The week date year is guaranteed to match the Gregorian year 4
        // days after the start of the first day of the week date year.
        let year = start_of_year.checked_add(4.days()).ok()?.year();
        let weekday = date.weekday();
        Some(WeekDate {
            start,
            year,
            week,
            weekday,
        })
    }

    /// Converts this week date to its corresponding Gregorian date.
    pub(crate) fn date(self) -> Option<Date> {
        let start_of_year = week_start_of_year(self.start, self.year)?;
        let mut days = i32::from(self.week - 1) * 7;
        days += i32::from(self.weekday.since(self.start));
        start_of_year.checked_add(days.days()).ok()
    }
}

pub(crate) fn weeks_in_year(start: Weekday, year: i16) -> i8 {
    if is_long_year(start, year) { 53 } else { 52 }
}

/// Returns the start of the week that the given date resides in.
///
/// The starting point of the week is determined by `start`.
pub(crate) fn first_of_week(start: Weekday, date: Date) -> Option<Date> {
    let wd = date.weekday();
    if start == wd {
        Some(date)
    } else {
        date.nth_weekday(-1, start).ok()
    }
}

/// Returns the end of the week that the given date resides in.
///
/// The starting point of the week is determined by `start`.
pub(crate) fn last_of_week(start: Weekday, date: Date) -> Option<Date> {
    let last = start.wrapping_sub(1);
    let wd = date.weekday();
    if last == wd {
        Some(date)
    } else {
        date.nth_weekday(1, last).ok()
    }
}

/// Returns true if the given week year (with weeks starting on `start`) is a
/// "long" year or not.
///
/// A "long" year is a year with 53 weeks. Otherwise, it's a "short" year with
/// 52 weeks.
fn is_long_year(start: Weekday, year: i16) -> bool {
    // Inspired by: https://en.wikipedia.org/wiki/ISO_week_date#Weeks_per_year
    let Ok(last) = Date::new(year, 12, 31) else {
        return false;
    };
    let weekday = last.weekday();
    weekday == start.wrapping_add(3) || (last.in_leap_year() && weekday == start.wrapping_add(4))
}

/// Returns the first date in the first week of the given year.
///
/// The date returned is guaranteed to have a weekday equivalent to `start`.
fn week_start_of_year(start: Weekday, year: i16) -> Option<Date> {
    // RFC 5545 says:
    //
    // > A week is defined as a seven day period, starting on the day of the
    // > week defined to be the week start (see WKST). Week number one of the
    // > calendar year is the first week that contains at least four (4) days
    // > in that calendar year.
    //
    // Which means that Jan 4 *must* be in the first week of the year.
    let date_in_first_week = Date::new(year, 1, 4).ok()?;
    // Now find the number of days since the start of the week from a date that
    // we know is in the first week of `year`.
    let diff_from_start = date_in_first_week.weekday().since(start);
    date_in_first_week.checked_sub(diff_from_start.days()).ok()
}

