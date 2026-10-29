/*
 * SPDX-FileCopyrightText: 2021 Fredrik Meringdal, Ralph Bisschops <https://github.com/fmeringdal/rust-rrule>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::counter_date::DateTimeIter;
use super::rrule::RRule;
use super::utils::add_time_to_date;
use super::{IterInfo, MAX_ITER_LOOP, build_pos_list, utils::date_from_ordinal};
use super::{get_hour, get_minute, get_second};
use crate::common::timezone::Tz;
use crate::icalendar::ICalendarFrequency;
use chrono::NaiveTime;
use std::collections::VecDeque;

// inbuxa: passes plus skipped times, counted for the expansion budget tests
#[cfg(test)]
thread_local! {
    pub(crate) static ITERATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone)]
pub(crate) struct RRuleIter {
    pub(crate) counter_date: DateTimeIter,
    pub(crate) ii: IterInfo,
    pub(crate) timeset: Vec<NaiveTime>,
    pub(crate) dt_start: chrono::DateTime<Tz>,
    pub(crate) buffer: VecDeque<chrono::DateTime<Tz>>,
    pub(crate) finished: bool,
    pub(crate) count: Option<u32>,
    pub(crate) limited: bool,
    pub(crate) was_limited: bool,
    // inbuxa: work left from the expansion budget, see `MAX_EXPANSION_WORK`
    pub(crate) budget: u32,
    pub(crate) budget_exhausted: bool,
}

impl RRuleIter {
    pub(crate) fn new(rrule: &RRule, dt_start: &chrono::DateTime<Tz>, limited: bool) -> Self {
        let ii = IterInfo::new(rrule, dt_start);

        let hour = get_hour(dt_start);
        let minute = get_minute(dt_start);
        let second = get_second(dt_start);
        let timeset = ii.get_timeset(hour, minute, second);
        let count = ii.rrule().count;

        Self {
            counter_date: dt_start.into(),
            ii,
            timeset,
            dt_start: *dt_start,
            buffer: VecDeque::new(),
            finished: false,
            count,
            limited,
            was_limited: false,
            budget: u32::MAX,
            budget_exhausted: false,
        }
    }

    /// inbuxa: limits the work this iterator may spend to `budget` units; once
    /// it runs out, the iterator ends and `budget_exhausted` is set.
    pub(crate) fn with_budget(mut self, budget: u32) -> Self {
        self.budget = budget;
        self
    }

    /// Attempts to add a date to the result. Returns `true` if we should
    /// terminate the iteration.
    fn try_add_datetime(
        dt: chrono::DateTime<Tz>,
        rrule: &RRule,
        count: &mut Option<u32>,
        buffer: &mut VecDeque<chrono::DateTime<Tz>>,
        dt_start: &chrono::DateTime<Tz>,
    ) -> bool {
        if matches!(rrule.until, Some(until) if dt > until) {
            // We can break because `pos_list` is sorted and
            // all the next dates will only be larger than `until`.
            return true;
        }

        if dt >= *dt_start {
            buffer.push_back(dt);

            if let Some(count) = count {
                *count -= 1;

                if *count == 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Generates a list of dates that will be added to the buffer.
    /// Returns true if finished, no more items should/can be returned.
    fn generate(&mut self) -> bool {
        // Do early check if done (if known)
        if self.finished {
            return true;
        }
        // Check if the count is set, and if 0
        if matches!(self.count, Some(count) if count == 0) {
            return true;
        }

        let rrule = self.ii.rrule();

        if rrule.interval == 0 {
            return true;
        }

        let mut loop_counter: u32 = 0;
        // Loop until there is at least 1 item in the buffer.
        while self.buffer.is_empty() {
            // Prevent infinite loops
            if self.limited {
                loop_counter += 1;
                if loop_counter >= MAX_ITER_LOOP {
                    self.finished = true;
                    self.was_limited = true;
                    return true;
                }
            }
            let rrule = self.ii.rrule();

            let dayset = self.ii.get_dayset(
                rrule.freq,
                self.counter_date.year,
                self.counter_date.month,
                self.counter_date.day,
            );

            let tz = self.dt_start.timezone();

            if rrule.by_set_pos.is_empty() {
                // Loop over `start..end`
                for current_day in &dayset {
                    let current_day = *current_day as i64;
                    let year_ordinal = self.ii.year_ordinal();
                    // Ordinal conversion uses UTC: if we apply local-TZ here, then
                    // just below we'll end up double-applying.
                    let date = date_from_ordinal(year_ordinal + current_day);
                    for time in &self.timeset {
                        let Some(dt) = add_time_to_date(tz, date, *time) else {
                            continue;
                        };
                        if Self::try_add_datetime(
                            dt,
                            rrule,
                            &mut self.count,
                            &mut self.buffer,
                            &self.dt_start,
                        ) {
                            return true;
                        }
                    }
                }
            } else {
                let pos_list = build_pos_list(
                    &rrule.by_set_pos,
                    &dayset,
                    &self.timeset,
                    self.ii.year_ordinal(),
                    self.dt_start.timezone(),
                );
                for dt in pos_list {
                    if Self::try_add_datetime(
                        dt,
                        rrule,
                        &mut self.count,
                        &mut self.buffer,
                        &self.dt_start,
                    ) {
                        return true;
                    }
                }
            }

            // inbuxa: what this pass cost; the buffer was empty when it began
            let produced = self.buffer.len();
            let candidates = dayset.len().saturating_mul(self.timeset.len());
            let mut work = if produced == 0 {
                let days = match rrule.freq {
                    ICalendarFrequency::Yearly => usize::from(self.ii.year_len()),
                    ICalendarFrequency::Monthly => 31,
                    ICalendarFrequency::Weekly => 7,
                    _ => 1,
                };
                // one unit per 16 days scanned keeps a unit near the cost of a
                // daily pass
                days.div_ceil(16).saturating_add(candidates)
            } else {
                1 + candidates.saturating_sub(produced)
            };

            let increment_day = dayset.is_empty();
            let mut steps = 0;
            let incremented = self
                .counter_date
                .increment_counted(rrule, increment_day, &mut steps);
            work = work.saturating_add(steps as usize);
            #[cfg(test)]
            ITERATIONS.with(|count| count.set(count.get() + 1 + u64::from(steps)));
            let Some(budget) = self
                .budget
                .checked_sub(u32::try_from(work).unwrap_or(u32::MAX))
            else {
                self.budget = 0;
                self.budget_exhausted = true;
                self.finished = true;
                return true;
            };
            self.budget = budget;
            if incremented.is_err() {
                self.finished = true;
                return true;
            }

            if matches!(
                rrule.freq,
                ICalendarFrequency::Hourly
                    | ICalendarFrequency::Minutely
                    | ICalendarFrequency::Secondly
            ) {
                let hour = self.counter_date.hour as u8;
                let minute = self.counter_date.minute as u8;
                let second = self.counter_date.second as u8;
                self.timeset = self.ii.get_timeset_unchecked(hour, minute, second);
            }

            self.ii.rebuild(&self.counter_date);
        }

        // Indicate that there might be more items on the next iteration.
        false
    }
}

impl Iterator for RRuleIter {
    type Item = chrono::DateTime<Tz>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.buffer.is_empty() {
            return self.buffer.pop_front();
        }

        if self.finished {
            return None;
        }

        self.finished = self.generate();

        if self.buffer.is_empty() {
            self.finished = true;
        }
        self.buffer.pop_front()
    }
}
