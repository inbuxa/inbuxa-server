/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{
    Alarm, ArchivedCalendarEventData, ArchivedTimezone, CalendarEventData, Timezone,
    alarm::ExpandAlarm,
    alerts::{DefaultAlerts, ICalendarDefaultAlerts},
    expand::RangeFlags,
    overlap::ICalendarOverlap,
};
use crate::calendar::ComponentTimeRange;
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponentType},
};
use compact_str::ToCompactString;
use indexmap::IndexMap;
use store::{
    ahash::{AHashMap, RandomState},
    write::key::KeySerializer,
};
use types::OverlapCondition;
#[cfg(all(test, inbuxa_tests))]
use utils::codec::leb128::Leb128;

const MAX_TIME_SPAN: i64 = u32::MAX as i64;

impl CalendarEventData {
    pub fn new(ical: ICalendar, default_tz: Tz, max_expansions: usize) -> Self {
        Self::new_with_default_alerts(ical, default_tz, max_expansions, &DefaultAlerts::disabled())
    }

    pub fn new_with_default_alerts(
        ical: ICalendar,
        default_tz: Tz,
        max_expansions: usize,
        default_alerts: &DefaultAlerts,
    ) -> Self {
        let mut ranges = TimeRanges::default();

        let expanded = ical.expand_dates(default_tz, max_expansions);
        let mut groups: IndexMap<(u16, u16, u16, i32, RangeFlags), Vec<i64>, RandomState> =
            IndexMap::with_capacity_and_hasher(16, RandomState::default());
        let mut components: AHashMap<u16, (Vec<Alarm>, OverlapCondition)> =
            AHashMap::with_capacity(16);

        for event in expanded.events {
            let Ok(comp_id) = u16::try_from(event.comp_id) else {
                continue;
            };
            let start_tz = event.start.timezone().as_id();
            let end_tz = event.end.timezone().as_id();
            let (start_timestamp_utc, end_timestamp_utc) = event.timestamps();
            let (start_timestamp_naive, end_timestamp_naive) = event.naive_timestamps();

            let (_, condition) = components.entry(comp_id).or_insert_with(|| {
                // Expand alarms
                let alarms = ical
                    .component_by_id(event.comp_id)
                    .map_or(&[][..], |c| c.component_ids.as_slice())
                    .iter()
                    .filter_map(|alarm_id| {
                        let id = u16::try_from(*alarm_id).ok()?;
                        ical.component_by_id(*alarm_id).and_then(|alarm| {
                            if alarm.component_type == ICalendarComponentType::VAlarm
                                && (!default_alerts.is_enabled()
                                    || ical.is_kept_with_default_alerts(alarm, default_alerts))
                            {
                                alarm.expand_alarm(id, comp_id)
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                (alarms, ical.overlap_condition(event.comp_id))
            });
            let condition = condition.for_instance(start_timestamp_utc, end_timestamp_utc);

            ranges.update_base_offset(start_timestamp_naive, end_timestamp_naive);
            ranges.update_utc_min_max(
                std::cmp::min(start_timestamp_utc, end_timestamp_utc),
                std::cmp::max(start_timestamp_utc, end_timestamp_utc),
            );
            groups
                .entry((
                    start_tz,
                    end_tz,
                    comp_id,
                    (end_timestamp_naive - start_timestamp_naive)
                        .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                    RangeFlags::of(&event.start, &event.end).with_condition(condition),
                ))
                .or_default()
                .push(start_timestamp_naive);
        }

        let mut events = Vec::with_capacity(groups.len());
        for ((start_tz, end_tz, id, duration, flags), mut instances) in groups {
            instances.sort_unstable();
            instances.dedup();
            instances.truncate(instances.partition_point(|instance| {
                instance.saturating_sub(ranges.base_offset) <= MAX_TIME_SPAN
            }));

            let instances = match instances.len() {
                0 => continue,
                1 => KeySerializer::new(std::mem::size_of::<u32>())
                    .write_leb128((instances[0] - ranges.base_offset) as u32)
                    .finalize(),
                len => {
                    // Bitpack instances
                    let mut instance_offsets = Vec::with_capacity(len);
                    for instance in instances {
                        debug_assert!(instance >= ranges.base_offset);
                        instance_offsets.push((instance - ranges.base_offset) as u32);
                    }

                    KeySerializer::new(instance_offsets.len() * std::mem::size_of::<u32>())
                        .bitpack_sorted(&instance_offsets)
                        .finalize()
                }
            };

            events.push(ComponentTimeRange {
                id,
                start_tz,
                end_tz,
                duration,
                flags: flags.bits(),
                instances: instances.into_boxed_slice(),
            });
        }

        if !expanded.errors.is_empty() {
            trc::event!(
                Calendar(trc::CalendarEvent::RuleExpansionError),
                Reason = expanded
                    .errors
                    .into_iter()
                    .map(|e| e.error.to_compact_string())
                    .collect::<Vec<_>>(),
                Contents = ical.to_compact_string(),
                ResourceUid = ical.uids().next().map(|uid| uid.to_compact_string()),
                Limit = max_expansions,
            );
        }

        let (base_offset, base_time_utc, duration) = if ranges.is_empty() {
            (0, 0, 0)
        } else {
            (
                ranges.base_offset,
                ranges
                    .min_time_utc
                    .saturating_sub(ranges.base_offset)
                    .clamp(0, MAX_TIME_SPAN) as u32,
                ranges
                    .max_time_utc
                    .saturating_sub(ranges.min_time_utc)
                    .clamp(0, MAX_TIME_SPAN) as u32,
            )
        };

        CalendarEventData {
            event: ical,
            time_ranges: events.into_boxed_slice(),
            alarms: components
                .into_values()
                .flat_map(|(alarms, _)| alarms)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            base_offset,
            base_time_utc,
            duration,
        }
    }

    pub fn event_range(&self) -> Option<(i64, u32)> {
        if !self.time_ranges.is_empty() {
            Some((self.event_range_start(), self.duration))
        } else {
            None
        }
    }

    pub fn has_floating_start(&self) -> bool {
        let floating = Tz::Floating.as_id();
        !self.time_ranges.is_empty()
            && self
                .time_ranges
                .iter()
                .all(|range| range.start_tz == floating)
    }
}

#[derive(Debug)]
struct TimeRanges {
    max_time_utc: i64,
    min_time_utc: i64,
    base_offset: i64,
}

impl Default for TimeRanges {
    fn default() -> Self {
        TimeRanges {
            max_time_utc: i64::MIN,
            min_time_utc: i64::MAX,
            base_offset: i64::MAX,
        }
    }
}

impl TimeRanges {
    pub fn update_base_offset(&mut self, t1: i64, t2: i64) {
        self.base_offset = self.base_offset.min(t1).min(t2);
    }

    pub fn update_utc_min_max(&mut self, min: i64, max: i64) {
        self.min_time_utc = self.min_time_utc.min(min);
        self.max_time_utc = self.max_time_utc.max(max);
        self.base_offset = self.base_offset.min(min);
    }

    pub fn is_empty(&self) -> bool {
        self.min_time_utc > self.max_time_utc
    }
}

impl ArchivedCalendarEventData {
    pub fn event_range(&self) -> Option<(i64, u32)> {
        if !self.time_ranges.is_empty() {
            Some((self.event_range_start(), self.duration.to_native()))
        } else {
            None
        }
    }

    pub fn event_range_start(&self) -> i64 {
        self.base_offset
            .to_native()
            .saturating_add(self.base_time_utc.to_native() as i64)
    }

    pub fn event_range_end(&self) -> i64 {
        self.event_range_start()
            .saturating_add(self.duration.to_native() as i64)
    }
}

impl CalendarEventData {
    pub fn event_range_start(&self) -> i64 {
        self.base_offset.saturating_add(self.base_time_utc as i64)
    }

    pub fn event_range_end(&self) -> i64 {
        self.event_range_start()
            .saturating_add(self.duration as i64)
    }
}

impl Timezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            Timezone::IANA(iana) => Tz::from_id(*iana),
            Timezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            Timezone::Default => None,
        }
    }
}

impl ArchivedTimezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            ArchivedTimezone::IANA(iana) => Tz::from_id(iana.to_native()),
            ArchivedTimezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            ArchivedTimezone::Default => None,
        }
    }
}

