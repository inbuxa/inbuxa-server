/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS, EVENT_INVITE_SELF, compare::ComparisonScope,
    expand::ComponentRecurrenceId,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarValue,
    },
};

pub const SCHEDULING_EVENT_FLAGS: u16 =
    EVENT_INVITE_SELF | EVENT_INVITE_OTHERS | EVENT_HIDE_ATTENDEES;

pub trait ICalendarSequence {
    fn has_scheduling_changes(&self, previous: &ICalendar) -> bool;

    fn increment_sequence(&mut self, previous: &ICalendar);
}

impl ICalendarSequence for ICalendar {
    fn has_scheduling_changes(&self, previous: &ICalendar) -> bool {
        !ComparisonScope::SchedulingData.component_eq(self, 0, previous, 0)
            || PreviousSequences::new(previous).are_lowered_by(self)
    }

    fn increment_sequence(&mut self, previous: &ICalendar) {
        let previous = PreviousSequences::new(previous);
        for component in self
            .components
            .iter_mut()
            .filter(|component| component.component_type.is_scheduling_object())
        {
            let previous_sequence = previous.of(component);
            if component.sequence().unwrap_or_default() <= previous_sequence {
                component.set_sequence(previous_sequence + 1);
            }
        }
    }
}

struct PreviousSequences<'x> {
    series: Option<i64>,
    components: Vec<(&'x ICalendarComponentType, Option<i64>, Option<i64>)>,
}

impl<'x> PreviousSequences<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        let components = ical
            .components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .map(|component| {
                (
                    &component.component_type,
                    component.recurrence_instant(),
                    component.sequence(),
                )
            })
            .collect::<Vec<_>>();
        PreviousSequences {
            series: ical
                .components
                .iter()
                .find(|component| {
                    component.component_type.is_scheduling_object()
                        && !component.is_recurrence_override()
                })
                .and_then(ComponentSequence::sequence),
            components,
        }
    }

    fn are_lowered_by(&self, ical: &ICalendar) -> bool {
        ical.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .any(|component| component.sequence().unwrap_or_default() < self.of(component))
    }

    fn of(&self, component: &ICalendarComponent) -> i64 {
        let recurrence_instant = component.recurrence_instant();
        self.components
            .iter()
            .find(|(component_type, instant, _)| {
                **component_type == component.component_type && *instant == recurrence_instant
            })
            .map_or(self.series, |(_, _, sequence)| *sequence)
            .unwrap_or_default()
    }
}

trait ComponentSequence {
    fn sequence(&self) -> Option<i64>;

    fn set_sequence(&mut self, sequence: i64);

    fn recurrence_instant(&self) -> Option<i64>;
}

impl ComponentSequence for ICalendarComponent {
    fn sequence(&self) -> Option<i64> {
        self.property(&ICalendarProperty::Sequence)
            .and_then(|entry| entry.values.first())
            .and_then(ICalendarValue::as_integer)
    }

    fn recurrence_instant(&self) -> Option<i64> {
        self.recurrence_id(Tz::Floating).map(|id| id.utc)
    }

    fn set_sequence(&mut self, sequence: i64) {
        match self
            .entries
            .iter_mut()
            .find(|entry| entry.name == ICalendarProperty::Sequence)
        {
            Some(entry) => entry.values = [ICalendarValue::Integer(sequence)].into(),
            None => self.add_sequence(sequence),
        }
    }
}

