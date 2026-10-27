/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedCalendarEventData, CalendarEventData};
use calcard::icalendar::{
    ArchivedICalendarEntry, ArchivedICalendarProperty, ArchivedICalendarValue, ICalendar,
    ICalendarEntry, ICalendarProperty, ICalendarValue,
};
use types::OverlapCondition;

pub trait ICalendarOverlap {
    fn overlap_condition(&self, comp_id: u32) -> OverlapCondition;
}

#[derive(Debug, Default, Clone, Copy)]
struct TodoDates {
    start: bool,
    recurrence_id: bool,
    end: bool,
    duration: bool,
    due: bool,
    completed: bool,
    created: bool,
}

trait TodoDateEntry {
    fn add_to(&self, dates: &mut TodoDates);
}

impl ICalendarOverlap for ICalendar {
    fn overlap_condition(&self, comp_id: u32) -> OverlapCondition {
        let Some(component) = self
            .component_by_id(comp_id)
            .filter(|component| component.component_type.is_todo())
        else {
            return OverlapCondition::Event;
        };
        let dates = TodoDates::of(&component.entries);
        dates
            .inherits_length()
            .then(|| {
                let uid = component.uid();
                self.components.iter().find(|series| {
                    series.component_type == component.component_type
                        && series.uid() == uid
                        && !series.is_recurrence_override()
                        && series.entries.iter().any(|entry| {
                            matches!(
                                entry.name,
                                ICalendarProperty::Rrule
                                    | ICalendarProperty::Rdate
                                    | ICalendarProperty::Exdate
                            )
                        })
                })
            })
            .flatten()
            .and_then(|series| TodoDates::of(&series.entries).condition())
            .or_else(|| dates.condition())
            .unwrap_or_default()
    }
}

impl CalendarEventData {
    pub fn has_unbounded_todo(&self) -> bool {
        self.event.components.iter().any(|component| {
            component.component_type.is_todo() && TodoDates::of(&component.entries).is_unbounded()
        })
    }

    pub fn undated_todos(&self) -> impl Iterator<Item = u32> + '_ {
        self.event
            .components
            .iter()
            .zip(0u32..)
            .filter(|(component, _)| {
                component.component_type.is_todo()
                    && TodoDates::of(&component.entries).condition().is_none()
            })
            .map(|(_, comp_id)| comp_id)
    }
}

impl ArchivedCalendarEventData {
    pub fn undated_todos(&self) -> impl Iterator<Item = u32> + '_ {
        self.event
            .components
            .iter()
            .zip(0u32..)
            .filter(|(component, _)| {
                component.component_type.is_todo()
                    && TodoDates::of(component.entries.iter())
                        .condition()
                        .is_none()
            })
            .map(|(_, comp_id)| comp_id)
    }
}

impl TodoDates {
    fn of<'x, E: TodoDateEntry + 'x>(entries: impl IntoIterator<Item = &'x E>) -> Self {
        let mut dates = TodoDates::default();
        for entry in entries {
            entry.add_to(&mut dates);
        }
        dates
    }

    fn is_unbounded(self) -> bool {
        matches!(self.condition(), None | Some(OverlapCondition::TodoCreated))
    }

    fn inherits_length(self) -> bool {
        self.recurrence_id && !(self.start || self.end || self.duration || self.due)
    }

    fn condition(self) -> Option<OverlapCondition> {
        match (
            self.start || self.recurrence_id,
            self.duration,
            self.due,
            self.completed,
            self.created,
        ) {
            (true, true, _, _, _) => Some(OverlapCondition::TodoStartDuration),
            (true, false, true, _, _) => Some(OverlapCondition::TodoStartDue),
            (true, false, false, _, _) => Some(OverlapCondition::TodoStart),
            (false, _, true, _, _) => Some(OverlapCondition::TodoDue),
            (false, _, false, true, true) => Some(OverlapCondition::TodoCreatedCompleted),
            (false, _, false, true, false) => Some(OverlapCondition::TodoCompleted),
            (false, _, false, false, true) => Some(OverlapCondition::TodoCreated),
            (false, _, false, false, false) => None,
        }
    }
}

impl TodoDateEntry for ICalendarEntry {
    fn add_to(&self, dates: &mut TodoDates) {
        let is_date_time = || {
            matches!(
                self.values.first(),
                Some(ICalendarValue::PartialDateTime(value)) if value.to_date_time().is_some()
            )
        };
        match self.name {
            ICalendarProperty::Dtstart => dates.start |= is_date_time(),
            ICalendarProperty::RecurrenceId => dates.recurrence_id |= is_date_time(),
            ICalendarProperty::Dtend => dates.end |= is_date_time(),
            ICalendarProperty::Due => dates.due |= is_date_time(),
            ICalendarProperty::Completed => dates.completed |= is_date_time(),
            ICalendarProperty::Created => dates.created |= is_date_time(),
            ICalendarProperty::Duration => {
                dates.duration |= matches!(self.values.first(), Some(ICalendarValue::Duration(_)));
            }
            _ => {}
        }
    }
}

impl TodoDateEntry for ArchivedICalendarEntry {
    fn add_to(&self, dates: &mut TodoDates) {
        let is_date_time = || {
            matches!(
                self.values.first(),
                Some(ArchivedICalendarValue::PartialDateTime(value)) if value.to_date_time().is_some()
            )
        };
        match self.name {
            ArchivedICalendarProperty::Dtstart => dates.start |= is_date_time(),
            ArchivedICalendarProperty::RecurrenceId => dates.recurrence_id |= is_date_time(),
            ArchivedICalendarProperty::Dtend => dates.end |= is_date_time(),
            ArchivedICalendarProperty::Due => dates.due |= is_date_time(),
            ArchivedICalendarProperty::Completed => dates.completed |= is_date_time(),
            ArchivedICalendarProperty::Created => dates.created |= is_date_time(),
            ArchivedICalendarProperty::Duration => {
                dates.duration |= matches!(
                    self.values.first(),
                    Some(ArchivedICalendarValue::Duration(_))
                );
            }
            _ => {}
        }
    }
}

