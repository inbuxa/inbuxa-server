/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{expand::NaiveTimestamp, user::UserDataEntry};
use ahash::AHashMap;
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty, ICalendarValue,
        ICalendarValueType, Uri,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonScope {
    SharedData,
    SchedulingData,
}

impl ComparisonScope {
    pub fn component_eq(self, a: &ICalendar, a_id: u32, b: &ICalendar, b_id: u32) -> bool {
        let (Some(a_component), Some(b_component)) =
            (a.component_by_id(a_id), b.component_by_id(b_id))
        else {
            return false;
        };
        a_component.component_type == b_component.component_type
            && self
                .entries(a_component)
                .same_entries(&self.entries(b_component))
            && self.children_eq(a, a_component, b, b_component)
    }

    fn children_eq(
        self,
        a: &ICalendar,
        a_component: &ICalendarComponent,
        b: &ICalendar,
        b_component: &ICalendarComponent,
    ) -> bool {
        let (a_children, b_children) =
            (self.children(a, a_component), self.children(b, b_component));
        if a_children.len() != b_children.len() {
            return false;
        }
        let mut candidates: AHashMap<ChildKey<'_>, Vec<u32>> =
            AHashMap::with_capacity(b_children.len());
        for b_child in b_children {
            let Some(key) = b.child_key(b_child) else {
                return false;
            };
            candidates.entry(key).or_default().push(b_child);
        }

        a_children.into_iter().all(|a_child| {
            let Some(candidates) = a
                .child_key(a_child)
                .and_then(|key| candidates.get_mut(&key))
            else {
                return false;
            };
            match candidates
                .iter()
                .position(|b_child| self.component_eq(a, a_child, b, *b_child))
            {
                Some(index) => {
                    candidates.swap_remove(index);
                    true
                }
                None => false,
            }
        })
    }

    fn entries(self, component: &ICalendarComponent) -> Vec<&ICalendarEntry> {
        let mut entries = component
            .entries
            .iter()
            .filter(|entry| match self {
                ComparisonScope::SharedData => !entry.name.is_volatile(),
                ComparisonScope::SchedulingData => {
                    !entry.name.is_volatile()
                        && !entry.is_user_data()
                        && entry.name != ICalendarProperty::Sequence
                }
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn children(self, ical: &ICalendar, component: &ICalendarComponent) -> Vec<u32> {
        component
            .component_ids
            .iter()
            .copied()
            .filter(|id| {
                self == ComparisonScope::SharedData
                    || ical
                        .component_by_id(*id)
                        .is_some_and(|c| c.component_type != ICalendarComponentType::VAlarm)
            })
            .collect()
    }
}

type ChildKey<'x> = (&'x ICalendarComponentType, Option<i64>);

trait ChildComponentKey {
    fn child_key(&self, comp_id: u32) -> Option<ChildKey<'_>>;
}

impl ChildComponentKey for ICalendar {
    fn child_key(&self, comp_id: u32) -> Option<ChildKey<'_>> {
        let component = self.component_by_id(comp_id)?;
        Some((
            &component.component_type,
            component
                .property(&ICalendarProperty::RecurrenceId)
                .and_then(|entry| entry.values.first())
                .and_then(ICalendarValue::as_partial_date_time)
                .and_then(PartialDateTime::naive_timestamp),
        ))
    }
}

pub trait RecurrenceComponents {
    fn base_component_id(&self) -> Option<u32>;
}

impl RecurrenceComponents for ICalendar {
    fn base_component_id(&self) -> Option<u32> {
        self.components
            .iter()
            .position(|component| {
                component.component_type.is_event_or_todo() && !component.is_recurrence_override()
            })
            .map(|id| id as u32)
    }
}

pub struct RedundantOverrides<'x> {
    ical: &'x ICalendar,
    base: &'x ICalendarComponent,
    base_start: &'x ICalendarEntry,
    base_entries: Vec<&'x ICalendarEntry>,
}

impl<'x> RedundantOverrides<'x> {
    pub fn new(ical: &'x ICalendar) -> Option<Self> {
        let base = ical.component_by_id(ical.base_component_id()?)?;
        Some(RedundantOverrides {
            ical,
            base,
            base_start: base.property(&ICalendarProperty::Dtstart)?,
            base_entries: base.occurrence_entries(),
        })
    }

    pub fn is_redundant(&self, override_id: u32) -> bool {
        let Some(component) = self.ical.component_by_id(override_id) else {
            return false;
        };
        let (Some(recurrence_id), Some(start)) = (
            component.property(&ICalendarProperty::RecurrenceId),
            component.property(&ICalendarProperty::Dtstart),
        ) else {
            return false;
        };
        let Some(shift) = self.base_start.shift_to(start) else {
            return false;
        };

        start.values == recurrence_id.values
            && start.tz_id() == recurrence_id.tz_id()
            && [ICalendarProperty::Dtend, ICalendarProperty::Due]
                .iter()
                .all(
                    |name| match (self.base.property(name), component.property(name)) {
                        (Some(base_entry), Some(entry)) => {
                            base_entry.shift_to(entry) == Some(shift)
                        }
                        (None, None) => true,
                        _ => false,
                    },
                )
            && component
                .occurrence_entries()
                .same_entries(&self.base_entries)
            && ComparisonScope::SharedData.children_eq(self.ical, component, self.ical, self.base)
    }
}

pub trait EntryEquivalence {
    fn is_equivalent(&self, other: &Self) -> bool;

    fn shift_to(&self, other: &Self) -> Option<i64>;
}

impl EntryEquivalence for ICalendarEntry {
    fn is_equivalent(&self, other: &Self) -> bool {
        self.name == other.name
            && self.values.len() == other.values.len()
            && self.values.iter().zip(&other.values).all(|(value, other)| {
                value == other
                    || (self.name.is_calendar_address()
                        && value
                            .as_address()
                            .is_some_and(|address| other.as_address() == Some(address)))
            })
            && self.has_equivalent_params(other)
    }

    fn shift_to(&self, other: &Self) -> Option<i64> {
        let ([ICalendarValue::PartialDateTime(from)], [ICalendarValue::PartialDateTime(to)]) =
            (self.values.as_slice(), other.values.as_slice())
        else {
            return None;
        };
        (from.has_same_shape(to) && self.has_equivalent_params(other))
            .then(|| to.naive_timestamp()?.checked_sub(from.naive_timestamp()?))
            .flatten()
    }
}

pub trait NaiveDateTime {
    fn naive_timestamp(&self) -> Option<i64>;

    fn has_same_shape(&self, other: &Self) -> bool;

    fn shifted(&self, shift: i64) -> Option<PartialDateTime>;
}

impl NaiveDateTime for PartialDateTime {
    fn naive_timestamp(&self) -> Option<i64> {
        self.to_date_time()
            .map(|date_time| date_time.date_time.naive_timestamp())
    }

    fn has_same_shape(&self, other: &Self) -> bool {
        self.has_date() == other.has_date()
            && self.has_time() == other.has_time()
            && self.tz_hour == other.tz_hour
            && self.tz_minute == other.tz_minute
            && self.tz_minus == other.tz_minus
    }

    fn shifted(&self, shift: i64) -> Option<PartialDateTime> {
        let timestamp = self.naive_timestamp()?.checked_add(shift)?;
        let shifted = if self.has_time() {
            PartialDateTime::from_naive_timestamp(timestamp)
        } else {
            PartialDateTime::from_date_timestamp(timestamp)
        };
        Some(PartialDateTime {
            second: shifted.second.filter(|_| self.second.is_some()),
            tz_hour: self.tz_hour,
            tz_minute: self.tz_minute,
            tz_minus: self.tz_minus,
            ..shifted
        })
    }
}

pub trait EntryList {
    fn same_entries(&self, other: &Self) -> bool;
}

impl EntryList for [&ICalendarEntry] {
    fn same_entries(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut matched = vec![false; other.len()];
        self.iter().all(|entry| {
            let start = other.partition_point(|candidate| candidate.name < entry.name);
            other
                .get(start..)
                .unwrap_or_default()
                .iter()
                .zip(matched.get_mut(start..).unwrap_or_default())
                .take_while(|(candidate, _)| candidate.name == entry.name)
                .find(|(candidate, is_matched)| !**is_matched && entry.is_equivalent(candidate))
                .map(|(_, is_matched)| *is_matched = true)
                .is_some()
        })
    }
}

trait OccurrenceEntries {
    fn occurrence_entries(&self) -> Vec<&ICalendarEntry>;
}

impl OccurrenceEntries for ICalendarComponent {
    fn occurrence_entries(&self) -> Vec<&ICalendarEntry> {
        let mut entries = self
            .entries
            .iter()
            .filter(|entry| {
                !entry.name.is_volatile()
                    && !matches!(
                        entry.name,
                        ICalendarProperty::RecurrenceId
                            | ICalendarProperty::Rrule
                            | ICalendarProperty::Rdate
                            | ICalendarProperty::Exrule
                            | ICalendarProperty::Exdate
                            | ICalendarProperty::Dtstart
                            | ICalendarProperty::Dtend
                            | ICalendarProperty::Due
                    )
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

trait EntryParameters {
    fn significant_params(&self) -> impl Iterator<Item = &ICalendarParameter> + Clone;

    fn has_equivalent_params(&self, other: &Self) -> bool;
}

impl EntryParameters for ICalendarEntry {
    fn significant_params(&self) -> impl Iterator<Item = &ICalendarParameter> + Clone {
        self.params.iter().filter(|param| match &param.value {
            ICalendarParameterValue::Value(value_type)
                if param.name == ICalendarParameterName::Value =>
            {
                self.values.is_empty()
                    || !self.values.iter().all(|value| value.is_of_type(value_type))
            }
            _ => true,
        })
    }

    fn has_equivalent_params(&self, other: &Self) -> bool {
        let (params, other_params) = (self.significant_params(), other.significant_params());
        params.clone().count() == other_params.clone().count()
            && params.clone().all(|param| {
                params.clone().filter(|item| *item == param).count()
                    == other_params.clone().filter(|item| *item == param).count()
            })
    }
}

trait ValueClass {
    fn is_of_type(&self, value_type: &ICalendarValueType) -> bool;

    fn as_address(&self) -> Option<&str>;
}

impl ValueClass for ICalendarValue {
    fn is_of_type(&self, value_type: &ICalendarValueType) -> bool {
        match (value_type, self) {
            (ICalendarValueType::Binary, ICalendarValue::Binary(_))
            | (ICalendarValueType::Boolean, ICalendarValue::Boolean(_))
            | (ICalendarValueType::CalAddress, ICalendarValue::Uri(_) | ICalendarValue::Text(_))
            | (ICalendarValueType::Duration, ICalendarValue::Duration(_))
            | (ICalendarValueType::Float, ICalendarValue::Float(_))
            | (ICalendarValueType::Integer, ICalendarValue::Integer(_))
            | (ICalendarValueType::Period, ICalendarValue::Period(_))
            | (ICalendarValueType::Recur, ICalendarValue::RecurrenceRule(_))
            | (ICalendarValueType::Text, ICalendarValue::Text(_))
            | (ICalendarValueType::Uri, ICalendarValue::Uri(_)) => true,
            (ICalendarValueType::Date, ICalendarValue::PartialDateTime(value)) => {
                value.has_date() && !value.has_time()
            }
            (ICalendarValueType::DateTime, ICalendarValue::PartialDateTime(value)) => {
                value.has_date() && value.has_time()
            }
            (ICalendarValueType::Time, ICalendarValue::PartialDateTime(value)) => {
                !value.has_date() && value.has_time()
            }
            _ => false,
        }
    }

    fn as_address(&self) -> Option<&str> {
        match self {
            ICalendarValue::Uri(Uri::Location(address)) | ICalendarValue::Text(address) => {
                Some(address)
            }
            _ => None,
        }
    }
}

pub trait PropertyClass {
    fn is_volatile(&self) -> bool;

    fn is_calendar_address(&self) -> bool;
}

impl PropertyClass for ICalendarProperty {
    fn is_volatile(&self) -> bool {
        matches!(
            self,
            ICalendarProperty::Dtstamp | ICalendarProperty::LastModified
        )
    }

    fn is_calendar_address(&self) -> bool {
        matches!(
            self,
            ICalendarProperty::Organizer
                | ICalendarProperty::Attendee
                | ICalendarProperty::CalendarAddress
        )
    }
}

