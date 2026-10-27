/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    query::{CalendarQueryHandler, EventTimeRange},
    view::{AlarmView, CalendarView, ChildIdView, ComponentView, EntryView, ParameterView},
};
use crate::common::{
    EventContent,
    search::{Candidates, IndexedText, QueryScope, TextIndex},
};
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
};
use common::storage::dav::CachedUid;
use dav_proto::schema::request::{
    CalendarPropFilter, CalendarPropMatch, CompFilter, CompFilterMatch, ParamFilter, Presence,
    PropValueMatch,
};
use groupware::calendar::{EVENT_HAS_ALARMS, EVENT_HAS_UNBOUNDED_TODO};
use store::search::{CalendarSearchField, SearchField};
use types::TimeRange;

pub(crate) trait CalendarFilterPlan {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates;
    fn time_ranges(&self) -> FilterTimeRanges;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FilterTimeRanges {
    pub range: Option<TimeRange>,
    pub has_alarms: bool,
}

const ALARM_EXPANSION_SLACK: i64 = 86_400;

trait AlarmReach {
    fn widen_for_alarms(&self, range: TimeRange) -> TimeRange;
}

trait PropFilterPlan {
    fn candidates(
        &self,
        component: &ICalendarComponentType,
        scope: &QueryScope<'_>,
        index: TextIndex<'_>,
    ) -> Candidates;
}

trait CalendarIndexField {
    fn search_field(&self) -> Option<(SearchField, IndexedText)>;
}

trait EntryFilter: EntryView {
    fn matches_prop(&self, test: &CalendarPropMatch, default_tz: Tz) -> bool;
    fn matches_param(&self, filter: &ParamFilter<ICalendarParameterName>) -> bool;
}

impl CalendarQueryHandler {
    pub fn matches_content(&self, content: &EventContent<'_>, filter: &CompFilter) -> bool {
        match content.view() {
            Some(view) => self.matches(view, filter),
            None => self.matches(content.stored(), filter),
        }
    }

    pub fn matches<V: CalendarView>(&self, event: &V, filter: &CompFilter) -> bool {
        match (&filter.test, event.components().first()) {
            (Presence::IsDefined(test), Some(root)) if root.component_type() == &filter.name => {
                self.component_matches(event, 0, root, test)
            }
            _ => false,
        }
    }

    fn component_matches<V: CalendarView>(
        &self,
        event: &V,
        comp_id: u32,
        component: &V::Component,
        test: &CompFilterMatch,
    ) -> bool {
        test.time_range
            .as_ref()
            .is_none_or(|range| self.component_in_range(event, comp_id, component, range))
            && test.prop_filters.iter().all(|filter| {
                let mut entries = component
                    .entries()
                    .iter()
                    .filter(|entry| entry.is_named(&filter.name))
                    .peekable();
                match &filter.test {
                    Presence::IsNotDefined => entries.peek().is_none(),
                    Presence::IsDefined(test) if entries.peek().is_some() => {
                        entries.any(|entry| entry.matches_prop(test, self.default_tz))
                    }
                    Presence::IsDefined(test) => {
                        test.param_filters.is_empty()
                            && matches!(&test.value, Some(PropValueMatch::TimeRange(range))
                            if component
                                .effective_end(&filter.name, self.default_tz)
                                .is_some_and(|timestamp| {
                                    range.start <= timestamp && range.end > timestamp
                                }))
                    }
                }
            })
            && test
                .comp_filters
                .iter()
                .all(|filter| self.child_filter_matches(event, component, filter))
    }

    fn child_filter_matches<V: CalendarView>(
        &self,
        event: &V,
        parent: &V::Component,
        filter: &CompFilter,
    ) -> bool {
        let components = event.components();
        let mut children = parent.child_ids().iter().filter_map(|child_id| {
            let child_id = child_id.child_id();
            components
                .get(child_id as usize)
                .filter(|child| child.component_type() == &filter.name)
                .map(|child| (child_id, child))
        });

        match &filter.test {
            Presence::IsNotDefined => children.next().is_none(),
            Presence::IsDefined(test) => children
                .any(|(child_id, child)| self.component_matches(event, child_id, child, test)),
        }
    }

    fn component_in_range<V: CalendarView>(
        &self,
        event: &V,
        comp_id: u32,
        component: &V::Component,
        range: &TimeRange,
    ) -> bool {
        if component.is_type(ICalendarComponentType::VAlarm) {
            let repetition = component.alarm_repetition();
            event
                .alarms()
                .iter()
                .filter(|alarm| alarm.id() == comp_id)
                .any(
                    |alarm| match alarm.delta().fixed_timestamp(self.default_tz) {
                        Some(timestamp) => repetition.triggers_in(timestamp, range),
                        None => self
                            .expansions_of(alarm.parent_id())
                            .iter()
                            .any(|expansion| {
                                alarm.timestamp(expansion, self.default_tz).is_some_and(
                                    |timestamp| repetition.triggers_in(timestamp, range),
                                )
                            }),
                    },
                )
        } else if component.is_type(ICalendarComponentType::VCalendar) {
            !self.undated_todos.is_empty()
                || self.expanded_times.iter().any(|expansion| {
                    range.is_in_range(expansion.flags.condition(), expansion.start, expansion.end)
                })
        } else {
            self.undated_todos.contains(&comp_id)
                || (self.dateless_events_match
                    && component.is_type(ICalendarComponentType::VEvent)
                    && !component
                        .entries()
                        .iter()
                        .any(|entry| entry.is_named(&ICalendarProperty::Dtstart)))
                || self.expansions_of(comp_id).iter().any(|expansion| {
                    range.is_in_range(expansion.flags.condition(), expansion.start, expansion.end)
                })
        }
    }
}

impl<E: EntryView> EntryFilter for E {
    fn matches_prop(&self, test: &CalendarPropMatch, default_tz: Tz) -> bool {
        test.value.as_ref().is_none_or(|value| match value {
            PropValueMatch::TimeRange(range) => self
                .date_time_timestamp(default_tz)
                .is_some_and(|timestamp| range.start <= timestamp && range.end > timestamp),
            PropValueMatch::Text(text_match) => text_match.is_match_any(self.text_values()),
        }) && test
            .param_filters
            .iter()
            .all(|filter| self.matches_param(filter))
    }

    fn matches_param(&self, filter: &ParamFilter<ICalendarParameterName>) -> bool {
        let mut params = self
            .params()
            .iter()
            .filter(|param| param.is_named(&filter.name))
            .peekable();
        match &filter.test {
            Presence::IsNotDefined => params.peek().is_none(),
            Presence::IsDefined(None) => params.peek().is_some(),
            Presence::IsDefined(Some(text_match)) => {
                params.peek().is_some()
                    && text_match.is_match_any(params.filter_map(|param| param.text()))
            }
        }
    }
}

impl CalendarFilterPlan for CompFilter {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates {
        let Presence::IsDefined(test) = &self.test else {
            return Candidates::All;
        };

        let time_range = test.time_range.as_ref().map(|range| match self.name {
            ICalendarComponentType::VEvent
            | ICalendarComponentType::VJournal
            | ICalendarComponentType::VFreebusy => {
                scope.matching(|resource| resource.resource.is_in_time_range(range))
            }
            ICalendarComponentType::VTodo | ICalendarComponentType::VCalendar => {
                scope.matching(|resource| {
                    resource.resource.is_in_time_range(range)
                        || resource
                            .event_flags()
                            .is_some_and(|flags| flags & EVENT_HAS_UNBOUNDED_TODO != 0)
                })
            }
            ICalendarComponentType::VAlarm => scope.matching(|resource| {
                resource
                    .event_flags()
                    .is_some_and(|flags| flags & EVENT_HAS_ALARMS != 0)
            }),
            _ => Candidates::All,
        });

        Candidates::and(
            time_range
                .into_iter()
                .chain(
                    test.prop_filters
                        .iter()
                        .map(|filter| filter.candidates(&self.name, scope, index)),
                )
                .chain(
                    test.comp_filters
                        .iter()
                        .map(|filter| filter.candidates(scope, index)),
                ),
        )
    }

    fn time_ranges(&self) -> FilterTimeRanges {
        let Presence::IsDefined(test) = &self.test else {
            return FilterTimeRanges::default();
        };
        test.comp_filters.iter().map(CompFilter::time_ranges).fold(
            FilterTimeRanges {
                range: test.time_range,
                has_alarms: test.time_range.is_some()
                    && self.name == ICalendarComponentType::VAlarm,
            },
            FilterTimeRanges::union,
        )
    }
}

impl FilterTimeRanges {
    pub fn union(self, other: FilterTimeRanges) -> Self {
        FilterTimeRanges {
            range: match (self.range, other.range) {
                (Some(range), Some(other)) => Some(range.union(other)),
                (range, other) => range.or(other),
            },
            has_alarms: self.has_alarms || other.has_alarms,
        }
    }

    pub fn expansion_range<V: CalendarView>(&self, event: &V) -> Option<TimeRange> {
        self.range.map(|range| {
            if self.has_alarms {
                event.widen_for_alarms(range)
            } else {
                range
            }
        })
    }
}

impl<V: CalendarView> AlarmReach for V {
    fn widen_for_alarms(&self, range: TimeRange) -> TimeRange {
        let components = self.components();
        let margin = self
            .alarms()
            .iter()
            .filter_map(|alarm| {
                let repetition = components
                    .get(alarm.id() as usize)
                    .map(ComponentView::alarm_repetition)
                    .unwrap_or_default();
                alarm
                    .trigger_offset()
                    .map(|offset| offset.saturating_add(repetition.span()))
            })
            .max()
            .unwrap_or_default()
            .saturating_add(ALARM_EXPANSION_SLACK);
        TimeRange {
            start: range.start.saturating_sub(margin),
            end: range.end.saturating_add(margin),
        }
    }
}

impl PropFilterPlan for CalendarPropFilter {
    fn candidates(
        &self,
        component: &ICalendarComponentType,
        scope: &QueryScope<'_>,
        index: TextIndex<'_>,
    ) -> Candidates {
        let Presence::IsDefined(CalendarPropMatch {
            value: Some(PropValueMatch::Text(text_match)),
            ..
        }) = &self.test
        else {
            return Candidates::All;
        };
        if text_match.negate {
            return Candidates::All;
        }

        match &self.name {
            ICalendarProperty::Uid
                if component.is_scheduling_object()
                    || *component == ICalendarComponentType::VAvailability =>
            {
                scope.matching(|resource| {
                    resource.uid().is_none_or(|uid| {
                        uid.is_empty() || uid.is_hashed_uid() || text_match.is_match(uid)
                    })
                })
            }
            name if component.is_scheduling_object() => match name.search_field() {
                Some((field, text)) => index.candidates(field, text, text_match),
                None => Candidates::All,
            },
            _ => Candidates::All,
        }
    }
}

impl CalendarIndexField for ICalendarProperty {
    fn search_field(&self) -> Option<(SearchField, IndexedText)> {
        let (field, text) = match self {
            ICalendarProperty::Summary => (CalendarSearchField::Title, IndexedText::Stemmed),
            ICalendarProperty::Description => {
                (CalendarSearchField::Description, IndexedText::Stemmed)
            }
            ICalendarProperty::Location => (CalendarSearchField::Location, IndexedText::Plain),
            ICalendarProperty::Organizer => (CalendarSearchField::Owner, IndexedText::Identifier),
            ICalendarProperty::Attendee => (CalendarSearchField::Attendee, IndexedText::Identifier),
            _ => return None,
        };
        Some((field.into(), text))
    }
}

