/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ALARM_EMAIL, Alarm, AlarmDelta, AlarmOffset, ArchivedAlarmDelta, ArchivedAlarmOffset,
    ArchivedCalendarEventContent, ArchivedCalendarEventData, ArchivedEventPreferences,
    ArchivedEventUserData, CalendarEventData, DefaultAlert, EventPreferences, PREF_HAS_ALERTS,
    alerts::{DefaultAlerts, SnoozeAlarm},
    expand::{
        ComponentRecurrenceId, NaiveTimestamp, RangeFlags, RecurrenceKey, RecurrenceShift,
        SECONDS_PER_DAY, resolve_local,
    },
    user::BASE_INSTANCE,
};
use calcard::{
    common::timezone::{NominalDuration, Tz, ZonedDateTime},
    icalendar::{
        ArchivedICalendar, ArchivedICalendarComponent, ArchivedICalendarEntry, ICalendar,
        ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty, ICalendarRelated,
        ICalendarValue,
    },
};
use std::str::FromStr;
use store::write::{TaskId, bitpack::BitpackIterator};
use utils::codec::leb128::Leb128;

const TZ_BOUND: i64 = 24 * 60 * 60;
const ALARM_KIND_SHIFT: u32 = 16;
const ALARM_INDEX_MASK: u64 = u16::MAX as u64;
const ALARM_KIND_STORED: u64 = 0;
const ALARM_KIND_PERSONAL: u64 = 1;
const ALARM_KIND_DEFAULT: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlarmId {
    Stored(u16),
    Personal(u16),
    Default(u16),
}

impl AlarmId {
    pub fn to_task_id(self) -> u64 {
        let (kind, index) = match self {
            AlarmId::Stored(index) => (ALARM_KIND_STORED, index),
            AlarmId::Personal(index) => (ALARM_KIND_PERSONAL, index),
            AlarmId::Default(index) => (ALARM_KIND_DEFAULT, index),
        };
        (kind << ALARM_KIND_SHIFT) | index as u64
    }

    pub fn from_task_id(task_id: u64) -> Option<Self> {
        let index = (task_id & ALARM_INDEX_MASK) as u16;
        match task_id >> ALARM_KIND_SHIFT {
            ALARM_KIND_STORED => Some(AlarmId::Stored(index)),
            ALARM_KIND_PERSONAL => Some(AlarmId::Personal(index)),
            ALARM_KIND_DEFAULT => Some(AlarmId::Default(index)),
            _ => None,
        }
    }

    pub fn index(self) -> u16 {
        match self {
            AlarmId::Stored(index) | AlarmId::Personal(index) | AlarmId::Default(index) => index,
        }
    }

    pub fn is_default(self) -> bool {
        matches!(self, AlarmId::Default(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlarmTarget {
    Owner,
    Sharee(u32),
}

impl AlarmTarget {
    pub fn for_account(owner_id: u32, target_id: u32) -> Self {
        if target_id == owner_id {
            AlarmTarget::Owner
        } else {
            AlarmTarget::Sharee(target_id)
        }
    }

    pub fn sharee_id(self) -> Option<u32> {
        match self {
            AlarmTarget::Owner => None,
            AlarmTarget::Sharee(account_id) => Some(account_id),
        }
    }

    pub fn account_id(self, owner_id: u32) -> u32 {
        self.sharee_id().unwrap_or(owner_id)
    }

    pub fn task_id(self) -> TaskId {
        match self {
            AlarmTarget::Owner => TaskId::Document,
            AlarmTarget::Sharee(account_id) => TaskId::DocumentTarget(account_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalendarAlarm {
    pub alarm_id: AlarmId,
    pub event_id: u16,
    pub alarm_time: i64,
    pub typ: CalendarAlarmType,
    pub target: AlarmTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CalendarAlarmType {
    Email {
        event_start: i64,
        event_start_tz: u16,
        event_end: i64,
        event_end_tz: u16,
        recurrence_id: Option<i64>,
    },
    Display {
        recurrence_id: Option<i64>,
    },
}

impl CalendarAlarm {
    pub fn with_target(mut self, target: AlarmTarget) -> Self {
        self.target = target;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersonalAlarm {
    id: u16,
    delta: AlarmDelta,
    is_email_alert: bool,
    snoozed_alarms: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PersonalAlarms {
    base: Vec<PersonalAlarm>,
    instances: Vec<(u32, Vec<PersonalAlarm>)>,
}

impl PersonalAlarm {
    fn new(alert: &ICalendarComponent, siblings: &[ICalendarComponent], id: u16) -> Option<Self> {
        alert.expand_alarm(id, 0).map(|alarm| PersonalAlarm {
            id,
            is_email_alert: alarm.is_email(),
            delta: alarm.delta,
            snoozed_alarms: alert
                .snoozed_alarms()
                .flat_map(|parent| {
                    std::iter::once(parent).chain(
                        siblings
                            .iter()
                            .filter(move |sibling| {
                                sibling.component_type == ICalendarComponentType::VAlarm
                                    && sibling.uid() == Some(parent)
                            })
                            .filter_map(ICalendarComponent::jsid),
                    )
                })
                .map(str::to_string)
                .collect(),
        })
    }

    fn is_kept_with(&self, defaults: &DefaultAlerts) -> bool {
        self.snoozed_alarms
            .iter()
            .any(|id| defaults.contains_id(id))
    }
}

impl PersonalAlarms {
    pub fn new(preferences: &EventPreferences) -> Self {
        let mut alarms = PersonalAlarms::default();
        for instance in preferences
            .instances
            .iter()
            .filter(|instance| instance.flags & PREF_HAS_ALERTS != 0)
        {
            let expanded = instance
                .alerts
                .iter()
                .zip(0u16..)
                .filter_map(|(alert, id)| PersonalAlarm::new(alert, &instance.alerts, id))
                .collect::<Vec<_>>();
            if instance.recurrence_key == BASE_INSTANCE {
                alarms.base = expanded;
            } else {
                alarms.instances.push((instance.recurrence_key, expanded));
            }
        }
        alarms
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty() && self.instances.iter().all(|(_, alarms)| alarms.is_empty())
    }

    fn scoped(&self) -> impl Iterator<Item = (&PersonalAlarm, AlarmScope)> {
        self.base
            .iter()
            .map(|alarm| (alarm, AlarmScope::Base))
            .chain(self.instances.iter().flat_map(|(key, alarms)| {
                alarms
                    .iter()
                    .map(move |alarm| (alarm, AlarmScope::Instance(*key)))
            }))
    }

    fn has_instance(&self, recurrence_key: u32) -> bool {
        self.instances.iter().any(|(key, _)| *key == recurrence_key)
    }
}

impl ArchivedEventPreferences {
    pub fn alerts_instance(&self, recurrence_key: Option<u32>) -> Option<&ArchivedEventUserData> {
        recurrence_key
            .and_then(|key| self.instance_with_alerts(key))
            .or_else(|| self.instance_with_alerts(BASE_INSTANCE))
    }

    pub fn personal_alert(
        &self,
        recurrence_key: Option<u32>,
        index: u16,
    ) -> Option<&ArchivedICalendarComponent> {
        self.alerts_instance(recurrence_key)
            .and_then(|instance| instance.alerts.get(index as usize))
    }

    fn instance_with_alerts(&self, recurrence_key: u32) -> Option<&ArchivedEventUserData> {
        self.instances
            .binary_search_by_key(&recurrence_key, |instance| {
                instance.recurrence_key.to_native()
            })
            .ok()
            .and_then(|idx| self.instances.get(idx))
            .filter(|instance| instance.flags.to_native() & PREF_HAS_ALERTS != 0)
    }
}

#[derive(Clone, Copy)]
pub enum TriggeredAlarm<'x> {
    Component(&'x ArchivedICalendarComponent),
    Default {
        alert: &'x DefaultAlert,
        acknowledged: Option<&'x ArchivedICalendarComponent>,
    },
}

impl<'x> TriggeredAlarm<'x> {
    pub fn component(&self) -> Option<&'x ArchivedICalendarComponent> {
        match self {
            TriggeredAlarm::Component(component) => Some(component),
            TriggeredAlarm::Default { .. } => None,
        }
    }

    pub fn alert_id(&self) -> Option<&'x str> {
        match self {
            TriggeredAlarm::Component(component) => component.alarm_jsid(),
            TriggeredAlarm::Default { alert, .. } => Some(alert.id.as_str()),
        }
    }

    pub fn acknowledged(&self) -> Option<i64> {
        match self {
            TriggeredAlarm::Component(component)
            | TriggeredAlarm::Default {
                acknowledged: Some(component),
                ..
            } => component.acknowledged(),
            TriggeredAlarm::Default {
                acknowledged: None, ..
            } => None,
        }
    }
}

pub trait ArchivedAlarmComponent {
    fn alarm_jsid(&self) -> Option<&str>;

    fn acknowledged(&self) -> Option<i64>;
}

impl ArchivedAlarmComponent for ArchivedICalendarComponent {
    fn alarm_jsid(&self) -> Option<&str> {
        self.property(&ICalendarProperty::Jsid)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_text())
    }

    fn acknowledged(&self) -> Option<i64> {
        self.property(&ICalendarProperty::Acknowledged)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date_time| date_time.to_date_time_with_tz(Tz::UTC))
            .map(|date_time| date_time.timestamp())
    }
}

impl ArchivedCalendarEventContent {
    pub fn triggered_alarm<'x>(
        &'x self,
        target: AlarmTarget,
        alarm_id: AlarmId,
        comp_id: u16,
        recurrence_key: Option<u32>,
        defaults: &'x DefaultAlerts,
    ) -> Option<TriggeredAlarm<'x>> {
        let components = &self.data.event.components;
        let preferences = target
            .sharee_id()
            .and_then(|account_id| self.preferences(account_id));
        match alarm_id {
            AlarmId::Default(index) => {
                let alert = defaults.get(index)?;
                let is_acknowledged_copy = |alarm: &&ArchivedICalendarComponent| {
                    alarm.alarm_jsid() == Some(alert.id.as_str())
                };
                let acknowledged = if target.sharee_id().is_some() {
                    preferences
                        .and_then(|preferences| preferences.alerts_instance(recurrence_key))
                        .and_then(|instance| instance.alerts.iter().find(is_acknowledged_copy))
                } else {
                    components
                        .get(comp_id as usize)
                        .into_iter()
                        .flat_map(|component| component.component_ids.iter())
                        .filter_map(|id| components.get(id.to_native() as usize))
                        .find(is_acknowledged_copy)
                };
                Some(TriggeredAlarm::Default {
                    alert,
                    acknowledged,
                })
            }
            AlarmId::Personal(index) => preferences?
                .personal_alert(recurrence_key, index)
                .map(TriggeredAlarm::Component),
            AlarmId::Stored(index) => components
                .get(index as usize)
                .filter(|component| component.component_type == ICalendarComponentType::VAlarm)
                .map(TriggeredAlarm::Component),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlarmRecurrence {
    is_recurrent: bool,
    shift: Option<RecurrenceShift>,
    tz: Tz,
    flags: RangeFlags,
    recurrence_tz: Tz,
}

impl AlarmRecurrence {
    pub fn recurrence_id(&self, start_date_naive: i64) -> Option<i64> {
        match (self.is_recurrent, &self.shift) {
            (false, _) => None,
            (true, Some(shift)) => shift
                .recurrence_id(self.tz, self.flags, start_date_naive, self.recurrence_tz)
                .map(|recurrence_id| recurrence_id.naive),
            (true, None) => Some(start_date_naive),
        }
    }

    pub fn recurrence_key(&self, start_date_naive: i64) -> Option<u32> {
        self.recurrence_id(start_date_naive)
            .and_then(RecurrenceKey::from_recurrence_id)
            .map(RecurrenceKey::prefix)
    }

    pub fn is_recurrent(&self) -> bool {
        self.is_recurrent
    }

    fn of<C: CalendarComponentView + ComponentRecurrenceId>(
        component: Option<&C>,
        own_tz: Tz,
        tz: Tz,
        flags: RangeFlags,
    ) -> Self {
        component.map_or_else(AlarmRecurrence::default, |component| AlarmRecurrence {
            is_recurrent: component.is_recurrent_or_override(),
            shift: component
                .timestamp(&ICalendarProperty::Dtstart)
                .zip(component.recurrence_id(own_tz))
                .zip(component.recurrence_tz(own_tz))
                .and_then(|((start, recurrence_id), recurrence_tz)| {
                    RecurrenceShift::new(own_tz, start, recurrence_id, recurrence_tz)
                }),
            tz,
            flags,
            recurrence_tz: component.recurrence_tz(tz).unwrap_or(tz),
        })
    }
}

pub trait CalendarEntryView {
    fn as_boolean(&self) -> Option<bool>;

    fn is_date_only(&self) -> bool;

    fn timestamp(&self) -> Option<i64>;
}

pub trait CalendarComponentView {
    type Entry: CalendarEntryView;

    fn entry(&self, property: &ICalendarProperty) -> Option<&Self::Entry>;

    fn is_event_or_todo(&self) -> bool;

    fn is_recurrence_override(&self) -> bool;

    fn is_recurrent_or_override(&self) -> bool;

    fn timestamp(&self, property: &ICalendarProperty) -> Option<i64> {
        self.entry(property).and_then(CalendarEntryView::timestamp)
    }

    fn is_shown_without_time(&self) -> bool {
        self.entry(&ICalendarProperty::ShowWithoutTime)
            .and_then(CalendarEntryView::as_boolean)
            .unwrap_or(false)
            || self
                .entry(&ICalendarProperty::Dtstart)
                .is_some_and(CalendarEntryView::is_date_only)
    }
}

pub trait CalendarView {
    type Component: CalendarComponentView;

    fn components(&self) -> impl Iterator<Item = &Self::Component>;

    fn main_component(&self) -> Option<&Self::Component> {
        self.components()
            .find(|component| component.is_event_or_todo() && !component.is_recurrence_override())
    }
}

macro_rules! calendar_view {
    ($calendar:ty, $component:ty, $entry:ty) => {
        impl CalendarEntryView for $entry {
            fn as_boolean(&self) -> Option<bool> {
                self.values.first().and_then(|value| value.as_boolean())
            }

            fn is_date_only(&self) -> bool {
                self.values
                    .first()
                    .and_then(|value| value.as_partial_date_time())
                    .is_some_and(|date_time| !date_time.has_time())
            }

            fn timestamp(&self) -> Option<i64> {
                self.values
                    .first()?
                    .as_partial_date_time()?
                    .to_date_time()
                    .map(|date_time| date_time.date_time.naive_timestamp())
            }
        }

        impl CalendarComponentView for $component {
            type Entry = $entry;

            fn entry(&self, property: &ICalendarProperty) -> Option<&Self::Entry> {
                self.property(property)
            }

            fn is_event_or_todo(&self) -> bool {
                self.component_type.is_event_or_todo()
            }

            fn is_recurrence_override(&self) -> bool {
                <$component>::is_recurrence_override(self)
            }

            fn is_recurrent_or_override(&self) -> bool {
                <$component>::is_recurrent_or_override(self)
            }
        }

        impl CalendarView for $calendar {
            type Component = $component;

            fn components(&self) -> impl Iterator<Item = &Self::Component> {
                self.components.iter()
            }
        }
    };
}

calendar_view!(ICalendar, ICalendarComponent, ICalendarEntry);
calendar_view!(
    ArchivedICalendar,
    ArchivedICalendarComponent,
    ArchivedICalendarEntry
);

#[derive(Debug, Clone, Copy)]
pub enum AlarmSource<'x> {
    Stored(&'x DefaultAlerts),
    Personal(&'x PersonalAlarms, &'x DefaultAlerts),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlarmScope {
    All,
    Base,
    Instance(u32),
}

impl AlarmScope {
    fn is_occurrence(self) -> bool {
        matches!(self, AlarmScope::Instance(_))
    }

    fn is_behind(self, recurrence_key: Option<u32>) -> bool {
        matches!(
            (self, recurrence_key),
            (AlarmScope::Instance(key), Some(current)) if current > key
        )
    }
}

impl AlarmSource<'_> {
    pub(crate) fn may_have_alarms(&self, has_stored_alarms: bool) -> bool {
        match self {
            AlarmSource::Stored(defaults) => has_stored_alarms || defaults.has_alerts(),
            AlarmSource::Personal(alarms, defaults) if defaults.is_enabled() => {
                defaults.has_alerts()
                    || alarms
                        .scoped()
                        .any(|(alarm, _)| alarm.is_kept_with(defaults))
            }
            AlarmSource::Personal(alarms, _) => !alarms.is_empty(),
        }
    }

    fn has_floating_triggers<D: EventAlarmData + ?Sized>(&self, data: &D) -> bool {
        match self {
            AlarmSource::Stored(_) => data.has_floating_stored_alarms(),
            AlarmSource::Personal(alarms, _) => alarms
                .scoped()
                .any(|(alarm, _)| matches!(alarm.delta, AlarmDelta::FixedFloating(_))),
        }
    }

    fn uses_stored_alarms(&self) -> bool {
        matches!(self, AlarmSource::Stored(_))
    }

    fn shared_candidates(&self, candidates: &mut Vec<AlarmCandidate>) {
        let (defaults, personal) = match self {
            AlarmSource::Stored(defaults) => (*defaults, None),
            AlarmSource::Personal(alarms, defaults) => (*defaults, Some(*alarms)),
        };
        candidates.extend(defaults.indexed_alerts().map(|(index, alert)| {
            AlarmCandidate::new(
                AlarmId::Default(index),
                AlarmScope::All,
                alert.delta(),
                alert.is_email(),
            )
        }));
        if let Some(alarms) = personal {
            let keep_snoozes_only = defaults.is_enabled();
            candidates.extend(
                alarms
                    .scoped()
                    .filter(|(alarm, _)| !keep_snoozes_only || alarm.is_kept_with(defaults))
                    .map(|(alarm, scope)| {
                        AlarmCandidate::new(
                            AlarmId::Personal(alarm.id),
                            scope,
                            alarm.delta.clone(),
                            alarm.is_email_alert,
                        )
                    }),
            );
        }
    }

    fn applies(&self, scope: AlarmScope, recurrence_key: Option<u32>) -> bool {
        match (scope, self) {
            (AlarmScope::All, _) => true,
            (AlarmScope::Instance(key), _) => recurrence_key == Some(key),
            (AlarmScope::Base, AlarmSource::Personal(alarms, _)) => {
                recurrence_key.is_none_or(|key| !alarms.has_instance(key))
            }
            (AlarmScope::Base, AlarmSource::Stored(_)) => true,
        }
    }
}

pub struct AlarmRange<'x> {
    pub comp_id: u16,
    pub start_tz: u16,
    pub end_tz: u16,
    pub duration: i64,
    pub flags: RangeFlags,
    pub instances: &'x [u8],
}

#[derive(Debug, Clone)]
struct AlarmCandidate {
    id: AlarmId,
    scope: AlarmScope,
    delta: AlarmDelta,
    is_email_alert: bool,
    naive_bias: Option<i64>,
    fixed_time: i64,
    is_pending: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct PendingAlarms {
    any: bool,
    any_unbounded: bool,
    min_bias: Option<i64>,
}

impl AlarmCandidate {
    fn new(id: AlarmId, scope: AlarmScope, delta: AlarmDelta, is_email_alert: bool) -> Self {
        AlarmCandidate {
            id,
            scope,
            delta,
            is_email_alert,
            naive_bias: None,
            fixed_time: 0,
            is_pending: false,
        }
    }

    fn from_stored(alarm: Alarm) -> Self {
        let is_email_alert = alarm.is_email();
        AlarmCandidate::new(
            AlarmId::Stored(alarm.id),
            AlarmScope::All,
            alarm.delta,
            is_email_alert,
        )
    }

    fn prepare(
        &mut self,
        duration: i64,
        default_tz: Tz,
        start_time: i64,
        best_so_far: Option<i64>,
    ) {
        match &self.delta {
            AlarmDelta::Start(offset) => {
                self.naive_bias = Some(offset.naive_seconds());
                self.is_pending = true;
            }
            AlarmDelta::End(offset) => {
                self.naive_bias = Some(offset.naive_seconds() + duration);
                self.is_pending = true;
            }
            AlarmDelta::FixedUtc(_) | AlarmDelta::FixedFloating(_) => {
                self.naive_bias = None;
                match self.delta.fixed_timestamp(default_tz).filter(|alarm_time| {
                    *alarm_time > start_time && best_so_far.is_none_or(|best| *alarm_time < best)
                }) {
                    Some(alarm_time) => {
                        self.fixed_time = alarm_time;
                        self.is_pending = true;
                    }
                    None => self.is_pending = false,
                }
            }
        }
    }

    fn alarm_time(
        &self,
        start: &ZonedDateTime,
        end: &ZonedDateTime,
        default_tz: Tz,
    ) -> Option<i64> {
        if self.naive_bias.is_some() {
            self.delta.to_timestamp(start, end, default_tz)
        } else {
            Some(self.fixed_time)
        }
    }
}

impl PendingAlarms {
    fn of(candidates: &[AlarmCandidate]) -> Self {
        let mut pending = PendingAlarms::default();
        for candidate in candidates.iter().filter(|candidate| candidate.is_pending) {
            pending.any = true;
            match candidate.naive_bias {
                Some(bias) => {
                    pending.min_bias =
                        Some(pending.min_bias.map_or(bias, |min_bias| min_bias.min(bias)));
                }
                None => pending.any_unbounded = true,
            }
        }
        pending
    }

    fn is_past(&self, start_date_naive: i64, best_so_far: Option<i64>) -> bool {
        if self.any_unbounded {
            return false;
        }
        match (self.min_bias, best_so_far) {
            (Some(min_bias), Some(best)) => {
                start_date_naive
                    .saturating_add(min_bias)
                    .saturating_sub(TZ_BOUND)
                    >= best
            }
            _ => false,
        }
    }
}

pub trait EventAlarmData {
    fn alarm_base_offset(&self) -> i64;

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>>;

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm>;

    fn has_stored_alarms(&self) -> bool;

    fn has_floating_stored_alarms(&self) -> bool;

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence;

    fn needs_default_tz(&self, source: &AlarmSource<'_>) -> bool {
        let floating = Tz::Floating.as_id();
        source.may_have_alarms(self.has_stored_alarms())
            && (self
                .alarm_ranges()
                .any(|range| range.start_tz == floating || range.end_tz == floating)
                || source.has_floating_triggers(self))
    }

    fn next_alarm_from(
        &self,
        start_time: i64,
        default_tz: Tz,
        source: &AlarmSource<'_>,
    ) -> Option<CalendarAlarm> {
        if !source.may_have_alarms(self.has_stored_alarms()) {
            return None;
        }

        let base_offset = self.alarm_base_offset();
        let mut next_alarm: Option<CalendarAlarm> = None;
        let mut shared = Vec::new();
        source.shared_candidates(&mut shared);
        let uses_stored_alarms = source.uses_stored_alarms();
        if shared.is_empty() && !uses_stored_alarms {
            return None;
        }
        let mut candidates: Vec<AlarmCandidate> = Vec::with_capacity(shared.len());

        for range in self.alarm_ranges() {
            let comp_id = range.comp_id;
            candidates.clear();
            if uses_stored_alarms {
                candidates.extend(self.stored_alarms(comp_id).map(AlarmCandidate::from_stored));
            }
            candidates.extend_from_slice(&shared);
            if candidates.is_empty() {
                continue;
            }

            let instances = range.instances;
            let Some((offset_or_count, bytes_read)) = u32::from_leb128(instances) else {
                continue;
            };
            let duration = range.duration;
            let flags = range.flags;
            let (Some(mut start_tz), Some(mut end_tz)) =
                (Tz::from_id(range.start_tz), Tz::from_id(range.end_tz))
            else {
                continue;
            };
            let component_tz = start_tz;
            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            let best_so_far = next_alarm.as_ref().map(|next| next.alarm_time);
            for candidate in &mut candidates {
                candidate.prepare(duration, default_tz, start_time, best_so_far);
            }
            let recurrence = self.component_recurrence(comp_id, component_tz, flags);
            if !recurrence.is_recurrent() {
                for candidate in &mut candidates {
                    candidate.is_pending &= !candidate.scope.is_occurrence();
                }
            }
            if !PendingAlarms::of(&candidates).any {
                continue;
            }

            let is_packed = instances.len() > bytes_read;
            let packed = is_packed.then(|| {
                BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count)
            });
            let single = (!is_packed).then_some(offset_or_count);

            for start_date_naive in packed
                .into_iter()
                .flatten()
                .chain(single)
                .map(|offset| base_offset.saturating_add(offset as i64))
            {
                let best_so_far = next_alarm.as_ref().map(|next| next.alarm_time);
                let pending = PendingAlarms::of(&candidates);
                if !pending.any || pending.is_past(start_date_naive, best_so_far) {
                    break;
                }

                let end_date_naive = start_date_naive.saturating_add(duration);
                let mut instance_key = None;
                let mut resolved = None;

                for candidate in &mut candidates {
                    if !candidate.is_pending {
                        continue;
                    }
                    if candidate.scope != AlarmScope::All {
                        let recurrence_key = *instance_key
                            .get_or_insert_with(|| recurrence.recurrence_key(start_date_naive));
                        if !source.applies(candidate.scope, recurrence_key) {
                            if candidate.scope.is_behind(recurrence_key) {
                                candidate.is_pending = false;
                            }
                            continue;
                        }
                    }
                    if let Some(naive_bias) = candidate.naive_bias {
                        let naive_alarm = start_date_naive.saturating_add(naive_bias);
                        if naive_alarm.saturating_add(TZ_BOUND) <= start_time {
                            continue;
                        }
                        if best_so_far
                            .is_some_and(|best| naive_alarm.saturating_sub(TZ_BOUND) >= best)
                        {
                            candidate.is_pending = false;
                            continue;
                        }
                    }

                    let (start, end) = match resolved {
                        Some(resolved) => resolved,
                        None => {
                            let (Some(start), Some(end)) = (
                                flags.resolve_start(start_tz, start_date_naive),
                                flags.resolve_end(end_tz, end_date_naive),
                            ) else {
                                break;
                            };
                            *resolved.insert((start, end))
                        }
                    };

                    if let Some(alarm_time) = candidate.alarm_time(&start, &end, default_tz)
                        && alarm_time > start_time
                    {
                        if next_alarm
                            .as_ref()
                            .is_none_or(|next| alarm_time < next.alarm_time)
                        {
                            next_alarm = Some(CalendarAlarm {
                                alarm_id: candidate.id,
                                event_id: comp_id,
                                alarm_time,
                                typ: if candidate.is_email_alert {
                                    CalendarAlarmType::Email {
                                        event_start: start.timestamp(),
                                        event_start_tz: start_tz.as_id(),
                                        event_end: end.timestamp(),
                                        event_end_tz: end_tz.as_id(),
                                        recurrence_id: recurrence.recurrence_id(start_date_naive),
                                    }
                                } else {
                                    CalendarAlarmType::Display {
                                        recurrence_id: recurrence.recurrence_id(start_date_naive),
                                    }
                                },
                                target: AlarmTarget::Owner,
                            });
                        }
                        candidate.is_pending = false;
                    }
                }
            }
        }

        next_alarm
    }
}

impl EventAlarmData for ArchivedCalendarEventData {
    fn alarm_base_offset(&self) -> i64 {
        self.base_offset.to_native()
    }

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>> {
        self.time_ranges.iter().map(|range| AlarmRange {
            comp_id: range.id.to_native(),
            start_tz: range.start_tz.to_native(),
            end_tz: range.end_tz.to_native(),
            duration: range.duration.to_native() as i64,
            flags: RangeFlags::from_bits(range.flags),
            instances: range.instances.as_ref(),
        })
    }

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm> {
        self.alarms
            .iter()
            .filter(move |alarm| alarm.parent_id == comp_id)
            .map(|alarm| Alarm {
                id: alarm.id.to_native(),
                parent_id: alarm.parent_id.to_native(),
                delta: AlarmDelta::from(&alarm.delta),
                flags: alarm.flags.to_native(),
            })
    }

    fn has_stored_alarms(&self) -> bool {
        !self.alarms.is_empty()
    }

    fn has_floating_stored_alarms(&self) -> bool {
        self.alarms
            .iter()
            .any(|alarm| matches!(alarm.delta, ArchivedAlarmDelta::FixedFloating(_)))
    }

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence {
        AlarmRecurrence::of(
            self.event.components.get(comp_id as usize),
            self.component_tz(u32::from(comp_id))
                .unwrap_or(component_tz),
            component_tz,
            flags,
        )
    }
}

impl EventAlarmData for CalendarEventData {
    fn alarm_base_offset(&self) -> i64 {
        self.base_offset
    }

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>> {
        self.time_ranges.iter().map(|range| AlarmRange {
            comp_id: range.id,
            start_tz: range.start_tz,
            end_tz: range.end_tz,
            duration: range.duration as i64,
            flags: RangeFlags::from_bits(range.flags),
            instances: range.instances.as_ref(),
        })
    }

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm> {
        self.alarms
            .iter()
            .filter(move |alarm| alarm.parent_id == comp_id)
            .cloned()
    }

    fn has_stored_alarms(&self) -> bool {
        !self.alarms.is_empty()
    }

    fn has_floating_stored_alarms(&self) -> bool {
        self.alarms
            .iter()
            .any(|alarm| matches!(alarm.delta, AlarmDelta::FixedFloating(_)))
    }

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence {
        AlarmRecurrence::of(
            self.event.components.get(comp_id as usize),
            self.component_tz(u32::from(comp_id))
                .unwrap_or(component_tz),
            component_tz,
            flags,
        )
    }
}

pub trait ExpandAlarm {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm>;
}

impl ExpandAlarm for ICalendarComponent {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm> {
        let mut trigger = None;
        let mut flags = 0;

        for entry in self.entries.iter() {
            match &entry.name {
                ICalendarProperty::Trigger => {
                    let mut tz = None;
                    let mut trigger_start = true;

                    for param in entry.params.iter() {
                        match (&param.name, &param.value) {
                            (
                                ICalendarParameterName::Related,
                                ICalendarParameterValue::Related(related),
                            ) => {
                                trigger_start = matches!(related, ICalendarRelated::Start);
                            }
                            (
                                ICalendarParameterName::Tzid,
                                ICalendarParameterValue::Text(tz_id),
                            ) => {
                                tz = Tz::from_str(tz_id).ok();
                            }
                            _ => {}
                        }
                    }

                    trigger = match entry.values.first()? {
                        ICalendarValue::PartialDateTime(dt) => {
                            let tz = tz.unwrap_or(Tz::Floating);

                            dt.to_date_time_with_tz(tz).map(|dt| {
                                let timestamp = dt.timestamp();
                                if !dt.timezone().is_floating() {
                                    AlarmDelta::FixedUtc(timestamp)
                                } else {
                                    AlarmDelta::FixedFloating(timestamp)
                                }
                            })
                        }
                        ICalendarValue::Duration(duration) => {
                            if trigger_start {
                                Some(AlarmDelta::Start(duration.into()))
                            } else {
                                Some(AlarmDelta::End(duration.into()))
                            }
                        }
                        _ => None,
                    };
                }
                ICalendarProperty::Action => {
                    if entry
                        .values
                        .first()
                        .and_then(|v| v.as_text())
                        .is_some_and(|v| v.eq_ignore_ascii_case("email"))
                    {
                        flags |= ALARM_EMAIL;
                    }
                }
                ICalendarProperty::Summary | ICalendarProperty::Description
                    if !entry.is_derived()
                        && entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .is_some_and(|v| v.contains("@email")) =>
                {
                    flags |= ALARM_EMAIL;
                }
                _ => {}
            }
        }

        trigger.map(|delta| Alarm {
            id,
            parent_id,
            delta,
            flags,
        })
    }
}

impl AlarmDelta {
    pub fn to_timestamp(
        &self,
        start: &ZonedDateTime,
        end: &ZonedDateTime,
        default_tz: Tz,
    ) -> Option<i64> {
        match self {
            AlarmDelta::Start(offset) => offset.apply(start),
            AlarmDelta::End(offset) => offset.apply(end),
            AlarmDelta::FixedUtc(_) | AlarmDelta::FixedFloating(_) => {
                self.fixed_timestamp(default_tz)
            }
        }
    }

    pub fn fixed_timestamp(&self, default_tz: Tz) -> Option<i64> {
        match self {
            AlarmDelta::FixedUtc(timestamp) => Some(*timestamp),
            AlarmDelta::FixedFloating(timestamp) => resolve_local(default_tz, *timestamp),
            AlarmDelta::Start(_) | AlarmDelta::End(_) => None,
        }
    }
}

impl From<&ArchivedAlarmDelta> for AlarmDelta {
    fn from(delta: &ArchivedAlarmDelta) -> Self {
        match delta {
            ArchivedAlarmDelta::Start(offset) => AlarmDelta::Start(offset.into()),
            ArchivedAlarmDelta::End(offset) => AlarmDelta::End(offset.into()),
            ArchivedAlarmDelta::FixedUtc(timestamp) => AlarmDelta::FixedUtc(timestamp.to_native()),
            ArchivedAlarmDelta::FixedFloating(timestamp) => {
                AlarmDelta::FixedFloating(timestamp.to_native())
            }
        }
    }
}

impl AlarmOffset {
    pub fn naive_seconds(&self) -> i64 {
        i64::from(self.days) * SECONDS_PER_DAY + i64::from(self.seconds)
    }

    pub fn apply(&self, from: &ZonedDateTime) -> Option<i64> {
        from.checked_add_nominal(NominalDuration::new(self.days, 0))
            .map(|at| at.timestamp() + i64::from(self.seconds))
    }
}

impl From<&ICalendarDuration> for AlarmOffset {
    fn from(duration: &ICalendarDuration) -> Self {
        let days = i32::try_from(u64::from(duration.weeks) * 7 + u64::from(duration.days))
            .unwrap_or(i32::MAX);
        let seconds = i32::try_from(
            u64::from(duration.hours) * 3600
                + u64::from(duration.minutes) * 60
                + u64::from(duration.seconds),
        )
        .unwrap_or(i32::MAX);
        if duration.neg {
            AlarmOffset {
                days: -days,
                seconds: -seconds,
            }
        } else {
            AlarmOffset { days, seconds }
        }
    }
}

impl From<&ArchivedAlarmOffset> for AlarmOffset {
    fn from(offset: &ArchivedAlarmOffset) -> Self {
        AlarmOffset {
            days: offset.days.to_native(),
            seconds: offset.seconds.to_native(),
        }
    }
}

