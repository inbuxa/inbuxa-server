/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::alarm::{AlarmTarget, CalendarComponentView, CalendarView};
use super::schedule::{AlarmTasks, EventAlarmContent, EventAlarmScheduler, EventAlarmUsers};
use super::{
    ALERT_EMAIL, ALERT_RELATIVE_TO_END, ALERT_WITH_TIME, AlarmDelta, ArchivedCalendar,
    CALENDAR_SUBSCRIBED, Calendar, CalendarEventContent, DefaultAlert, EVENT_HAS_ALARMS,
    EVENT_USES_DEFAULT_ALERTS, default_preference_flags,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarRelated, ICalendarRelationshipType, ICalendarValue, Uri,
    },
};
use common::{GroupwareResources, Server, storage::batch::MAX_BATCH_DOCUMENTS};
use std::{collections::hash_map::Entry, sync::Arc};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

const MAX_DEFAULT_ALERTS: usize = 1024;
const DEFAULT_ALARM_DESCRIPTION: &str = "Reminder";
const MAILTO_PREFIX: &str = "mailto:";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DefaultAlerts {
    enabled: bool,
    alerts: Vec<DefaultAlert>,
    recipient: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultAlarmText<'x> {
    pub description: &'x str,
    pub recipient: Option<&'x str>,
}

impl DefaultAlerts {
    pub fn disabled() -> Self {
        DefaultAlerts::default()
    }

    pub(crate) fn merge<'x>(
        calendars: impl Iterator<Item = &'x CalendarSettings>,
        personal_id: u32,
        inherit_from: Option<u32>,
        with_time: bool,
    ) -> Self {
        let mut alert_ids = AHashSet::new();
        DefaultAlerts {
            enabled: true,
            alerts: calendars
                .filter_map(|settings| settings.user_or_inherited(personal_id, inherit_from))
                .flat_map(|settings| settings.alerts.iter())
                .filter(|alert| {
                    (alert.flags & ALERT_WITH_TIME != 0) == with_time
                        && alert_ids.insert(alert.id.as_str())
                })
                .take(MAX_DEFAULT_ALERTS)
                .cloned()
                .collect(),
            recipient: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn has_alerts(&self) -> bool {
        !self.alerts.is_empty()
    }

    pub fn has_email_alerts(&self) -> bool {
        self.alerts.iter().any(DefaultAlert::is_email)
    }

    pub fn get(&self, index: u16) -> Option<&DefaultAlert> {
        self.alerts.get(index as usize)
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.alerts.iter().any(|alert| alert.id == id)
    }

    pub fn indexed_alerts(&self) -> impl Iterator<Item = (u16, &DefaultAlert)> {
        self.alerts
            .iter()
            .zip(0u16..)
            .map(|(alert, index)| (index, alert))
    }
}

impl DefaultAlert {
    pub fn is_email(&self) -> bool {
        self.flags & ALERT_EMAIL != 0
    }

    pub fn delta(&self) -> AlarmDelta {
        if self.flags & ALERT_RELATIVE_TO_END != 0 {
            AlarmDelta::End((&self.offset).into())
        } else {
            AlarmDelta::Start((&self.offset).into())
        }
    }

    pub fn to_ical(&self, text: Option<DefaultAlarmText<'_>>) -> ICalendarComponent {
        let mut entries = Vec::with_capacity(6);
        entries.push(
            ICalendarEntry::new(ICalendarProperty::Jsid)
                .with_value(ICalendarValue::Text(self.id.clone())),
        );
        entries.push(ICalendarEntry::new(ICalendarProperty::Action).with_value(
            if self.is_email() {
                ICalendarValue::Action(ICalendarAction::Email)
            } else {
                ICalendarValue::Action(ICalendarAction::Display)
            },
        ));
        entries.push(
            ICalendarEntry::new(ICalendarProperty::Trigger)
                .with_param_opt((self.flags & ALERT_RELATIVE_TO_END != 0).then_some(
                    ICalendarParameter::related(ICalendarParameterValue::Related(
                        ICalendarRelated::End,
                    )),
                ))
                .with_value(ICalendarValue::Duration(self.offset.clone())),
        );
        if let Some(text) = text {
            entries.push(
                ICalendarEntry::new(ICalendarProperty::Description).with_value(text.description),
            );
            if self.is_email() {
                entries.push(
                    ICalendarEntry::new(ICalendarProperty::Summary).with_value(text.description),
                );
                if let Some(recipient) = text.recipient {
                    let mut address = String::with_capacity(MAILTO_PREFIX.len() + recipient.len());
                    address.push_str(MAILTO_PREFIX);
                    address.push_str(recipient);
                    entries.push(
                        ICalendarEntry::new(ICalendarProperty::Attendee)
                            .with_value(Uri::Location(address)),
                    );
                }
            }
        }

        ICalendarComponent {
            component_type: ICalendarComponentType::VAlarm,
            entries,
            component_ids: vec![],
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CalendarSettings(Vec<UserCalendarSettings>);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserCalendarSettings {
    pub account_id: u32,
    pub is_subscribed: bool,
    pub time_zone: Tz,
    pub alerts: Vec<DefaultAlert>,
}

impl UserCalendarSettings {
    fn differs_only_in_alerts(&self, other: &Self) -> bool {
        self.is_subscribed == other.is_subscribed && self.time_zone == other.time_zone
    }
}

impl CalendarSettings {
    pub fn user(&self, account_id: u32) -> Option<&UserCalendarSettings> {
        self.0
            .iter()
            .find(|settings| settings.account_id == account_id)
    }

    fn user_or_inherited(
        &self,
        account_id: u32,
        inherit_from: Option<u32>,
    ) -> Option<&UserCalendarSettings> {
        self.user(account_id)
            .or_else(|| inherit_from.and_then(|account_id| self.user(account_id)))
    }

    fn changes<'x>(&'x self, other: &'x Self) -> impl Iterator<Item = (u32, bool)> + 'x {
        self.0
            .iter()
            .map(|settings| settings.account_id)
            .chain(
                other
                    .0
                    .iter()
                    .map(|settings| settings.account_id)
                    .filter(|account_id| self.user(*account_id).is_none()),
            )
            .filter_map(move |account_id| {
                let previous = self.user(account_id);
                let current = other.user(account_id);
                (previous != current).then(|| {
                    (
                        account_id,
                        previous.zip(current).is_some_and(|(previous, current)| {
                            previous.differs_only_in_alerts(current)
                        }),
                    )
                })
            })
    }

    async fn fetch(server: &Server, account_id: u32, calendar_id: u32) -> trc::Result<Self> {
        server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                calendar_id,
            ))
            .await
            .caused_by(trc::location!())?
            .map(|archive| archive.unarchive::<Calendar>().map(CalendarSettings::from))
            .transpose()
            .map(Option::unwrap_or_default)
            .caused_by(trc::location!())
    }
}

impl From<&Calendar> for CalendarSettings {
    fn from(calendar: &Calendar) -> Self {
        CalendarSettings(
            calendar
                .preferences
                .iter()
                .map(|preferences| UserCalendarSettings {
                    account_id: preferences.account_id,
                    is_subscribed: preferences.flags & CALENDAR_SUBSCRIBED != 0,
                    time_zone: preferences.time_zone.tz().unwrap_or_default(),
                    alerts: preferences.default_alerts.clone(),
                })
                .collect(),
        )
    }
}

impl From<&ArchivedCalendar> for CalendarSettings {
    fn from(calendar: &ArchivedCalendar) -> Self {
        CalendarSettings(
            calendar
                .preferences
                .iter()
                .map(|preferences| UserCalendarSettings {
                    account_id: preferences.account_id.to_native(),
                    is_subscribed: preferences.flags.to_native() & CALENDAR_SUBSCRIBED != 0,
                    time_zone: preferences.time_zone.tz().unwrap_or_default(),
                    alerts: preferences
                        .default_alerts
                        .iter()
                        .map(|alert| DefaultAlert {
                            id: alert.id.to_string(),
                            offset: alert.offset.to_native(),
                            flags: alert.flags.to_native(),
                        })
                        .collect(),
                })
                .collect(),
        )
    }
}

#[derive(Default)]
pub struct DefaultAlertsResolver {
    calendars: AHashMap<(u32, u32), CalendarSettings>,
    resources: Option<(u32, Arc<GroupwareResources>)>,
    recipients: AHashMap<u32, Option<Arc<str>>>,
    members: AHashMap<(u32, u32), bool>,
}

impl DefaultAlertsResolver {
    pub fn with_resources(account_id: u32, resources: Arc<GroupwareResources>) -> Self {
        DefaultAlertsResolver {
            resources: Some((account_id, resources)),
            ..Default::default()
        }
    }

    pub fn with_calendar(
        mut self,
        account_id: u32,
        calendar_id: u32,
        settings: CalendarSettings,
    ) -> Self {
        self.set_calendar_settings(account_id, calendar_id, settings);
        self
    }

    pub fn set_calendar_settings(
        &mut self,
        account_id: u32,
        calendar_id: u32,
        settings: CalendarSettings,
    ) {
        self.calendars.insert((account_id, calendar_id), settings);
    }

    async fn settings(
        &mut self,
        server: &Server,
        account_id: u32,
        calendar_id: u32,
    ) -> trc::Result<&CalendarSettings> {
        Ok(match self.calendars.entry((account_id, calendar_id)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(CalendarSettings::fetch(server, account_id, calendar_id).await?)
            }
        })
    }

    fn cached_subscription(
        &self,
        account_id: u32,
        personal_id: u32,
        calendar_id: u32,
    ) -> Option<Option<bool>> {
        if let Some(settings) = self.calendars.get(&(account_id, calendar_id)) {
            return Some(
                settings
                    .user(personal_id)
                    .map(|settings| settings.is_subscribed),
            );
        }
        self.resources
            .as_ref()
            .filter(|(resources_account_id, _)| *resources_account_id == account_id)
            .and_then(|(_, resources)| resources.container_resource_by_id(calendar_id))
            .map(|calendar| {
                calendar
                    .personal_calendar_preferences(personal_id)
                    .map(|preferences| preferences.flags & CALENDAR_SUBSCRIBED != 0)
            })
    }

    async fn is_member(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
    ) -> trc::Result<bool> {
        if personal_id == account_id {
            return Ok(true);
        }
        Ok(match self.members.entry((account_id, personal_id)) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => *entry.insert(
                server
                    .account(personal_id)
                    .await
                    .caused_by(trc::location!())?
                    .id_member_of
                    .contains(&account_id),
            ),
        })
    }

    pub async fn is_subscribed(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        calendar_ids: impl IntoIterator<Item = u32>,
    ) -> trc::Result<bool> {
        let mut default_subscription = None;
        for calendar_id in calendar_ids {
            let is_subscribed = match self.cached_subscription(account_id, personal_id, calendar_id)
            {
                Some(is_subscribed) => is_subscribed,
                None => self
                    .settings(server, account_id, calendar_id)
                    .await?
                    .user(personal_id)
                    .map(|settings| settings.is_subscribed),
            };
            let is_subscribed = match is_subscribed {
                Some(is_subscribed) => is_subscribed,
                None => match default_subscription {
                    Some(is_subscribed) => is_subscribed,
                    None => {
                        let is_member = self.is_member(server, account_id, personal_id).await?;
                        *default_subscription
                            .insert(default_preference_flags(is_member) & CALENDAR_SUBSCRIBED != 0)
                    }
                },
            };
            if is_subscribed {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn time_zone(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        calendar_ids: impl IntoIterator<Item = u32>,
    ) -> trc::Result<Tz> {
        let inherit_from = self
            .is_member(server, account_id, personal_id)
            .await?
            .then_some(account_id);
        for calendar_id in calendar_ids {
            if let Some(time_zone) = self
                .settings(server, account_id, calendar_id)
                .await?
                .user_or_inherited(personal_id, inherit_from)
                .map(|settings| settings.time_zone)
                .filter(|time_zone| !time_zone.is_floating())
            {
                return Ok(time_zone);
            }
        }
        Ok(Tz::Floating)
    }

    pub async fn resolve(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        use_default_alerts: bool,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
        with_time: bool,
    ) -> trc::Result<DefaultAlerts> {
        if !use_default_alerts {
            return Ok(DefaultAlerts::disabled());
        }

        for calendar_id in calendar_ids.clone() {
            self.settings(server, account_id, calendar_id).await?;
        }
        let inherit_from = self
            .is_member(server, account_id, personal_id)
            .await?
            .then_some(account_id);

        Ok(DefaultAlerts::merge(
            calendar_ids
                .into_iter()
                .filter_map(|calendar_id| self.calendars.get(&(account_id, calendar_id))),
            personal_id,
            inherit_from,
            with_time,
        ))
    }

    async fn recipient(
        &mut self,
        server: &Server,
        personal_id: u32,
    ) -> trc::Result<Option<Arc<str>>> {
        Ok(match self.recipients.entry(personal_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let account = server
                    .account(personal_id)
                    .await
                    .caused_by(trc::location!())?;
                entry
                    .insert((!account.name.is_empty()).then(|| Arc::from(account.name.as_ref())))
                    .clone()
            }
        })
    }
}

impl DefaultAlertsResolver {
    pub async fn resolve_for_content<C: EventAlarmContent + Sync>(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        content: &C,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
    ) -> trc::Result<DefaultAlerts> {
        self.resolve(
            server,
            account_id,
            personal_id,
            content.uses_default_alerts(personal_id),
            calendar_ids,
            !content.shows_without_time(),
        )
        .await
    }

    pub async fn resolve_for_ical_view<C: EventAlarmContent + Sync>(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        content: &C,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
    ) -> trc::Result<DefaultAlerts> {
        let mut default_alerts = self
            .resolve_for_content(server, account_id, personal_id, content, calendar_ids)
            .await?;
        if default_alerts.has_email_alerts() {
            default_alerts.recipient = self.recipient(server, personal_id).await?;
        }
        Ok(default_alerts)
    }
}

pub trait CalendarAlarmsReschedule: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    fn reschedule_calendar_alarms(
        &self,
        resources: &Arc<GroupwareResources>,
        account_id: u32,
        calendar_id: u32,
        previous: CalendarSettings,
        current: CalendarSettings,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl CalendarAlarmsReschedule for Server {
    async fn reschedule_calendar_alarms(
        &self,
        resources: &Arc<GroupwareResources>,
        account_id: u32,
        calendar_id: u32,
        previous: CalendarSettings,
        current: CalendarSettings,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let mut targets = Vec::new();
        let mut required_flags = 0;
        for (changed_id, differs_only_in_alerts) in previous.changes(&current) {
            targets.push(AlarmTarget::for_account(account_id, changed_id));
            required_flags |= if differs_only_in_alerts {
                EVENT_USES_DEFAULT_ALERTS
            } else {
                EVENT_HAS_ALARMS
            };
        }
        if targets.is_empty() {
            return Ok(());
        }

        let mut previous_resolver = DefaultAlertsResolver::with_resources(
            account_id,
            resources.clone(),
        )
        .with_calendar(account_id, calendar_id, previous);
        let mut current_resolver = DefaultAlertsResolver::with_resources(
            account_id,
            resources.clone(),
        )
        .with_calendar(account_id, calendar_id, current);
        let now = now() as i64;
        let mut calendar_ids = Vec::new();

        let mut children = resources
            .children(calendar_id)
            .filter_map(|resource| {
                resource
                    .resource
                    .event_flags()
                    .filter(|flags| flags & required_flags != 0)
                    .map(|flags| (resource.document_id(), flags, resource.resource))
            })
            .collect::<Vec<_>>();
        children.sort_unstable_by_key(|(document_id, ..)| *document_id);
        let mut content_ids = Vec::new();

        for chunk in children.chunks(MAX_BATCH_DOCUMENTS) {
            content_ids.clear();
            content_ids.extend(chunk.iter().map(|(document_id, ..)| *document_id));
            let mut contents = self
                .archive_chunk(
                    account_id,
                    Collection::CalendarEvent,
                    &[],
                    Some((CalendarEventField::Content.field(), &content_ids)),
                )
                .await
                .caused_by(trc::location!())?;
            let mut tasks = AlarmTasks::pending(
                content_ids
                    .iter()
                    .flat_map(|document_id| {
                        targets
                            .iter()
                            .map(|target| target.task_id().resolve(account_id, *document_id))
                    })
                    .collect(),
            );

            for &(document_id, event_flags, resource) in chunk {
                let Some(content_) = contents.take_value(document_id) else {
                    continue;
                };
                let content = content_
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                calendar_ids.clear();
                calendar_ids.extend(resource.child_names().iter().map(|name| name.parent_id));

                for target in targets.iter().copied() {
                    let users = EventAlarmUsers::for_target(account_id, content, target)?
                        .with_event_flags(event_flags);
                    let previous_alarm = self
                        .next_event_alarms(
                            account_id,
                            &users,
                            &content.data,
                            &calendar_ids,
                            now,
                            &mut previous_resolver,
                        )
                        .await?
                        .into_alarm();
                    let next_alarm = self
                        .next_event_alarms(
                            account_id,
                            &users,
                            &content.data,
                            &calendar_ids,
                            now,
                            &mut current_resolver,
                        )
                        .await?
                        .into_alarm();
                    self.replace_user_alarm(
                        account_id,
                        document_id,
                        previous_alarm,
                        next_alarm,
                        &mut tasks,
                        batch,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }
}

pub trait ICalendarShowWithoutTime {
    fn shows_without_time(&self) -> bool;
}

impl<T: CalendarView> ICalendarShowWithoutTime for T {
    fn shows_without_time(&self) -> bool {
        self.main_component()
            .is_some_and(CalendarComponentView::is_shown_without_time)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAlertsView {
    Replace,
    Merge,
    ICalendar,
}

pub trait ICalendarDefaultAlerts {
    fn apply_default_alerts(&mut self, defaults: &DefaultAlerts, view: DefaultAlertsView);

    fn strip_default_alerts(&mut self, defaults: &DefaultAlerts);

    fn is_kept_with_default_alerts(
        &self,
        alarm: &ICalendarComponent,
        defaults: &DefaultAlerts,
    ) -> bool;

    fn restore_hidden_alerts(&mut self, previous: &ICalendar, defaults: &DefaultAlerts);
}

impl ICalendarDefaultAlerts for ICalendar {
    fn apply_default_alerts(&mut self, defaults: &DefaultAlerts, view: DefaultAlertsView) {
        if !defaults.is_enabled() {
            return;
        }

        for comp_id in 0..self.components.len() {
            let Some(component) = self.components.get(comp_id) else {
                continue;
            };
            if !component.component_type.is_event_or_todo() {
                continue;
            }

            let text = (view == DefaultAlertsView::ICalendar).then(|| DefaultAlarmText {
                description: component
                    .property(&ICalendarProperty::Summary)
                    .and_then(|entry| entry.values.first())
                    .and_then(|value| value.as_text())
                    .filter(|summary| !summary.is_empty())
                    .unwrap_or(DEFAULT_ALARM_DESCRIPTION),
                recipient: defaults.recipient.as_deref(),
            });
            let mut stored_defaults: Vec<(&str, &[ICalendarEntry])> = Vec::new();
            let mut kept_ids = Vec::new();
            let mut removed_ids = Vec::new();
            for alarm_id in &component.component_ids {
                let Some(alarm) = self
                    .components
                    .get(*alarm_id as usize)
                    .filter(|c| c.component_type == ICalendarComponentType::VAlarm)
                else {
                    continue;
                };
                removed_ids.push(*alarm_id);
                if let Some(jsid) = alarm.jsid().filter(|id| defaults.contains_id(id)) {
                    stored_defaults.push((jsid, &alarm.entries));
                } else if view == DefaultAlertsView::Merge
                    || self.is_kept_with_default_alerts(alarm, defaults)
                {
                    kept_ids.push(*alarm_id);
                }
            }

            let mut new_alarms = Vec::with_capacity(defaults.alerts.len());
            for alert in &defaults.alerts {
                let mut alarm = alert.to_ical(text);
                if let Some((_, entries)) = stored_defaults.iter().find(|(id, _)| *id == alert.id) {
                    let generated = alarm.entries.len();
                    for entry in entries.iter() {
                        if !alarm
                            .entries
                            .iter()
                            .take(generated)
                            .any(|generated| generated.name == entry.name)
                        {
                            alarm.entries.push(entry.clone());
                        }
                    }
                }
                new_alarms.push(alarm);
            }

            let mut new_ids = Vec::with_capacity(new_alarms.len());
            for alarm in new_alarms {
                new_ids.push(self.components.len() as u32);
                self.components.push(alarm);
            }

            if let Some(component) = self.components.get_mut(comp_id) {
                component
                    .component_ids
                    .retain(|id| !removed_ids.contains(id) || kept_ids.contains(id));
                component.component_ids.extend(new_ids);
            }
        }
    }

    fn strip_default_alerts(&mut self, defaults: &DefaultAlerts) {
        if !defaults.is_enabled() {
            return;
        }

        let redundant = (0u32..)
            .zip(&self.components)
            .filter(|(_, c)| {
                c.component_type == ICalendarComponentType::VAlarm
                    && c.jsid().is_some_and(|id| defaults.contains_id(id))
                    && !c.has_property(&ICalendarProperty::Acknowledged)
            })
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        if !redundant.is_empty() && !self.remove_component_ids(&redundant) {
            for component in &mut self.components {
                component.component_ids.retain(|id| !redundant.contains(id));
            }
        }
    }

    fn is_kept_with_default_alerts(
        &self,
        alarm: &ICalendarComponent,
        defaults: &DefaultAlerts,
    ) -> bool {
        alarm.snoozed_alarms().any(|parent| {
            defaults.contains_id(parent)
                || self.components.iter().any(|c| {
                    c.component_type == ICalendarComponentType::VAlarm
                        && c.uid() == Some(parent)
                        && c.jsid().is_some_and(|id| defaults.contains_id(id))
                })
        })
    }
    fn restore_hidden_alerts(&mut self, previous: &ICalendar, defaults: &DefaultAlerts) {
        if !defaults.is_enabled() {
            return;
        }

        for comp_id in 0..self.components.len() {
            let Some(component) = self
                .components
                .get(comp_id)
                .filter(|c| c.component_type.is_event_or_todo())
            else {
                continue;
            };
            let recurrence_id = component.property(&ICalendarProperty::RecurrenceId);
            let Some(previous_component) = previous.components.iter().find(|c| {
                c.component_type == component.component_type
                    && c.property(&ICalendarProperty::RecurrenceId) == recurrence_id
            }) else {
                continue;
            };
            let hidden = previous_component
                .component_ids
                .iter()
                .filter_map(|id| previous.components.get(*id as usize))
                .filter(|alarm| {
                    alarm.component_type == ICalendarComponentType::VAlarm
                        && alarm.jsid().is_none_or(|id| !defaults.contains_id(id))
                        && !previous.is_kept_with_default_alerts(alarm, defaults)
                        && !component
                            .component_ids
                            .iter()
                            .filter_map(|id| self.components.get(*id as usize))
                            .any(|existing| existing == *alarm)
                })
                .cloned()
                .collect::<Vec<_>>();

            let first_id = self.components.len() as u32;
            let new_ids = first_id..first_id + hidden.len() as u32;
            self.components.extend(hidden);
            if let Some(component) = self.components.get_mut(comp_id) {
                component.component_ids.extend(new_ids);
            }
        }
    }
}

pub trait SnoozeAlarm {
    fn snoozed_alarms(&self) -> impl Iterator<Item = &str>;
}

impl SnoozeAlarm for ICalendarComponent {
    fn snoozed_alarms(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.name == ICalendarProperty::RelatedTo
                    && entry.params.iter().any(|param| {
                        param.name == ICalendarParameterName::Reltype
                            && matches!(
                                param.value,
                                ICalendarParameterValue::Reltype(ICalendarRelationshipType::Snooze)
                            )
                    })
            })
            .filter_map(|entry| entry.values.first().and_then(|value| value.as_text()))
    }
}

