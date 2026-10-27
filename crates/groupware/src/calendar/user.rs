/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEventContent, ArchivedEventPreferences, CalendarEventContent,
    CalendarEventData, EventPreferences, EventUserData, MAX_USER_ALERTS, MAX_USER_INSTANCES,
    MAX_USER_KEYWORD_LEN, MAX_USER_KEYWORDS, PREF_FREE_BUSY_FREE, PREF_HAS_ALERTS, PREF_HAS_COLOR,
    PREF_HAS_FREE_BUSY, PREF_HAS_KEYWORDS, PREF_HAS_USE_DEFAULT_ALERTS, PREF_USE_DEFAULT_ALERTS,
    color::CssColor,
    compare::{
        ComparisonScope, EntryList, NaiveDateTime, RecurrenceComponents, RedundantOverrides,
    },
    expand::{ComponentRecurrenceId, RecurrenceKey},
};
use ahash::AHashSet;
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameterName, ICalendarProperty, ICalendarTransparency, ICalendarValue,
        timezone::TzResolver,
    },
};

pub const BASE_INSTANCE: u32 = 0;

const DEFAULT_ALERT_FLAGS: u16 = PREF_HAS_USE_DEFAULT_ALERTS | PREF_USE_DEFAULT_ALERTS;
const MAX_COMPONENT_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataError {
    TooManyKeywords,
    KeywordTooLong,
    TooManyAlerts,
    TooManyInstances,
    InvalidColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserDataLookup {
    Inherited,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataView {
    Full,
    AlertsOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataSplit {
    UserDataOnly,
    SharedDataChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatedPolicy {
    Server(i64),
    Client,
}

#[derive(Debug, Clone, Copy)]
pub struct UserDataUpdate<'x> {
    pub account_id: u32,
    pub view: UserDataView,
    pub previous: Option<&'x EventPreferences>,
    pub current: Option<&'x EventPreferences>,
    pub updated: UpdatedPolicy,
}

impl CalendarEventContent {
    pub fn preferences(&self, account_id: u32) -> Option<&EventPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }

    pub fn preferences_mut(&mut self, account_id: u32) -> &mut EventPreferences {
        let idx = if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            idx
        } else {
            self.preferences.push(EventPreferences {
                account_id,
                ..Default::default()
            });
            self.preferences.len() - 1
        };

        &mut self.preferences[idx]
    }

    pub fn set_preferences(&mut self, preferences: EventPreferences) {
        let account_id = preferences.account_id;
        if preferences.is_empty() {
            self.preferences.retain(|p| p.account_id != account_id);
        } else if let Some(current) = self
            .preferences
            .iter_mut()
            .find(|p| p.account_id == account_id)
        {
            *current = preferences;
        } else {
            self.preferences.push(preferences);
        }
    }
}

impl ArchivedCalendarEventContent {
    pub fn preferences(&self, account_id: u32) -> Option<&ArchivedEventPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }
}

impl CalendarEventData {
    pub fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView) {
        if let Some(overrides) = self.user_data_overrides(preferences, view) {
            overrides.append_to(&mut self.event);
        }
        self.event.apply_user_data(preferences, view);
    }

    pub fn user_data_view(
        &self,
        preferences: Option<&EventPreferences>,
        view: UserDataView,
    ) -> ICalendar {
        let mut event = self.event.clone();
        if let Some(overrides) = self.user_data_overrides(preferences, view) {
            overrides.append_to(&mut event);
        }
        event.apply_user_data(preferences, view);
        event
    }

    fn user_data_overrides(
        &self,
        preferences: Option<&EventPreferences>,
        view: UserDataView,
    ) -> Option<PersonalOverrides> {
        let preferences = preferences.filter(|_| view == UserDataView::Full)?;
        let mut keys = preferences
            .instances
            .iter()
            .filter_map(|instance| RecurrenceKey::from_prefix(instance.recurrence_key))
            .collect::<AHashSet<_>>();
        let mut instance_keys = InstanceKeys::new(&self.event);
        for key in self
            .event
            .components
            .iter()
            .filter(|component| {
                component.is_user_data_component() && component.is_recurrence_override()
            })
            .filter_map(|component| instance_keys.of(component))
            .filter_map(RecurrenceKey::from_prefix)
            .collect::<Vec<_>>()
        {
            keys.remove(&key);
        }
        if keys.is_empty() {
            return None;
        }
        let base_id = self.event.base_component_id()?;
        let expansions = self.expand_from_ids(&mut keys, Tz::Floating)?;
        let root_id = self
            .event
            .components
            .iter()
            .position(|component| component.component_ids.contains(&base_id))?;
        let mut overrides = OccurrenceOverrides::new(&self.event, base_id)?;
        for expansion in expansions
            .iter()
            .filter(|expansion| expansion.comp_id == base_id)
        {
            overrides.push(expansion.start_naive);
        }
        Some(overrides.into_personal_overrides(root_id))
    }
}

struct PersonalOverrides {
    root_id: usize,
    override_ids: Vec<u32>,
    components: Vec<ICalendarComponent>,
}

impl PersonalOverrides {
    fn append_to(self, event: &mut ICalendar) {
        event.components.extend(self.components);
        if let Some(root) = event.components.get_mut(self.root_id) {
            root.component_ids.extend(self.override_ids);
        }
    }
}

impl EventPreferences {
    pub fn instance(&self, recurrence_key: u32) -> Option<&EventUserData> {
        self.instances
            .binary_search_by_key(&recurrence_key, |i| i.recurrence_key)
            .ok()
            .and_then(|idx| self.instances.get(idx))
    }

    pub fn instance_mut(
        &mut self,
        recurrence_key: u32,
    ) -> Result<&mut EventUserData, UserDataError> {
        let idx = match self
            .instances
            .binary_search_by_key(&recurrence_key, |i| i.recurrence_key)
        {
            Ok(idx) => idx,
            Err(idx) => {
                if self.instances.len() >= MAX_USER_INSTANCES {
                    return Err(UserDataError::TooManyInstances);
                }
                self.instances.insert(
                    idx,
                    EventUserData {
                        recurrence_key,
                        ..Default::default()
                    },
                );
                idx
            }
        };
        self.instances
            .get_mut(idx)
            .ok_or(UserDataError::TooManyInstances)
    }

    pub fn use_default_alerts(&self) -> bool {
        self.instance(BASE_INSTANCE)
            .is_some_and(|i| i.flags & PREF_USE_DEFAULT_ALERTS != 0)
    }

    pub fn set_use_default_alerts(&mut self, value: bool) -> Result<(), UserDataError> {
        let instance = self.instance_mut(BASE_INSTANCE)?;
        instance.flags |= PREF_HAS_USE_DEFAULT_ALERTS;
        if value {
            instance.flags |= PREF_USE_DEFAULT_ALERTS;
        } else {
            instance.flags &= !PREF_USE_DEFAULT_ALERTS;
        }
        Ok(())
    }

    pub fn inherit_default_alerts(
        &mut self,
        current: Option<&EventPreferences>,
    ) -> Result<(), UserDataError> {
        if let Some(flags) = current
            .and_then(|preferences| preferences.instance(BASE_INSTANCE))
            .map(|base| base.flags & DEFAULT_ALERT_FLAGS)
            .filter(|flags| *flags != 0)
        {
            self.instance_mut(BASE_INSTANCE)?.flags |= flags;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.updated == 0 && self.instances.iter().all(|i| i.flags == 0)
    }

    pub fn size(&self) -> usize {
        self.instances.iter().map(|i| i.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }

    fn stamp_updated(&mut self, update: &UserDataUpdate<'_>, client_updated: Option<i64>) {
        let previous_updated = update.previous.map_or(0, |previous| previous.updated);
        let is_changed = update
            .previous
            .map_or(!self.instances.is_empty(), |previous| {
                previous.instances != self.instances
            });
        self.updated = match update.updated {
            UpdatedPolicy::Server(now) if is_changed => now,
            UpdatedPolicy::Client => client_updated.unwrap_or(previous_updated),
            UpdatedPolicy::Server(_) => previous_updated,
        };
    }
}

impl ArchivedEventPreferences {
    pub fn use_default_alerts(&self) -> bool {
        self.instances
            .iter()
            .find(|i| i.recurrence_key == BASE_INSTANCE)
            .is_some_and(|i| i.flags & PREF_USE_DEFAULT_ALERTS != 0)
    }

    pub fn is_free(&self, recurrence_key: u32) -> Option<bool> {
        [recurrence_key, BASE_INSTANCE]
            .into_iter()
            .filter_map(|key| {
                self.instances
                    .binary_search_by_key(&key, |i| i.recurrence_key.to_native())
                    .ok()
                    .and_then(|idx| self.instances.get(idx))
            })
            .map(|i| i.flags.to_native())
            .find(|flags| flags & PREF_HAS_FREE_BUSY != 0)
            .map(|flags| flags & PREF_FREE_BUSY_FREE != 0)
    }

    pub fn size(&self) -> usize {
        self.instances
            .iter()
            .map(|i| {
                i.keywords.iter().map(|k| k.len()).sum::<usize>()
                    + i.alerts.iter().map(|a| a.size()).sum::<usize>()
                    + std::mem::size_of::<EventUserData>()
            })
            .sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl EventUserData {
    pub fn set_color(&mut self, color: Option<CssColor>) {
        self.flags |= PREF_HAS_COLOR;
        self.color = color;
    }

    pub fn set_free_busy(&mut self, is_free: bool) {
        self.flags |= PREF_HAS_FREE_BUSY;
        if is_free {
            self.flags |= PREF_FREE_BUSY_FREE;
        } else {
            self.flags &= !PREF_FREE_BUSY_FREE;
        }
    }

    pub fn set_keywords<'x>(
        &mut self,
        keywords: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), UserDataError> {
        self.keywords.clear();
        for keyword in keywords {
            if keyword.len() > MAX_USER_KEYWORD_LEN {
                return Err(UserDataError::KeywordTooLong);
            }
            if self.keywords.len() >= MAX_USER_KEYWORDS {
                return Err(UserDataError::TooManyKeywords);
            }
            if !self.keywords.iter().any(|k| k == keyword) {
                self.keywords.push(keyword.to_string());
            }
        }
        self.flags |= PREF_HAS_KEYWORDS;
        Ok(())
    }

    pub fn set_alerts(&mut self, alerts: Vec<ICalendarComponent>) -> Result<(), UserDataError> {
        if alerts.len() > MAX_USER_ALERTS {
            return Err(UserDataError::TooManyAlerts);
        }
        self.flags |= PREF_HAS_ALERTS;
        self.alerts = alerts;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.keywords.iter().map(|k| k.len()).sum::<usize>()
            + self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + std::mem::size_of::<EventUserData>()
    }

    fn clear_alerts(&mut self) {
        self.flags &= !PREF_HAS_ALERTS;
        self.alerts.clear();
    }

    fn remove_inherited(&mut self, base: &EventUserData) {
        for flag in [
            PREF_HAS_COLOR,
            PREF_HAS_KEYWORDS,
            PREF_HAS_FREE_BUSY,
            PREF_HAS_ALERTS,
        ] {
            let (has_self, has_base) = (self.flags & flag != 0, base.flags & flag != 0);
            let is_inherited = match (has_self, has_base) {
                (false, false) => true,
                (true, true) => match flag {
                    PREF_HAS_COLOR => self.color == base.color,
                    PREF_HAS_KEYWORDS => self.keywords == base.keywords,
                    PREF_HAS_FREE_BUSY => {
                        self.flags & PREF_FREE_BUSY_FREE == base.flags & PREF_FREE_BUSY_FREE
                    }
                    _ => self.alerts == base.alerts,
                },
                _ => false,
            };
            if is_inherited {
                self.flags &= !flag;
                match flag {
                    PREF_HAS_COLOR => self.color = None,
                    PREF_HAS_KEYWORDS => self.keywords.clear(),
                    PREF_HAS_FREE_BUSY => self.flags &= !PREF_FREE_BUSY_FREE,
                    _ => self.alerts.clear(),
                }
            } else {
                self.flags |= flag;
            }
        }
    }
}

pub trait UserDataEntry {
    fn is_user_data(&self) -> bool;
}

impl UserDataEntry for ICalendarEntry {
    fn is_user_data(&self) -> bool {
        match &self.name {
            ICalendarProperty::Color
            | ICalendarProperty::Categories
            | ICalendarProperty::Transp => true,
            ICalendarProperty::Jsprop => self
                .parameter(&ICalendarParameterName::Jsptr)
                .and_then(|pointer| pointer.as_text())
                .and_then(|pointer| pointer.split('/').next())
                .is_some_and(|property| {
                    hashify::set!(
                        property.as_bytes(),
                        "alerts",
                        "color",
                        "freeBusyStatus",
                        "keywords",
                        "useDefaultAlerts"
                    )
                }),
            _ => false,
        }
    }
}

pub trait ICalendarUserData {
    fn validate_user_data(&self) -> Result<(), UserDataError>;

    fn validate_user_data_changes(&self, stored: &ICalendar) -> Result<(), UserDataError>;

    fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView);

    fn extract_user_data(&self, account_id: u32) -> Result<EventPreferences, UserDataError>;

    fn extract_user_preferences(
        &self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<EventPreferences, UserDataError>;

    fn copy_user_data(&mut self, source: &ICalendar) -> Vec<i64>;

    fn split_user_data(
        &mut self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<(EventPreferences, UserDataSplit), UserDataError>;

    fn user_data_override(
        &self,
        comp_id: u32,
        recurrence_key: RecurrenceKey,
    ) -> Option<&ICalendarComponent>;

    fn has_same_user_data(&self, stored: &ICalendar) -> bool;
}

impl ICalendarUserData for ICalendar {
    fn validate_user_data(&self) -> Result<(), UserDataError> {
        self.components
            .iter()
            .filter(|c| c.is_user_data_component())
            .try_for_each(|component| UserDataUsage::new(self, component).validate(None))
    }

    fn validate_user_data_changes(&self, stored: &ICalendar) -> Result<(), UserDataError> {
        let stored_components = UserDataComponents::new(stored);
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .iter()
            .filter(|c| c.is_user_data_component())
            .try_for_each(|component| {
                UserDataUsage::new(self, component).validate(
                    instance_keys
                        .of(component)
                        .and_then(|key| {
                            stored_components.counterpart(key, UserDataLookup::Inherited)
                        })
                        .map(|stored_component| UserDataUsage::new(stored, stored_component))
                        .as_ref(),
                )
            })
    }

    fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView) {
        let base = preferences.and_then(|p| p.instance(BASE_INSTANCE));
        for (comp_id, key) in self.user_data_component_ids() {
            let instance = preferences
                .filter(|_| key != BASE_INSTANCE)
                .and_then(|p| p.instance(key));
            let resolve = |flag: u16| {
                instance
                    .filter(|i| i.flags & flag != 0)
                    .or_else(|| base.filter(|b| b.flags & flag != 0))
            };

            let first_alert_id = self.components.len() as u32;
            self.components.extend(
                resolve(PREF_HAS_ALERTS)
                    .into_iter()
                    .flat_map(|i| i.alerts.iter())
                    .map(ICalendarComponent::detached),
            );
            let alert_ids = first_alert_id..self.components.len() as u32;

            let entries = (view == UserDataView::Full).then(|| {
                [
                    resolve(PREF_HAS_COLOR)
                        .and_then(|i| i.color.as_ref())
                        .map(|color| ICalendarEntry {
                            name: ICalendarProperty::Color,
                            params: vec![],
                            values: [ICalendarValue::Text(color.to_string())].into(),
                        }),
                    resolve(PREF_HAS_KEYWORDS)
                        .filter(|i| !i.keywords.is_empty())
                        .map(|i| ICalendarEntry {
                            name: ICalendarProperty::Categories,
                            params: vec![],
                            values: i
                                .keywords
                                .iter()
                                .map(|k| ICalendarValue::Text(k.clone()))
                                .collect(),
                        }),
                    resolve(PREF_HAS_FREE_BUSY).map(|i| ICalendarEntry {
                        name: ICalendarProperty::Transp,
                        params: vec![],
                        values: [ICalendarValue::Transparency(
                            if i.flags & PREF_FREE_BUSY_FREE != 0 {
                                ICalendarTransparency::Transparent
                            } else {
                                ICalendarTransparency::Opaque
                            },
                        )]
                        .into(),
                    }),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
            });
            self.replace_user_data(comp_id, alert_ids, entries);
        }
    }

    fn extract_user_data(&self, account_id: u32) -> Result<EventPreferences, UserDataError> {
        let mut preferences = EventPreferences {
            account_id,
            ..Default::default()
        };
        let base = match self
            .base_component_id()
            .and_then(|id| self.component_by_id(id))
        {
            Some(component) => self.component_user_data(component)?,
            None => EventUserData::default(),
        };

        let mut instance_keys = InstanceKeys::new(self);
        for component in self
            .components
            .iter()
            .filter(|c| c.is_user_data_component() && c.is_recurrence_override())
        {
            let Some(key) = instance_keys.of(component) else {
                continue;
            };
            let mut data = self.component_user_data(component)?;
            data.remove_inherited(&base);
            if data.flags != 0 {
                *preferences.instance_mut(key)? = EventUserData {
                    recurrence_key: key,
                    ..data
                };
            }
        }
        if base.flags != 0 {
            *preferences.instance_mut(BASE_INSTANCE)? = base;
        }

        Ok(preferences)
    }

    fn extract_user_preferences(
        &self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<EventPreferences, UserDataError> {
        let mut preferences = match update.view {
            UserDataView::Full => {
                let mut preferences = self.extract_user_data(update.account_id)?;
                preferences.inherit_default_alerts(update.current)?;
                preferences
            }
            UserDataView::AlertsOnly => {
                self.extract_alerts(update.current.cloned().unwrap_or_else(|| EventPreferences {
                    account_id: update.account_id,
                    ..Default::default()
                }))?
            }
        };
        preferences.stamp_updated(
            &update,
            self.base_updated()
                .filter(|updated| stored.base_updated() != Some(*updated)),
        );

        Ok(preferences)
    }

    fn copy_user_data(&mut self, source: &ICalendar) -> Vec<i64> {
        let dropped = {
            let stored = UserDataComponents::new(self);
            let mut instance_keys = InstanceKeys::new(source);
            source
                .components
                .iter()
                .filter(|component| component.is_user_data_component())
                .filter_map(|component| {
                    let recurrence_id = instance_keys.recurrence_id(component)?;
                    let key = RecurrenceKey::from_recurrence_id(recurrence_id)?.prefix();
                    (!stored.contains(key)).then_some(recurrence_id)
                })
                .collect::<Vec<_>>()
        };

        self.restore_user_data(
            &UserDataComponents::new(source),
            UserDataView::Full,
            UserDataLookup::Exact,
        );
        self.drop_unreachable_components();
        dropped
    }

    fn split_user_data(
        &mut self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<(EventPreferences, UserDataSplit), UserDataError> {
        let preferences = self.extract_user_preferences(stored, update)?;
        let stored_components = UserDataComponents::new(stored);
        self.restore_user_data(&stored_components, update.view, UserDataLookup::Inherited);
        self.prune_user_data_overrides(&stored_components);

        let split = if ComparisonScope::SharedData.component_eq(self, 0, stored, 0) {
            UserDataSplit::UserDataOnly
        } else {
            UserDataSplit::SharedDataChanged
        };

        Ok((preferences, split))
    }

    fn user_data_override(
        &self,
        comp_id: u32,
        recurrence_key: RecurrenceKey,
    ) -> Option<&ICalendarComponent> {
        if self
            .component_by_id(comp_id)
            .is_none_or(|c| c.is_recurrence_override())
        {
            return None;
        }
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .first()?
            .component_ids
            .iter()
            .filter_map(|id| self.component_by_id(*id))
            .find(|c| {
                c.is_user_data_component()
                    && c.is_recurrence_override()
                    && instance_keys.of(c) == Some(recurrence_key.prefix())
            })
    }

    fn has_same_user_data(&self, stored: &ICalendar) -> bool {
        let stored_components = UserDataComponents::new(stored);
        self.user_data_component_ids()
            .into_iter()
            .filter_map(|(comp_id, key)| self.component_by_id(comp_id).map(|c| (c, key)))
            .all(|(component, key)| {
                let entries = component.user_data_entries();
                match stored_components.counterpart(key, UserDataLookup::Inherited) {
                    Some(source) => entries.same_entries(&source.user_data_entries()),
                    None => entries.is_empty(),
                }
            })
    }
}

trait UserDataComponent {
    fn is_user_data_component(&self) -> bool;

    fn user_data_entries(&self) -> Vec<&ICalendarEntry>;

    fn detached(&self) -> ICalendarComponent;
}

impl UserDataComponent for ICalendarComponent {
    fn is_user_data_component(&self) -> bool {
        self.component_type.is_event_or_todo()
    }

    fn user_data_entries(&self) -> Vec<&ICalendarEntry> {
        let mut entries = self
            .entries
            .iter()
            .filter(|entry| entry.is_user_data())
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn detached(&self) -> ICalendarComponent {
        ICalendarComponent {
            component_type: self.component_type.clone(),
            entries: self.entries.clone(),
            component_ids: Vec::new(),
        }
    }
}

trait UserDataTree {
    fn user_data_component_ids(&self) -> Vec<(u32, u32)>;

    fn alarms<'x>(
        &'x self,
        component: &'x ICalendarComponent,
    ) -> impl Iterator<Item = (u32, &'x ICalendarComponent)>;

    fn component_user_data(
        &self,
        component: &ICalendarComponent,
    ) -> Result<EventUserData, UserDataError>;

    fn extract_alerts(
        &self,
        preferences: EventPreferences,
    ) -> Result<EventPreferences, UserDataError>;

    fn restore_user_data(
        &mut self,
        stored: &UserDataComponents<'_>,
        view: UserDataView,
        lookup: UserDataLookup,
    );

    fn drop_unreachable_components(&mut self);

    fn prune_user_data_overrides(&mut self, stored: &UserDataComponents<'_>);

    fn replace_user_data(
        &mut self,
        comp_id: u32,
        alert_ids: impl IntoIterator<Item = u32>,
        entries: Option<Vec<ICalendarEntry>>,
    );

    fn base_updated(&self) -> Option<i64>;
}

impl UserDataTree for ICalendar {
    fn user_data_component_ids(&self) -> Vec<(u32, u32)> {
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .iter()
            .enumerate()
            .filter(|(_, component)| component.is_user_data_component())
            .filter_map(|(id, component)| Some((id as u32, instance_keys.of(component)?)))
            .collect()
    }

    fn alarms<'x>(
        &'x self,
        component: &'x ICalendarComponent,
    ) -> impl Iterator<Item = (u32, &'x ICalendarComponent)> {
        component.component_ids.iter().filter_map(|id| {
            self.component_by_id(*id)
                .filter(|child| child.component_type == ICalendarComponentType::VAlarm)
                .map(|child| (*id, child))
        })
    }

    fn component_user_data(
        &self,
        component: &ICalendarComponent,
    ) -> Result<EventUserData, UserDataError> {
        let mut data = EventUserData::default();
        let mut keywords: Vec<&str> = Vec::new();
        let mut has_keywords = false;

        for entry in &component.entries {
            match &entry.name {
                ICalendarProperty::Color => {
                    if let Some(value) = entry.values.first().and_then(|v| v.as_text()) {
                        data.set_color(Some(
                            CssColor::parse(value).ok_or(UserDataError::InvalidColor)?,
                        ));
                    }
                }
                ICalendarProperty::Categories => {
                    has_keywords = true;
                    keywords.extend(entry.values.iter().filter_map(|v| v.as_text()));
                }
                ICalendarProperty::Transp => {
                    data.set_free_busy(matches!(
                        entry.values.first(),
                        Some(ICalendarValue::Transparency(
                            ICalendarTransparency::Transparent
                        ))
                    ));
                }
                _ => {}
            }
        }
        if has_keywords {
            data.set_keywords(keywords)?;
        }

        let alerts = self
            .alarms(component)
            .map(|(_, alarm)| alarm.detached())
            .collect::<Vec<_>>();
        if !alerts.is_empty() {
            data.set_alerts(alerts)?;
        }

        Ok(data)
    }

    fn extract_alerts(
        &self,
        mut preferences: EventPreferences,
    ) -> Result<EventPreferences, UserDataError> {
        let base_alerts = self
            .base_component_id()
            .and_then(|id| self.component_by_id(id))
            .map(|base| {
                self.alarms(base)
                    .map(|(_, alarm)| alarm.detached())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let mut instance_keys = InstanceKeys::new(self);
        for component in self
            .components
            .iter()
            .filter(|c| c.is_user_data_component() && c.is_recurrence_override())
        {
            let Some(key) = instance_keys.of(component) else {
                continue;
            };
            let alerts = self
                .alarms(component)
                .map(|(_, alarm)| alarm.detached())
                .collect::<Vec<_>>();
            if alerts != base_alerts {
                preferences.instance_mut(key)?.set_alerts(alerts)?;
            } else if let Some(instance) = preferences
                .instances
                .iter_mut()
                .find(|instance| instance.recurrence_key == key)
            {
                instance.clear_alerts();
            }
        }

        if !base_alerts.is_empty() {
            preferences
                .instance_mut(BASE_INSTANCE)?
                .set_alerts(base_alerts)?;
        } else if let Some(base) = preferences
            .instances
            .iter_mut()
            .find(|instance| instance.recurrence_key == BASE_INSTANCE)
        {
            base.clear_alerts();
        }
        preferences.instances.retain(|instance| instance.flags != 0);

        Ok(preferences)
    }

    fn restore_user_data(
        &mut self,
        stored: &UserDataComponents<'_>,
        view: UserDataView,
        lookup: UserDataLookup,
    ) {
        let mut appender = ComponentAppender::new(stored.ical, self.components.len() as u32);
        let replacements = self
            .user_data_component_ids()
            .into_iter()
            .filter_map(|(comp_id, key)| match stored.counterpart(key, lookup) {
                Some(source) => Some((
                    comp_id,
                    stored
                        .ical
                        .alarms(source)
                        .filter_map(|(alarm_id, _)| appender.copy_tree(alarm_id))
                        .collect::<Vec<_>>(),
                    (view == UserDataView::Full).then(|| {
                        source
                            .entries
                            .iter()
                            .filter(|entry| entry.is_user_data())
                            .cloned()
                            .collect::<Vec<_>>()
                    }),
                )),
                None if lookup == UserDataLookup::Exact => None,
                None => Some((
                    comp_id,
                    Vec::new(),
                    (view == UserDataView::Full).then(Vec::new),
                )),
            })
            .collect::<Vec<_>>();

        self.components.extend(appender.into_components());
        for (comp_id, alert_ids, entries) in replacements {
            self.replace_user_data(comp_id, alert_ids, entries);
        }
    }

    fn drop_unreachable_components(&mut self) {
        let mut is_reachable = vec![false; self.components.len()];
        let mut pending = vec![0u32];
        while let Some(comp_id) = pending.pop() {
            match is_reachable.get_mut(comp_id as usize) {
                Some(is_reachable) if !*is_reachable => *is_reachable = true,
                _ => continue,
            }
            if let Some(component) = self.components.get(comp_id as usize) {
                pending.extend_from_slice(&component.component_ids);
            }
        }

        let unreachable = is_reachable
            .into_iter()
            .enumerate()
            .filter(|(_, is_reachable)| !*is_reachable)
            .map(|(comp_id, _)| comp_id as u32)
            .collect::<Vec<_>>();
        if !unreachable.is_empty() && !self.remove_component_ids(&unreachable) {
            for component in &mut self.components {
                component
                    .component_ids
                    .retain(|id| !unreachable.contains(id));
            }
        }
    }

    fn prune_user_data_overrides(&mut self, stored: &UserDataComponents<'_>) {
        let Some(overrides) = RedundantOverrides::new(self) else {
            return;
        };
        let redundant = self
            .user_data_component_ids()
            .into_iter()
            .filter(|(comp_id, key)| {
                *key != BASE_INSTANCE && !stored.contains(*key) && overrides.is_redundant(*comp_id)
            })
            .map(|(comp_id, _)| comp_id)
            .collect::<Vec<_>>();

        if !redundant.is_empty() {
            for component in &mut self.components {
                component.component_ids.retain(|id| !redundant.contains(id));
            }
        }
    }

    fn replace_user_data(
        &mut self,
        comp_id: u32,
        alert_ids: impl IntoIterator<Item = u32>,
        entries: Option<Vec<ICalendarEntry>>,
    ) {
        let Some(mut children) = self
            .components
            .get_mut(comp_id as usize)
            .map(|component| std::mem::take(&mut component.component_ids))
        else {
            return;
        };
        children.retain(|id| {
            self.component_by_id(*id)
                .is_none_or(|child| child.component_type != ICalendarComponentType::VAlarm)
        });
        children.extend(alert_ids);

        if let Some(component) = self.components.get_mut(comp_id as usize) {
            component.component_ids = children;
            if let Some(entries) = entries {
                component.entries.retain(|entry| !entry.is_user_data());
                component.entries.extend(entries);
            }
        }
    }

    fn base_updated(&self) -> Option<i64> {
        self.base_component_id()
            .and_then(|id| self.component_by_id(id))
            .and_then(|component| component.property(&ICalendarProperty::Dtstamp))
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time())
            .and_then(|value| value.to_timestamp())
    }
}

struct UserDataComponents<'x> {
    ical: &'x ICalendar,
    ids: Vec<(u32, u32)>,
}

struct UserDataUsage<'x> {
    ical: &'x ICalendar,
    component: &'x ICalendarComponent,
}

impl<'x> UserDataUsage<'x> {
    fn new(ical: &'x ICalendar, component: &'x ICalendarComponent) -> Self {
        UserDataUsage { ical, component }
    }

    fn keywords(&self) -> impl Iterator<Item = &'x str> {
        self.component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Categories)
            .flat_map(|entry| entry.values.iter())
            .filter_map(|value| value.as_text())
    }

    fn colors(&self) -> impl Iterator<Item = &'x str> {
        self.component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Color)
            .filter_map(|entry| entry.values.first().and_then(|value| value.as_text()))
    }

    fn alerts(&self) -> usize {
        self.ical.alarms(self.component).count()
    }

    fn validate(&self, stored: Option<&UserDataUsage<'_>>) -> Result<(), UserDataError> {
        let mut keywords = 0;
        for keyword in self.keywords() {
            if keyword.len() > MAX_USER_KEYWORD_LEN
                && stored.is_none_or(|stored| stored.keywords().all(|stored| stored != keyword))
            {
                return Err(UserDataError::KeywordTooLong);
            }
            keywords += 1;
        }
        if keywords > MAX_USER_KEYWORDS
            && stored.is_none_or(|stored| keywords > stored.keywords().count())
        {
            return Err(UserDataError::TooManyKeywords);
        }
        if self.colors().any(|color| {
            CssColor::parse(color).is_none()
                && stored.is_none_or(|stored| stored.colors().all(|stored| stored != color))
        }) {
            return Err(UserDataError::InvalidColor);
        }
        let alerts = self.alerts();
        if alerts > MAX_USER_ALERTS && stored.is_none_or(|stored| alerts > stored.alerts()) {
            return Err(UserDataError::TooManyAlerts);
        }
        Ok(())
    }
}

struct InstanceKeys<'x> {
    ical: &'x ICalendar,
    resolver: Option<TzResolver<&'x str>>,
}

impl<'x> InstanceKeys<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        InstanceKeys {
            ical,
            resolver: None,
        }
    }

    fn of(&mut self, component: &ICalendarComponent) -> Option<u32> {
        match self.recurrence_id(component) {
            Some(recurrence_id) => {
                RecurrenceKey::from_recurrence_id(recurrence_id).map(RecurrenceKey::prefix)
            }
            None if !component.is_recurrence_override() => Some(BASE_INSTANCE),
            None => None,
        }
    }

    fn recurrence_id(&mut self, component: &ICalendarComponent) -> Option<i64> {
        if !component.is_recurrence_override() {
            return None;
        }
        let tz = self.start_tz(component);
        component
            .recurrence_id(tz)
            .map(|recurrence_id| recurrence_id.naive)
    }

    fn start_tz(&mut self, component: &ICalendarComponent) -> Tz {
        let Some(entry) = component.property(&ICalendarProperty::Dtstart) else {
            return Tz::Floating;
        };
        if let Some(tz) = entry
            .values
            .first()
            .and_then(ICalendarValue::as_partial_date_time)
            .and_then(PartialDateTime::to_date_time)
            .and_then(|start| start.tz())
        {
            return tz;
        }
        let ical = self.ical;
        self.resolver
            .get_or_insert_with(|| ical.build_tz_resolver())
            .resolve_or_default(entry.tz_id())
    }
}

impl<'x> UserDataComponents<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        let mut ids = ical
            .user_data_component_ids()
            .into_iter()
            .map(|(comp_id, key)| (key, comp_id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        UserDataComponents { ical, ids }
    }

    fn contains(&self, key: u32) -> bool {
        self.position(key).is_some()
    }

    fn counterpart(&self, key: u32, lookup: UserDataLookup) -> Option<&'x ICalendarComponent> {
        match lookup {
            UserDataLookup::Inherited => {
                self.position(key).or_else(|| self.position(BASE_INSTANCE))
            }
            UserDataLookup::Exact => self.position(key),
        }
        .and_then(|index| self.ids.get(index))
        .and_then(|(_, comp_id)| self.ical.component_by_id(*comp_id))
    }

    fn position(&self, key: u32) -> Option<usize> {
        let index = self
            .ids
            .partition_point(|(stored_key, _)| *stored_key < key);
        self.ids
            .get(index)
            .filter(|(stored_key, _)| *stored_key == key)
            .map(|_| index)
    }
}

struct ComponentAppender<'x> {
    source: &'x ICalendar,
    first_id: u32,
    components: Vec<ICalendarComponent>,
}

impl<'x> ComponentAppender<'x> {
    fn new(source: &'x ICalendar, first_id: u32) -> Self {
        ComponentAppender {
            source,
            first_id,
            components: Vec::new(),
        }
    }

    fn push(&mut self, component: ICalendarComponent) -> u32 {
        let id = self.first_id + self.components.len() as u32;
        self.components.push(component);
        id
    }

    fn copy_tree(&mut self, id: u32) -> Option<u32> {
        self.copy_subtree(id, 0)
    }

    fn copy_subtree(&mut self, id: u32, depth: usize) -> Option<u32> {
        let source = self.source;
        let component = source
            .component_by_id(id)
            .filter(|_| depth < MAX_COMPONENT_DEPTH)?;
        let copy_id = self.push(component.detached());
        let children = component
            .component_ids
            .iter()
            .filter_map(|child_id| self.copy_subtree(*child_id, depth + 1))
            .collect::<Vec<_>>();
        if let Some(copy) = self.components.get_mut((copy_id - self.first_id) as usize) {
            copy.component_ids = children;
        }
        Some(copy_id)
    }

    fn into_components(self) -> Vec<ICalendarComponent> {
        self.components
    }
}

struct OccurrenceOverrides<'x> {
    appender: ComponentAppender<'x>,
    base: &'x ICalendarComponent,
    base_start: i64,
    override_ids: Vec<u32>,
}

impl<'x> OccurrenceOverrides<'x> {
    fn new(ical: &'x ICalendar, base_id: u32) -> Option<Self> {
        let base = ical.component_by_id(base_id)?;
        let base_start = base
            .property(&ICalendarProperty::Dtstart)?
            .values
            .first()?
            .as_partial_date_time()?
            .naive_timestamp()?;
        Some(OccurrenceOverrides {
            appender: ComponentAppender::new(ical, ical.components.len() as u32),
            base,
            base_start,
            override_ids: Vec::new(),
        })
    }

    fn push(&mut self, start: i64) {
        let (base, source) = (self.base, self.appender.source);
        let shift = start - self.base_start;
        let mut entries = Vec::with_capacity(base.entries.len() + 1);
        for entry in &base.entries {
            match entry.name {
                ICalendarProperty::Rrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Exrule
                | ICalendarProperty::Exdate => {}
                ICalendarProperty::Dtstart => {
                    let Some(start) = entry.shifted(shift) else {
                        return;
                    };
                    entries.push(ICalendarEntry {
                        name: ICalendarProperty::RecurrenceId,
                        params: start
                            .params
                            .iter()
                            .filter(|param| {
                                matches!(
                                    param.name,
                                    ICalendarParameterName::Tzid | ICalendarParameterName::Value
                                )
                            })
                            .cloned()
                            .collect(),
                        values: start.values.clone(),
                    });
                    entries.push(start);
                }
                ICalendarProperty::Dtend | ICalendarProperty::Due => {
                    entries.push(entry.shifted(shift).unwrap_or_else(|| entry.clone()));
                }
                _ => entries.push(entry.clone()),
            }
        }

        let children = base
            .component_ids
            .iter()
            .filter(|id| {
                source
                    .component_by_id(**id)
                    .is_some_and(|child| child.component_type != ICalendarComponentType::VAlarm)
            })
            .filter_map(|id| self.appender.copy_tree(*id))
            .collect();
        let override_id = self.appender.push(ICalendarComponent {
            component_type: base.component_type.clone(),
            entries,
            component_ids: children,
        });
        self.override_ids.push(override_id);
    }

    fn into_personal_overrides(self, root_id: usize) -> PersonalOverrides {
        PersonalOverrides {
            root_id,
            override_ids: self.override_ids,
            components: self.appender.into_components(),
        }
    }
}

trait ShiftedEntry {
    fn shifted(&self, shift: i64) -> Option<ICalendarEntry>;
}

impl ShiftedEntry for ICalendarEntry {
    fn shifted(&self, shift: i64) -> Option<ICalendarEntry> {
        let [ICalendarValue::PartialDateTime(value)] = self.values.as_slice() else {
            return None;
        };
        Some(ICalendarEntry {
            name: self.name.clone(),
            params: self.params.clone(),
            values: [ICalendarValue::PartialDateTime(value.shifted(shift)?)].into(),
        })
    }
}

