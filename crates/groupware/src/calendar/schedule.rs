/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEvent, ArchivedCalendarEventContent, ArchivedEventPreferences,
    CalendarEventContent, EVENT_DRAFT, EVENT_HAS_ALARMS, EventPreferences, PREF_HAS_ALERTS,
    alarm::{AlarmSource, AlarmTarget, CalendarAlarm, EventAlarmData, PersonalAlarms},
    alerts::{DefaultAlerts, DefaultAlertsResolver, ICalendarShowWithoutTime},
};
use calcard::common::timezone::Tz;
use common::{ArchivedDavName, Server, storage::chunk::ArchiveChunk};
use registry::schema::{enums::TaskType, structs::Task};
use std::cmp::Ordering;
use store::{
    Deserialize, IterateParams, U64_LEN, ValueKey,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, BatchBuilder, TaskId, TaskQueueClass, ValueClass,
        key::DeserializeBigEndian, now, serialize::rkyv_deserialize,
    },
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

#[derive(Debug, Default)]
pub struct EventAlarmUsers {
    with_time: bool,
    is_draft: bool,
    owner: Option<EventAlarmUser>,
    sharees: Vec<EventAlarmUser>,
}

#[derive(Debug)]
struct EventAlarmUser {
    target: AlarmTarget,
    uses_defaults: bool,
    alarms: PersonalAlarms,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventAlarms(Vec<CalendarAlarm>);

pub trait EventAlarmPreferences {
    fn account_id(&self) -> u32;

    fn uses_default_alerts(&self) -> bool;

    fn has_stored_alerts(&self) -> bool;

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms>;
}

pub trait EventAlarmContent {
    type Preferences: EventAlarmPreferences;

    fn shows_without_time(&self) -> bool;

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences>;

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences>;

    fn uses_default_alerts(&self, account_id: u32) -> bool {
        self.user_preferences(account_id)
            .is_some_and(EventAlarmPreferences::uses_default_alerts)
    }
}

impl EventAlarmPreferences for EventPreferences {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn uses_default_alerts(&self) -> bool {
        EventPreferences::use_default_alerts(self)
    }

    fn has_stored_alerts(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| instance.flags & PREF_HAS_ALERTS != 0)
    }

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms> {
        Ok(PersonalAlarms::new(self))
    }
}

impl EventAlarmPreferences for ArchivedEventPreferences {
    fn account_id(&self) -> u32 {
        self.account_id.to_native()
    }

    fn uses_default_alerts(&self) -> bool {
        ArchivedEventPreferences::use_default_alerts(self)
    }

    fn has_stored_alerts(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| instance.flags & PREF_HAS_ALERTS != 0)
    }

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms> {
        rkyv_deserialize::<_, EventPreferences>(self)
            .caused_by(trc::location!())
            .map(|preferences| PersonalAlarms::new(&preferences))
    }
}

impl EventAlarmContent for CalendarEventContent {
    type Preferences = EventPreferences;

    fn shows_without_time(&self) -> bool {
        self.data.event.shows_without_time()
    }

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences> {
        self.preferences(account_id)
    }

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences> {
        self.preferences.iter()
    }
}

impl EventAlarmContent for ArchivedCalendarEventContent {
    type Preferences = ArchivedEventPreferences;

    fn shows_without_time(&self) -> bool {
        self.data.event.shows_without_time()
    }

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences> {
        self.preferences(account_id)
    }

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences> {
        self.preferences.iter()
    }
}

impl EventAlarmUser {
    fn owner<C: EventAlarmContent>(account_id: u32, content: &C) -> Self {
        EventAlarmUser {
            target: AlarmTarget::Owner,
            uses_defaults: content.uses_default_alerts(account_id),
            alarms: PersonalAlarms::default(),
        }
    }

    fn has_alarms(&self) -> bool {
        match self.target {
            AlarmTarget::Owner => true,
            AlarmTarget::Sharee(_) => self.uses_defaults || !self.alarms.is_empty(),
        }
    }

    fn source<'x>(&'x self, defaults: &'x DefaultAlerts) -> AlarmSource<'x> {
        match self.target {
            AlarmTarget::Owner => AlarmSource::Stored(defaults),
            AlarmTarget::Sharee(_) => AlarmSource::Personal(&self.alarms, defaults),
        }
    }
}

impl EventAlarmUsers {
    pub fn new<C: EventAlarmContent>(account_id: u32, content: &C) -> trc::Result<Self> {
        let mut sharees = Vec::new();
        for preferences in content
            .all_preferences()
            .filter(|preferences| sharee_has_alerts(account_id, *preferences))
        {
            let sharee = EventAlarmUser {
                target: AlarmTarget::Sharee(preferences.account_id()),
                uses_defaults: preferences.uses_default_alerts(),
                alarms: preferences.personal_alarms()?,
            };
            if sharee.has_alarms() {
                sharees.push(sharee);
            }
        }
        sharees.sort_unstable_by_key(|sharee| sharee.target);

        Ok(EventAlarmUsers {
            with_time: !content.shows_without_time(),
            is_draft: false,
            owner: Some(EventAlarmUser::owner(account_id, content)),
            sharees,
        })
    }

    pub fn for_target<C: EventAlarmContent>(
        account_id: u32,
        content: &C,
        target: AlarmTarget,
    ) -> trc::Result<Self> {
        let mut users = EventAlarmUsers {
            with_time: !content.shows_without_time(),
            is_draft: false,
            owner: None,
            sharees: Vec::new(),
        };
        match target {
            AlarmTarget::Owner => {
                users.owner = Some(EventAlarmUser::owner(account_id, content));
            }
            AlarmTarget::Sharee(sharee_id) => {
                if let Some(preferences) = content
                    .user_preferences(sharee_id)
                    .filter(|preferences| sharee_has_alerts(account_id, *preferences))
                {
                    let sharee = EventAlarmUser {
                        target,
                        uses_defaults: preferences.uses_default_alerts(),
                        alarms: preferences.personal_alarms()?,
                    };
                    if sharee.has_alarms() {
                        users.sharees.push(sharee);
                    }
                }
            }
        }

        Ok(users)
    }

    fn users(&self) -> impl Iterator<Item = &EventAlarmUser> {
        self.owner.iter().chain(self.sharees.iter())
    }

    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.sharees.is_empty()
    }

    pub fn targets<C: EventAlarmContent>(
        account_id: u32,
        content: &C,
    ) -> impl Iterator<Item = AlarmTarget> {
        std::iter::once(AlarmTarget::Owner).chain(
            content
                .all_preferences()
                .filter(move |preferences| sharee_has_alerts(account_id, *preferences))
                .map(|preferences| AlarmTarget::Sharee(preferences.account_id())),
        )
    }

    pub fn task_ids<C: EventAlarmContent>(
        account_id: u32,
        document_id: u32,
        content: &C,
    ) -> impl Iterator<Item = u64> {
        Self::targets(account_id, content)
            .map(move |target| target.task_id().resolve(account_id, document_id))
    }

    pub fn with_event_flags(mut self, flags: u16) -> Self {
        self.is_draft = flags & EVENT_DRAFT != 0;
        self
    }
}

fn sharee_has_alerts<P: EventAlarmPreferences>(account_id: u32, preferences: &P) -> bool {
    preferences.account_id() != account_id
        && (preferences.uses_default_alerts() || preferences.has_stored_alerts())
}

impl EventAlarms {
    pub fn into_alarm(mut self) -> Option<CalendarAlarm> {
        self.0.pop()
    }
}

impl IntoIterator for EventAlarms {
    type Item = CalendarAlarm;
    type IntoIter = std::vec::IntoIter<CalendarAlarm>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub trait EventAlarmScheduler: Sync + Send {
    fn next_event_alarms<D: EventAlarmData + Sync>(
        &self,
        account_id: u32,
        users: &EventAlarmUsers,
        data: &D,
        calendar_ids: &[u32],
        start_time: i64,
        resolver: &mut DefaultAlertsResolver,
    ) -> impl Future<Output = trc::Result<EventAlarms>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn reschedule_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        event: &ArchivedCalendarEvent,
        content: Option<Archive<ArchiveBytes>>,
        calendar_ids: &[u32],
        tasks: &mut AlarmTasks,
        resolver: &mut DefaultAlertsResolver,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn replace_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        previous: EventAlarms,
        next: EventAlarms,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn replace_user_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        previous: Option<CalendarAlarm>,
        next: Option<CalendarAlarm>,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn clear_event_alarms<T>(
        &self,
        account_id: u32,
        document_id: u32,
        targets: T,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        T: IntoIterator<Item = AlarmTarget> + Send,
        T::IntoIter: Send;

    fn queued_alarm_due(
        &self,
        account_id: u32,
        document_id: u32,
        target: AlarmTarget,
        tasks: &mut AlarmTasks,
    ) -> impl Future<Output = trc::Result<Option<(TaskType, u64)>>> + Send;
}

#[derive(Debug, Default)]
pub enum AlarmTasks {
    #[default]
    None,
    Pending(Vec<u64>),
    Loaded(Vec<(u64, Option<(TaskType, u64)>)>),
}

impl AlarmTasks {
    pub fn pending(mut task_ids: Vec<u64>) -> Self {
        task_ids.sort_unstable();
        task_ids.dedup();
        AlarmTasks::Pending(task_ids)
    }

    pub fn for_chunk(
        account_id: u32,
        chunk: &[u32],
        alarm_ids: &RoaringBitmap,
        archives: &ArchiveChunk,
    ) -> trc::Result<Self> {
        let mut task_ids = Vec::new();
        for &document_id in chunk
            .iter()
            .filter(|document_id| alarm_ids.contains(**document_id))
        {
            if let Some(content) = archives.value(document_id) {
                let content = content
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                task_ids.extend(EventAlarmUsers::task_ids(account_id, document_id, content));
            }
        }
        Ok(AlarmTasks::pending(task_ids))
    }

    fn due(&self, task_id: u64) -> Option<Option<(TaskType, u64)>> {
        match self {
            AlarmTasks::Loaded(tasks) => tasks
                .binary_search_by_key(&task_id, |(id, _)| *id)
                .ok()
                .and_then(|idx| tasks.get(idx))
                .map(|(_, due)| *due),
            AlarmTasks::None | AlarmTasks::Pending(_) => None,
        }
    }

    fn is_pending(&self, task_id: u64) -> bool {
        matches!(self, AlarmTasks::Pending(task_ids) if task_ids.binary_search(&task_id).is_ok())
    }
}

impl EventAlarmScheduler for Server {
    async fn next_event_alarms<D: EventAlarmData + Sync>(
        &self,
        account_id: u32,
        users: &EventAlarmUsers,
        data: &D,
        calendar_ids: &[u32],
        start_time: i64,
        resolver: &mut DefaultAlertsResolver,
    ) -> trc::Result<EventAlarms> {
        if !self.core.groupware.alarms_enabled || users.is_draft || users.is_empty() {
            return Ok(EventAlarms::default());
        }

        let mut alarms = Vec::new();
        let has_stored_alarms = data.has_stored_alarms();
        for user in users.users() {
            let target_id = user.target.account_id(account_id);
            let defaults = if user.uses_defaults {
                if !resolver
                    .is_subscribed(self, account_id, target_id, calendar_ids.iter().copied())
                    .await?
                {
                    continue;
                }
                resolver
                    .resolve(
                        self,
                        account_id,
                        target_id,
                        true,
                        calendar_ids.iter().copied(),
                        users.with_time,
                    )
                    .await?
            } else {
                let defaults = DefaultAlerts::disabled();
                if !user.source(&defaults).may_have_alarms(has_stored_alarms)
                    || !resolver
                        .is_subscribed(self, account_id, target_id, calendar_ids.iter().copied())
                        .await?
                {
                    continue;
                }
                defaults
            };
            let source = user.source(&defaults);
            let default_tz = if data.needs_default_tz(&source) {
                resolver
                    .time_zone(self, account_id, target_id, calendar_ids.iter().copied())
                    .await?
            } else {
                Tz::Floating
            };
            if let Some(alarm) = data.next_alarm_from(start_time, default_tz, &source) {
                alarms.push(alarm.with_target(user.target));
            }
        }

        Ok(EventAlarms(alarms))
    }

    async fn replace_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        previous: EventAlarms,
        next: EventAlarms,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if previous == next {
            return Ok(());
        }

        let mut previous = previous.0.into_iter().peekable();
        let mut next = next.0.into_iter().peekable();
        loop {
            let (previous_alarm, next_alarm) = match (previous.peek(), next.peek()) {
                (Some(previous_alarm), Some(next_alarm)) => {
                    match previous_alarm.target.cmp(&next_alarm.target) {
                        Ordering::Equal => (previous.next(), next.next()),
                        Ordering::Less => (previous.next(), None),
                        Ordering::Greater => (None, next.next()),
                    }
                }
                (Some(_), None) => (previous.next(), None),
                (None, Some(_)) => (None, next.next()),
                (None, None) => break,
            };
            self.replace_user_alarm(
                account_id,
                document_id,
                previous_alarm,
                next_alarm,
                tasks,
                batch,
            )
            .await?;
        }

        Ok(())
    }

    async fn replace_user_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        previous: Option<CalendarAlarm>,
        next: Option<CalendarAlarm>,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if previous == next {
            return Ok(());
        }
        let Some(target) = next
            .as_ref()
            .or(previous.as_ref())
            .map(|alarm| alarm.target)
        else {
            return Ok(());
        };

        let queued_due = self
            .queued_alarm_due(account_id, document_id, target, tasks)
            .await?
            .or_else(|| {
                previous.map(|previous| (previous.task_type(), previous.alarm_time as u64))
            });
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);
        if let Some((typ, due)) = queued_due {
            batch.clear_document_task(target.task_id(), typ, due);
        }
        if let Some(next) = next {
            next.write_task(batch)?;
        }

        Ok(())
    }

    async fn clear_event_alarms<T>(
        &self,
        account_id: u32,
        document_id: u32,
        targets: T,
        tasks: &mut AlarmTasks,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()>
    where
        T: IntoIterator<Item = AlarmTarget> + Send,
        T::IntoIter: Send,
    {
        for target in targets {
            if let Some((typ, due)) = self
                .queued_alarm_due(account_id, document_id, target, tasks)
                .await?
            {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEvent)
                    .with_document(document_id)
                    .clear_document_task(target.task_id(), typ, due);
            }
        }

        Ok(())
    }

    async fn queued_alarm_due(
        &self,
        account_id: u32,
        document_id: u32,
        target: AlarmTarget,
        tasks: &mut AlarmTasks,
    ) -> trc::Result<Option<(TaskType, u64)>> {
        let task_id = target.task_id().resolve(account_id, document_id);
        if tasks.is_pending(task_id)
            && let AlarmTasks::Pending(task_ids) = std::mem::take(tasks)
        {
            *tasks = AlarmTasks::Loaded(load_alarm_tasks(self, task_ids).await?);
        }
        if let Some(due) = tasks.due(task_id) {
            return Ok(due);
        }
        queued_task_due(self, task_id).await
    }

    async fn reschedule_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        event: &ArchivedCalendarEvent,
        content: Option<Archive<ArchiveBytes>>,
        calendar_ids: &[u32],
        tasks: &mut AlarmTasks,
        resolver: &mut DefaultAlertsResolver,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if event.flags.to_native() & EVENT_HAS_ALARMS == 0 {
            return Ok(());
        }
        let content = match content {
            Some(content) => content,
            None => {
                let Some(content) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(());
                };
                content
            }
        };
        let content = content
            .unarchive::<CalendarEventContent>()
            .caused_by(trc::location!())?;
        let users =
            EventAlarmUsers::new(account_id, content)?.with_event_flags(event.flags.to_native());
        let now = now() as i64;
        let previous_alarms = self
            .next_event_alarms(
                account_id,
                &users,
                &content.data,
                &event
                    .names
                    .iter()
                    .map(ArchivedDavName::parent_id)
                    .collect::<Vec<_>>(),
                now,
                resolver,
            )
            .await?;
        let next_alarms = self
            .next_event_alarms(
                account_id,
                &users,
                &content.data,
                calendar_ids,
                now,
                resolver,
            )
            .await?;

        self.replace_event_alarms(
            account_id,
            document_id,
            previous_alarms,
            next_alarms,
            tasks,
            batch,
        )
        .await
    }
}

async fn queued_task_due(server: &Server, task_id: u64) -> trc::Result<Option<(TaskType, u64)>> {
    server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task {
                id: TaskId::Assigned(task_id),
            },
        )))
        .await
        .map(|task| task.map(|task| (task.object_type(), task.due_timestamp())))
        .caused_by(trc::location!())
}

async fn load_alarm_tasks(
    server: &Server,
    task_ids: Vec<u64>,
) -> trc::Result<Vec<(u64, Option<(TaskType, u64)>)>> {
    if let [task_id] = task_ids.as_slice() {
        let due = queued_task_due(server, *task_id).await?;
        return Ok(vec![(*task_id, due)]);
    }
    let mut tasks = task_ids
        .into_iter()
        .map(|task_id| (task_id, None))
        .collect::<Vec<(u64, Option<(TaskType, u64)>)>>();
    let ranges = tasks
        .iter()
        .map(|(task_id, _)| {
            let key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
                id: TaskId::Assigned(*task_id),
            }));
            IterateParams::new(key.clone(), key)
        })
        .collect();
    server
        .store()
        .iterate_many(ranges, |key, value| {
            let task_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
            if let Ok(idx) = tasks.binary_search_by_key(&task_id, |(id, _)| *id)
                && let Some((_, due)) = tasks.get_mut(idx)
            {
                let task = <Task as Deserialize>::deserialize(value)?;
                *due = Some((task.object_type(), task.due_timestamp()));
            }
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;
    Ok(tasks)
}

