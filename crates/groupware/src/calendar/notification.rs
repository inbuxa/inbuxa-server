/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEventNotification, CALENDAR_SUBSCRIBED, CalendarEventNotification,
    EVENT_HIDE_ATTENDEES, EVENT_NOTIFICATION_HIDE_ATTENDEES, EVENT_NOTIFICATION_PRIVATE,
    default_preference_flags, privacy::EventPrivacy,
};
use crate::{DestroyArchive, cache::GroupwareCache};
use common::{
    GroupwareResources, Server,
    auth::{AccessToken, AccountCache},
    storage::dav::resource::NotificationRef,
};
use std::sync::Arc;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
};

pub struct NotificationViewer {
    viewer_id: u32,
    is_member: bool,
    calendar_ids: RoaringBitmap,
    known_calendar_ids: RoaringBitmap,
    writable_calendar_ids: RoaringBitmap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationAudience {
    Readers,
    Writers,
    Members,
}

impl NotificationViewer {
    pub fn new(
        calendars: &GroupwareResources,
        access_token: &AccessToken,
        account_id: u32,
    ) -> Self {
        let viewer_id = access_token.account_id();
        let is_member = access_token.is_member(account_id);
        let mut calendar_ids = RoaringBitmap::new();
        let mut known_calendar_ids = RoaringBitmap::new();
        let mut writable_calendar_ids = RoaringBitmap::new();

        for calendar in calendars.resources.iter().filter(|r| r.is_container()) {
            known_calendar_ids.insert(calendar.document_id());
            let flags = calendar
                .personal_calendar_preferences(viewer_id)
                .map_or_else(|| default_preference_flags(is_member), |prefs| prefs.flags);
            if flags & CALENDAR_SUBSCRIBED != 0
                && (is_member || has_grant(access_token, calendar.acls(), Acl::ReadItems))
            {
                calendar_ids.insert(calendar.document_id());
            }
            if !is_member && has_grant(access_token, calendar.acls(), Acl::ModifyItems) {
                writable_calendar_ids.insert(calendar.document_id());
            }
        }

        NotificationViewer {
            viewer_id,
            is_member,
            calendar_ids,
            known_calendar_ids,
            writable_calendar_ids,
        }
    }

    pub fn without_calendars(access_token: &AccessToken, account_id: u32) -> Self {
        NotificationViewer {
            viewer_id: access_token.account_id(),
            is_member: access_token.is_member(account_id),
            calendar_ids: RoaringBitmap::new(),
            known_calendar_ids: RoaringBitmap::new(),
            writable_calendar_ids: RoaringBitmap::new(),
        }
    }

    pub fn is_member(&self) -> bool {
        self.is_member
    }

    pub fn can_view(&self, notification: &NotificationRef<'_>) -> bool {
        notification.changed_by != self.viewer_id
            && !notification.dismissed_by.contains(&self.viewer_id)
            && match NotificationAudience::from_flags(notification.flags) {
                NotificationAudience::Readers => true,
                NotificationAudience::Writers => {
                    self.is_member
                        || (!notification.calendar_ids.is_empty()
                            && notification.calendar_ids.iter().all(|calendar_id| {
                                self.writable_calendar_ids.contains(*calendar_id)
                            }))
                }
                NotificationAudience::Members => self.is_member,
            }
            && if notification
                .calendar_ids
                .iter()
                .any(|calendar_id| self.known_calendar_ids.contains(*calendar_id))
            {
                notification
                    .calendar_ids
                    .iter()
                    .any(|calendar_id| self.calendar_ids.contains(*calendar_id))
            } else {
                self.is_member
            }
    }

    pub fn visible_notifications(&self, notifications: &GroupwareResources) -> RoaringBitmap {
        notifications
            .resources
            .iter()
            .filter(|resource| {
                !resource.is_container()
                    && resource
                        .notification()
                        .is_some_and(|notification| self.can_view(&notification))
            })
            .map(|resource| resource.document_id())
            .collect()
    }
}

impl NotificationAudience {
    pub fn of_event(event_flags: u16) -> Self {
        if !EventPrivacy::from_flags(event_flags).is_public() {
            NotificationAudience::Members
        } else if event_flags & EVENT_HIDE_ATTENDEES != 0 {
            NotificationAudience::Writers
        } else {
            NotificationAudience::Readers
        }
    }

    pub fn from_flags(notification_flags: u16) -> Self {
        if notification_flags & EVENT_NOTIFICATION_PRIVATE != 0 {
            NotificationAudience::Members
        } else if notification_flags & EVENT_NOTIFICATION_HIDE_ATTENDEES != 0 {
            NotificationAudience::Writers
        } else {
            NotificationAudience::Readers
        }
    }

    pub fn with_privacy(self, is_public: bool) -> Self {
        if is_public {
            self
        } else {
            NotificationAudience::Members
        }
    }

    pub fn flags(self) -> u16 {
        match self {
            NotificationAudience::Readers => 0,
            NotificationAudience::Writers => EVENT_NOTIFICATION_HIDE_ATTENDEES,
            NotificationAudience::Members => EVENT_NOTIFICATION_PRIVATE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountViewers {
    Owner,
    Members,
}

impl AccountViewers {
    pub fn of(account: &AccountCache) -> Self {
        if account.is_user_account() {
            AccountViewers::Owner
        } else {
            AccountViewers::Members
        }
    }
}

pub fn may_have_viewers(
    access_token: &AccessToken,
    account_id: u32,
    calendars: &GroupwareResources,
    calendar_ids: &[u32],
    audience: NotificationAudience,
) -> bool {
    has_viewers(
        access_token,
        account_id,
        calendars,
        calendar_ids,
        audience,
        AccountViewers::Members,
    )
}

pub fn has_viewers(
    access_token: &AccessToken,
    account_id: u32,
    calendars: &GroupwareResources,
    calendar_ids: &[u32],
    audience: NotificationAudience,
    account_viewers: AccountViewers,
) -> bool {
    if calendar_ids.is_empty() {
        return !access_token.is_account_id(account_id);
    } else if !access_token.is_account_id(account_id)
        && match account_viewers {
            AccountViewers::Owner => is_subscribed(calendars, calendar_ids, account_id),
            AccountViewers::Members => true,
        }
    {
        return true;
    }

    subscribed_viewers(calendars, calendar_ids, audience)
        .any(|reader_id| !is_actor(access_token, reader_id))
}

fn is_actor(access_token: &AccessToken, account_id: u32) -> bool {
    access_token
        .member_ids()
        .any(|member_id| member_id == account_id)
}

fn is_subscribed(calendars: &GroupwareResources, calendar_ids: &[u32], account_id: u32) -> bool {
    calendar_ids
        .iter()
        .filter_map(|calendar_id| calendars.resources.find(*calendar_id, true))
        .any(|calendar| {
            calendar
                .personal_calendar_preferences(account_id)
                .is_some_and(|preferences| preferences.flags & CALENDAR_SUBSCRIBED != 0)
        })
}

fn subscribed_readers<'x>(
    calendars: &'x GroupwareResources,
    calendar_ids: &'x [u32],
) -> impl Iterator<Item = u32> + 'x {
    calendar_ids
        .iter()
        .filter_map(|calendar_id| calendars.resources.find(*calendar_id, true))
        .flat_map(|calendar| {
            let preferences = calendar.all_calendar_preferences();
            calendar
                .acls()
                .iter()
                .filter(|acl| acl.grants.contains(Acl::ReadItems))
                .map(|acl| acl.account_id)
                .filter(move |account_id| {
                    preferences.iter().any(|preferences| {
                        preferences.account_id == *account_id
                            && preferences.flags & CALENDAR_SUBSCRIBED != 0
                    })
                })
        })
}

fn subscribed_viewers<'x>(
    calendars: &'x GroupwareResources,
    calendar_ids: &'x [u32],
    audience: NotificationAudience,
) -> impl Iterator<Item = u32> + 'x {
    subscribed_readers(calendars, calendar_ids).filter(move |reader_id| match audience {
        NotificationAudience::Readers => true,
        NotificationAudience::Writers => may_modify_all(calendars, calendar_ids, *reader_id),
        NotificationAudience::Members => false,
    })
}

fn may_modify_all(calendars: &GroupwareResources, calendar_ids: &[u32], account_id: u32) -> bool {
    calendar_ids.iter().all(|calendar_id| {
        calendars
            .resources
            .find(*calendar_id, true)
            .is_some_and(|calendar| {
                calendar.acls().iter().any(|acl| {
                    acl.account_id == account_id && acl.grants.contains(Acl::ModifyItems)
                })
            })
    })
}

fn has_grant(access_token: &AccessToken, acls: &[AclGrant], grant: Acl) -> bool {
    acls.iter()
        .any(|acl| acl.grants.contains(grant) && access_token.is_member(acl.account_id))
}

pub trait CalendarNotificationViewers: Sync + Send {
    fn notification_viewer(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<NotificationViewer>> + Send;

    fn calendars_if_any(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Arc<GroupwareResources>>>> + Send;
}

impl CalendarNotificationViewers for Server {
    async fn notification_viewer(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<NotificationViewer> {
        Ok(
            match self
                .calendars_if_any(access_token, account_id)
                .await
                .caused_by(trc::location!())?
            {
                Some(calendars) => NotificationViewer::new(&calendars, access_token, account_id),
                None => NotificationViewer::without_calendars(access_token, account_id),
            },
        )
    }

    async fn calendars_if_any(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Option<Arc<GroupwareResources>>> {
        if self
            .count_documents(account_id, Collection::Calendar, 1)
            .await
            .caused_by(trc::location!())?
            == 0
        {
            return Ok(None);
        }

        self.fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            SyncCollection::Calendar,
        )
        .await
        .caused_by(trc::location!())
        .map(Some)
    }
}

pub trait CalendarNotificationReap: Sync + Send {
    fn reap_calendar_notifications(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendar_ids: &[u32],
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl CalendarNotificationReap for Server {
    async fn reap_calendar_notifications(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendar_ids: &[u32],
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let notifications = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .caused_by(trc::location!())?;
        let is_member = access_token.is_member(account_id);
        let orphaned = notifications
            .resources
            .iter()
            .filter(|resource| {
                !resource.is_container()
                    && resource.notification().is_some_and(|notification| {
                        (is_member || notification.changed_by == account_id)
                            && !notification.calendar_ids.is_empty()
                            && notification
                                .calendar_ids
                                .iter()
                                .all(|calendar_id| calendar_ids.contains(calendar_id))
                    })
            })
            .map(|resource| resource.document_id())
            .collect::<Vec<_>>();

        for document_id in orphaned {
            if let Some(notification) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                DestroyArchive(
                    notification
                        .to_unarchived::<CalendarEventNotification>()
                        .caused_by(trc::location!())?,
                )
                .delete(access_token.changed_by(), account_id, document_id, batch)
                .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }
}

pub trait CalendarNotificationDismiss: Sync + Send {
    fn dismiss_notification(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        notification: Archive<&ArchivedCalendarEventNotification>,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn has_pending_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &ArchivedCalendarEventNotification,
        dismissed_by: &[u32],
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl CalendarNotificationDismiss for Server {
    async fn dismiss_notification(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        notification: Archive<&ArchivedCalendarEventNotification>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let viewer_id = access_token.account_id();
        let is_owner_only = NotificationAudience::from_flags(notification.inner.flags.to_native())
            == NotificationAudience::Members;
        let mut dismissed_by = notification.inner.dismissed_ids().collect::<Vec<_>>();
        if !dismissed_by.contains(&viewer_id) {
            dismissed_by.push(viewer_id);
        }

        if !(is_owner_only && access_token.is_member(account_id))
            && self
                .has_pending_viewers(access_token, account_id, notification.inner, &dismissed_by)
                .await
                .caused_by(trc::location!())?
        {
            let mut updated = notification
                .deserialize::<CalendarEventNotification>()
                .caused_by(trc::location!())?;
            updated.dismissed_by = dismissed_by;
            updated
                .update_meta(
                    access_token.changed_by(),
                    notification,
                    account_id,
                    document_id,
                    batch,
                )
                .caused_by(trc::location!())?;
        } else {
            DestroyArchive(notification)
                .delete(access_token.changed_by(), account_id, document_id, batch)
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    async fn has_pending_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &ArchivedCalendarEventNotification,
        dismissed_by: &[u32],
    ) -> trc::Result<bool> {
        let changed_by = notification.changed_by_id();
        let audience = NotificationAudience::from_flags(notification.flags.to_native());
        if changed_by != account_id && !dismissed_by.contains(&account_id) {
            return Ok(true);
        } else if audience == NotificationAudience::Members || notification.calendar_ids.is_empty()
        {
            return Ok(false);
        }

        let Some(calendars) = self
            .calendars_if_any(access_token, account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(false);
        };

        let calendar_ids = notification.calendar_ids().collect::<Vec<_>>();
        Ok(subscribed_viewers(&calendars, &calendar_ids, audience)
            .any(|account_id| account_id != changed_by && !dismissed_by.contains(&account_id)))
    }
}

