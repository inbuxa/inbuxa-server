/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cleanup::{GranteeCleanup, Purge};
use common::{
    ArchivedDavName,
    auth::AccessToken,
    sharing::EffectiveAcl,
    storage::index::{CurrentObject, ObjectIndexBuilder, RevokeCleanup, SerializableObject},
};
use email::mailbox::Mailbox;
use groupware::{
    calendar::{
        Calendar, CalendarEvent, CalendarEventContent, CalendarEventNotification, EVENT_HAS_ALARMS,
        alarm::AlarmTarget,
        schedule::{AlarmTasks, EventAlarmScheduler},
    },
    contact::AddressBook,
    file::FileNode,
};
use store::{
    ValueKey,
    rkyv::vec::ArchivedVec,
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use types::{
    acl::ArchivedAclGrant,
    collection::Collection,
    field::{CalendarEventField, Field},
};

impl GranteeCleanup<'_> {
    pub(super) async fn stage(
        &self,
        collection: Collection,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        match collection {
            Collection::Mailbox => self.stage_mailbox(document_id, batch).await,
            Collection::Calendar => self.stage_calendar(document_id, batch).await,
            Collection::CalendarEvent => self.stage_event(document_id, batch).await,
            Collection::CalendarEventNotification => {
                self.stage_notification(document_id, batch).await
            }
            Collection::AddressBook => self.stage_address_book(document_id, batch).await,
            Collection::FileNode => self.stage_file_node(document_id, batch).await,
            _ => Ok(false),
        }
    }

    async fn stage_mailbox(&self, document_id: u32, batch: &mut BatchBuilder) -> trc::Result<bool> {
        let Some(archive) = self.archive(Collection::Mailbox, document_id).await? else {
            return Ok(false);
        };
        let current = archive.to_unarchived::<Mailbox>()?;
        let candidates = self.candidates(current.inner.subscribers.iter().map(|id| id.to_native()));
        let has_grants = self.has_purged_grants(&current.inner.acls);
        if candidates.is_empty() && !has_grants {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                !current.inner.acls.effective_acl(viewer).is_empty()
            })
        };
        if !has_grants && !candidates.iter().any(|account_id| lost(*account_id)) {
            return Ok(false);
        }

        let mut mailbox = current.deserialize::<Mailbox>()?;
        mailbox
            .acls
            .retain(|grant| !self.purges_grant(grant.account_id));
        mailbox.subscribers.retain(|id| !lost(*id));

        self.write(Collection::Mailbox, document_id, current, mailbox, batch)
    }

    async fn stage_calendar(
        &self,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        let Some(archive) = self.archive(Collection::Calendar, document_id).await? else {
            return Ok(false);
        };
        let current = archive.to_unarchived::<Calendar>()?;
        let candidates = self.candidates(
            current
                .inner
                .preferences
                .iter()
                .map(|pref| pref.account_id.to_native()),
        );
        let has_grants = self.has_purged_grants(&current.inner.acls);
        if candidates.is_empty() && !has_grants {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                !current.inner.acls.effective_acl(viewer).is_empty()
            })
        };
        if !has_grants && !candidates.iter().any(|account_id| lost(*account_id)) {
            return Ok(false);
        }

        let mut calendar = current.deserialize::<Calendar>()?;
        calendar
            .acls
            .retain(|grant| !self.purges_grant(grant.account_id));
        calendar.preferences.retain(|pref| !lost(pref.account_id));
        calendar.modified = now() as i64;

        self.write(Collection::Calendar, document_id, current, calendar, batch)
    }

    async fn stage_event(&self, document_id: u32, batch: &mut BatchBuilder) -> trc::Result<bool> {
        let Some(content) = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                self.owner_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content,
            ))
            .await?
        else {
            return Ok(false);
        };
        let content = content.to_unarchived::<CalendarEventContent>()?;
        let candidates = self.candidates(
            content
                .inner
                .preferences
                .iter()
                .map(|pref| pref.account_id.to_native()),
        );
        if candidates.is_empty() {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let Some(meta) = self.archive(Collection::CalendarEvent, document_id).await? else {
            return Ok(false);
        };
        let event = meta.to_unarchived::<CalendarEvent>()?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                self.has_calendar_access(
                    viewer,
                    event.inner.names.iter().map(ArchivedDavName::parent_id),
                )
            })
        };
        let lost_ids = candidates
            .into_iter()
            .filter(|account_id| lost(*account_id))
            .collect::<Vec<_>>();
        if lost_ids.is_empty() {
            return Ok(false);
        }

        self.guard(batch);
        batch
            .with_account_id(self.owner_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id)
            .assert_value(CalendarEventField::Content.field(), &content);
        if event.inner.flags.to_native() & EVENT_HAS_ALARMS != 0 {
            for &account_id in &lost_ids {
                self.server
                    .clear_event_alarms(
                        self.owner_id,
                        document_id,
                        [AlarmTarget::Sharee(account_id)],
                        &mut AlarmTasks::None,
                        batch,
                    )
                    .await?;
            }
        }

        let mut new_content = content.deserialize::<CalendarEventContent>()?;
        new_content
            .preferences
            .retain(|pref| !lost_ids.contains(&pref.account_id));
        event.deserialize::<CalendarEvent>()?.update_full(
            new_content,
            self.changed_by,
            event,
            content.inner,
            self.owner_id,
            document_id,
            None,
            batch,
        )?;
        Ok(true)
    }

    async fn stage_notification(
        &self,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        let Some(archive) = self
            .archive(Collection::CalendarEventNotification, document_id)
            .await?
        else {
            return Ok(false);
        };
        let current = archive.to_unarchived::<CalendarEventNotification>()?;
        let candidates = self.candidates(current.inner.dismissed_ids());
        if candidates.is_empty() {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                self.has_calendar_access(
                    viewer,
                    current.inner.calendar_ids.iter().map(|id| id.to_native()),
                )
            })
        };
        if !candidates.iter().any(|account_id| lost(*account_id)) {
            return Ok(false);
        }

        let mut notification = current.deserialize::<CalendarEventNotification>()?;
        notification.dismissed_by.retain(|id| !lost(*id));
        self.guard(batch);

        notification.update_meta(self.changed_by, current, self.owner_id, document_id, batch)?;
        Ok(true)
    }

    async fn stage_address_book(
        &self,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        let Some(archive) = self.archive(Collection::AddressBook, document_id).await? else {
            return Ok(false);
        };
        let current = archive.to_unarchived::<AddressBook>()?;
        let candidates = self.candidates(
            current
                .inner
                .subscribers
                .iter()
                .map(|id| id.to_native())
                .chain(
                    current
                        .inner
                        .preferences
                        .iter()
                        .map(|pref| pref.account_id.to_native()),
                ),
        );
        let has_grants = self.has_purged_grants(&current.inner.acls);
        if candidates.is_empty() && !has_grants {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                !current.inner.acls.effective_acl(viewer).is_empty()
            })
        };
        if !has_grants && !candidates.iter().any(|account_id| lost(*account_id)) {
            return Ok(false);
        }

        let mut book = current.deserialize::<AddressBook>()?;
        book.acls
            .retain(|grant| !self.purges_grant(grant.account_id));
        book.subscribers.retain(|id| !lost(*id));
        book.preferences.retain(|pref| !lost(pref.account_id));
        book.modified = now() as i64;

        self.write(Collection::AddressBook, document_id, current, book, batch)
    }

    async fn stage_file_node(
        &self,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        let Some(archive) = self.archive(Collection::FileNode, document_id).await? else {
            return Ok(false);
        };
        let current = archive.to_unarchived::<FileNode>()?;
        let candidates =
            self.candidates(current.inner.unsubscribed.iter().map(|id| id.to_native()));
        let has_grants = self.has_purged_grants(&current.inner.acls);
        if candidates.is_empty() && !has_grants {
            return Ok(false);
        }
        self.load_viewers(&candidates).await?;
        let lost = |account_id| {
            self.lost_access(account_id, |viewer| {
                self.files
                    .as_deref()
                    .is_none_or(|files| !files.file_acl(viewer, document_id).is_empty())
            })
        };
        if !has_grants && !candidates.iter().any(|account_id| lost(*account_id)) {
            return Ok(false);
        }

        let mut node = current.deserialize::<FileNode>()?;
        node.acls
            .retain(|grant| !self.purges_grant(grant.account_id));
        node.unsubscribed.retain(|id| !lost(*id));
        node.stamp_update(false);

        self.write(Collection::FileNode, document_id, current, node, batch)
    }

    fn has_purged_grants(&self, acls: &ArchivedVec<ArchivedAclGrant>) -> bool {
        acls.iter()
            .any(|grant| self.purges_grant(u32::from(grant.account_id)))
    }

    fn lost_access(&self, account_id: u32, has_access: impl Fn(&AccessToken) -> bool) -> bool {
        match self.purge {
            Purge::Grantee(grantee_id) => account_id == grantee_id,
            Purge::LostAccess => {
                account_id != self.owner_id
                    && self.viewers.lock().get(&account_id).is_some_and(|viewer| {
                        viewer.as_ref().is_some_and(|viewer| {
                            !viewer.is_member(self.owner_id) && !has_access(viewer)
                        })
                    })
            }
        }
    }

    fn has_calendar_access(
        &self,
        viewer: &AccessToken,
        mut calendar_ids: impl Iterator<Item = u32>,
    ) -> bool {
        self.calendars.as_deref().is_none_or(|calendars| {
            calendar_ids.any(|calendar_id| !calendars.container_acl(viewer, calendar_id).is_empty())
        })
    }

    fn write<C: CurrentObject, N: SerializableObject>(
        &self,
        collection: Collection,
        document_id: u32,
        current: C,
        changes: N,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        self.guard(batch);
        batch
            .with_account_id(self.owner_id)
            .with_collection(collection)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(changes)
                    .with_changed_by(self.changed_by)
                    .with_revoke_cleanup(RevokeCleanup::Inline),
            )?
            .commit_point();
        Ok(true)
    }

    fn guard(&self, batch: &mut BatchBuilder) {
        if let Some((collection, document_id, archive)) = self.guard {
            batch
                .with_account_id(self.owner_id)
                .with_collection(collection)
                .with_document(document_id)
                .assert_value(Field::ARCHIVE, archive);
        }
    }

    async fn archive(
        &self,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                self.owner_id,
                collection,
                document_id,
            ))
            .await
    }
}
