/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{is_transient, skip_unless_transient};
use common::{
    GroupwareResources, Server,
    auth::{AccessToken, ChangedBy},
    storage::dav::resource::NotificationRef,
};
use groupware::cache::GroupwareCache;
use groupware::{calendar::CalendarEventContent, file::FileNode};
use std::{mem, sync::Arc};
use store::{
    ahash::AHashMap,
    parking_lot::Mutex,
    roaring::RoaringBitmap,
    write::{BatchBuilder, assert::AssertValue},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, Field},
};

const MAX_WRITE_ATTEMPTS: usize = 3;

pub(super) enum Purge {
    Grantee(u32),
    LostAccess,
}

pub(super) struct GranteeCleanup<'x> {
    pub(super) server: &'x Server,
    pub(super) owner_id: u32,
    pub(super) changed_by: ChangedBy,
    pub(super) purge: Purge,
    pub(super) calendars: Option<Arc<GroupwareResources>>,
    pub(super) files: Option<Arc<GroupwareResources>>,
    pub(super) guard: Option<(Collection, u32, AssertValue)>,
    pub(super) viewers: Mutex<AHashMap<u32, Option<AccessToken>>>,
}

#[derive(Default)]
struct PendingWrites {
    batch: BatchBuilder,
    staged: Vec<(Collection, u32)>,
}

impl<'x> GranteeCleanup<'x> {
    pub(super) fn new(
        server: &'x Server,
        owner_id: u32,
        changed_by: ChangedBy,
        purge: Purge,
    ) -> Self {
        GranteeCleanup {
            server,
            owner_id,
            changed_by,
            purge,
            calendars: None,
            files: None,
            guard: None,
            viewers: Mutex::new(AHashMap::new()),
        }
    }

    pub(super) fn is_candidate(&self, account_id: u32) -> bool {
        match self.purge {
            Purge::Grantee(grantee_id) => grantee_id == account_id,
            Purge::LostAccess => account_id != self.owner_id,
        }
    }

    pub(super) fn purges_grant(&self, account_id: u32) -> bool {
        matches!(self.purge, Purge::Grantee(grantee_id) if grantee_id == account_id)
    }

    pub(super) fn candidates(&self, account_ids: impl Iterator<Item = u32>) -> Vec<u32> {
        let mut candidates = account_ids
            .filter(|account_id| self.is_candidate(*account_id))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }

    pub(super) async fn load_viewers(&self, account_ids: &[u32]) -> trc::Result<()> {
        if matches!(self.purge, Purge::Grantee(_)) {
            return Ok(());
        }
        for &account_id in account_ids {
            let is_loaded = self.viewers.lock().contains_key(&account_id);
            if is_loaded {
                continue;
            }
            let viewer = match self.server.try_account(account_id).await {
                Ok(Some(account)) => Some(AccessToken::from_account_maybe_invalid(&account)),
                Ok(None) => None,
                Err(err) if is_transient(&err) => return Err(err),
                Err(err) => {
                    trc::error!(
                        err.account_id(account_id)
                            .ctx(trc::Key::Reason, "Skipped during revoked share cleanup")
                    );
                    None
                }
            };
            self.viewers.lock().insert(account_id, viewer);
        }
        Ok(())
    }

    pub(super) fn with_guard(
        mut self,
        collection: Collection,
        document_id: u32,
        archive: AssertValue,
    ) -> Self {
        self.guard = Some((collection, document_id, archive));
        self
    }

    pub(super) async fn run(
        mut self,
        objects: impl Iterator<Item = (Collection, u32)> + Clone,
    ) -> trc::Result<()> {
        let mut calendar_ids = RoaringBitmap::new();
        let mut file_ids = RoaringBitmap::new();
        for (collection, document_id) in objects.clone() {
            match collection {
                Collection::Calendar => {
                    calendar_ids.insert(document_id);
                }
                Collection::FileNode => {
                    file_ids.insert(document_id);
                }
                _ => {}
            }
        }
        if !calendar_ids.is_empty() {
            self.calendars = Some(self.resources(SyncCollection::Calendar).await?);
        }
        if !file_ids.is_empty() {
            self.files = Some(self.resources(SyncCollection::FileNode).await?);
        }
        let mut pending = PendingWrites::default();
        if !calendar_ids.is_empty() {
            self.clean_calendar_items(&mut pending, &calendar_ids)
                .await?;
        }
        if !file_ids.is_empty() {
            self.clean_file_nodes(&mut pending, &file_ids).await?;
        }
        for (collection, document_id) in
            objects.filter(|(collection, _)| *collection != Collection::FileNode)
        {
            self.clean(&mut pending, collection, document_id).await?;
        }

        self.flush(&mut pending).await
    }

    async fn resources(&self, collection: SyncCollection) -> trc::Result<Arc<GroupwareResources>> {
        self.server
            .fetch_groupware_resources_at(self.owner_id, self.owner_id, collection, u64::MAX)
            .await
            .caused_by(trc::location!())
    }

    async fn clean_calendar_items(
        &self,
        pending: &mut PendingWrites,
        calendar_ids: &RoaringBitmap,
    ) -> trc::Result<()> {
        let event_ids = self
            .calendars
            .as_deref()
            .map(|calendars| {
                calendar_ids
                    .iter()
                    .flat_map(|calendar_id| calendars.children_ids(calendar_id))
                    .collect::<RoaringBitmap>()
            })
            .unwrap_or_default();
        let mut staged_ids = RoaringBitmap::new();
        if !event_ids.is_empty() {
            self.server
                .archives(
                    self.owner_id,
                    Collection::CalendarEvent,
                    CalendarEventField::Content.field(),
                    &event_ids,
                    |document_id, archive| {
                        if archive
                            .unarchive::<CalendarEventContent>()
                            .map_or(true, |content| {
                                content
                                    .preferences
                                    .iter()
                                    .any(|pref| self.is_candidate(pref.account_id.to_native()))
                            })
                        {
                            staged_ids.insert(document_id);
                        }
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
        for event_id in staged_ids {
            self.clean(pending, Collection::CalendarEvent, event_id)
                .await?;
        }

        let notifications = self
            .resources(SyncCollection::CalendarEventNotification)
            .await?;
        let notification_ids = notifications
            .resources
            .iter()
            .filter(|resource| {
                !resource.is_container()
                    && resource.notification().is_some_and(|notification| {
                        self.selects_notification(&notification, calendar_ids)
                    })
            })
            .map(|resource| resource.document_id())
            .collect::<RoaringBitmap>();
        drop(notifications);
        for notification_id in notification_ids {
            self.clean(
                pending,
                Collection::CalendarEventNotification,
                notification_id,
            )
            .await?;
        }

        Ok(())
    }

    fn selects_notification(
        &self,
        notification: &NotificationRef<'_>,
        calendar_ids: &RoaringBitmap,
    ) -> bool {
        notification
            .dismissed_by
            .iter()
            .any(|account_id| self.is_candidate(*account_id))
            && match self.purge {
                Purge::Grantee(_) => true,
                Purge::LostAccess => notification
                    .calendar_ids
                    .iter()
                    .any(|calendar_id| calendar_ids.contains(*calendar_id)),
            }
    }

    async fn clean_file_nodes(
        &self,
        pending: &mut PendingWrites,
        root_ids: &RoaringBitmap,
    ) -> trc::Result<()> {
        let mut descendant_ids = RoaringBitmap::new();
        if let Some(files) = self.files.as_deref() {
            for document_id in root_ids {
                if !descendant_ids.contains(document_id)
                    && let Some(root) = files.any_resource_path_by_id(document_id)
                {
                    descendant_ids.extend(
                        files
                            .subtree(root.path())
                            .map(|resource| resource.document_id()),
                    );
                }
            }
        }
        descendant_ids -= root_ids;
        let mut staged_ids = RoaringBitmap::new();
        self.server
            .archives(
                self.owner_id,
                Collection::FileNode,
                Field::ARCHIVE,
                &(&descendant_ids | root_ids),
                |document_id, archive| {
                    if archive.unarchive::<FileNode>().map_or(true, |node| {
                        node.unsubscribed
                            .iter()
                            .any(|id| self.is_candidate(id.to_native()))
                            || node
                                .acls
                                .iter()
                                .any(|grant| self.purges_grant(u32::from(grant.account_id)))
                    }) {
                        staged_ids.insert(document_id);
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        descendant_ids &= &staged_ids;
        for document_id in descendant_ids.iter().chain(root_ids & &staged_ids) {
            self.clean(pending, Collection::FileNode, document_id)
                .await?;
        }

        Ok(())
    }

    async fn clean(
        &self,
        pending: &mut PendingWrites,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<()> {
        match self
            .stage(collection, document_id, &mut pending.batch)
            .await
        {
            Ok(true) => {
                pending.staged.push((collection, document_id));
                if pending.batch.is_large_batch() {
                    self.flush(pending).await?;
                }
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(err) if is_transient(&err) => Err(err),
            Err(err) => {
                self.replay(pending).await?;
                skip_unless_transient(
                    err.account_id(self.owner_id)
                        .document_id(document_id)
                        .caused_by(trc::location!()),
                )
            }
        }
    }

    async fn flush(&self, pending: &mut PendingWrites) -> trc::Result<()> {
        if pending.staged.is_empty() {
            return Ok(());
        }
        match self
            .server
            .commit_batch(mem::take(&mut pending.batch))
            .await
        {
            Ok(_) => {
                pending.staged.clear();
                Ok(())
            }
            Err(err) if err.is_assertion_failure() => self.replay(pending).await,
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    async fn replay(&self, pending: &mut PendingWrites) -> trc::Result<()> {
        pending.batch = BatchBuilder::new();
        for (collection, document_id) in mem::take(&mut pending.staged) {
            self.clean_one(collection, document_id).await?;
        }
        Ok(())
    }

    async fn clean_one(&self, collection: Collection, document_id: u32) -> trc::Result<()> {
        let mut attempt = 1;
        loop {
            let mut batch = BatchBuilder::new();
            let result = match self.stage(collection, document_id, &mut batch).await {
                Ok(true) => self.server.commit_batch(batch).await.map(|_| ()),
                Ok(false) => Ok(()),
                Err(err) => Err(err),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(err) if err.is_assertion_failure() && attempt < MAX_WRITE_ATTEMPTS => {
                    attempt += 1;
                }
                Err(err) => {
                    return skip_unless_transient(
                        err.account_id(self.owner_id)
                            .document_id(document_id)
                            .caused_by(trc::location!()),
                    );
                }
            }
        }
    }
}
