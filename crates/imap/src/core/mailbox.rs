/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AccountCaches, AccountView, CounterDelta, Counters, MailboxChange, MailboxCounters, MailboxId,
    MailboxName, MailboxRefresh, MailboxSource, MailboxSync, SelectedAccess, Session, SessionData,
};
use common::{
    MailboxesCache, MessageStoreCache,
    auth::AccessToken,
    config::mailstore::email::DefaultFolder,
    network::{SessionStream, limiter::InFlight},
    sharing::EffectiveAcl,
};
use compact_str::CompactString;
use email::{
    cache::{
        MessageCacheFetch,
        mailbox::{AccountMailboxes, MailboxCacheAccess, MailboxCacheFetch},
    },
    mailbox::INBOX_ID,
};
use imap_proto::protocol::{MailboxObjectId, ObjectId};
use parking_lot::Mutex;
use std::{
    mem,
    sync::{Arc, atomic::Ordering},
};
use store::{ValueKey, roaring::RoaringBitmap, write::ValueClass};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, special_use::SpecialUse};

const REVOKED_BYE: &[u8] = b"* BYE [NOPERM] Read access to the selected mailbox was revoked.\r\n";

impl<T: SessionStream> SessionData<T> {
    pub async fn new(
        session: &Session<T>,
        access_token: AccessToken,
        in_flight: Option<InFlight>,
    ) -> trc::Result<Self> {
        let data = SessionData {
            stream_tx: session.stream_tx.clone(),
            server: session.server.clone(),
            account_id: access_token.account_id(),
            session_id: session.session_id,
            mailboxes: Mutex::new(Vec::new()),
            state: token_state(&access_token).into(),
            remote_addr: session.remote_addr,
            access_token,
            in_flight,
        };

        let shared = data
            .access_token
            .shared_accounts(Collection::Mailbox)
            .copied()
            .collect::<Vec<_>>();
        let mut accounts = Vec::with_capacity(shared.len() + 1);
        accounts.push(
            data.account_view(data.account_id, None, &data.access_token)
                .await
                .caused_by(trc::location!())?,
        );
        for account_id in shared {
            let prefix = data.shared_prefix(account_id).await?;
            accounts.push(
                data.account_view(account_id, Some(prefix), &data.access_token)
                    .await
                    .caused_by(trc::location!())?,
            );
        }
        *data.mailboxes.lock() = accounts;

        Ok(data)
    }

    async fn shared_prefix(&self, account_id: u32) -> trc::Result<String> {
        Ok(format!(
            "{}/{}",
            self.server.core.email.shared_folder,
            self.server
                .account(account_id)
                .await
                .caused_by(trc::location!())?
                .name()
        ))
    }

    async fn account_view(
        &self,
        account_id: u32,
        prefix: Option<String>,
        access_token: &AccessToken,
    ) -> trc::Result<AccountView> {
        let (mailboxes, source) = if access_token.member_ids().any(|id| id == account_id) {
            let cache = self
                .server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            (cache.mailboxes.clone(), MailboxSource::Messages)
        } else {
            let fetched = self
                .server
                .fetch_mailboxes(account_id, None)
                .await
                .caused_by(trc::location!())?;
            (
                fetched.mailboxes,
                MailboxSource::Folders {
                    change_id: fetched.change_id,
                    verified_at: self.server.inner.cache.revalidate.now(),
                },
            )
        };
        Ok(AccountView::build(
            &self.server.core.email.default_folders,
            mailboxes,
            source,
            account_id,
            prefix,
            access_token,
        ))
    }

    pub async fn synchronize_mailboxes(&self, return_changes: bool) -> trc::Result<MailboxRefresh> {
        self.synchronize_mailboxes_using(return_changes, AccountCaches::default())
            .await
    }

    pub async fn synchronize_mailboxes_using(
        &self,
        return_changes: bool,
        caches: AccountCaches,
    ) -> trc::Result<MailboxRefresh> {
        let access_token = self
            .refresh_access_token()
            .await
            .caused_by(trc::location!())?;
        self.synchronize_mailboxes_as(access_token, return_changes, caches)
            .await
    }

    pub async fn synchronize_mailboxes_as(
        &self,
        access_token: AccessToken,
        return_changes: bool,
        mut caches: AccountCaches,
    ) -> trc::Result<MailboxRefresh> {
        let mut changes = return_changes.then(MailboxSync::default);
        let state = token_state(&access_token);

        if self.state.load(Ordering::Relaxed) != state {
            let added_account_ids = {
                let mut accounts = self.mailboxes.lock();
                let has_access_to = access_token
                    .shared_accounts(Collection::Mailbox)
                    .copied()
                    .collect::<Vec<_>>();
                accounts.retain_mut(|account| {
                    let keep = access_token.is_account_id(account.account_id)
                        || has_access_to.contains(&account.account_id);
                    if keep {
                        account.expire_folders();
                    } else if let Some(changes) = &mut changes {
                        let account_id = account.account_id;
                        changes
                            .deleted
                            .extend(mem::take(&mut account.names).into_iter().map(|entry| {
                                MailboxChange {
                                    account_id,
                                    name: entry.name,
                                    objectid: MailboxObjectId::Empty,
                                }
                            }));
                    }
                    keep
                });
                has_access_to
                    .iter()
                    .copied()
                    .filter(|account_id| {
                        !accounts
                            .iter()
                            .skip(1)
                            .any(|account| account.account_id == *account_id)
                    })
                    .collect::<Vec<_>>()
            };

            for account_id in added_account_ids {
                let prefix = self.shared_prefix(account_id).await?;
                let account = self
                    .account_view(account_id, Some(prefix), &access_token)
                    .await?;
                if let Some(changes) = &mut changes {
                    changes.added.extend(
                        account
                            .names
                            .iter()
                            .map(|entry| entry.to_change(account_id)),
                    );
                }
                self.mailboxes.lock().push(account);
            }

            self.state.store(state, Ordering::Relaxed);
        }

        let account_states = self
            .mailboxes
            .lock()
            .iter()
            .map(|account| {
                (
                    account.account_id,
                    account.mailboxes.clone(),
                    account.source,
                )
            })
            .collect::<Vec<_>>();

        for (account_id, mailboxes, source) in account_states {
            if let MailboxSource::Folders { verified_at, .. } = source {
                if !self.server.inner.cache.revalidate.is_within(verified_at) {
                    self.refresh_folders(account_id, &access_token, &mut changes)
                        .await?;
                }
                continue;
            }

            let cache = caches.fetch(&self.server, account_id).await?;
            if !Arc::ptr_eq(&cache.mailboxes, &mailboxes)
                && !self.refresh_account_structure(
                    account_id,
                    &cache.mailboxes,
                    &access_token,
                    &mut changes,
                )
            {
                continue;
            }

            if let Some(changes) = &mut changes {
                let mut accounts = self.mailboxes.lock();
                if let Some(account) = accounts
                    .iter_mut()
                    .find(|account| account.account_id == account_id)
                    && let Some(previous) = account.refresh_counters(&cache)
                {
                    for entry in account.names.iter().filter(|entry| {
                        !changes
                            .added
                            .iter()
                            .any(|added| added.account_id == account_id && added.name == entry.name)
                    }) {
                        let before = previous
                            .get(entry.mailbox_id as usize)
                            .copied()
                            .unwrap_or_default();
                        let after = account.counters_of(entry.mailbox_id);
                        if before.total != after.total || before.unseen != after.unseen {
                            changes.changed.push(entry.name.clone());
                        }
                    }
                }
            }
        }

        Ok(MailboxRefresh {
            changes,
            caches,
            access_token,
        })
    }

    async fn refresh_folders(
        &self,
        account_id: u32,
        access_token: &AccessToken,
        changes: &mut Option<MailboxSync>,
    ) -> trc::Result<()> {
        let Some(known) = self.known_folders(account_id) else {
            return Ok(());
        };
        let verified_at = self.server.inner.cache.revalidate.now();
        let fetched = self
            .server
            .fetch_mailboxes(account_id, Some(&known))
            .await
            .caused_by(trc::location!())?;
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
            && let MailboxSource::Folders { change_id, .. } = account.source
            && fetched.change_id >= change_id
        {
            if !Arc::ptr_eq(&fetched.mailboxes, &account.mailboxes) {
                account.restructure(
                    &self.server.core.email.default_folders,
                    fetched.mailboxes,
                    access_token,
                    changes,
                );
            }
            account.source = MailboxSource::Folders {
                change_id: fetched.change_id,
                verified_at,
            };
        }
        Ok(())
    }

    pub fn expire_folders(&self, account_id: u32) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.expire_folders();
        }
    }

    pub fn expire_folders_of(&self, mailbox_name: &str) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.holds_name(mailbox_name))
        {
            account.expire_folders();
        }
    }

    pub fn use_messages_of(&self, mailbox_name: &str) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.holds_name(mailbox_name))
        {
            account.source = MailboxSource::Messages;
        }
    }

    fn known_folders(&self, account_id: u32) -> Option<AccountMailboxes> {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == account_id)
            .and_then(|account| match account.source {
                MailboxSource::Folders { change_id, .. } => Some(AccountMailboxes {
                    mailboxes: account.mailboxes.clone(),
                    change_id,
                }),
                MailboxSource::Messages => None,
            })
    }

    pub fn use_messages(&self, account_id: u32) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.source = MailboxSource::Messages;
        }
    }

    fn refresh_account_structure(
        &self,
        account_id: u32,
        mailboxes: &Arc<MailboxesCache>,
        access_token: &AccessToken,
        changes: &mut Option<MailboxSync>,
    ) -> bool {
        let mut accounts = self.mailboxes.lock();
        let Some(account) = accounts
            .iter_mut()
            .find(|account| account.account_id == account_id)
        else {
            return false;
        };
        account.restructure(
            &self.server.core.email.default_folders,
            mailboxes.clone(),
            access_token,
            changes,
        );
        true
    }

    pub fn ensure_counters(&self, account_id: u32, cache: &MessageStoreCache) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.ensure_counters(cache);
        }
    }

    pub fn has_counters_at(&self, account_id: u32, change_id: u64) -> bool {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == account_id)
            .and_then(|account| account.counters.as_ref())
            .is_some_and(|counters| counters.change_id == change_id)
    }

    pub fn take_previous_counters(&self, account_id: u32) -> Option<Vec<Counters>> {
        self.mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
            .and_then(|account| account.previous_counters.take())
    }

    pub fn apply_counter_deltas(
        &self,
        account_id: u32,
        from_change_id: u64,
        to_change_id: u64,
        deltas: &[CounterDelta],
        rebuilt: bool,
    ) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.apply_counter_deltas(from_change_id, to_change_id, deltas, rebuilt);
        }
    }

    pub async fn seed_mailbox_counters(&self) -> trc::Result<()> {
        let account_ids = self
            .mailboxes
            .lock()
            .iter()
            .filter(|account| account.source == MailboxSource::Messages)
            .map(|account| account.account_id)
            .collect::<Vec<_>>();
        for account_id in account_ids {
            let cache = self
                .server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            if let Some(account) = self
                .mailboxes
                .lock()
                .iter_mut()
                .find(|account| account.account_id == account_id)
            {
                account.ensure_counters(&cache);
                account.previous_counters = None;
            }
        }
        Ok(())
    }

    pub fn get_mailbox_by_name(&self, mailbox_name: &str) -> Option<MailboxId> {
        let is_inbox = mailbox_name.eq_ignore_ascii_case("inbox");
        for account in self.mailboxes.lock().iter() {
            if account
                .prefix
                .as_ref()
                .is_none_or(|prefix| mailbox_name.starts_with(prefix.as_str()))
            {
                let mailbox_id = if is_inbox {
                    account.has_mailbox_id(INBOX_ID).then_some(INBOX_ID)
                } else {
                    account.id_by_name(mailbox_name)
                };
                if let Some(mailbox_id) = mailbox_id {
                    return MailboxId {
                        account_id: account.account_id,
                        mailbox_id,
                    }
                    .into();
                }
            }
        }
        None
    }

    pub fn get_mailbox_by_object_id(
        &self,
        object_id: &ObjectId,
        access_token: &AccessToken,
    ) -> Option<(MailboxId, CompactString)> {
        let mailbox_id = u32::try_from(object_id.mailbox_id?.id()).ok()?;
        let account_id = match object_id.account_id {
            Some(account_id) => u32::try_from(account_id.id()).ok()?,
            None => self.account_id,
        };
        let accounts = self.mailboxes.lock();
        let account = accounts
            .iter()
            .find(|account| account.account_id == account_id)?;
        let entry = account
            .names
            .iter()
            .find(|entry| entry.mailbox_id == mailbox_id && !entry.is_alias)?;
        let is_readable = access_token.is_member(account_id)
            || account.mailbox(mailbox_id).is_some_and(|mailbox| {
                mailbox
                    .acls
                    .as_slice()
                    .effective_acl(access_token)
                    .contains(Acl::ReadItems)
            });
        is_readable.then(|| {
            (
                MailboxId {
                    account_id,
                    mailbox_id,
                },
                entry.name.as_str().into(),
            )
        })
    }

    pub fn mailbox_object_id(&self, mailbox: MailboxId, name: &str) -> ObjectId {
        let is_alias = self
            .mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == mailbox.account_id)
            .and_then(|account| account.alias_target(&self.server.core.email.default_folders, name))
            .is_some_and(|target| target != mailbox.mailbox_id);
        if is_alias {
            ObjectId::default()
        } else {
            ObjectId::from(mailbox)
        }
    }

    pub fn uid_validity(&self, mailbox: &MailboxId) -> u32 {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == mailbox.account_id)
            .map_or(0, |account| account.uid_validity(mailbox.mailbox_id))
    }

    pub async fn uid_next(
        &self,
        cache: &MessageStoreCache,
        mailbox: &MailboxId,
    ) -> trc::Result<u32> {
        cache
            .refresh
            .uid_next
            .get_or_read(mailbox.mailbox_id, || async {
                self.server
                    .core
                    .storage
                    .data
                    .get_counter(ValueKey {
                        account_id: mailbox.account_id,
                        collection: Collection::Mailbox.into(),
                        document_id: mailbox.mailbox_id,
                        class: ValueClass::MailboxUid,
                    })
                    .await
                    .caused_by(trc::location!())
                    .map(|v| (v + 1) as u32)
            })
            .await
    }

    pub async fn check_mailbox_acl(
        &self,
        cache: Option<&MessageStoreCache>,
        account_id: u32,
        mailbox_id: u32,
        item: Acl,
    ) -> trc::Result<bool> {
        let access_token = self.refresh_access_token().await?;
        self.check_mailbox_acl_as(&access_token, cache, account_id, mailbox_id, item)
            .await
    }

    pub async fn check_mailbox_acl_as(
        &self,
        access_token: &AccessToken,
        cache: Option<&MessageStoreCache>,
        account_id: u32,
        mailbox_id: u32,
        item: Acl,
    ) -> trc::Result<bool> {
        if access_token.is_member(account_id) {
            return Ok(true);
        }
        let synchronized;
        let mailboxes = match cache {
            Some(cache) => &cache.mailboxes,
            None => {
                synchronized = self
                    .mailboxes
                    .lock()
                    .iter()
                    .find(|account| account.account_id == account_id)
                    .map(|account| account.mailboxes.clone())
                    .ok_or_else(|| {
                        trc::ImapEvent::Error
                            .caused_by(trc::location!())
                            .details("Mailbox no longer exists.")
                    })?;
                &synchronized
            }
        };
        mailboxes
            .mailbox_by_id(&mailbox_id)
            .map(|mailbox| {
                mailbox
                    .acls
                    .as_slice()
                    .effective_acl(access_token)
                    .contains(item)
            })
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .caused_by(trc::location!())
                    .details("Mailbox no longer exists.")
            })
    }

    pub fn is_acl_shared(&self, account_id: u32) -> bool {
        !self.access_token.member_ids().any(|id| id == account_id)
    }

    pub async fn selected_access(&self, mailbox: &MailboxId) -> trc::Result<SelectedAccess> {
        let cache = self
            .server
            .get_cached_messages(mailbox.account_id)
            .await
            .caused_by(trc::location!())?;
        let access_token = self
            .refresh_access_token()
            .await
            .caused_by(trc::location!())?;
        let is_readable = matches!(
            self.check_mailbox_acl_as(
                &access_token,
                Some(&cache),
                mailbox.account_id,
                mailbox.mailbox_id,
                Acl::ReadItems,
            )
            .await,
            Ok(true)
        );
        Ok(if is_readable {
            SelectedAccess::Readable {
                access_token,
                cache,
            }
        } else {
            SelectedAccess::Revoked
        })
    }

    pub async fn close_revoked(&self) -> trc::Error {
        self.write_bytes(REVOKED_BYE).await.ok();
        trc::NetworkEvent::Closed
            .into_err()
            .details("Read access to the selected mailbox was revoked.")
    }
}

fn token_state(access_token: &AccessToken) -> u32 {
    access_token.state() ^ access_token.revision() as u32
}

impl AccountView {
    pub fn build(
        default_folders: &[DefaultFolder],
        mailboxes: Arc<MailboxesCache>,
        source: MailboxSource,
        account_id: u32,
        prefix: Option<String>,
        access_token: &AccessToken,
    ) -> Self {
        let visible = if access_token.is_member(account_id) {
            None
        } else {
            Some(mailboxes.shared_mailboxes(access_token, Acl::Read))
        };
        let is_visible = |mailbox_id: u32| {
            visible
                .as_ref()
                .is_none_or(|visible| visible.contains(mailbox_id))
        };

        let mut parents = RoaringBitmap::new();
        let mut special_uses = Vec::new();
        for mailbox in mailboxes.items.iter() {
            if let Some(parent_id) = mailbox.parent_id() {
                parents.insert(parent_id);
            }
            if !matches!(mailbox.role, SpecialUse::None) && is_visible(mailbox.document_id) {
                special_uses.push((mailbox.role, mailbox.document_id));
            }
        }

        let mut names = Vec::with_capacity(mailboxes.items.len());
        for mailbox in mailboxes
            .items
            .iter()
            .filter(|mailbox| is_visible(mailbox.document_id))
        {
            let name = match &prefix {
                Some(prefix) => {
                    let mut name = String::with_capacity(prefix.len() + mailbox.path.len() + 1);
                    name.push_str(prefix);
                    name.push('/');
                    name.push_str(&mailbox.path);
                    name
                }
                None => mailbox.path.to_string(),
            };
            let mailbox_id = AccountView::default_folder_role(default_folders, &name)
                .and_then(|role| {
                    special_uses
                        .iter()
                        .find(|(special_use, _)| *special_use == role)
                        .map(|(_, mailbox_id)| *mailbox_id)
                })
                .unwrap_or(mailbox.document_id);
            names.push(MailboxName {
                name,
                mailbox_id,
                is_alias: mailbox_id != mailbox.document_id,
            });
        }
        names.sort_unstable_by(|a, b| a.name.cmp(&b.name));

        AccountView {
            account_id,
            prefix,
            mailboxes,
            source,
            visible,
            names,
            parents,
            counters: None,
            previous_counters: None,
        }
    }

    fn restructure(
        &mut self,
        default_folders: &[DefaultFolder],
        mailboxes: Arc<MailboxesCache>,
        access_token: &AccessToken,
        changes: &mut Option<MailboxSync>,
    ) {
        if self.keeps_structure(&mailboxes, access_token) {
            self.mailboxes = mailboxes;
            return;
        }
        let refreshed = AccountView::build(
            default_folders,
            mailboxes,
            self.source,
            self.account_id,
            self.prefix.take(),
            access_token,
        );
        let previous = mem::replace(&mut self.names, refreshed.names);
        if let Some(changes) = changes {
            let account_id = self.account_id;
            for entry in &self.names {
                match previous
                    .binary_search_by(|known| known.name.cmp(&entry.name))
                    .ok()
                    .and_then(|pos| previous.get(pos))
                {
                    Some(known) if known.object_id(account_id) == entry.object_id(account_id) => {}
                    Some(known) => {
                        changes.deleted.push(known.to_change(account_id));
                        changes.added.push(entry.to_change(account_id));
                    }
                    None => changes.added.push(entry.to_change(account_id)),
                }
            }
            for entry in previous {
                if self.entry_by_name(&entry.name).is_none() {
                    changes.deleted.push(entry.into_change(account_id));
                }
            }
        }
        self.mailboxes = refreshed.mailboxes;
        self.visible = refreshed.visible;
        self.parents = refreshed.parents;
        self.prefix = refreshed.prefix;
    }

    fn keeps_structure(&self, mailboxes: &MailboxesCache, access_token: &AccessToken) -> bool {
        self.mailboxes.items.len() == mailboxes.items.len()
            && self
                .mailboxes
                .items
                .iter()
                .zip(mailboxes.items.iter())
                .all(|(current, next)| {
                    current.document_id == next.document_id
                        && current.parent_id == next.parent_id
                        && current.role == next.role
                        && current.path == next.path
                })
            && match &self.visible {
                None => access_token.is_member(self.account_id),
                Some(visible) => {
                    !access_token.is_member(self.account_id)
                        && mailboxes.shared_mailboxes(access_token, Acl::Read) == *visible
                }
            }
    }

    pub fn ensure_counters(&mut self, cache: &MessageStoreCache) {
        if let Some(stale) = self
            .counters
            .take_if(|counters| counters.change_id != cache.emails.change_id)
        {
            self.previous_counters.get_or_insert(stale.by_mailbox);
        }
        if self.counters.is_none() {
            self.counters = Some(MailboxCounters::compute(cache));
        }
    }

    pub fn refresh_counters(&mut self, cache: &MessageStoreCache) -> Option<Vec<Counters>> {
        self.ensure_counters(cache);
        self.previous_counters.take()
    }

    pub fn apply_counter_deltas(
        &mut self,
        from_change_id: u64,
        to_change_id: u64,
        deltas: &[CounterDelta],
        rebuilt: bool,
    ) {
        match &mut self.counters {
            Some(counters) if !rebuilt && counters.change_id == from_change_id => {
                if self.previous_counters.is_none() {
                    self.previous_counters = Some(counters.by_mailbox.clone());
                }
                counters.apply_deltas(deltas, to_change_id);
            }
            Some(counters) if counters.change_id == to_change_id => {}
            Some(counters) => {
                if self.previous_counters.is_none() {
                    self.previous_counters = Some(std::mem::take(&mut counters.by_mailbox));
                }
                self.counters = None;
            }
            None => {}
        }
    }
}

