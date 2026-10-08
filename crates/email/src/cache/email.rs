/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::message::metadata::{
    ArchivedMessageData, MESSAGE_RECEIVED_MASK, MessageData, MessageMetadata,
};
use common::{
    MessageCache, MessageStoreCache, MessageUidCache, MessagesCache, Server, auth::AccessToken,
    sharing::EffectiveAcl,
};
use store::write::{AlignedBytes, Archive, SearchIndex};
use store::{
    READ_BATCH_SIZE, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{EmailSearchField, SearchField},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::Collection,
    field::EmailField,
    keyword::{Keyword, OTHER},
};
use utils::map::bitmap::Bitmap;

struct MessagesCacheBuilder {
    pub change_id: u64,
    pub items: Vec<MessageCache>,
    pub index: AHashMap<u32, u32>,
    pub keywords: Vec<Box<str>>,
    pub size: u64,
    pub has_received_at: bool,
}

pub(crate) async fn update_email_cache(
    server: &Server,
    account_id: u32,
    changed_ids: &AHashMap<u32, bool>,
    store_cache: &MessageStoreCache,
) -> trc::Result<MessagesCache> {
    let mut new_cache = MessagesCacheBuilder {
        index: AHashMap::with_capacity(store_cache.emails.items.len()),
        items: Vec::with_capacity(store_cache.emails.items.len()),
        size: 0,
        change_id: 0,
        keywords: store_cache.emails.keywords.to_vec(),
        has_received_at: store_cache.emails.has_received_at,
    };

    // inbuxa: one round trip per batch of changed messages, not one per
    // message; every node runs this after any write it hears about
    let updated = changed_ids
        .iter()
        .filter(|(_, is_update)| **is_update)
        .map(|(document_id, _)| *document_id)
        .collect::<Vec<_>>();
    for document_ids in updated.chunks(READ_BATCH_SIZE) {
        let keys = document_ids
            .iter()
            .map(|document_id| ValueKey::archive(account_id, Collection::Email, *document_id))
            .collect::<Vec<_>>();
        for (document_id, archive) in document_ids.iter().zip(
            server
                .store()
                .get_values::<Archive<AlignedBytes>>(&keys)
                .await
                .caused_by(trc::location!())?,
        ) {
            if let Some(archive) = archive {
                insert_item(
                    &mut new_cache,
                    *document_id,
                    archive.to_unarchived::<MessageData>()?,
                );
            }
        }
    }

    // inbuxa: a message's received date never changes, so an updated
    // message keeps the date the old cache had; a new one reads its metadata
    if new_cache.has_received_at {
        let mut new_ids = Vec::new();
        for document_id in &updated {
            let Some(idx) = new_cache.index.get(document_id) else {
                continue;
            };
            match store_cache.email_by_id(document_id) {
                Some(old) => new_cache.items[*idx as usize].received_at = old.received_at,
                None => new_ids.push(*document_id),
            }
        }
        fill_received_dates(server, account_id, &mut new_cache, new_ids).await?;
    }

    for item in &store_cache.emails.items {
        if !changed_ids.contains_key(&item.document_id) {
            email_insert(&mut new_cache, item.clone());
        }
    }

    Ok(new_cache.build())
}

pub(crate) async fn full_email_cache_build(
    server: &Server,
    account_id: u32,
) -> trc::Result<MessagesCache> {
    // Build cache
    let mut cache = MessagesCacheBuilder {
        items: Vec::with_capacity(16),
        index: AHashMap::with_capacity(16),
        keywords: Vec::new(),
        size: 0,
        change_id: 0,
        has_received_at: false,
    };

    server
        .archives(
            account_id,
            Collection::Email,
            &(),
            |document_id, archive| {
                insert_item(
                    &mut cache,
                    document_id,
                    archive.to_unarchived::<MessageData>()?,
                );
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    // inbuxa: the received dates come from the search index in one query
    // (an SQL search store), and from the metadata of the messages the
    // index task has not reached yet. With another search store the dates
    // stay unknown and sorts keep going through the store.
    if let Some(values) = server
        .search_store()
        .unsigned_values(
            SearchIndex::Email,
            SearchField::Email(EmailSearchField::ReceivedAt),
            account_id,
        )
        .await
        .caused_by(trc::location!())?
    {
        let mut missing = cache.index.clone();
        for (document_id, received_at) in values {
            if let Some(idx) = missing.remove(&document_id) {
                cache.items[idx as usize].received_at = received_at.min(u32::MAX as u64) as u32;
            }
        }
        cache.has_received_at = true;
        fill_received_dates(
            server,
            account_id,
            &mut cache,
            missing.into_keys().collect(),
        )
        .await?;
    }

    Ok(cache.build())
}

/// inbuxa: sets the received date of `document_ids` from their metadata,
/// a batch at a time
async fn fill_received_dates(
    server: &Server,
    account_id: u32,
    cache: &mut MessagesCacheBuilder,
    mut document_ids: Vec<u32>,
) -> trc::Result<()> {
    document_ids.sort_unstable();
    for document_ids in document_ids.chunks(READ_BATCH_SIZE) {
        let keys = document_ids
            .iter()
            .map(|document_id| {
                ValueKey::property(
                    account_id,
                    Collection::Email,
                    *document_id,
                    EmailField::Metadata,
                )
            })
            .collect::<Vec<_>>();
        for (document_id, metadata) in document_ids.iter().zip(
            server
                .store()
                .get_values::<Archive<AlignedBytes>>(&keys)
                .await
                .caused_by(trc::location!())?,
        ) {
            if let (Some(metadata), Some(idx)) = (metadata, cache.index.get(document_id)) {
                let received_at = metadata
                    .unarchive::<MessageMetadata>()
                    .caused_by(trc::location!())?
                    .rcvd_attach
                    .to_native()
                    & MESSAGE_RECEIVED_MASK;
                cache.items[*idx as usize].received_at = received_at.min(u32::MAX as u64) as u32;
            }
        }
    }
    Ok(())
}

fn insert_item(
    cache: &mut MessagesCacheBuilder,
    document_id: u32,
    archive: Archive<&ArchivedMessageData>,
) {
    let message = archive.inner;
    let mut item = MessageCache {
        mailboxes: message
            .mailboxes
            .iter()
            .map(|m| MessageUidCache {
                mailbox_id: m.mailbox_id.to_native(),
                uid: m.uid.to_native(),
            })
            .collect(),
        keywords: 0,
        thread_id: message.thread_id.to_native(),
        change_id: archive.version.change_id().unwrap_or_default(),
        document_id,
        size: message.size.to_native(),
        received_at: 0,
    };
    for keyword in message.keywords.iter() {
        match keyword.id() {
            Ok(id) => {
                item.keywords |= 1 << id;
            }
            Err(custom) => {
                if let Some(idx) = cache.keywords.iter().position(|k| **k == *custom) {
                    item.keywords |= 1 << (OTHER + idx);
                } else if cache.keywords.len() < (128 - OTHER) {
                    cache.keywords.push(custom.into());
                    item.keywords |= 1 << (OTHER + cache.keywords.len() - 1);
                }
            }
        }
    }

    email_insert(cache, item);
}

impl MessagesCacheBuilder {
    pub fn build(mut self) -> MessagesCache {
        self.index.shrink_to_fit();
        MessagesCache {
            change_id: self.change_id,
            items: self.items.into_boxed_slice(),
            index: self.index,
            keywords: self.keywords.into_boxed_slice(),
            size: self.size,
            has_received_at: self.has_received_at,
        }
    }
}

pub trait MessageCacheAccess {
    fn email_by_id(&self, id: &u32) -> Option<&MessageCache>;

    fn has_email_id(&self, id: &u32) -> bool;

    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = &MessageCache>;

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn email_document_ids(&self) -> RoaringBitmap;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword>;

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool;

    /// inbuxa: every message's received date, for a local receivedAt sort;
    /// `None` when the cache has no dates (see `MessagesCache`)
    fn received_at_order(&self) -> Option<AHashMap<u32, u32>>;

    /// inbuxa: the messages received in `[from, to)` seconds, for a local
    /// date filter; `None` when the cache has no dates
    fn received_between(&self, from: u64, to: u64) -> Option<RoaringBitmap>;
}

impl MessageCacheAccess for MessageStoreCache {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id))
    }

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| {
            m.mailboxes
                .iter()
                .any(|mb| mailbox_ids.contains(&mb.mailbox_id))
        })
    }

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| m.thread_id == thread_id)
    }

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.emails
            .items
            .iter()
            .filter(move |m| keyword_id.is_some_and(|id| m.keywords & (1 << id) != 0))
    }

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.emails
            .items
            .iter()
            .filter(move |m| keyword_id.is_none_or(|id| m.keywords & (1 << id) == 0))
    }

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.emails.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
                && keyword_id.is_some_and(|id| m.keywords & (1 << id) != 0)
        })
    }

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.emails.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
                && keyword_id.is_none_or(|id| m.keywords & (1 << id) == 0)
        })
    }

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();
        let mut shared_messages = RoaringBitmap::new();
        for mailbox in &self.mailboxes.items {
            if mailbox
                .acls
                .as_slice()
                .effective_acl(access_token)
                .contains_all(check_acls)
            {
                shared_messages.extend(
                    self.in_mailbox(mailbox.document_id)
                        .map(|item| item.document_id),
                );
            }
        }
        shared_messages
    }

    fn email_document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_iter(self.emails.index.keys())
    }

    fn email_by_id(&self, id: &u32) -> Option<&MessageCache> {
        self.emails
            .index
            .get(id)
            .and_then(|idx| self.emails.items.get(*idx as usize))
    }

    fn has_email_id(&self, id: &u32) -> bool {
        self.emails.index.contains_key(id)
    }

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword> {
        KeywordsIter(message.keywords).map(move |id| match Keyword::try_from_id(id) {
            Ok(keyword) => keyword,
            Err(id) => Keyword::Other(self.emails.keywords[id - OTHER].clone()),
        })
    }

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool {
        keyword_to_id(self, keyword).is_some_and(|id| message.keywords & (1 << id) != 0)
    }

    fn received_at_order(&self) -> Option<AHashMap<u32, u32>> {
        self.emails.has_received_at.then(|| {
            self.emails
                .items
                .iter()
                .map(|m| (m.document_id, m.received_at))
                .collect()
        })
    }

    fn received_between(&self, from: u64, to: u64) -> Option<RoaringBitmap> {
        self.emails.has_received_at.then(|| {
            self.emails
                .items
                .iter()
                .filter(|m| (from..to).contains(&(m.received_at as u64)))
                .map(|m| m.document_id)
                .collect()
        })
    }
}

fn email_insert(cache: &mut MessagesCacheBuilder, item: MessageCache) {
    let id = item.document_id;
    if let Some(idx) = cache.index.get(&id) {
        cache.items[*idx as usize] = item;
    } else {
        cache.size += (std::mem::size_of::<MessageCache>()
            + (std::mem::size_of::<u32>() * 2)
            + (item.mailboxes.len() * std::mem::size_of::<MessageUidCache>()))
            as u64;

        let idx = cache.items.len() as u32;
        cache.items.push(item);
        cache.index.insert(id, idx);
    }
}

#[inline]
fn keyword_to_id(cache: &MessageStoreCache, keyword: &Keyword) -> Option<u32> {
    match keyword.id() {
        Ok(id) => Some(id),
        Err(name) => cache
            .emails
            .keywords
            .iter()
            .position(|k| **k == *name)
            .map(|idx| (OTHER + idx) as u32),
    }
}

#[derive(Clone, Copy, Debug)]
struct KeywordsIter(u128);

impl Iterator for KeywordsIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0 != 0 {
            let item = 127 - self.0.leading_zeros();
            self.0 ^= 1 << item;
            Some(item as usize)
        } else {
            None
        }
    }
}
