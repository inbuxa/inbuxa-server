/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::email::HAS_CUSTOM_KEYWORDS,
    message::metadata::{ArchivedMessageMetadata, MetadataRow, MetadataStructure},
};
use common::{
    MessageUid, Server,
    config::mailstore::limits::{EmailLimitError, EmailLimits},
    storage::batch::DocumentBatch,
};
use compact_str::CompactString;
use std::borrow::Cow;
use store::{
    Deserialize, IterateParams, Key, Serialize, U32_LEN, U64_LEN, ValueKey,
    dispatch::{DocumentSet, ScanGap},
    write::{
        AnyKey, AssignedIds, BatchBuilder, MergeResult, PendingId, SerializeWithIds, SetValue,
        SizedSetValue, Slot, SlotRange, ValueClass, key::DeserializeBigEndian, serialize::RawValue,
    },
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{EmailField, Field},
    keyword::{HASATTACHMENT, HASNOATTACHMENT, Keyword, OTHER},
};
use utils::codec::leb128::{Leb128Reader, Leb128Writer};

pub const SERVER_SET_KEYWORDS: u32 = (1 << HASATTACHMENT) | (1 << HASNOATTACHMENT);
pub const KEYWORD_BITS: u32 = (1 << OTHER) - 1;
pub const HAS_JMAP_METADATA: u32 = 1 << 30;
const METADATA_SCAN_GAP: ScanGap = ScanGap::new(1, 2);

const _: () = assert!(KEYWORD_BITS & HAS_JMAP_METADATA == 0);

#[derive(Debug, Clone)]
pub struct MessageData {
    pub mailboxes: TinyVec<[MessageUid; 2]>,
    pub keywords: u32,
    pub keywords_extra: Vec<CompactString>,
    pub thread_id: u32,
    pub size: u32,
    pub received_at: u64,
    pub sent_at: i32,
    pub change_id: u64,
}

pub trait EmailMessageData: Sync + Send {
    fn message_datas<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, MessageData) -> trc::Result<bool> + Send + Sync;

    fn message_metadata<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, &[u8]) -> trc::Result<bool> + Send + Sync;

    fn read_metadata_batch(
        &self,
        account_id: u32,
        form: MetadataForm,
        batch: &mut DocumentBatch<MetadataValue>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

pub enum MetadataValue {
    Structure(MetadataStructure),
    Row(MetadataRow),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataForm {
    Structure,
    Row,
}

impl EmailMessageData for Server {
    async fn message_datas<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, MessageData) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = Collection::Email.into();
        let ranges = documents
            .scan_ranges(self.core.storage.data.scan_gap())
            .into_iter()
            .map(|(from_document_id, to_document_id)| {
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: from_document_id,
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: to_document_id,
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                )
            })
            .collect::<Vec<_>>();

        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                MessageData::deserialize(value).and_then(|archive| cb(document_id, archive))
            } else {
                Ok(true)
            }
        };

        match ranges.len() {
            0 => Ok(()),
            1 => {
                self.core
                    .storage
                    .data
                    .iterate(ranges.into_iter().next().unwrap(), &mut collect)
                    .await
            }
            _ => {
                self.core
                    .storage
                    .data
                    .iterate_many(ranges, &mut collect)
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })
    }

    async fn message_metadata<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, &[u8]) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = Collection::Email.into();
        let class = ValueClass::Immutable(EmailField::Metadata.into());
        let subspace = class.subspace(collection);
        let key = |document_id| ValueKey {
            account_id,
            collection,
            document_id,
            class: class.clone(),
        };
        let params = |from_document_id, to_document_id| {
            let begin = key(from_document_id).serialize(0);
            let end = if from_document_id == to_document_id {
                begin.clone()
            } else {
                let mut end = key(to_document_id).serialize(0);
                end.push(u8::MAX);
                end
            };
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: begin,
                },
                AnyKey { subspace, key: end },
            )
        };
        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                cb(document_id, value)
            } else {
                Ok(true)
            }
        };
        let store = &self.core.storage.data;

        if documents.len() == 1 {
            let document_id = documents.min();
            return store
                .get_value::<RawValue>(key(document_id))
                .await
                .and_then(|value| {
                    value.map_or(Ok(()), |RawValue(value)| {
                        cb(document_id, &value).map(|_| ())
                    })
                })
                .add_context(|err| {
                    err.caused_by(trc::location!())
                        .account_id(account_id)
                        .collection(collection)
                });
        }

        let ranges = documents.scan_ranges(METADATA_SCAN_GAP);
        match ranges.as_slice() {
            [] => Ok(()),
            &[(from_document_id, to_document_id)] => {
                store
                    .iterate(params(from_document_id, to_document_id), &mut collect)
                    .await
            }
            _ => {
                store
                    .iterate_many(
                        ranges
                            .iter()
                            .map(|&(from_document_id, to_document_id)| {
                                params(from_document_id, to_document_id)
                            })
                            .collect(),
                        &mut collect,
                    )
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })
    }

    async fn read_metadata_batch(
        &self,
        account_id: u32,
        form: MetadataForm,
        batch: &mut DocumentBatch<MetadataValue>,
    ) -> trc::Result<()> {
        let Some((pending, mut sink)) = batch.begin_read() else {
            return Ok(());
        };
        if let &[document_id] = pending.as_slice() {
            let key = ValueKey::immutable(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata,
            );
            let store = self.store();
            let metadata = match form {
                MetadataForm::Structure => store
                    .get_value::<MetadataStructure>(key)
                    .await?
                    .map(MetadataValue::Structure),
                MetadataForm::Row => store
                    .get_value::<MetadataRow>(key)
                    .await?
                    .map(MetadataValue::Row),
            };
            if let Some(metadata) = metadata {
                let bytes = metadata.decoded_len();
                sink.push(document_id, metadata, bytes);
            }
        } else {
            self.message_metadata(account_id, pending, |document_id, value| {
                MetadataValue::decode(value, form).map(|metadata| {
                    let bytes = metadata.decoded_len();
                    sink.push(document_id, metadata, bytes)
                })
            })
            .await?;
        }
        batch.end_read();
        Ok(())
    }
}

impl MetadataValue {
    pub fn decode(bytes: &[u8], form: MetadataForm) -> trc::Result<Self> {
        match form {
            MetadataForm::Structure => {
                MetadataStructure::deserialize(bytes).map(MetadataValue::Structure)
            }
            MetadataForm::Row => MetadataRow::deserialize(bytes).map(MetadataValue::Row),
        }
    }

    pub fn unarchive(&self) -> trc::Result<&ArchivedMessageMetadata> {
        match self {
            MetadataValue::Structure(structure) => structure.unarchive(),
            MetadataValue::Row(row) => row.unarchive(),
        }
    }

    pub fn decoded_len(&self) -> usize {
        match self {
            MetadataValue::Structure(structure) => structure.decoded_len(),
            MetadataValue::Row(row) => row.decoded_len(),
        }
    }

    pub fn raw_headers(&self) -> trc::Result<Option<Cow<'_, [u8]>>> {
        match self {
            MetadataValue::Structure(_) => Ok(None),
            MetadataValue::Row(row) => row.raw_headers().map(Some),
        }
    }
}

impl MessageData {
    pub fn sent_at_offset(sent_at: Option<i64>, received_at: u64) -> i32 {
        sent_at.map_or(0, |sent_at| {
            let received_at = i64::try_from(received_at).unwrap_or(i64::MAX);
            sent_at
                .saturating_sub(received_at)
                .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
        })
    }

    pub fn set_keywords(&mut self, keywords: Vec<Keyword>) {
        self.keywords &= SERVER_SET_KEYWORDS | !KEYWORD_BITS;
        self.keywords_extra.clear();
        for keyword in keywords {
            match keyword.into_id() {
                Ok(id) => self.keywords |= 1 << id,
                Err(name) => {
                    if !self
                        .keywords_extra
                        .iter()
                        .any(|k| k.as_str() == name.as_str())
                    {
                        self.keywords_extra.push(name);
                    }
                }
            }
        }
    }

    pub fn add_keyword(&mut self, keyword: Keyword) -> bool {
        match keyword.into_id() {
            Ok(id) => {
                let id = 1 << id;
                if self.keywords & id == 0 {
                    self.keywords |= id;
                    true
                } else {
                    false
                }
            }
            Err(name) => {
                if !self
                    .keywords_extra
                    .iter()
                    .any(|k| k.as_str() == name.as_str())
                {
                    self.keywords_extra.push(name);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn remove_keyword(&mut self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => {
                let id = 1 << id;
                if self.keywords & id != 0 {
                    self.keywords &= !id;
                    true
                } else {
                    false
                }
            }
            Err(name) => {
                let prev_len = self.keywords_extra.len();
                self.keywords_extra.retain(|k| k.as_str() != name);
                self.keywords_extra.len() != prev_len
            }
        }
    }

    pub fn set_mailboxes(&mut self, mailboxes: TinyVec<[MessageUid; 2]>) {
        self.mailboxes = mailboxes;
    }

    pub fn add_mailbox(&mut self, mailbox: MessageUid) {
        if !self.has_mailbox_id(mailbox.mailbox_id) {
            self.mailboxes.push(mailbox);
        }
    }

    pub fn remove_mailbox(&mut self, mailbox: u32) {
        self.mailboxes.retain(|m| m.mailbox_id != mailbox);
    }

    pub fn has_keyword(&self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => (self.keywords & (1 << id)) != 0,
            Err(name) => self.keywords_extra.iter().any(|k| k.as_str() == name),
        }
    }

    pub fn keyword_count(&self) -> usize {
        (self.keywords & KEYWORD_BITS & !SERVER_SET_KEYWORDS).count_ones() as usize
            + self.keywords_extra.len()
    }

    pub fn validate_limits(
        &self,
        prev_data: &MessageData,
        limits: &EmailLimits,
    ) -> Result<(), EmailLimitError> {
        limits.validate_mailbox_change(prev_data.mailboxes.len(), self.mailboxes.len())?;
        limits.validate_keyword_change(prev_data.keyword_count(), self.keyword_count())?;
        limits.validate_keyword_names(
            self.keywords_extra
                .iter()
                .filter(|keyword| !prev_data.keywords_extra.contains(keyword))
                .map(|keyword| keyword.as_str()),
        )
    }

    pub fn has_keyword_changes(&self, prev_data: &MessageData) -> bool {
        (self.keywords ^ prev_data.keywords) & KEYWORD_BITS != 0
            || self.keywords_extra != prev_data.keywords_extra
    }

    pub fn keyword_diff(&self, prev_data: &MessageData) -> KeywordDiff {
        KeywordDiff::Patch {
            added: self.keywords & !prev_data.keywords & KEYWORD_BITS,
            removed: prev_data.keywords & !self.keywords & KEYWORD_BITS,
            added_extra: self
                .keywords_extra
                .iter()
                .filter(|k| !prev_data.keywords_extra.contains(*k))
                .cloned()
                .collect(),
            removed_extra: prev_data
                .keywords_extra
                .iter()
                .filter(|k| !self.keywords_extra.contains(*k))
                .cloned()
                .collect(),
        }
    }

    pub fn added_keywords(&self, prev_data: &MessageData) -> impl Iterator<Item = Keyword> {
        KeywordsIter(self.keywords & !prev_data.keywords & KEYWORD_BITS)
    }

    pub fn removed_keywords(&self, prev_data: &MessageData) -> impl Iterator<Item = Keyword> {
        KeywordsIter(prev_data.keywords & !self.keywords & KEYWORD_BITS)
    }

    pub fn keywords(&self) -> impl Iterator<Item = Keyword> {
        KeywordsIter(self.keywords & KEYWORD_BITS)
            .chain(self.keywords_extra.iter().cloned().map(Keyword::Other))
    }

    pub fn added_mailboxes(&self, prev_data: &MessageData) -> impl Iterator<Item = &MessageUid> {
        self.mailboxes.iter().filter(|m| {
            prev_data
                .mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn removed_mailboxes<'x>(
        &'x self,
        prev_data: &'x MessageData,
    ) -> impl Iterator<Item = &'x MessageUid> {
        prev_data.mailboxes.iter().filter(|m| {
            self.mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn has_mailbox_changes(&self, prev_data: &MessageData) -> bool {
        self.mailboxes.len() != prev_data.mailboxes.len()
            || !self.mailboxes.iter().all(|m| {
                prev_data
                    .mailboxes
                    .iter()
                    .any(|pm| pm.mailbox_id == m.mailbox_id)
            })
    }

    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
    }

    pub fn message_uid(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes
            .iter()
            .find(|m| m.mailbox_id == mailbox_id)
            .map(|m| m.uid)
    }
}

impl Serialize for MessageData {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        self.serialize_with_change_id(self.change_id)
    }
}

#[derive(Debug)]
pub enum KeywordDiff {
    Replace(Vec<Keyword>),
    Patch {
        added: u32,
        removed: u32,
        added_extra: Vec<CompactString>,
        removed_extra: Vec<CompactString>,
    },
}

impl KeywordDiff {
    pub fn replace(keywords: Vec<Keyword>) -> Self {
        KeywordDiff::Replace(keywords)
    }

    pub fn added(keyword: Keyword) -> Self {
        let (added, added_extra) = match keyword.into_id() {
            Ok(id) => (1 << id, Vec::new()),
            Err(name) => (0, vec![name]),
        };

        KeywordDiff::Patch {
            added,
            removed: 0,
            added_extra,
            removed_extra: Vec::new(),
        }
    }

    pub fn keyword_bits(&self, keywords: u32) -> Option<u32> {
        match self {
            KeywordDiff::Replace(list) if keywords & HAS_CUSTOM_KEYWORDS == 0 => {
                list.iter().try_fold(
                    keywords & (SERVER_SET_KEYWORDS | !KEYWORD_BITS),
                    |bits, keyword| keyword.id().ok().map(|id| bits | (1 << id)),
                )
            }
            KeywordDiff::Patch {
                added,
                removed,
                added_extra,
                removed_extra,
            } if added_extra.is_empty() && removed_extra.is_empty() => {
                Some((keywords | (added & KEYWORD_BITS)) & !(removed & KEYWORD_BITS))
            }
            _ => None,
        }
    }

    fn apply(&self, data: &mut MessageData) -> bool {
        let prev_keywords = data.keywords;

        match self {
            KeywordDiff::Replace(keywords) => {
                let prev_extra = data.keywords_extra.clone();
                data.set_keywords(keywords.clone());

                data.keywords != prev_keywords || data.keywords_extra != prev_extra
            }
            KeywordDiff::Patch {
                added,
                removed,
                added_extra,
                removed_extra,
            } => {
                let prev_extra_len = data.keywords_extra.len();

                data.keywords =
                    (data.keywords | (added & KEYWORD_BITS)) & !(removed & KEYWORD_BITS);
                if !removed_extra.is_empty() {
                    data.keywords_extra.retain(|k| !removed_extra.contains(k));
                }

                let mut extra_changed = data.keywords_extra.len() != prev_extra_len;
                for keyword in added_extra {
                    if !data.keywords_extra.contains(keyword) {
                        data.keywords_extra.push(keyword.clone());
                        extra_changed = true;
                    }
                }

                data.keywords != prev_keywords || extra_changed
            }
        }
    }
}

pub fn merge_keywords(batch: &mut BatchBuilder, thread_id: u32, diff: KeywordDiff) {
    batch.log_item_update(SyncCollection::Email, Some(PendingId::Assigned(thread_id)));
    batch.merge_fnc(Field::ARCHIVE, move |ids, bytes| {
        let Some(bytes) = bytes else {
            return Ok(MergeResult::Skip);
        };

        let mut data = MessageData::deserialize(bytes)?;
        if !diff.apply(&mut data) {
            return Ok(MergeResult::Skip);
        }

        data.serialize_with_change_id(ids.current_change_id())
            .map(MergeResult::Update)
    });
}

impl MessageData {
    pub fn serialize_with_change_id(&self, change_id: u64) -> trc::Result<Vec<u8>> {
        Ok(self.serialize_resolved(change_id, None, SlotRange::default(), None))
    }

    pub fn size_hint(&self) -> usize {
        std::mem::size_of::<MessageData>()
            + (std::mem::size_of::<MessageUid>() * self.mailboxes.len().saturating_sub(2))
            + (self
                .keywords_extra
                .iter()
                .map(|k| k.len() + 1)
                .sum::<usize>())
    }

    pub fn pending_uids(&self) -> usize {
        self.mailboxes.iter().filter(|mb| mb.uid == 0).count()
    }

    fn serialize_resolved(
        &self,
        change_id: u64,
        ids: Option<&AssignedIds>,
        uid_slots: SlotRange,
        thread_slot: Option<Slot>,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size_hint());
        let mut uid_slots = uid_slots.iter();

        out.push_leb128(self.mailboxes.len());
        for mb in self.mailboxes.iter() {
            out.push_leb128(mb.mailbox_id);
            let uid = match ids {
                Some(ids) if mb.uid == 0 => uid_slots.next().map_or(mb.uid, |slot| ids.slot(slot)),
                _ => mb.uid,
            };
            out.push_leb128(uid);
        }

        out.push_leb128(match (ids, thread_slot) {
            (Some(ids), Some(thread_slot)) => ids.slot(thread_slot),
            _ => self.thread_id,
        });

        out.push_leb128(self.size);
        out.push_leb128(self.received_at);
        out.push_leb128(((self.sent_at << 1) ^ (self.sent_at >> 31)) as u32);

        out.extend_from_slice(&self.keywords.to_be_bytes());

        for s in self.keywords_extra.iter() {
            out.push_leb128(s.len());
            out.extend_from_slice(s.as_bytes());
        }

        out.extend_from_slice(&change_id.to_be_bytes());

        out
    }
}

pub struct PendingMessageData {
    pub data: MessageData,
    pub uid_slots: SlotRange,
    pub thread_slot: Option<Slot>,
    pub change_id: Option<u64>,
}

impl SerializeWithIds for PendingMessageData {
    fn serialize_with_ids(&mut self, ids: &AssignedIds) -> trc::Result<(Vec<u8>, Option<u32>)> {
        let change_id = match self.change_id {
            Some(change_id) => change_id,
            None => ids.try_current_change_id().ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .ctx(
                        trc::Key::Reason,
                        "No change id was allocated for this message",
                    )
            })?,
        };

        Ok((
            self.data
                .serialize_resolved(change_id, Some(ids), self.uid_slots, self.thread_slot),
            None,
        ))
    }

    fn size_hint(&self) -> usize {
        self.data.size_hint()
    }
}

impl From<PendingMessageData> for SizedSetValue {
    fn from(data: PendingMessageData) -> Self {
        SetValue::serializable(data)
    }
}

impl Deserialize for MessageData {
    fn deserialize(data: &[u8]) -> trc::Result<Self> {
        deserialize(data)
            .ok_or_else(|| trc::Error::corrupted_key(b"", data.into(), trc::location!()))
    }
}

#[inline(always)]
fn deserialize(mut bytes: &[u8]) -> Option<MessageData> {
    let num_mailboxes: usize = bytes.read_leb128()?;
    let mut data = MessageData {
        mailboxes: TinyVec::with_capacity(num_mailboxes),
        keywords: 0,
        keywords_extra: Vec::new(),
        thread_id: 0,
        size: 0,
        received_at: 0,
        sent_at: 0,
        change_id: 0,
    };
    for _ in 0..num_mailboxes {
        let mailbox_id: u32 = bytes.read_leb128()?;
        let uid: u32 = bytes.read_leb128()?;
        data.mailboxes.push(MessageUid { mailbox_id, uid });
    }

    data.thread_id = bytes.read_leb128()?;
    data.size = bytes.read_leb128()?;
    data.received_at = bytes.read_leb128()?;
    data.sent_at = {
        let v: u32 = bytes.read_leb128()?;
        ((v >> 1) as i32) ^ -((v & 1) as i32)
    };

    let (keywords, mut bytes) = bytes.split_first_chunk::<U32_LEN>()?;
    data.keywords = u32::from_be_bytes(*keywords);

    while bytes.len() > U64_LEN {
        let len: usize = bytes.read_leb128()?;
        let (text, rest) = bytes.split_at_checked(len)?;
        data.keywords_extra
            .push(CompactString::from(std::str::from_utf8(text).ok()?));
        bytes = rest;
    }

    data.change_id = u64::from_be_bytes(*bytes.first_chunk::<U64_LEN>()?);

    Some(data)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct KeywordsIter(pub u32);

impl Iterator for KeywordsIter {
    type Item = Keyword;

    fn next(&mut self) -> Option<Self::Item> {
        while self.0 != 0 {
            let item = 31 - self.0.leading_zeros();
            self.0 ^= 1 << item;
            if let Ok(keyword) = Keyword::try_from_id(item as usize) {
                return Some(keyword);
            }
        }
        None
    }
}

