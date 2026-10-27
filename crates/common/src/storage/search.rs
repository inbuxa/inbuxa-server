/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{KV_LOCK_SEARCH_INDEX, Server};
use store::{
    IterateParams, U32_LEN, U64_LEN, ValueKey,
    write::{
        QueueDocumentId, SearchIndex, SearchIndexClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        serialize::RawValue,
    },
};
use trc::AddContext;

pub(crate) const MAX_PENDING_SCAN: u64 = 250_000;

#[derive(Debug, Clone, Default)]
pub struct SearchIndexStatus {
    pub next_retry: u64,
    pub attempts: u32,
    pub reason: String,
}

impl SearchIndexStatus {
    pub fn deserialize(value: &[u8]) -> trc::Result<Self> {
        Ok(SearchIndexStatus {
            next_retry: value.deserialize_be_u64(0)?,
            attempts: value.deserialize_be_u32(U64_LEN)?,
            reason: value
                .get(U64_LEN + U32_LEN..)
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .into_owned(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(U64_LEN + U32_LEN + self.reason.len())
            .write(self.next_retry)
            .write(self.attempts)
            .write(self.reason.as_bytes())
            .finalize()
    }
}

impl Server {
    pub async fn total_index_pending(&self) -> trc::Result<[u64; 5]> {
        let mut pending = [0u64; 5];
        let mut scanned = 0u64;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                        index: SearchIndex::Email,
                        id_prefix: 0,
                        id_suffix: QueueDocumentId::Assigned(0),
                        created_at: 0,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                        index: SearchIndex::Tracing,
                        id_prefix: u32::MAX,
                        id_suffix: QueueDocumentId::Assigned(u32::MAX),
                        created_at: u64::MAX,
                    })),
                ),
                |key, value| {
                    if value.first().is_some_and(|flag| *flag != 0)
                        && let Some(count) = key
                            .first()
                            .and_then(|index| pending.get_mut(*index as usize))
                    {
                        *count += 1;
                    }
                    scanned += 1;
                    Ok(scanned < MAX_PENDING_SCAN)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| pending)
    }

    pub async fn search_index_status(
        &self,
        index: SearchIndex,
        partition: u32,
    ) -> trc::Result<Option<SearchIndexStatus>> {
        match self
            .store()
            .get_value::<RawValue>(ValueKey::from(ValueClass::SearchIndex(
                SearchIndexClass::QueueStatus { index, partition },
            )))
            .await
            .caused_by(trc::location!())?
        {
            Some(value) => SearchIndexStatus::deserialize(value.0.as_slice()).map(Some),
            None => Ok(None),
        }
    }

    pub async fn try_lock_search_index(
        &self,
        index: SearchIndex,
        partition: u32,
        expiry: u64,
    ) -> bool {
        match self
            .in_memory_store()
            .try_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
                expiry,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock search index partition")
                        .ctx(trc::Key::Index, index.name())
                        .ctx(trc::Key::Partition, partition)
                        .caused_by(trc::location!())
                );

                false
            }
        }
    }

    pub async fn renew_search_index_lock(
        &self,
        index: SearchIndex,
        partition: u32,
        expiry: u64,
    ) -> bool {
        match self
            .in_memory_store()
            .renew_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
                expiry,
            )
            .await
        {
            Ok(_) => true,
            Err(err) => {
                trc::error!(
                    err.details("Failed to renew search index partition lock")
                        .ctx(trc::Key::Index, index.name())
                        .ctx(trc::Key::Partition, partition)
                        .caused_by(trc::location!())
                );

                false
            }
        }
    }

    pub async fn unlock_search_index(&self, index: SearchIndex, partition: u32) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(
                KV_LOCK_SEARCH_INDEX,
                &search_index_lock_key(index, partition),
            )
            .await
        {
            trc::error!(
                err.details("Failed to unlock search index partition")
                    .ctx(trc::Key::Index, index.name())
                    .ctx(trc::Key::Partition, partition)
                    .caused_by(trc::location!())
            );
        }
    }
}

fn search_index_lock_key(index: SearchIndex, partition: u32) -> [u8; U32_LEN + 1] {
    let mut key = [index.to_u8(); U32_LEN + 1];
    key[1..].copy_from_slice(&partition.to_be_bytes());
    key
}
