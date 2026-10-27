/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    IterateParams, Key, U32_LEN, ValueKey,
    dispatch::{DocumentSet, ReadShape},
    write::{AnyKey, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField};

const CHUNK_SIZE: usize = 256;
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

pub struct CopySource {
    metadata: Vec<u8>,
    sort_keys: Option<Vec<u8>>,
}

pub struct CopySources {
    account_id: u32,
    order: Vec<u32>,
    cursor: usize,
    rows: Vec<(u32, Option<CopySource>)>,
    deferred: Vec<u32>,
}

enum ReadInto {
    Replace,
    Merge,
}

impl CopySource {
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    pub(super) fn into_parts(self) -> (Vec<u8>, Option<Vec<u8>>) {
        (self.metadata, self.sort_keys)
    }
}

impl CopySources {
    pub fn new(account_id: u32, order: Vec<u32>) -> Self {
        CopySources {
            account_id,
            order,
            cursor: 0,
            rows: Vec::new(),
            deferred: Vec::new(),
        }
    }

    pub async fn take(
        &mut self,
        server: &Server,
        document_id: u32,
    ) -> trc::Result<Option<CopySource>> {
        if let Some(source) = self.remove(document_id) {
            return Ok(Some(source));
        }

        let (documents, into) = if self.deferred.binary_search(&document_id).is_ok() {
            (std::mem::take(&mut self.deferred), ReadInto::Merge)
        } else if let Some(offset) = self
            .order
            .get(self.cursor..)
            .and_then(|pending| pending.iter().position(|id| *id == document_id))
        {
            let start = self.cursor + offset;
            let end = start.saturating_add(CHUNK_SIZE).min(self.order.len());
            self.cursor = end;
            let mut chunk = self.order.get(start..end).unwrap_or_default().to_vec();
            chunk.sort_unstable();
            chunk.dedup();
            (chunk, ReadInto::Replace)
        } else {
            (vec![document_id], ReadInto::Merge)
        };
        self.read(server, documents, document_id, into).await?;

        Ok(self.remove(document_id))
    }

    fn remove(&mut self, document_id: u32) -> Option<CopySource> {
        self.rows
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.rows.get_mut(idx))
            .and_then(|(_, source)| source.take())
    }

    async fn read(
        &mut self,
        server: &Server,
        documents: Vec<u32>,
        required: u32,
        into: ReadInto,
    ) -> trc::Result<()> {
        let account_id = self.account_id;
        let collection: u8 = Collection::Email.into();
        let store = server.store();
        let gaps = match store.read_shape() {
            ReadShape::Keys => documents
                .iter()
                .map(|&document_id| (document_id, document_id))
                .collect(),
            ReadShape::Ranges(gap) => documents.scan_ranges(gap),
        };
        let metadata_field: u8 = EmailField::Metadata.into();
        let sort_keys_field: u8 = EmailField::SortKeys.into();
        let ranges = [metadata_field, sort_keys_field]
            .into_iter()
            .flat_map(|field| {
                let class = ValueClass::Immutable(field);
                let subspace = class.subspace(collection);
                let key = move |document_id| {
                    ValueKey {
                        account_id,
                        collection,
                        document_id,
                        class: class.clone(),
                    }
                    .serialize(0)
                };
                gaps.iter().map(move |&(from_document_id, to_document_id)| {
                    let begin = key(from_document_id);
                    let end = if from_document_id == to_document_id {
                        begin.clone()
                    } else {
                        let mut end = key(to_document_id);
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
                })
            })
            .collect::<Vec<_>>();

        if matches!(into, ReadInto::Replace) {
            self.rows.clear();
            self.deferred.clear();
        }
        let mut fetched = Vec::with_capacity(documents.len());
        let rows = &mut fetched;
        let deferred = &mut self.deferred;
        let mut bytes = 0usize;
        store
            .iterate_many(ranges, |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                if !documents.contains(document_id) {
                    return Ok(true);
                }
                let field = key
                    .len()
                    .checked_sub(U32_LEN + 1)
                    .and_then(|offset| key.get(offset).copied());
                if field == Some(metadata_field) {
                    if bytes < CHUNK_BYTES || document_id == required {
                        bytes = bytes.saturating_add(value.len());
                        rows.push((
                            document_id,
                            Some(CopySource {
                                metadata: value.to_vec(),
                                sort_keys: None,
                            }),
                        ));
                    } else {
                        deferred.push(document_id);
                    }
                } else if let Some(source) = rows
                    .binary_search_by_key(&document_id, |(id, _)| *id)
                    .ok()
                    .and_then(|idx| rows.get_mut(idx))
                    .and_then(|(_, source)| source.as_mut())
                {
                    source.sort_keys = Some(value.to_vec());
                }
                Ok(true)
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })?;

        if self.rows.is_empty() {
            self.rows = fetched;
        } else {
            for (document_id, source) in fetched {
                match self.rows.binary_search_by_key(&document_id, |(id, _)| *id) {
                    Ok(idx) => {
                        if let Some((_, slot)) = self.rows.get_mut(idx) {
                            *slot = source;
                        }
                    }
                    Err(idx) => self.rows.insert(idx, (document_id, source)),
                }
            }
        }
        Ok(())
    }
}
