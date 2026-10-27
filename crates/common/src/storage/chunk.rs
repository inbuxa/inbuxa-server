/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use store::{
    ValueKey,
    dispatch::DocumentSet,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{collection::Collection, field::Field};

#[derive(Default)]
pub struct ArchiveChunk {
    archives: Vec<(u32, Option<Archive<ArchiveBytes>>)>,
    values: Vec<(u32, Option<Archive<ArchiveBytes>>)>,
}

struct SortedIds<'x>(&'x [u32]);

impl Server {
    pub async fn archive_chunk(
        &self,
        account_id: u32,
        collection: Collection,
        document_ids: &[u32],
        value: Option<(Field, &[u32])>,
    ) -> trc::Result<ArchiveChunk> {
        debug_assert!(document_ids.is_sorted_by(|a, b| a < b));
        debug_assert!(value.is_none_or(|(_, ids)| ids.is_sorted_by(|a, b| a < b)));

        let value = value.filter(|(_, ids)| !ids.is_empty());
        let mut chunk = ArchiveChunk {
            archives: Vec::with_capacity(document_ids.len()),
            values: Vec::with_capacity(value.map_or(0, |(_, ids)| ids.len())),
        };
        match (document_ids, value) {
            ([], None) => {}
            ([document_id], None) => {
                let archive = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                        account_id,
                        collection,
                        *document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?;
                chunk.archives.push((*document_id, archive));
            }
            ([], Some((field, [document_id]))) => {
                let value = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        collection,
                        *document_id,
                        field,
                    ))
                    .await
                    .caused_by(trc::location!())?;
                chunk.values.push((*document_id, value));
            }
            (document_ids, value) => {
                let shape = self.core.storage.data.read_shape();
                let archive_ids = SortedIds(document_ids);
                let ArchiveChunk { archives, values } = &mut chunk;
                let collect = |field: Field, document_id: u32, archive| {
                    if field == Field::ARCHIVE {
                        archives.push((document_id, Some(archive)));
                    } else {
                        values.push((document_id, Some(archive)));
                    }
                    Ok(true)
                };
                match value {
                    Some((field, value_ids)) => {
                        self.archives_fields(
                            account_id,
                            collection,
                            shape,
                            &[
                                (field, &SortedIds(value_ids)),
                                (Field::ARCHIVE, &archive_ids),
                            ],
                            collect,
                        )
                        .await
                    }
                    None => {
                        self.archives_fields(
                            account_id,
                            collection,
                            shape,
                            &[(Field::ARCHIVE, &archive_ids)],
                            collect,
                        )
                        .await
                    }
                }
                .caused_by(trc::location!())?;
            }
        }
        Ok(chunk)
    }
}

impl ArchiveChunk {
    pub fn take_archive(&mut self, document_id: u32) -> Option<Archive<ArchiveBytes>> {
        take(&mut self.archives, document_id)
    }

    pub fn take_value(&mut self, document_id: u32) -> Option<Archive<ArchiveBytes>> {
        take(&mut self.values, document_id)
    }

    pub fn value(&self, document_id: u32) -> Option<&Archive<ArchiveBytes>> {
        self.values
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.values.get(idx))
            .and_then(|(_, archive)| archive.as_ref())
    }
}

fn take(
    entries: &mut [(u32, Option<Archive<ArchiveBytes>>)],
    document_id: u32,
) -> Option<Archive<ArchiveBytes>> {
    entries
        .binary_search_by_key(&document_id, |(id, _)| *id)
        .ok()
        .and_then(|idx| entries.get_mut(idx))
        .and_then(|(_, archive)| archive.take())
}

impl DocumentSet for SortedIds<'_> {
    fn min(&self) -> u32 {
        self.0.first().copied().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.0.last().map_or(0, |id| id.saturating_add(1))
    }

    fn contains(&self, id: u32) -> bool {
        self.0.binary_search(&id).is_ok()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.0.iter().copied()
    }
}
