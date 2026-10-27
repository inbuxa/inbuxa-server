/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{collection::Collection, field::Field};

pub const MAX_BATCH_DOCUMENTS: usize = 256;
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

pub struct DocumentBatch<T> {
    values: Vec<(u32, T)>,
    pending: Vec<u32>,
    bytes: usize,
    max_bytes: usize,
    round: u32,
    state: BatchState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchState {
    Requesting,
    Partial,
    Settled,
}

#[derive(Debug)]
pub enum Lookup<'x, T> {
    Found(&'x T),
    Missing,
    Skip,
}

pub struct BatchSink<'x, T> {
    values: &'x mut Vec<(u32, T)>,
    bytes: &'x mut usize,
    max_bytes: usize,
}

impl<T> DocumentBatch<T> {
    pub fn new(max_bytes: usize) -> Self {
        DocumentBatch {
            values: Vec::new(),
            pending: Vec::new(),
            bytes: 0,
            max_bytes,
            round: 0,
            state: BatchState::Requesting,
        }
    }

    pub fn reset(&mut self) {
        self.values.clear();
        self.pending.clear();
        self.bytes = 0;
        self.round = 0;
        self.state = BatchState::Requesting;
    }

    pub fn request(&mut self, document_id: u32) {
        debug_assert_eq!(self.state, BatchState::Requesting);
        self.pending.push(document_id);
    }

    pub fn is_first_round(&self) -> bool {
        self.round == 0
    }

    pub fn begin_read(&mut self) -> Option<(&Vec<u32>, BatchSink<'_, T>)> {
        if self.state == BatchState::Requesting {
            self.pending.sort_unstable();
            self.pending.dedup();
        }
        self.values.clear();
        self.bytes = 0;
        if self.pending.is_empty() {
            self.state = BatchState::Settled;
            return None;
        }
        self.state = BatchState::Partial;
        Some((
            &self.pending,
            BatchSink {
                values: &mut self.values,
                bytes: &mut self.bytes,
                max_bytes: self.max_bytes,
            },
        ))
    }

    pub fn end_read(&mut self) {
        if !self
            .values
            .is_sorted_by_key(|(document_id, _)| *document_id)
        {
            self.values
                .sort_unstable_by_key(|(document_id, _)| *document_id);
        }
        if self.bytes < self.max_bytes || self.values.len() >= self.pending.len() {
            self.state = BatchState::Settled;
        }
    }

    pub fn lookup(&self, document_id: u32) -> Lookup<'_, T> {
        if self.pending.binary_search(&document_id).is_err() {
            Lookup::Skip
        } else if let Some(value) = self.get(document_id) {
            Lookup::Found(value)
        } else if self.state == BatchState::Settled {
            Lookup::Missing
        } else {
            Lookup::Skip
        }
    }

    pub fn get(&self, document_id: u32) -> Option<&T> {
        self.values
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.values.get(idx))
            .map(|(_, value)| value)
    }

    pub fn next_round(&mut self) -> bool {
        match self.state {
            BatchState::Requesting => true,
            BatchState::Settled => false,
            BatchState::Partial => {
                let values = &self.values;
                self.pending.retain(|document_id| {
                    values
                        .binary_search_by_key(document_id, |(id, _)| *id)
                        .is_err()
                });
                self.values.clear();
                self.bytes = 0;
                self.round += 1;
                true
            }
        }
    }
}

impl<T> BatchSink<'_, T> {
    pub fn push(&mut self, document_id: u32, value: T, bytes: usize) -> bool {
        self.values.push((document_id, value));
        *self.bytes = self.bytes.saturating_add(bytes);
        *self.bytes < self.max_bytes
    }
}

impl Server {
    pub async fn read_archive_batch(
        &self,
        account_id: u32,
        collection: Collection,
        field: Field,
        batch: &mut DocumentBatch<Archive<ArchiveBytes>>,
    ) -> trc::Result<()> {
        let Some((pending, mut sink)) = batch.begin_read() else {
            return Ok(());
        };
        if let &[document_id] = pending.as_slice() {
            if let Some(archive) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    collection,
                    document_id,
                    field,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let bytes = archive.as_bytes().len();
                sink.push(document_id, archive, bytes);
            }
        } else {
            self.archives(
                account_id,
                collection,
                field,
                pending,
                |document_id, archive| {
                    let bytes = archive.as_bytes().len();
                    Ok(sink.push(document_id, archive, bytes))
                },
            )
            .await
            .caused_by(trc::location!())?;
        }
        batch.end_read();
        Ok(())
    }
}

