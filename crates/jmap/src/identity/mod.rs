/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::{Archive, ArchiveBytes};

pub mod get;
pub mod set;

#[derive(Default)]
pub struct StoredIdentities(Vec<(u32, Archive<ArchiveBytes>)>);

impl StoredIdentities {
    pub fn get(&self, document_id: u32) -> Option<&Archive<ArchiveBytes>> {
        self.0
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.0.get(idx))
            .map(|(_, archive)| archive)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &Archive<ArchiveBytes>)> {
        self.0.iter().map(|(id, archive)| (*id, archive))
    }

    fn push(&mut self, document_id: u32, archive: Archive<ArchiveBytes>) {
        self.0.push((document_id, archive));
    }
}
