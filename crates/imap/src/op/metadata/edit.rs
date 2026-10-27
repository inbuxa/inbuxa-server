/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::metadata::ContainerChange;
use imap_proto::protocol::metadata::MetadataCode;
use std::borrow::Cow;
use store::write::metadata::MetadataBuf;
use types::metadata::{EntryBound, LimitViolation, MetadataBuilder, MetadataLimits, MetadataScope};

struct ContainerEdit<'x> {
    builder: MetadataBuilder<'x>,
    previous_len: usize,
    previous_entries: usize,
    entry_bound: EntryBound,
    largest: usize,
    changed: bool,
}

pub(crate) fn edit_container<'x>(
    previous: Option<&'x MetadataBuf>,
    entries: impl Iterator<Item = (&'x str, Option<&'x [u8]>)> + Clone,
    scope: MetadataScope,
    limits: &MetadataLimits,
) -> Result<Option<ContainerChange>, MetadataCode> {
    let mut edit = ContainerEdit::new(previous, limits);
    for (name, _) in entries.clone().filter(|(_, value)| value.is_none()) {
        edit.remove(name);
    }
    for (name, value) in entries.filter_map(|(name, value)| value.map(|value| (name, value))) {
        edit.set(name, value, limits)?;
    }
    edit.finish(previous, scope, limits)
}

impl<'x> ContainerEdit<'x> {
    fn new(previous: Option<&'x MetadataBuf>, limits: &MetadataLimits) -> Self {
        let view = previous.map(MetadataBuf::view);
        let (previous_len, previous_entries) = view
            .as_ref()
            .map_or((0, 0), |view| (view.as_bytes().len(), view.len()));
        ContainerEdit {
            builder: view
                .as_ref()
                .map_or_else(MetadataBuilder::new, MetadataBuilder::from_view),
            previous_len,
            previous_entries,
            entry_bound: limits.entry_bound(previous_entries),
            largest: 0,
            changed: false,
        }
    }

    fn remove(&mut self, name: &str) {
        self.changed |= self.builder.remove_imap(name);
    }

    fn set(
        &mut self,
        name: &'x str,
        value: &'x [u8],
        limits: &MetadataLimits,
    ) -> Result<(), MetadataCode> {
        limits
            .check_entry_size(value.len())
            .map_err(|_| MetadataCode::MaxSize(to_u32(limits.max_entry_size)))?;
        self.largest = self.largest.max(value.len());
        if self.builder.imap(name) != Some(value) {
            self.builder.set_imap(Cow::Borrowed(name), value);
            self.changed = true;
            self.entry_bound
                .check(self.builder.len(), 0)
                .map_err(|_| MetadataCode::TooMany)?;
        }
        Ok(())
    }

    fn finish(
        self,
        previous: Option<&MetadataBuf>,
        scope: MetadataScope,
        limits: &MetadataLimits,
    ) -> Result<Option<ContainerChange>, MetadataCode> {
        if !self.changed {
            return Ok(None);
        }
        let edit = self.builder.edit();
        let next = self.builder.encode();
        if let Some(next) = &next {
            match limits.check_edit(scope, self.previous_len, self.previous_entries, next) {
                Ok(()) => {}
                Err(LimitViolation::ContainerSize { size, max }) => {
                    let available = (max + self.largest).saturating_sub(size);
                    return Err(MetadataCode::MaxSize(to_u32(
                        available.min(limits.max_entry_size),
                    )));
                }
                Err(_) => return Err(MetadataCode::TooMany),
            }
        }
        Ok(ContainerChange::new(previous, next, edit))
    }
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

