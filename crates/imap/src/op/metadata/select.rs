/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SPECIAL_USE_ENTRY;
use imap_proto::protocol::metadata::{Depth, Entry, EntryValue, Scope};
use std::borrow::Cow;

#[derive(Debug, Default)]
pub(crate) struct EntrySource<'x> {
    entries: Vec<(&'x str, &'x [u8])>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PrivateEntries<'s, 'x> {
    All(&'s EntrySource<'x>),
    SpecialUse(&'s EntrySource<'x>),
    Hidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectOptions {
    pub depth: Depth,
    pub max_size: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Selection<'x> {
    pub entries: Vec<EntryValue<'x>>,
    pub longest: Option<u32>,
}

struct Emitted(Vec<bool>);

impl<'x> EntrySource<'x> {
    pub fn new(entries: impl IntoIterator<Item = (&'x str, &'x [u8])>) -> Self {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        if !entries.is_sorted_by(|a, b| a.0 < b.0) {
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            entries.dedup_by(|a, b| a.0 == b.0);
        }
        EntrySource { entries }
    }

    pub fn insert(&mut self, name: &'x str, value: &'x [u8]) {
        match self.position(name) {
            Ok(position) => {
                if let Some(entry) = self.entries.get_mut(position) {
                    entry.1 = value;
                }
            }
            Err(position) => self.entries.insert(position, (name, value)),
        }
    }

    fn position(&self, name: &str) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|(entry, _)| (*entry).cmp(name))
    }

    fn get(&self, name: &str) -> Option<(usize, &'x str, &'x [u8])> {
        let position = self.position(name).ok()?;
        self.entries
            .get(position)
            .map(|&(name, value)| (position, name, value))
    }

    fn children<'y>(
        &'y self,
        prefix: &'y str,
        depth: Depth,
    ) -> impl Iterator<Item = (usize, &'x str, &'x [u8])> + 'y {
        let start = self.entries.partition_point(|(name, _)| *name < prefix);
        self.entries
            .get(start..)
            .unwrap_or_default()
            .iter()
            .zip(start..)
            .map_while(move |(&(name, value), position)| {
                name.strip_prefix(prefix)
                    .map(|child| (position, name, value, child))
            })
            .filter(move |(_, _, _, child)| {
                !child.is_empty() && (depth == Depth::Infinity || !child.contains('/'))
            })
            .map(|(position, name, value, _)| (position, name, value))
    }
}

impl<'s, 'x> PrivateEntries<'s, 'x> {
    fn source(self) -> Option<&'s EntrySource<'x>> {
        match self {
            PrivateEntries::All(source) | PrivateEntries::SpecialUse(source) => Some(source),
            PrivateEntries::Hidden => None,
        }
    }

    fn exposes(self, path: &str) -> bool {
        match self {
            PrivateEntries::All(_) => true,
            PrivateEntries::SpecialUse(_) => path == SPECIAL_USE_ENTRY,
            PrivateEntries::Hidden => false,
        }
    }
}

impl Emitted {
    fn new(source: &EntrySource<'_>, depth: Depth) -> Self {
        if depth == Depth::Zero {
            Emitted(Vec::new())
        } else {
            Emitted(vec![false; source.entries.len()])
        }
    }

    fn insert(&mut self, position: usize) -> bool {
        self.0.is_empty()
            || self
                .0
                .get_mut(position)
                .is_some_and(|emitted| !std::mem::replace(emitted, true))
    }
}

impl<'x> Selection<'x> {
    fn push(&mut self, scope: Scope, name: &'x str, value: &'x [u8], max_size: Option<u32>) {
        match max_size {
            Some(max_size) if value.len() > max_size as usize => {
                let size = u32::try_from(value.len()).unwrap_or(u32::MAX);
                self.longest = Some(self.longest.map_or(size, |longest| longest.max(size)));
            }
            _ => self.entries.push(EntryValue {
                entry: Entry {
                    scope,
                    path: Cow::Borrowed(name),
                },
                value: Some(Cow::Borrowed(value)),
            }),
        }
    }
}

pub(crate) fn select_entries<'x>(
    requested: &'x [Entry<'x>],
    options: SelectOptions,
    shared: &EntrySource<'x>,
    private: PrivateEntries<'_, 'x>,
) -> Selection<'x> {
    let mut selection = Selection {
        entries: Vec::with_capacity(requested.len()),
        longest: None,
    };
    let private_source = private.source();
    let mut shared_emitted = Emitted::new(shared, options.depth);
    let mut private_emitted = private_source.map(|source| Emitted::new(source, options.depth));
    let mut prefix = String::new();

    for entry in requested {
        let (source, emitted) = match (entry.scope, private_source, private_emitted.as_mut()) {
            (Scope::Shared, _, _) => (shared, &mut shared_emitted),
            (Scope::Private, Some(source), Some(emitted)) if private.exposes(&entry.path) => {
                (source, emitted)
            }
            (Scope::Private, _, _) => continue,
        };
        let path = entry.path.as_ref();

        if !path.is_empty() {
            match source.get(path) {
                Some((position, name, value)) => {
                    if emitted.insert(position) {
                        selection.push(entry.scope, name, value, options.max_size);
                    }
                }
                None if options.depth == Depth::Zero => selection.entries.push(EntryValue {
                    entry: Entry {
                        scope: entry.scope,
                        path: Cow::Borrowed(path),
                    },
                    value: None,
                }),
                None => {}
            }
        }

        if options.depth != Depth::Zero {
            prefix.clear();
            prefix.push_str(path);
            prefix.push('/');
            for (position, name, value) in source.children(&prefix, options.depth) {
                if emitted.insert(position) {
                    selection.push(entry.scope, name, value, options.max_size);
                }
            }
        }
    }

    selection
}

