/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ArenaRef, DAV_CHUNK, DavPath, PathChunk, PathIndex};
use ahash::AHashSet;
use std::{cmp::Ordering, sync::Arc};

struct ArenaRun {
    old_start: usize,
    old_end: usize,
    new_base: usize,
}

struct ChunkWriter<'a> {
    source: &'a PathChunk,
    paths: Vec<DavPath>,
    bytes: Vec<u8>,
    run: Option<ArenaRun>,
}

impl<'a> ChunkWriter<'a> {
    fn new(source: &'a PathChunk, adds: &[(String, DavPath)]) -> Self {
        Self {
            source,
            paths: Vec::with_capacity(source.paths.len() + adds.len()),
            bytes: Vec::with_capacity(
                source.bytes.len() + adds.iter().map(|(name, _)| name.len()).sum::<usize>(),
            ),
            run: None,
        }
    }

    fn keep(&mut self, path: &DavPath) {
        let range = path.path.range();
        let (old_start, new_base) = match &mut self.run {
            Some(run) if run.old_end == range.start => {
                run.old_end = range.end;
                (run.old_start, run.new_base)
            }
            _ => {
                self.flush();
                let new_base = self.bytes.len();
                self.run = Some(ArenaRun {
                    old_start: range.start,
                    old_end: range.end,
                    new_base,
                });
                (range.start, new_base)
            }
        };
        self.paths.push(DavPath {
            path: ArenaRef {
                off: (new_base + (range.start - old_start)) as u32,
                len: path.path.len,
            },
            ..*path
        });
    }

    fn insert(&mut self, name: &str, path: &DavPath) {
        self.flush();
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(name.as_bytes());
        self.paths.push(DavPath {
            path: ArenaRef {
                off,
                len: name.len() as u32,
            },
            ..*path
        });
    }

    fn flush(&mut self) {
        if let Some(run) = self.run.take() {
            self.bytes
                .extend_from_slice(&self.source.bytes[run.old_start..run.old_end]);
        }
    }

    fn finish(mut self) -> Vec<Arc<PathChunk>> {
        self.flush();
        PathChunk::from_contiguous(self.paths, self.bytes)
    }
}

impl PathChunk {
    fn from_contiguous(paths: Vec<DavPath>, bytes: Vec<u8>) -> Vec<Arc<PathChunk>> {
        if paths.is_empty() {
            Vec::new()
        } else if paths.len() <= 2 * DAV_CHUNK {
            vec![Arc::new(PathChunk {
                paths: paths.into_boxed_slice(),
                bytes: bytes.into_boxed_slice(),
            })]
        } else {
            paths
                .chunks(DAV_CHUNK)
                .map(|group| {
                    let start = group[0].path.off as usize;
                    let end = group[group.len() - 1].path.range().end;
                    let paths = group
                        .iter()
                        .map(|path| DavPath {
                            path: ArenaRef {
                                off: path.path.off - start as u32,
                                len: path.path.len,
                            },
                            ..*path
                        })
                        .collect::<Vec<_>>();
                    Arc::new(PathChunk {
                        paths: paths.into_boxed_slice(),
                        bytes: bytes[start..end].to_vec().into_boxed_slice(),
                    })
                })
                .collect()
        }
    }

    fn splice(&self, removed_slots: &[usize], adds: &[(String, DavPath)]) -> Vec<Arc<PathChunk>> {
        let mut writer = ChunkWriter::new(self, adds);
        let mut next_removed = 0usize;
        let mut next_add = 0usize;

        'paths: for (slot, path) in self.paths.iter().enumerate() {
            if removed_slots.get(next_removed) == Some(&slot) {
                next_removed += 1;
                continue;
            }
            let name = &self.bytes[path.path.range()];
            while let Some((add_name, add_path)) = adds.get(next_add) {
                match add_name.as_bytes().cmp(name) {
                    Ordering::Less => {
                        writer.insert(add_name, add_path);
                        next_add += 1;
                    }
                    Ordering::Equal => {
                        next_add += 1;
                        if add_path.document_id < path.document_id {
                            writer.insert(add_name, add_path);
                            continue 'paths;
                        }
                        break;
                    }
                    Ordering::Greater => break,
                }
            }
            writer.keep(path);
        }

        for (add_name, add_path) in &adds[next_add..] {
            writer.insert(add_name, add_path);
        }

        writer.finish()
    }

    #[inline(always)]
    pub fn path_at(&self, idx: usize) -> &str {
        self.path_str(&self.paths[idx])
    }

    #[inline(always)]
    pub fn path_str(&self, path: &DavPath) -> &str {
        std::str::from_utf8(self.path_bytes(path)).unwrap_or_default()
    }

    #[inline(always)]
    pub fn path_bytes(&self, path: &DavPath) -> &[u8] {
        &self.bytes[path.path.range()]
    }

    #[inline(always)]
    fn first_path_bytes(&self) -> &[u8] {
        self.path_bytes(&self.paths[0])
    }

    #[inline(always)]
    pub fn first_path(&self) -> &str {
        self.path_at(0)
    }

    #[inline(always)]
    pub fn last_path(&self) -> &str {
        self.path_at(self.paths.len() - 1)
    }

    pub fn heap_size(&self) -> u64 {
        (self.paths.len() * std::mem::size_of::<DavPath>()
            + self.bytes.len()
            + std::mem::size_of::<PathChunk>()) as u64
    }
}

impl PathIndex {
    fn entry_order(a: &(String, DavPath), b: &(String, DavPath)) -> Ordering {
        a.0.as_bytes()
            .cmp(b.0.as_bytes())
            .then_with(|| a.1.document_id.cmp(&b.1.document_id))
    }

    fn sort_entries(entries: &mut Vec<(String, DavPath)>) {
        entries.sort_unstable_by(Self::entry_order);
        entries.dedup_by(|a, b| a.0 == b.0);
    }

    pub fn pack(mut entries: Vec<(String, DavPath)>) -> Self {
        Self::sort_entries(&mut entries);

        let total = entries.len();
        let mut chunks = Vec::with_capacity(total.div_ceil(DAV_CHUNK).max(1));
        for group in entries.chunks(DAV_CHUNK) {
            let mut bytes: Vec<u8> = Vec::with_capacity(group.len() * 48);
            let mut paths = Vec::with_capacity(group.len());
            for (name, path) in group {
                let off = bytes.len() as u32;
                bytes.extend_from_slice(name.as_bytes());
                paths.push(DavPath {
                    path: ArenaRef {
                        off,
                        len: name.len() as u32,
                    },
                    ..*path
                });
            }
            chunks.push(Arc::new(PathChunk {
                paths: paths.into_boxed_slice(),
                bytes: bytes.into_boxed_slice(),
            }));
        }

        Self { chunks, total }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.total
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PathChunk, &DavPath)> + '_ {
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.paths.iter().map(move |path| (chunk.as_ref(), path)))
    }

    fn chunk_for(&self, key: &[u8]) -> usize {
        let mut lo = 0usize;
        let mut hi = self.chunks.len();
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.chunks[mid].first_path_bytes() <= key {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn locate(&self, name: &str) -> Option<(usize, usize)> {
        if self.chunks.is_empty() {
            return None;
        }
        let key = name.as_bytes();
        let idx = self.chunk_for(key);
        let chunk = &self.chunks[idx];
        chunk
            .paths
            .binary_search_by(|probe| chunk.path_bytes(probe).cmp(key))
            .ok()
            .map(|slot| (idx, slot))
    }

    pub fn get(&self, name: &str) -> Option<(&PathChunk, &DavPath)> {
        self.locate(name).map(|(idx, slot)| {
            let chunk = &self.chunks[idx];
            (chunk.as_ref(), &chunk.paths[slot])
        })
    }

    fn lower_bound(&self, key: &[u8]) -> (usize, usize) {
        if self.chunks.is_empty() {
            return (0, 0);
        }
        let idx = self.chunk_for(key);
        let chunk = &self.chunks[idx];
        let slot = chunk
            .paths
            .partition_point(|probe| chunk.path_bytes(probe) < key);
        if slot < chunk.paths.len() {
            (idx, slot)
        } else {
            (idx + 1, 0)
        }
    }

    pub fn range(&self, prefix: String) -> impl Iterator<Item = (&PathChunk, &DavPath)> + '_ {
        let (start_chunk, start_slot) = self.lower_bound(prefix.as_bytes());
        self.chunks
            .iter()
            .skip(start_chunk)
            .enumerate()
            .flat_map(move |(offset, chunk)| {
                chunk
                    .paths
                    .iter()
                    .skip(if offset == 0 { start_slot } else { 0 })
                    .map(move |path| (chunk.as_ref(), path))
            })
            .take_while(move |(chunk, path)| chunk.path_bytes(path).starts_with(prefix.as_bytes()))
    }

    pub fn heap_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.heap_size()).sum()
    }

    pub fn patch(&self, removes: &AHashSet<String>, mut adds: Vec<(String, DavPath)>) -> Self {
        if removes.is_empty() && adds.is_empty() {
            return self.clone();
        }

        if self.chunks.is_empty() {
            return PathIndex::pack(adds);
        }

        Self::sort_entries(&mut adds);

        let mut removed: Vec<(usize, usize)> =
            removes.iter().filter_map(|key| self.locate(key)).collect();
        removed.sort_unstable();

        let mut chunks = Vec::with_capacity(self.chunks.len() + 2);
        let mut total = 0usize;
        let mut add_start = 0usize;
        let mut removed_start = 0usize;

        for (idx, chunk) in self.chunks.iter().enumerate() {
            let add_end = match self.chunks.get(idx + 1) {
                Some(next) => {
                    let bound = next.first_path_bytes();
                    add_start
                        + adds[add_start..].partition_point(|(name, _)| name.as_bytes() < bound)
                }
                None => adds.len(),
            };
            let removed_end = removed_start
                + removed[removed_start..].partition_point(|(target, _)| *target <= idx);

            if add_start == add_end && removed_start == removed_end {
                total += chunk.paths.len();
                chunks.push(Arc::clone(chunk));
                continue;
            }

            let removed_slots = removed[removed_start..removed_end]
                .iter()
                .map(|(_, slot)| *slot)
                .collect::<Vec<_>>();
            for piece in chunk.splice(&removed_slots, &adds[add_start..add_end]) {
                total += piece.paths.len();
                chunks.push(piece);
            }

            add_start = add_end;
            removed_start = removed_end;
        }

        Self { chunks, total }
    }
}

