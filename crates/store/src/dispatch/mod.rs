/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Store;
use roaring::RoaringBitmap;

pub mod blob;
pub mod lookup;
pub mod search;
pub mod store;


#[cfg(stalwart_tests)]
pub use ops::{CommitFailureGuard, Latency, LatencyGuard, OpsSnapshot, StoreOps, SubspaceOps};


#[cfg(stalwart_tests)]
pub use rocksdb_skips::RocksDbSkips;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanGap {
    gap: u32,
    ratio: u32,
}

pub const POINT_SCAN_GAP: ScanGap = ScanGap::new(0, 2);
pub const MAX_SCAN_GAP: ScanGap = ScanGap::new(8, 64);
pub const ROCKSDB_SCAN_GAP: ScanGap = ScanGap::new(8, 17);
const MAX_RANGES_RESERVE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum ScanShape {
    Range(u32, u32),
    Ranges(Vec<(u32, u32)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadShape {
    Ranges(ScanGap),
    Keys,
}

impl Store {
    pub fn id(&self) -> &'static str {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(_) => "sqlite",
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => "foundationdb",
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => "postgresql",
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => "mysql",
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => "rocksdb",
            Self::Ephemeral(_) => "ephemeral",
            Self::None => "none",
        }
    }

    pub fn scan_gap(&self) -> ScanGap {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => POINT_SCAN_GAP,
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => POINT_SCAN_GAP,
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => ROCKSDB_SCAN_GAP,
            _ => MAX_SCAN_GAP,
        }
    }

    pub fn read_shape(&self) -> ReadShape {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => ReadShape::Keys,
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => ReadShape::Keys,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => ReadShape::Ranges(POINT_SCAN_GAP),
            _ => ReadShape::Ranges(self.scan_gap()),
        }
    }
}

impl ScanGap {
    pub const fn new(gap: u32, ratio: u32) -> Self {
        assert!(ratio > gap, "the scan ratio must exceed the gap");
        ScanGap { gap, ratio }
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait DocumentSet: Sync + Send {
    fn min(&self) -> u32;
    fn max(&self) -> u32;
    fn contains(&self, id: u32) -> bool;
    fn len(&self) -> usize;
    fn iterate(&self) -> impl Iterator<Item = u32>;

    fn is_dense(&self, gap: ScanGap) -> bool {
        self.len() as u64 * u64::from(gap.ratio) >= u64::from(self.max() - self.min())
    }

    fn scan_shape(&self, gap: ScanGap) -> ScanShape {
        let min = self.min();
        let max = self.max();
        if self.len() == 0 || self.is_dense(gap) {
            return ScanShape::Range(min, max);
        }

        let ranges = self.scan_ranges(gap);
        match ranges.as_slice() {
            [] => ScanShape::Range(min, max),
            &[(from, to)] => ScanShape::Range(from, to),
            _ => ScanShape::Ranges(ranges),
        }
    }

    fn scan_ranges(&self, gap: ScanGap) -> Vec<(u32, u32)> {
        if self.len() == 0 {
            return Vec::new();
        }
        if self.is_dense(gap) {
            let min = self.min();
            return vec![(min, self.max().saturating_sub(1).max(min))];
        }

        let mut ids = self.iterate();
        let Some(first) = ids.next() else {
            return Vec::new();
        };
        let mut ranges = Vec::with_capacity(self.len().min(MAX_RANGES_RESERVE));
        let mut range = (first, first);
        for id in ids {
            if id - range.1 <= gap.gap {
                range.1 = id;
            } else {
                ranges.push(range);
                range = (id, id);
            }
        }
        ranges.push(range);
        ranges
    }
}

impl DocumentSet for RoaringBitmap {
    fn min(&self) -> u32 {
        self.min().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.max().map(|m| m + 1).unwrap_or(0)
    }

    fn contains(&self, id: u32) -> bool {
        self.contains(id)
    }

    fn len(&self) -> usize {
        self.len() as usize
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter()
    }
}

impl DocumentSet for u32 {
    fn min(&self) -> u32 {
        *self
    }

    fn max(&self) -> u32 {
        self.saturating_add(1)
    }

    fn contains(&self, id: u32) -> bool {
        *self == id
    }

    fn len(&self) -> usize {
        1
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        std::iter::once(*self)
    }
}

impl DocumentSet for Vec<u32> {
    fn contains(&self, id: u32) -> bool {
        self.binary_search(&id).is_ok()
    }

    fn min(&self) -> u32 {
        self.first().copied().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.last().copied().map(|m| m + 1).unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter().copied()
    }
}

impl DocumentSet for () {
    fn min(&self) -> u32 {
        0
    }

    fn max(&self) -> u32 {
        u32::MAX
    }

    fn contains(&self, _: u32) -> bool {
        true
    }

    fn len(&self) -> usize {
        0
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        std::iter::empty()
    }

    fn scan_ranges(&self, _: ScanGap) -> Vec<(u32, u32)> {
        vec![(0, u32::MAX)]
    }
}

