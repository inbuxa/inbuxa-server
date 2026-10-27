/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use std::{collections::hash_map::Entry, iter, net::IpAddr, sync::Arc};

const LOW_64: u128 = u64::MAX as u128;
const BLOCK_LEN: usize = 32;

pub(crate) trait RowIndex: Copy + Eq {
    const NONE: Self;

    fn index(self) -> usize;
}

impl RowIndex for u8 {
    const NONE: Self = u8::MAX;

    #[inline(always)]
    fn index(self) -> usize {
        usize::from(self)
    }
}

impl RowIndex for u16 {
    const NONE: Self = u16::MAX;

    #[inline(always)]
    fn index(self) -> usize {
        usize::from(self)
    }
}

impl RowIndex for u32 {
    const NONE: Self = u32::MAX;

    #[inline(always)]
    fn index(self) -> usize {
        self as usize
    }
}

trait RangeBound: Copy + Ord {
    fn successor(self) -> Option<Self>;
}

impl RangeBound for u32 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl RangeBound for u128 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

struct Row<B, I> {
    start: B,
    end: B,
    data: I,
}

struct Ranges<S, I> {
    block_starts: Box<[S]>,
    starts: Box<[S]>,
    data: Box<[I]>,
}

enum V6Ranges<I> {
    Prefix(Ranges<u64, I>),
    Full(Ranges<u128, I>),
}

struct RangeTable<I> {
    v4: Ranges<u32, I>,
    v6: V6Ranges<I>,
}

struct RangeRows<I> {
    v4: Vec<Row<u32, I>>,
    v6: Vec<Row<u128, I>>,
}

pub struct AsnTable {
    ranges: RangeTable<u32>,
    asns: Box<[AsnData]>,
}

pub struct CountryTable {
    ranges: CountryRanges,
    codes: Box<[Arc<str>]>,
}

enum CountryRanges {
    Narrow(RangeTable<u8>),
    Wide(RangeTable<u16>),
}

#[derive(Clone, Default, Debug)]
pub struct AsnData {
    pub id: u32,
    pub name: Option<Arc<str>>,
}

pub(crate) struct AsnBuilder {
    rows: RangeRows<u32>,
    index: AHashMap<u32, u32>,
    asns: Vec<AsnData>,
}

pub(crate) struct CountryBuilder {
    rows: RangeRows<u16>,
    index: AHashMap<[u8; 3], u16>,
    codes: Vec<Arc<str>>,
}

impl<S: Copy + Ord, I: RowIndex> Ranges<S, I> {
    fn empty() -> Self {
        Ranges {
            block_starts: Box::default(),
            starts: Box::default(),
            data: Box::default(),
        }
    }

    fn build<B: RangeBound, J: Copy>(
        rows: &[Row<B, J>],
        key: impl Fn(B) -> S,
        map: impl Fn(J) -> I,
    ) -> Self {
        let capacity = rows.len() + with_gaps(rows).filter(|(_, gap)| gap.is_some()).count();
        let mut starts = Vec::with_capacity(capacity);
        let mut data = Vec::with_capacity(capacity);
        for (row, gap) in with_gaps(rows) {
            starts.push(key(row.start));
            data.push(map(row.data));
            if let Some(gap) = gap {
                starts.push(key(gap));
                data.push(I::NONE);
            }
        }
        Ranges {
            block_starts: starts.iter().step_by(BLOCK_LEN).copied().collect(),
            starts: starts.into_boxed_slice(),
            data: data.into_boxed_slice(),
        }
    }

    #[inline(always)]
    fn lookup(&self, ip: S) -> Option<usize> {
        let block = self
            .block_starts
            .partition_point(|start| *start <= ip)
            .checked_sub(1)?;
        let pos = self
            .starts
            .chunks(BLOCK_LEN)
            .nth(block)?
            .partition_point(|start| *start <= ip);
        let data = *self.data.get(block * BLOCK_LEN + pos.checked_sub(1)?)?;
        (data != I::NONE).then(|| data.index())
    }
}

impl<I: RowIndex> RangeTable<I> {
    fn empty() -> Self {
        RangeTable {
            v4: Ranges::empty(),
            v6: V6Ranges::Prefix(Ranges::empty()),
        }
    }

    fn build<J: Copy>(rows: &RangeRows<J>, data: impl Fn(J) -> I) -> Self {
        let v4 = Ranges::build(&rows.v4, |bound| bound, &data);
        let v6 = if rows
            .v6
            .iter()
            .all(|row| row.start & LOW_64 == 0 && row.end & LOW_64 == LOW_64)
        {
            V6Ranges::Prefix(Ranges::build(&rows.v6, |bound| (bound >> 64) as u64, &data))
        } else {
            V6Ranges::Full(Ranges::build(&rows.v6, |bound| bound, &data))
        };
        RangeTable { v4, v6 }
    }

    #[inline(always)]
    fn lookup(&self, ip: IpAddr) -> Option<usize> {
        match ip {
            IpAddr::V4(ip) => self.v4.lookup(u32::from(ip)),
            IpAddr::V6(ip) => match &self.v6 {
                V6Ranges::Prefix(ranges) => ranges.lookup((u128::from(ip) >> 64) as u64),
                V6Ranges::Full(ranges) => ranges.lookup(u128::from(ip)),
            },
        }
    }
}

fn with_gaps<B: RangeBound, J>(
    rows: &[Row<B, J>],
) -> impl Iterator<Item = (&Row<B, J>, Option<B>)> {
    rows.iter()
        .zip(rows.iter().skip(1).map(Some).chain(iter::once(None)))
        .map(|(row, next)| {
            let gap = row
                .end
                .successor()
                .filter(|gap| next.is_none_or(|next| next.start > *gap));
            (row, gap)
        })
}

impl<I> RangeRows<I> {
    fn new() -> Self {
        RangeRows {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    fn insert(&mut self, from_ip: IpAddr, to_ip: IpAddr, data: I) -> bool {
        match (from_ip, to_ip) {
            (IpAddr::V4(from), IpAddr::V4(to)) if from <= to => {
                self.v4.push(Row {
                    start: u32::from(from),
                    end: u32::from(to),
                    data,
                });
                true
            }
            (IpAddr::V6(from), IpAddr::V6(to)) if from <= to => {
                self.v6.push(Row {
                    start: u128::from(from),
                    end: u128::from(to),
                    data,
                });
                true
            }
            _ => false,
        }
    }

    fn sort(&mut self) {
        self.v4.sort_unstable_by_key(|row| row.start);
        self.v6.sort_unstable_by_key(|row| row.start);
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

impl AsnBuilder {
    pub(crate) fn new() -> Self {
        AsnBuilder {
            rows: RangeRows::new(),
            index: AHashMap::new(),
            asns: Vec::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        from_ip: IpAddr,
        to_ip: IpAddr,
        asn: u32,
        name: Option<&str>,
    ) -> bool {
        let data = match self.index.entry(asn) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let Ok(data) = u32::try_from(self.asns.len()) else {
                    return false;
                };
                if data == u32::NONE {
                    return false;
                }
                self.asns.push(AsnData {
                    id: asn,
                    name: name.map(Arc::from),
                });
                *entry.insert(data)
            }
        };
        self.rows.insert(from_ip, to_ip, data)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(crate) fn build(mut self) -> AsnTable {
        self.rows.sort();
        AsnTable {
            ranges: RangeTable::build(&self.rows, |data| data),
            asns: self.asns.into_boxed_slice(),
        }
    }
}

impl CountryBuilder {
    pub(crate) fn new() -> Self {
        CountryBuilder {
            rows: RangeRows::new(),
            index: AHashMap::new(),
            codes: Vec::new(),
        }
    }

    pub(crate) fn insert(&mut self, from_ip: IpAddr, to_ip: IpAddr, code: &str) -> bool {
        let mut key = [0u8; 3];
        for (key, byte) in key.iter_mut().zip(code.bytes()) {
            *key = byte.to_ascii_uppercase();
        }
        let data = match self.index.entry(key) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let Ok(data) = u16::try_from(self.codes.len()) else {
                    return false;
                };
                if data == u16::NONE {
                    return false;
                }
                self.codes.push(code.to_uppercase().into());
                *entry.insert(data)
            }
        };
        self.rows.insert(from_ip, to_ip, data)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(crate) fn build(mut self) -> CountryTable {
        self.rows.sort();
        let ranges = if self.codes.len() < usize::from(u8::NONE) {
            CountryRanges::Narrow(RangeTable::build(&self.rows, |data| {
                u8::try_from(data).unwrap_or(u8::NONE)
            }))
        } else {
            CountryRanges::Wide(RangeTable::build(&self.rows, |data| data))
        };
        CountryTable {
            ranges,
            codes: self.codes.into_boxed_slice(),
        }
    }
}

impl AsnTable {
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnData> {
        self.asns.get(self.ranges.lookup(ip)?).cloned()
    }
}

impl Default for AsnTable {
    fn default() -> Self {
        AsnTable {
            ranges: RangeTable::empty(),
            asns: Box::default(),
        }
    }
}

impl CountryTable {
    pub fn lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        let idx = match &self.ranges {
            CountryRanges::Narrow(ranges) => ranges.lookup(ip),
            CountryRanges::Wide(ranges) => ranges.lookup(ip),
        }?;
        self.codes.get(idx).cloned()
    }
}

impl Default for CountryTable {
    fn default() -> Self {
        CountryTable {
            ranges: CountryRanges::Narrow(RangeTable::empty()),
            codes: Box::default(),
        }
    }
}

