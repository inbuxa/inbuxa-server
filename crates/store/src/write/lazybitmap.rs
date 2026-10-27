/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::{RoaringBitmap, RoaringTreemap};
use utils::codec::leb128::{Leb128Iterator, Leb128Writer};

const IS_ROARING: u8 = 1;

pub(crate) struct LazyBitmap(pub RoaringBitmap);
pub(crate) struct LazyTreemap(pub RoaringTreemap);

impl LazyBitmap {
    pub fn serialize_optimized(&mut self, block_base: u32) -> Vec<u8> {
        self.0.optimize();
        let roaring_size = self.0.serialized_size();

        if roaring_size <= self.0.len() as usize {
            return self.serialize_roaring(roaring_size);
        }

        let delta = self.serialize_delta(block_base);
        if roaring_size + 1 < delta.len() {
            self.serialize_roaring(roaring_size)
        } else {
            delta
        }
    }

    fn serialize_roaring(&self, roaring_size: usize) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(roaring_size + 1);
        serialized.push(IS_ROARING);
        let _ = self.0.serialize_into(&mut serialized);
        serialized
    }

    fn serialize_delta(&self, mut delta: u32) -> Vec<u8> {
        let mut serialized = Vec::with_capacity((self.0.len() as usize * 2) + 1);
        serialized.push(0);
        for id in self.0.iter() {
            serialized.push_leb128(id - delta);
            delta = id;
        }
        serialized
    }

    pub fn deserialize_delta(bytes: &[u8], mut delta: u32) -> trc::Result<Self> {
        let Some((is_roaring, bytes)) = bytes
            .split_at_checked(1)
            .map(|(byte, bytes)| (byte == [IS_ROARING], bytes))
        else {
            return Err(trc::Error::corrupted_key(bytes, None, trc::location!()));
        };

        if is_roaring {
            RoaringBitmap::deserialize_from(bytes)
                .ok()
                .map(Self)
                .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))
        } else {
            let mut bitmap = RoaringBitmap::new();
            let mut iter = bytes.iter().copied();

            while let Some(delta_id) = iter.next_leb128::<u32>() {
                delta = delta
                    .checked_add(delta_id)
                    .filter(|delta| bitmap.try_push(*delta).is_ok())
                    .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))?;
            }

            if iter.next().is_none() {
                Ok(Self(bitmap))
            } else {
                Err(trc::Error::corrupted_key(bytes, None, trc::location!()))
            }
        }
    }
}

impl LazyTreemap {
    pub fn serialize_delta(&self, mut delta: u64) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(self.0.len() as usize * 8);
        for id in self.0.iter() {
            serialized.push_leb128(id - delta);
            delta = id;
        }
        serialized
    }

    pub fn deserialize_delta(bytes: &[u8], mut delta: u64) -> trc::Result<Self> {
        let mut treemap = RoaringTreemap::new();
        let mut iter = bytes.iter().copied();

        while let Some(delta_id) = iter.next_leb128::<u64>() {
            delta = delta
                .checked_add(delta_id)
                .filter(|delta| treemap.try_push(*delta).is_ok())
                .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))?;
        }

        if iter.next().is_none() {
            Ok(Self(treemap))
        } else {
            Err(trc::Error::corrupted_key(bytes, None, trc::location!()))
        }
    }
}

impl AsRef<RoaringBitmap> for LazyBitmap {
    fn as_ref(&self) -> &RoaringBitmap {
        &self.0
    }
}

