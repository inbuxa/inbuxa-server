/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod kernel;

use std::ops::Deref;

mod sealed {
    pub trait Sealed: Copy {
        const MAX_LEN: usize;

        fn widen(self) -> u64;
        fn narrow(value: u64) -> Option<Self>;
    }
}

use sealed::Sealed;

pub trait Leb128: Sealed {
    #[inline(always)]
    fn leb128_len(self) -> usize {
        kernel::encoded_len(self.widen())
    }

    #[inline(always)]
    fn to_leb128(self) -> Leb128Bytes {
        Leb128Bytes::new(self.widen())
    }

    #[inline(always)]
    fn from_leb128(bytes: &[u8]) -> Option<(Self, usize)> {
        let (value, len) = kernel::decode(bytes, Self::MAX_LEN)?;
        Self::narrow(value).map(|value| (value, len))
    }

    #[inline(always)]
    fn from_leb128_wide(bytes: &[u8]) -> Option<(Self, usize)> {
        let (value, len) = kernel::decode_wide(bytes, Self::MAX_LEN)?;
        Self::narrow(value).map(|value| (value, len))
    }
}

pub trait Leb128Writer {
    fn push_leb128<T: Leb128>(&mut self, value: T);
}

pub trait Leb128Reader {
    fn read_leb128<T: Leb128>(&mut self) -> Option<T>;
    fn read_leb128_wide<T: Leb128>(&mut self) -> Option<T>;
    fn skip_leb128(&mut self, count: usize) -> Option<()>;
}

pub trait Leb128Iterator: Iterator<Item = u8> {
    #[inline]
    fn next_leb128<T: Leb128>(&mut self) -> Option<T> {
        let mut value = 0u64;
        for (shift, byte) in (0..T::MAX_LEN).map(|index| index * 7).zip(self) {
            let bits = u64::from(byte & 0x7F);
            if (bits << shift) >> shift != bits {
                return None;
            }
            value |= bits << shift;
            if byte < 0x80 {
                return T::narrow(value);
            }
        }
        None
    }
}

impl<I: Iterator<Item = u8>> Leb128Iterator for I {}

impl Leb128Writer for Vec<u8> {
    #[inline(always)]
    fn push_leb128<T: Leb128>(&mut self, value: T) {
        kernel::push(self, value.widen());
    }
}

impl Leb128Reader for &[u8] {
    #[inline(always)]
    fn read_leb128<T: Leb128>(&mut self) -> Option<T> {
        let (value, len) = T::from_leb128(self)?;
        *self = self.get(len..)?;
        Some(value)
    }

    #[inline(always)]
    fn read_leb128_wide<T: Leb128>(&mut self) -> Option<T> {
        let (value, len) = T::from_leb128_wide(self)?;
        *self = self.get(len..)?;
        Some(value)
    }

    #[inline]
    fn skip_leb128(&mut self, count: usize) -> Option<()> {
        *self = self.get(kernel::skip(self, count)?..)?;
        Some(())
    }
}

#[derive(Clone, Copy)]
pub struct Leb128Bytes {
    bytes: [u8; 16],
    len: usize,
}

impl Leb128Bytes {
    #[inline(always)]
    fn new(value: u64) -> Self {
        let (low, high, len) = kernel::encode(value);
        Leb128Bytes {
            bytes: ((u128::from(high) << 64) | u128::from(low)).to_le_bytes(),
            len,
        }
    }
}

impl Deref for Leb128Bytes {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for Leb128Bytes {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

macro_rules! impl_leb128 {
    ($($ty:ty),+) => {$(
        impl Sealed for $ty {
            const MAX_LEN: usize = <$ty>::BITS.div_ceil(7) as usize;

            #[inline(always)]
            fn widen(self) -> u64 {
                self as u64
            }

            #[inline(always)]
            fn narrow(value: u64) -> Option<Self> {
                <$ty>::try_from(value).ok()
            }
        }

        impl Leb128 for $ty {}
    )+};
}

impl_leb128!(u8, u16, u32, u64, usize);
