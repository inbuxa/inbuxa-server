/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use simdutf8::basic::from_utf8;
use std::fmt::{self, Write};

const MAX_DIGITS: usize = 20;
const DIRECT_WRITE_LEN: usize = 256;

trait CopyShort {
    fn copy_short_from(&mut self, src: &[u8]);
}

impl CopyShort for [u8] {
    #[inline(always)]
    fn copy_short_from(&mut self, src: &[u8]) {
        match src.len() {
            0 => {}
            len @ 1..=3 => {
                for pos in [0, len / 2, len - 1] {
                    if let (Some(dst), Some(src)) = (self.get_mut(pos), src.get(pos)) {
                        *dst = *src;
                    }
                }
            }
            4..=7 => {
                if let (Some(dst), Some(src)) =
                    (self.first_chunk_mut::<4>(), src.first_chunk::<4>())
                {
                    *dst = *src;
                }
                if let (Some(dst), Some(src)) = (self.last_chunk_mut::<4>(), src.last_chunk::<4>())
                {
                    *dst = *src;
                }
            }
            8..=16 => {
                if let (Some(dst), Some(src)) =
                    (self.first_chunk_mut::<8>(), src.first_chunk::<8>())
                {
                    *dst = *src;
                }
                if let (Some(dst), Some(src)) = (self.last_chunk_mut::<8>(), src.last_chunk::<8>())
                {
                    *dst = *src;
                }
            }
            17..=32 => {
                if let (Some(dst), Some(src)) =
                    (self.first_chunk_mut::<16>(), src.first_chunk::<16>())
                {
                    *dst = *src;
                }
                if let (Some(dst), Some(src)) =
                    (self.last_chunk_mut::<16>(), src.last_chunk::<16>())
                {
                    *dst = *src;
                }
            }
            33..=64 => {
                if let (Some(dst), Some(src)) =
                    (self.first_chunk_mut::<32>(), src.first_chunk::<32>())
                {
                    *dst = *src;
                }
                if let (Some(dst), Some(src)) =
                    (self.last_chunk_mut::<32>(), src.last_chunk::<32>())
                {
                    *dst = *src;
                }
            }
            65..=128 => {
                if let (Some(dst), Some(src)) =
                    (self.first_chunk_mut::<64>(), src.first_chunk::<64>())
                {
                    *dst = *src;
                }
                if let (Some(dst), Some(src)) =
                    (self.last_chunk_mut::<64>(), src.last_chunk::<64>())
                {
                    *dst = *src;
                }
            }
            _ => self.copy_from_slice(src),
        }
    }
}

pub(crate) trait AsciiPush {
    fn push_ascii(&mut self, bytes: &[u8]) -> fmt::Result;

    #[inline(always)]
    fn push_ascii_str(&mut self, text: &'static str) -> fmt::Result {
        self.push_ascii(text.as_bytes())
    }

    #[inline(always)]
    fn push_byte(&mut self, ch: u8) -> fmt::Result {
        self.push_ascii(&[ch])
    }

    #[inline(always)]
    fn push_u64(&mut self, value: u64) -> fmt::Result {
        if value < 10 {
            self.push_digits::<1>(value)
        } else {
            self.push_digits::<2>(value)
        }
    }

    #[inline(always)]
    fn push_i64(&mut self, value: i64) -> fmt::Result {
        if value < 0 {
            self.push_byte(b'-')?;
        }
        self.push_u64(value.unsigned_abs())
    }

    #[inline(always)]
    fn push_2_digits(&mut self, value: u8) -> fmt::Result {
        self.push_digits::<2>(value.into())
    }

    #[inline(always)]
    fn push_4_digits(&mut self, value: u16) -> fmt::Result {
        self.push_digits::<4>(value.into())
    }

    #[inline(always)]
    fn push_digits<const WIDTH: usize>(&mut self, value: u64) -> fmt::Result {
        match u32::try_from(value) {
            Ok(value) if value < 10u32.pow(WIDTH as u32) => {
                let mut digits = [b'0'; WIDTH];
                for (place, digit) in digits.iter_mut().rev().enumerate() {
                    *digit += (value / 10u32.pow(place as u32) % 10) as u8;
                }
                self.push_ascii(&digits)
            }
            _ => self.push_padded(value, WIDTH),
        }
    }

    fn push_padded(&mut self, value: u64, width: usize) -> fmt::Result {
        let mut digits = [b'0'; MAX_DIGITS];
        let mut rest = value;
        let mut count = 0;
        for slot in digits.iter_mut().rev() {
            *slot = b'0' + (rest % 10) as u8;
            rest /= 10;
            count += 1;
            if rest == 0 {
                break;
            }
        }
        let start = MAX_DIGITS - count.max(width).min(MAX_DIGITS);
        self.push_ascii(digits.get(start..).unwrap_or_default())
    }

    fn push_list<T>(
        &mut self,
        name: &'static str,
        items: &[T],
        mut push_item: impl FnMut(&mut Self, &T) -> fmt::Result,
    ) -> fmt::Result
    where
        Self: Sized,
    {
        for (pos, item) in items.iter().enumerate() {
            self.push_ascii_str(if pos == 0 { name } else { "," })?;
            push_item(self, item)?;
        }
        Ok(())
    }

    fn push_duration(&mut self, duration: DurationParts) -> fmt::Result {
        let DurationParts {
            neg,
            weeks,
            days,
            hours,
            minutes,
            seconds,
        } = duration;
        self.push_ascii(if neg { b"-P" } else { b"P" })?;
        if weeks == 0 && days == 0 && hours == 0 && minutes == 0 && seconds == 0 {
            return self.push_ascii(b"T0S");
        }
        for (value, unit) in [(weeks, b'W'), (days, b'D')] {
            if value != 0 {
                self.push_u64(value.into())?;
                self.push_byte(unit)?;
            }
        }
        if hours != 0 || minutes != 0 || seconds != 0 {
            self.push_byte(b'T')?;
            for (value, unit) in [(hours, b'H'), (minutes, b'M'), (seconds, b'S')] {
                if value != 0 {
                    self.push_u64(value.into())?;
                    self.push_byte(unit)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct BufferedWriter<'x, W: Write + ?Sized, const N: usize> {
    out: &'x mut W,
    len: usize,
    buf: [u8; N],
}

impl<'x, W: Write + ?Sized, const N: usize> BufferedWriter<'x, W, N> {
    #[inline(always)]
    pub(crate) fn new(out: &'x mut W) -> Self {
        Self {
            out,
            len: 0,
            buf: [0; N],
        }
    }

    pub(crate) fn flush(&mut self) -> fmt::Result {
        if self.len > 0 {
            let text = self
                .buf
                .get(..self.len)
                .and_then(|bytes| from_utf8(bytes).ok())
                .ok_or(fmt::Error)?;
            self.out.write_str(text)?;
            self.len = 0;
        }
        Ok(())
    }

    #[inline(always)]
    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        if bytes.len() < DIRECT_WRITE_LEN
            && let Some(slot) = self.buf.get_mut(self.len..self.len + bytes.len())
        {
            slot.copy_short_from(bytes);
            self.len += bytes.len();
            Some(())
        } else {
            None
        }
    }

    #[inline(never)]
    fn write_str_after_flush(&mut self, text: &str) -> fmt::Result {
        self.flush()?;
        match self.buf.get_mut(..text.len()) {
            Some(slot) if text.len() < DIRECT_WRITE_LEN => {
                slot.copy_from_slice(text.as_bytes());
                self.len = text.len();
                Ok(())
            }
            _ => self.out.write_str(text),
        }
    }

    #[inline(never)]
    fn push_ascii_after_flush(&mut self, bytes: &[u8]) -> fmt::Result {
        self.write_str_after_flush(str::from_utf8(bytes).map_err(|_| fmt::Error)?)
    }
}

impl<W: Write + ?Sized, const N: usize> AsciiPush for BufferedWriter<'_, W, N> {
    #[inline(always)]
    fn push_ascii(&mut self, bytes: &[u8]) -> fmt::Result {
        match self.push_bytes(bytes) {
            Some(()) => Ok(()),
            None => self.push_ascii_after_flush(bytes),
        }
    }
}

impl<W: Write + ?Sized, const N: usize> Write for BufferedWriter<'_, W, N> {
    #[inline(always)]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        match self.push_bytes(text.as_bytes()) {
            Some(()) => Ok(()),
            None => self.write_str_after_flush(text),
        }
    }
}

impl AsciiPush for String {
    fn push_ascii(&mut self, bytes: &[u8]) -> fmt::Result {
        self.push_str(str::from_utf8(bytes).map_err(|_| fmt::Error)?);
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DurationParts {
    pub neg: bool,
    pub weeks: u32,
    pub days: u32,
    pub hours: u32,
    pub minutes: u32,
    pub seconds: u32,
}

pub(crate) trait BufferedWrite: Write {
    fn write_buffered<const N: usize>(
        &mut self,
        push: impl FnOnce(&mut BufferedWriter<'_, Self, N>) -> fmt::Result,
    ) -> fmt::Result {
        let mut buf = BufferedWriter::new(self);
        push(&mut buf)?;
        buf.flush()
    }
}

impl<W: Write + ?Sized> BufferedWrite for W {}

