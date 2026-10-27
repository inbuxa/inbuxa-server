/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::code::{Code, MAX_CODE_LEN};
use crate::pdf::tables::{CmapDecoder, PredefinedCmap};
use encoding_rs::{BIG5, EUC_JP, EUC_KR, Encoding, GB18030, GBK, SHIFT_JIS};

const JIS_HIGH_BIT: u8 = 0x80;

impl PredefinedCmap {
    pub(crate) fn is_text_encoding(self) -> bool {
        !matches!(self.decoder(), CmapDecoder::Identity | CmapDecoder::EucTw)
    }

    pub(crate) fn decode(self, code: Code, out: &mut String) -> bool {
        let mut bytes = [0u8; MAX_CODE_LEN];
        let mut len = 0;
        for (slot, byte) in bytes.iter_mut().zip(code.bytes()) {
            *slot = byte;
            len += 1;
        }
        let bytes = bytes.get(..len).unwrap_or_default();
        let mark = out.len();
        match self.decoder() {
            CmapDecoder::Identity | CmapDecoder::EucTw => return false,
            CmapDecoder::Utf16Be => {
                let (units, _) = bytes.as_chunks::<2>();
                for ch in char::decode_utf16(units.iter().map(|pair| u16::from_be_bytes(*pair))) {
                    match ch {
                        Ok(ch) => out.push(ch),
                        Err(_) => {
                            out.truncate(mark);
                            return false;
                        }
                    }
                }
            }
            CmapDecoder::Utf8 => match std::str::from_utf8(bytes) {
                Ok(text) => out.push_str(text),
                Err(_) => return false,
            },
            CmapDecoder::Utf32Be => match char::from_u32(code.value) {
                Some(ch) => out.push(ch),
                None => return false,
            },
            CmapDecoder::JisRowCell => {
                let mut shifted = [0u8; MAX_CODE_LEN];
                for (slot, byte) in shifted.iter_mut().zip(bytes) {
                    *slot = byte | JIS_HIGH_BIT;
                }
                return legacy(EUC_JP, shifted.get(..bytes.len()).unwrap_or_default(), out);
            }
            decoder => {
                if let [byte] = bytes
                    && let Some(ch) = self.single_byte(*byte)
                {
                    out.push(ch);
                    return true;
                }
                let encoding = match decoder {
                    CmapDecoder::Gbk => GBK,
                    CmapDecoder::Gb18030 => GB18030,
                    CmapDecoder::Big5 => BIG5,
                    CmapDecoder::ShiftJis => SHIFT_JIS,
                    CmapDecoder::EucJp => EUC_JP,
                    _ => EUC_KR,
                };
                return legacy(encoding, bytes, out);
            }
        }
        out.len() > mark
    }
}

fn legacy(encoding: &'static Encoding, bytes: &[u8], out: &mut String) -> bool {
    match encoding.decode_without_bom_handling_and_without_replacement(bytes) {
        Some(text) if !text.is_empty() => {
            out.push_str(&text);
            true
        }
        _ => false,
    }
}

