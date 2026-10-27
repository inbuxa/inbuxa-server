/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::{base64, qp};
use mail_parser::{Encoding, MessagePart};
use std::borrow::Cow;

pub const SNIFF_WINDOW: usize = 64 * 1024;
const SNIFF_MIN: usize = 8 * 1024;
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
const OOXML_SCAN: usize = 49 + 3 * (6000 + 4 + 26) + 26 + 8;
const ZSTD_SKIPPABLE: u32 = 0x184D_2A50;
const ZSTD_SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
const HTML_SIGNATURE_LEN: usize = b"<!DOCTYPE HTML".len() + 1;
const XML_SIGNATURE_LEN: usize = b"<?xml".len();

pub enum Sniffed<'m> {
    Prefix(Cow<'m, [u8]>),
    Whole(Cow<'m, [u8]>),
}

pub trait SniffPrefix<'m> {
    fn sniff(&self) -> Sniffed<'m>;

    fn sniff_prefix(&self) -> Cow<'m, [u8]> {
        match self.sniff() {
            Sniffed::Prefix(bytes) | Sniffed::Whole(bytes) => bytes,
        }
    }
}

impl<'m> SniffPrefix<'m> for MessagePart<'m> {
    fn sniff(&self) -> Sniffed<'m> {
        let Some((window, _)) = self
            .raw_body()
            .split_at_checked(SNIFF_WINDOW)
            .filter(|(_, rest)| !rest.is_empty())
        else {
            return Sniffed::Whole(self.decoded());
        };
        let prefix = match self.encoding() {
            Encoding::None => Cow::Borrowed(window),
            Encoding::Base64 => {
                let mut decoded = Vec::with_capacity(window.len() / 4 * 3 + 3);
                base64::MIME.decode_prefix(window, &mut decoded);
                Cow::Owned(decoded)
            }
            Encoding::QuotedPrintable => {
                let lines = window
                    .iter()
                    .rposition(|&byte| byte == b'\n')
                    .and_then(|end| window.get(..=end))
                    .unwrap_or_default();
                qp::BODY.decode(lines).unwrap_or(Cow::Borrowed(lines))
            }
        };
        if is_enough_to_sniff(&prefix) {
            Sniffed::Prefix(prefix)
        } else {
            Sniffed::Whole(self.decoded())
        }
    }
}

fn is_enough_to_sniff(prefix: &[u8]) -> bool {
    let Some(&[b0, b1, b2, b3, b4, b5, b6, b7]) = prefix.first_chunk::<8>() else {
        return false;
    };
    let magic = [b0, b1, b2, b3];
    if prefix.len() < SNIFF_MIN
        || prefix.starts_with(OLE2_MAGIC)
        || u32::from_le_bytes(magic) & ZSTD_SKIPPABLE_MASK == ZSTD_SKIPPABLE
        || ([b4, b5, b6, b7] == *b"ftyp" && u32::from_be_bytes(magic) as usize > prefix.len())
    {
        false
    } else if magic == *ZIP_MAGIC {
        prefix
            .get(18..22)
            .and_then(|size| size.try_into().ok())
            .is_some_and(|size: [u8; 4]| {
                (u32::from_le_bytes(size) as usize).saturating_add(OOXML_SCAN) < prefix.len()
            })
    } else {
        let text = trim_blanks(prefix);
        text.len() >= HTML_SIGNATURE_LEN && trim_byte_order_marks(text).len() >= XML_SIGNATURE_LEN
    }
}

fn trim_blanks(bytes: &[u8]) -> &[u8] {
    let blanks = bytes
        .iter()
        .take_while(|byte| matches!(byte, 0x09 | 0x0A | 0x0C | 0x0D | 0x20))
        .count();
    bytes.get(blanks..).unwrap_or_default()
}

fn trim_byte_order_marks(mut bytes: &[u8]) -> &[u8] {
    loop {
        bytes = match bytes {
            [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
            [0xFE, 0xFF, _, ..] | [0xFF, 0xFE, _, ..] => bytes.get(2..).unwrap_or_default(),
            _ => return bytes,
        };
    }
}

