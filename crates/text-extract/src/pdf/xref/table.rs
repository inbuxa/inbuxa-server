/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Builder, Entry, NO_SLOT};
use crate::pdf::{
    lexer::{Lexer, Token},
    object::{Dict, Object},
};

const MIN_ENTRY_BYTES: usize = 18;
const FREE_HEAD_GEN: i64 = 65535;

enum Flag {
    Used,
    Free,
}

pub(super) fn read_table<'a>(
    data: &'a [u8],
    pos: usize,
    builder: &mut Builder<'_>,
    section: u16,
) -> Option<Dict<'a>> {
    let mut lexer = Lexer::at(data, pos);
    let mut current = 0u64;
    let mut first_subsection = true;
    loop {
        let before = lexer.pos();
        match lexer.next()? {
            Token::Keyword(b"trailer") => {
                return Object::read(&mut lexer, None).and_then(|object| object.as_dict());
            }
            Token::Int(first) => {
                let Token::Int(second) = lexer.next()? else {
                    return None;
                };
                if let Some(flag) = flag(&lexer) {
                    lexer.next();
                    emit(builder, current, first, second, flag, section);
                    current = current.saturating_add(1);
                    continue;
                }
                let Ok(start) = u64::try_from(first) else {
                    return None;
                };
                let room = data.len().saturating_sub(lexer.pos()) / MIN_ENTRY_BYTES + 1;
                let count = usize::try_from(second).unwrap_or(0).min(room);
                current = start;
                for index in 0..count {
                    let mut probe = lexer;
                    let (Some(Token::Int(offset)), Some(Token::Int(generation))) =
                        (probe.next(), probe.next())
                    else {
                        break;
                    };
                    lexer = probe;
                    let flag = match flag(&lexer) {
                        Some(flag) => {
                            lexer.next();
                            flag
                        }
                        None => Flag::Free,
                    };
                    if first_subsection
                        && index == 0
                        && start == 1
                        && offset == 0
                        && generation == FREE_HEAD_GEN
                        && matches!(flag, Flag::Free)
                    {
                        current = 0;
                    }
                    emit(builder, current, offset, generation, flag, section);
                    current = current.saturating_add(1);
                }
                first_subsection = false;
            }
            _ => {
                lexer.set_pos(before);
                return None;
            }
        }
    }
}

fn flag(lexer: &Lexer<'_>) -> Option<Flag> {
    match lexer.peek()? {
        Token::Keyword(b"n" | b"N") => Some(Flag::Used),
        Token::Keyword(b"f" | b"F") => Some(Flag::Free),
        Token::Keyword(word) if word.len() == 1 => Some(Flag::Free),
        _ => None,
    }
}

fn emit(
    builder: &mut Builder<'_>,
    num: u64,
    offset: i64,
    generation: i64,
    flag: Flag,
    section: u16,
) {
    let offset = u32::try_from(offset).ok().filter(|&offset| offset > 0);
    let entry = match (flag, offset) {
        (Flag::Used, Some(offset)) => Entry::Offset {
            offset,
            generation: u16::try_from(generation.clamp(0, i64::from(u16::MAX))).unwrap_or(u16::MAX),
            slot: NO_SLOT,
        },
        _ => Entry::Free { section },
    };
    builder.merge(num, entry, section);
}

