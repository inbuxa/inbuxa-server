/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Name, ObjRef, Object};
use crate::pdf::lexer::{Lexer, Token};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Array<'a> {
    body: &'a [u8],
    owner: Option<ObjRef>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Dict<'a> {
    body: &'a [u8],
    owner: Option<ObjRef>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ArrayIter<'a> {
    lexer: Lexer<'a>,
    owner: Option<ObjRef>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DictIter<'a> {
    lexer: Lexer<'a>,
    owner: Option<ObjRef>,
}

pub(super) fn skip<'a>(lexer: &mut Lexer<'a>) -> &'a [u8] {
    skip_container(lexer).0
}

pub(crate) fn skip_container<'a>(lexer: &mut Lexer<'a>) -> (&'a [u8], bool) {
    let data = lexer.data();
    let start = lexer.pos();
    let mut depth = 1usize;
    loop {
        let before = lexer.pos();
        let Some(token) = lexer.next() else {
            return (data.get(start..).unwrap_or_default(), false);
        };
        match token {
            Token::ArrayOpen | Token::DictOpen => depth += 1,
            Token::ArrayClose | Token::DictClose => {
                depth -= 1;
                if depth == 0 {
                    return (data.get(start..before).unwrap_or_default(), true);
                }
            }
            Token::Keyword(
                b"endobj" | b"stream" | b"endstream" | b"obj" | b"trailer" | b"xref",
            ) => {
                lexer.set_pos(before);
                return (data.get(start..before).unwrap_or_default(), false);
            }
            _ => {}
        }
    }
}

impl<'a> Array<'a> {
    pub(crate) fn new(body: &'a [u8], owner: Option<ObjRef>) -> Self {
        Array { body, owner }
    }

    pub(crate) fn iter(&self) -> ArrayIter<'a> {
        ArrayIter {
            lexer: Lexer::new(self.body),
            owner: self.owner,
        }
    }

    pub(crate) fn get(&self, index: usize) -> Option<Object<'a>> {
        self.iter().nth(index)
    }

    pub(crate) fn body(&self) -> &'a [u8] {
        self.body
    }
}

impl<'a> Dict<'a> {
    pub(crate) fn new(body: &'a [u8], owner: Option<ObjRef>) -> Self {
        Dict { body, owner }
    }

    pub(crate) fn iter(&self) -> DictIter<'a> {
        DictIter {
            lexer: Lexer::new(self.body),
            owner: self.owner,
        }
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<Object<'a>> {
        self.iter()
            .filter(|(name, _)| name.is(key))
            .last()
            .map(|(_, value)| value)
    }

    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        self.iter().any(|(name, _)| name.is(key))
    }

    pub(crate) fn is_type(&self, name: &[u8]) -> bool {
        self.get(b"Type").is_some_and(|value| value.is_name(name))
    }

    pub(crate) fn body(&self) -> &'a [u8] {
        self.body
    }
}

impl<'a> Iterator for ArrayIter<'a> {
    type Item = Object<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(object) = Object::read(&mut self.lexer, self.owner) {
                return Some(object);
            }
            self.lexer.next()?;
        }
    }
}

impl<'a> Iterator for DictIter<'a> {
    type Item = (Name<'a>, Object<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.lexer.next()? {
                Token::Name(raw) => {
                    if let Some(value) = Object::read(&mut self.lexer, self.owner) {
                        return Some((Name::new(raw), value));
                    }
                }
                Token::ArrayOpen | Token::DictOpen => {
                    skip(&mut self.lexer);
                }
                _ => {}
            }
        }
    }
}

