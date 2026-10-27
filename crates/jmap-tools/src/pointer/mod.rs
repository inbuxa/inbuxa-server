/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod eval;
pub(crate) mod parser;

use crate::{Element, Key, Property, Value};
use std::{
    borrow::Cow,
    fmt::{self, Debug, Display, Formatter, Write},
    iter::Peekable,
    slice::Iter,
    str::from_utf8,
};

const ENCODE_CAPACITY: usize = 32;

pub trait JsonPointerHandler<'x, P: Property, E: Element>: Debug {
    fn eval_jptr<'y>(
        &'y self,
        pointer: JsonPointerIter<'_, P>,
        results: &mut Vec<Cow<'y, Value<'x, P, E>>>,
    );
    fn patch_jptr<'y: 'x>(
        &mut self,
        pointer: JsonPointerIter<'_, P>,
        value: Value<'y, P, E>,
    ) -> bool;
    fn to_value<'y>(&'y self) -> Cow<'y, Value<'x, P, E>>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointer<P: Property>(pub(crate) Vec<JsonPointerItem<P>>);

pub type JsonPointerIter<'x, P> = Peekable<Iter<'x, JsonPointerItem<P>>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JsonPointerItem<P: Property> {
    Root,
    Wildcard,
    Invalid(String),
    Key(Key<'static, P>),
    Number(u64),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointerDepth(u8);

impl PointerDepth {
    pub const LIMIT: u8 = 16;

    fn inner(self) -> Self {
        PointerDepth(self.0 + 1)
    }

    fn can_nest(self) -> bool {
        self.0 < Self::LIMIT
    }
}

impl<P: Property> JsonPointer<P> {
    pub fn new(items: Vec<JsonPointerItem<P>>) -> Self {
        Self(items)
    }

    pub fn iter(&self) -> JsonPointerIter<'_, P> {
        self.0.iter().peekable()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = JsonPointerItem<P>> {
        self.0.into_iter()
    }

    pub fn into_inner(self) -> Vec<JsonPointerItem<P>> {
        self.0
    }

    pub fn encode<I, T>(items: I) -> String
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut encoded = String::with_capacity(ENCODE_CAPACITY);
        for (pos, item) in items.into_iter().enumerate() {
            if pos > 0 {
                encoded.push('/');
            }
            encoded.extend(EscapedToken(item.as_ref()).pieces());
        }
        encoded
    }

    pub fn first(&self) -> Option<&JsonPointerItem<P>> {
        self.0.first()
    }

    pub fn first_mut(&mut self) -> Option<&mut JsonPointerItem<P>> {
        self.0.first_mut()
    }

    pub fn last(&self) -> Option<&JsonPointerItem<P>> {
        self.0.last()
    }

    pub fn last_mut(&mut self) -> Option<&mut JsonPointerItem<P>> {
        self.0.last_mut()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[JsonPointerItem<P>] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [JsonPointerItem<P>] {
        &mut self.0
    }
}

impl<P: Property> JsonPointerItem<P> {
    pub fn as_key(&self) -> Option<&Key<'static, P>> {
        match self {
            JsonPointerItem::Key(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_property_key(&self) -> Option<&P> {
        match self {
            JsonPointerItem::Key(Key::Property(key)) => Some(key),
            _ => None,
        }
    }

    pub fn as_string_key(&self) -> Option<&str> {
        match self {
            JsonPointerItem::Key(Key::Borrowed(key)) => Some(key),
            JsonPointerItem::Key(Key::Owned(key)) => Some(key),
            _ => None,
        }
    }

    pub fn to_cow(&self) -> Option<Cow<'_, str>> {
        match self {
            JsonPointerItem::Key(Key::Property(key)) => Some(key.to_cow()),
            JsonPointerItem::Key(Key::Borrowed(key)) => Some(Cow::Borrowed(key)),
            JsonPointerItem::Key(Key::Owned(key)) => Some(Cow::Borrowed(key)),
            _ => None,
        }
    }
}

impl<P: Property> Display for JsonPointer<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for (i, ptr) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_char('/')?;
            }

            match ptr {
                JsonPointerItem::Root => {}
                JsonPointerItem::Wildcard => f.write_char('*')?,
                JsonPointerItem::Invalid(text) => f.write_str(text)?,
                JsonPointerItem::Key(k) => EscapedToken(&k.to_string())
                    .pieces()
                    .try_for_each(|piece| f.write_str(piece))?,
                JsonPointerItem::Number(n) => f.write_str(NumberKey::default().format(*n))?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct EscapedToken<'x>(&'x str);

impl<'x> EscapedToken<'x> {
    fn pieces(self) -> impl Iterator<Item = &'x str> {
        self.0
            .split_inclusive(['~', '/'])
            .flat_map(|piece| match piece.strip_suffix(['~', '/']) {
                Some(text) if piece.ends_with('~') => [text, "~0"],
                Some(text) => [text, "~1"],
                None => [piece, ""],
            })
            .filter(|piece| !piece.is_empty())
    }
}

#[derive(Default)]
pub(crate) struct NumberKey([u8; 20]);

impl NumberKey {
    pub(crate) fn format(&mut self, mut n: u64) -> &str {
        let mut pos = self.0.len();
        loop {
            pos -= 1;
            if let Some(digit) = self.0.get_mut(pos) {
                *digit = b'0' + (n % 10) as u8;
            }
            n /= 10;
            if n == 0 || pos == 0 {
                break;
            }
        }
        self.0
            .get(pos..)
            .and_then(|digits| from_utf8(digits).ok())
            .unwrap_or_default()
    }
}
