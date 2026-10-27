/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JsonPointer, JsonPointerItem, Key, PointerDepth, Property};
use std::borrow::Cow;

#[derive(Clone, Copy)]
struct Token<'x> {
    text: &'x str,
    digits: bool,
    escaped: bool,
}

impl<P: Property> JsonPointer<P> {
    pub const MAX_SEGMENTS: usize = 128;

    pub fn parse(value: &str) -> Self {
        Self::parse_tokens(value, PointerDepth::default().inner())
    }

    pub fn parse_nested(value: &str, depth: PointerDepth) -> Option<Self> {
        depth
            .can_nest()
            .then(|| Self::parse_tokens(value, depth.inner()))
    }

    fn parse_tokens(value: &str, depth: PointerDepth) -> Self {
        if value.is_empty() {
            return JsonPointer(vec![JsonPointerItem::Root]);
        }

        let text = value.strip_prefix('/').unwrap_or(value);
        let separators = text
            .bytes()
            .filter(|&byte| byte == b'/')
            .take(Self::MAX_SEGMENTS)
            .count();
        let (token, mut rest) = Token::split(text);
        let first = JsonPointerItem::parse_segment(None, token, depth);
        if separators == Self::MAX_SEGMENTS {
            return Self::too_long(first);
        }

        let mut path = Vec::with_capacity(separators + 1);
        let opaque = first.is_opaque();
        path.push(first);

        if opaque {
            return Self::parse_opaque_tail(path, rest);
        }

        while let Some(text) = rest {
            let (token, tail) = Token::split(text);
            let item = JsonPointerItem::parse_segment(
                path.last().and_then(JsonPointerItem::as_key),
                token,
                depth,
            );
            path.push(item);
            rest = tail;
        }

        JsonPointer(path)
    }

    #[cold]
    #[inline(never)]
    fn too_long(first: JsonPointerItem<P>) -> Self {
        JsonPointer(vec![first, JsonPointerItem::Invalid(String::new())])
    }

    #[cold]
    #[inline(never)]
    fn parse_opaque_tail(mut path: Vec<JsonPointerItem<P>>, mut rest: Option<&str>) -> Self {
        while let Some(text) = rest {
            let (token, tail) = Token::split(text);
            path.push(JsonPointerItem::parse_opaque_token(token));
            rest = tail;
        }

        JsonPointer(path)
    }
}

impl<'x> Token<'x> {
    fn split(text: &'x str) -> (Self, Option<&'x str>) {
        let mut digits = true;
        let mut escaped = false;
        let mut end = text.len();
        for (pos, byte) in text.bytes().enumerate() {
            match byte {
                b'/' => {
                    end = pos;
                    break;
                }
                b'~' => {
                    escaped = true;
                    digits = false;
                }
                b'0'..=b'9' => {}
                _ => digits = false,
            }
        }
        let token = Token {
            text: text.get(..end).unwrap_or_default(),
            digits,
            escaped,
        };
        (token, text.get(end + 1..))
    }

    fn unescape(self) -> Option<String> {
        let (head, mut rest) = self.text.split_once('~')?;
        let mut text = String::with_capacity(self.text.len());
        text.push_str(head);
        loop {
            match rest.split_at_checked(1) {
                Some(("0", tail)) => {
                    text.push('~');
                    rest = tail;
                }
                Some(("1", tail)) => {
                    text.push('/');
                    rest = tail;
                }
                _ => return None,
            }

            match rest.split_once('~') {
                Some((segment, tail)) => {
                    text.push_str(segment);
                    rest = tail;
                }
                None => {
                    text.push_str(rest);
                    return Some(text);
                }
            }
        }
    }
}

impl<P: Property> JsonPointerItem<P> {
    fn is_opaque(&self) -> bool {
        matches!(self, JsonPointerItem::Key(key) if key.is_opaque())
    }

    #[inline(always)]
    fn parse_segment(
        parent: Option<&Key<'static, P>>,
        token: Token<'_>,
        depth: PointerDepth,
    ) -> Self {
        if token.text.is_empty() {
            JsonPointerItem::empty_segment()
        } else {
            JsonPointerItem::parse_token(parent, token, depth)
        }
    }

    #[cold]
    #[inline(never)]
    fn empty_segment() -> Self {
        JsonPointerItem::Key("".into())
    }

    fn parse_opaque_token(token: Token<'_>) -> Self {
        if !token.escaped {
            JsonPointerItem::Key(Key::Owned(token.text.to_string()))
        } else {
            match token.unescape() {
                Some(text) => JsonPointerItem::Key(Key::Owned(text)),
                None => JsonPointerItem::Invalid(token.text.to_string()),
            }
        }
    }

    fn parse_token(
        parent: Option<&Key<'static, P>>,
        token: Token<'_>,
        depth: PointerDepth,
    ) -> Self {
        let text = token.text;
        if token.digits {
            match P::try_parse_nested(parent, text, depth) {
                Some(prop) => JsonPointerItem::Key(Key::Property(prop)),
                None => match text.parse::<u64>() {
                    Ok(index) if text == "0" || !text.starts_with('0') => {
                        JsonPointerItem::Number(index)
                    }
                    _ => JsonPointerItem::Key(Key::Owned(text.to_string())),
                },
            }
        } else if text == "*" {
            JsonPointerItem::Wildcard
        } else if !token.escaped {
            JsonPointerItem::Key(match P::try_parse_nested(parent, text, depth) {
                Some(prop) => Key::Property(prop),
                None => Key::Owned(text.to_string()),
            })
        } else {
            match token.unescape() {
                Some(text) => {
                    JsonPointerItem::Key(match P::try_parse_nested(parent, &text, depth) {
                        Some(prop) => Key::Property(prop),
                        None => Key::Owned(text),
                    })
                }
                None => JsonPointerItem::Invalid(text.to_string()),
            }
        }
    }
}

impl<'de, P: Property> serde::Deserialize<'de> for JsonPointer<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Cow<'de, str>>::deserialize(deserializer).map(|s| JsonPointer::parse(s.as_ref()))
    }
}

impl<P: Property> serde::Serialize for JsonPointer<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

