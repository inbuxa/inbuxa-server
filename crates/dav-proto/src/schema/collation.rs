/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{Namespace, request::TextMatch};
use std::{borrow::Cow, convert::identity};
use types::collation::unicode_casemap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    all(test, inbuxa_tests),
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum Collation {
    AsciiCasemap,
    Octet,
    UnicodeCasemap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    all(test, inbuxa_tests),
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum MatchType {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

impl Collation {
    pub fn default_for(namespace: Namespace) -> Self {
        if namespace == Namespace::CardDav {
            Collation::UnicodeCasemap
        } else {
            Collation::AsciiCasemap
        }
    }

    pub fn try_parse(s: &str) -> Option<Self> {
        hashify::fnc_map!(s.as_bytes(),
            "i;ascii-casemap" => Some(Collation::AsciiCasemap),
            "i;octet" => Some(Collation::Octet),
            "i;unicode-casemap" => Some(Collation::UnicodeCasemap),
            _ => None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Collation::AsciiCasemap => "i;ascii-casemap",
            Collation::Octet => "i;octet",
            Collation::UnicodeCasemap => "i;unicode-casemap",
        }
    }

    fn prepare<'x>(&self, text: &'x str) -> Cow<'x, str> {
        match self {
            Collation::Octet => Cow::Borrowed(text),
            Collation::AsciiCasemap => {
                if text.bytes().any(|ch| ch.is_ascii_lowercase()) {
                    Cow::Owned(text.to_ascii_uppercase())
                } else {
                    Cow::Borrowed(text)
                }
            }
            Collation::UnicodeCasemap => {
                if text.is_ascii() {
                    Collation::AsciiCasemap.prepare(text)
                } else {
                    let mut folded = String::with_capacity(text.len());
                    unicode_casemap(text, &mut folded);
                    Cow::Owned(folded)
                }
            }
        }
    }
}

impl MatchType {
    pub fn try_parse(s: &str) -> Option<Self> {
        hashify::fnc_map!(s.as_bytes(),
            "equals" => Some(MatchType::Equals),
            "contains" => Some(MatchType::Contains),
            "starts-with" => Some(MatchType::StartsWith),
            "ends-with" => Some(MatchType::EndsWith),
            _ => None,
        )
    }

    fn matches(&self, haystack: &[u8], needle: &[u8], fold: Fold) -> bool {
        match fold {
            Fold::Identity => self.matches_with(haystack, needle, identity, |haystack, needle| {
                memchr::memmem::find(haystack, needle).is_some()
            }),
            Fold::AsciiUppercase => self.matches_with(
                haystack,
                needle,
                |byte| byte.to_ascii_uppercase(),
                ascii_uppercase_contains,
            ),
        }
    }

    fn matches_with(
        &self,
        haystack: &[u8],
        needle: &[u8],
        fold: impl Fn(u8) -> u8,
        prefiltered_contains: impl Fn(&[u8], &[u8]) -> bool,
    ) -> bool {
        let is_equal = |(h, n): (&u8, &u8)| fold(*h) == *n;
        match self {
            MatchType::Equals => {
                haystack.len() == needle.len() && haystack.iter().zip(needle).all(is_equal)
            }
            MatchType::StartsWith => {
                haystack.len() >= needle.len() && haystack.iter().zip(needle).all(is_equal)
            }
            MatchType::EndsWith => {
                haystack.len() >= needle.len()
                    && haystack.iter().rev().zip(needle.iter().rev()).all(is_equal)
            }
            MatchType::Contains if needle.is_empty() => true,
            MatchType::Contains if haystack.len() < PREFILTER_MIN_LEN => haystack
                .windows(needle.len())
                .any(|window| window.iter().zip(needle).all(is_equal)),
            MatchType::Contains => prefiltered_contains(haystack, needle),
        }
    }
}

const PREFILTER_MIN_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fold {
    Identity,
    AsciiUppercase,
}

fn ascii_uppercase_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let Some(first) = needle.first() else {
        return true;
    };
    memchr::memchr2_iter(
        first.to_ascii_uppercase(),
        first.to_ascii_lowercase(),
        haystack,
    )
    .any(|start| {
        haystack
            .get(start..start + needle.len())
            .is_some_and(|window| {
                window
                    .iter()
                    .zip(needle)
                    .all(|(h, n)| h.to_ascii_uppercase() == *n)
            })
    })
}

impl TextMatch {
    pub fn new(value: String, match_type: MatchType, collation: Collation, negate: bool) -> Self {
        TextMatch {
            needle: collation.prepare(&value).into_owned(),
            match_type,
            value,
            collation,
            negate,
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.is_match_with(text, &mut String::new())
    }

    fn is_match_with(&self, text: &str, folded: &mut String) -> bool {
        let needle = self.needle.as_bytes();
        match self.collation {
            Collation::Octet => self
                .match_type
                .matches(text.as_bytes(), needle, Fold::Identity),
            Collation::AsciiCasemap => {
                self.match_type
                    .matches(text.as_bytes(), needle, Fold::AsciiUppercase)
            }
            Collation::UnicodeCasemap if text.is_ascii() => {
                self.needle.is_ascii()
                    && self
                        .match_type
                        .matches(text.as_bytes(), needle, Fold::AsciiUppercase)
            }
            Collation::UnicodeCasemap => {
                folded.clear();
                unicode_casemap(text, folded);
                self.match_type
                    .matches(folded.as_bytes(), needle, Fold::Identity)
            }
        }
    }

    pub fn is_match_any<T: AsRef<str>>(&self, mut values: impl Iterator<Item = T>) -> bool {
        let mut folded = String::new();
        values.any(|value| self.is_match_with(value.as_ref(), &mut folded)) != self.negate
    }
}

