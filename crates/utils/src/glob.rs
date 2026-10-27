/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::text::{ConstNeedle, IgnoreCaseNeedle, lowercase};
use ahash::{AHashMap, AHashSet};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
    Matches(GlobPattern),
    All,
}

#[derive(Debug, Clone)]
pub struct GlobPattern {
    pattern: Vec<PatternChar>,
    to_lower: bool,
    literal: Option<Box<Literal>>,
}

#[derive(Debug, Clone)]
enum Literal {
    Contains(ConstNeedle),
    ContainsIgnoreCase(IgnoreCaseNeedle),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternChar {
    WildcardMany { num: usize, match_pos: usize },
    WildcardSingle { match_pos: usize },
    Char { char: char, match_pos: usize },
}

impl GlobPattern {
    pub fn compile(pattern: &str, to_lower: bool) -> Self {
        let mut chars = Vec::new();
        let mut is_escaped = false;
        let mut str = pattern.chars().peekable();

        while let Some(char) = str.next() {
            match char {
                '*' if !is_escaped => {
                    let mut num = 1;
                    while let Some('*') = str.peek() {
                        num += 1;
                        str.next();
                    }
                    chars.push(PatternChar::WildcardMany { num, match_pos: 0 });
                }
                '?' if !is_escaped => {
                    chars.push(PatternChar::WildcardSingle { match_pos: 0 });
                }
                '\\' if !is_escaped => {
                    is_escaped = true;
                    continue;
                }
                _ => {
                    if is_escaped {
                        is_escaped = false;
                    }
                    if to_lower && char.is_uppercase() {
                        for char in char.to_lowercase() {
                            chars.push(PatternChar::Char { char, match_pos: 0 });
                        }
                    } else {
                        chars.push(PatternChar::Char { char, match_pos: 0 });
                    }
                }
            }
        }

        GlobPattern {
            literal: Literal::classify(&chars, to_lower).map(Box::new),
            pattern: chars,
            to_lower,
        }
    }

    pub fn try_compile(pattern: &str, to_lower: bool) -> Result<Self, String> {
        // Detect if the key is a glob pattern
        let mut last_ch = '\0';
        let mut has_escape = false;
        let mut is_glob = false;
        for ch in pattern.chars() {
            match ch {
                '\\' => {
                    has_escape = true;
                }
                '*' | '?' if last_ch != '\\' => {
                    is_glob = true;
                }
                _ => {}
            }

            last_ch = ch;
        }

        if is_glob {
            Ok(GlobPattern::compile(pattern, to_lower))
        } else {
            Err(if has_escape {
                pattern.replace('\\', "")
            } else {
                pattern.to_string()
            })
        }
    }

    pub fn matches(&self, value: &str) -> bool {
        match self.literal.as_deref() {
            Some(Literal::Contains(needle)) => needle.contains(value),
            Some(Literal::ContainsIgnoreCase(needle)) => needle.contains(value),
            None if !self.to_lower => self.matches_chars(value, identity),
            None if value.is_ascii() => self.matches_chars(value, char::to_ascii_lowercase),
            None => self.matches_chars(&lowercase(value), identity),
        }
    }

    // Credits: Algorithm ported from https://research.swtch.com/glob
    fn matches_chars(&self, value: &str, fold: impl Fn(&char) -> char) -> bool {
        let mut px = 0;
        let mut nx = 0;
        let mut next_px = 0;
        let mut next_nx = 0;

        while px < self.pattern.len() || nx < value.len() {
            let next = value.get(nx..).and_then(|rest| rest.chars().next());
            match self.pattern.get(px) {
                Some(PatternChar::Char { char, .. }) => {
                    if let Some(next) = next.filter(|next| fold(next) == *char) {
                        px += 1;
                        nx += next.len_utf8();
                        continue;
                    }
                }
                Some(PatternChar::WildcardSingle { .. }) => {
                    if let Some(next) = next {
                        px += 1;
                        nx += next.len_utf8();
                        continue;
                    }
                }
                Some(PatternChar::WildcardMany { .. }) => {
                    next_px = px;
                    next_nx = nx + next.map_or(1, char::len_utf8);
                    px += 1;
                    continue;
                }
                None => (),
            }
            if 0 < next_nx && next_nx <= value.len() {
                px = next_px;
                nx = next_nx;
                continue;
            }
            return false;
        }
        true
    }
}

impl Literal {
    fn classify(pattern: &[PatternChar], to_lower: bool) -> Option<Self> {
        let [
            PatternChar::WildcardMany { .. },
            middle @ ..,
            PatternChar::WildcardMany { .. },
        ] = pattern
        else {
            return None;
        };
        let literal = middle
            .iter()
            .map(|item| match item {
                PatternChar::Char { char, .. } => Some(*char),
                _ => None,
            })
            .collect::<Option<String>>()?;
        if !to_lower {
            Some(Literal::Contains(ConstNeedle::new(&literal)))
        } else if literal.is_ascii() {
            Some(Literal::ContainsIgnoreCase(IgnoreCaseNeedle::new(&literal)))
        } else {
            None
        }
    }
}

impl PartialEq for GlobPattern {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.to_lower == other.to_lower
    }
}

impl Eq for GlobPattern {}

fn identity(char: &char) -> char {
    *char
}

#[derive(Debug, Clone, Default)]
pub struct GlobSet {
    entries: AHashSet<String>,
    patterns: Vec<GlobPattern>,
}

#[derive(Debug, Clone)]
pub struct GlobMap<V> {
    entries: AHashMap<String, V>,
    patterns: Vec<(GlobPattern, V)>,
}

impl GlobSet {
    pub fn new() -> Self {
        GlobSet::default()
    }

    pub fn insert_pattern(&mut self, pattern: &str) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push(glob);
            }
            Err(entry) => {
                self.entries.insert(entry);
            }
        }
    }

    pub fn insert_entry(&mut self, entry: String) {
        self.entries.insert(entry);
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains(key) || self.patterns.iter().any(|pattern| pattern.matches(key))
    }
}

impl<V> GlobMap<V> {
    pub fn new() -> Self {
        GlobMap {
            entries: AHashMap::new(),
            patterns: Vec::new(),
        }
    }

    pub fn insert_pattern(&mut self, pattern: &str, value: V) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push((glob, value));
            }
            Err(entry) => {
                self.entries.insert(entry, value);
            }
        }
    }

    pub fn insert_entry(&mut self, entry: String, value: V) {
        self.entries.insert(entry, value);
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key).or_else(|| {
            self.patterns
                .iter()
                .find_map(|(pattern, value)| pattern.matches(key).then_some(value))
        })
    }
}

impl<V> Default for GlobMap<V> {
    fn default() -> Self {
        GlobMap::new()
    }
}

impl MatchType {
    pub fn parse(value: &str) -> Self {
        if value == "*" {
            MatchType::All
        } else if let Some(value) = value.strip_suffix('*') {
            MatchType::StartsWith(value.to_string())
        } else if let Some(value) = value.strip_prefix('*') {
            MatchType::EndsWith(value.to_string())
        } else if value.contains('*') {
            MatchType::Matches(GlobPattern::compile(value, false))
        } else {
            MatchType::Equal(value.to_string())
        }
    }

    pub fn matches(&self, value: &str) -> bool {
        match self {
            MatchType::Equal(pattern) => value == pattern,
            MatchType::StartsWith(pattern) => value.starts_with(pattern),
            MatchType::EndsWith(pattern) => value.ends_with(pattern),
            MatchType::Matches(pattern) => pattern.matches(value),
            MatchType::All => true,
        }
    }
}

impl<'de> Deserialize<'de> for GlobPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GlobPattern::compile(
            <Cow<&str>>::deserialize(deserializer)?.as_ref(),
            true,
        ))
    }
}

