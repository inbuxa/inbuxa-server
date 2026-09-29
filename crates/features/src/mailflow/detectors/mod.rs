/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Detectors (dlp-and-mail-flow-rules spec, §2.3): each finds one kind of
//! identifier in text and reports the distinct ones it found.
//!
//! A detector is one of two strengths:
//!
//! - **Checked**: the identifier carries a published check digit or
//!   checksum, so a random number rarely passes; found on its own.
//! - **Needs a word**: the format alone is too common, so a candidate counts
//!   only with a corroborating word within [`WINDOW`] characters either
//!   side.
//!
//! Findings are distinct normalized values (digits only, upper case), so the
//! same card number pasted twice counts once. They stay in memory: callers
//! read only [`Findings::len`].

pub mod any;
pub mod checks;

use ahash::AHashSet;

/// How far, in characters, a corroborating word may be from a candidate.
pub const WINDOW: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    Checked,
    NeedsWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Any,
    Us,
    Uk,
    Canada,
    Australia,
    Eu,
    Europe,
    Asia,
    Americas,
    Africa,
}

/// The distinct values one detector found.
#[derive(Debug, Default)]
pub struct Findings(AHashSet<String>);

impl Findings {
    pub fn insert(&mut self, value: impl Into<String>) {
        self.0.insert(value.into());
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub struct Detector {
    /// Stable id, stored in rules: `payment-card`, `iban`, `us-ssn`.
    pub id: &'static str,
    pub name: &'static str,
    pub region: Region,
    pub strength: Strength,
    find: fn(&str, &mut Findings),
}

impl Detector {
    pub const fn new(
        id: &'static str,
        name: &'static str,
        region: Region,
        strength: Strength,
        find: fn(&str, &mut Findings),
    ) -> Self {
        Self {
            id,
            name,
            region,
            strength,
            find,
        }
    }

    /// Adds what this detector finds in `text` to `findings`. Call once per
    /// piece of text (subject, each part, each attachment) with the same
    /// `findings`, then read its length.
    pub fn find(&self, text: &str, findings: &mut Findings) {
        (self.find)(text, findings)
    }

    /// The distinct values found in one text.
    pub fn count(&self, text: &str) -> usize {
        let mut findings = Findings::default();
        self.find(text, &mut findings);
        findings.len()
    }
}

/// Every detector, in the order the console lists them.
pub fn all() -> impl Iterator<Item = &'static Detector> {
    any::DETECTORS.iter()
}

pub fn by_id(id: &str) -> Option<&'static Detector> {
    all().find(|detector| detector.id == id)
}

/// Whether one of `words` appears, as a whole word and ignoring case, within
/// [`WINDOW`] characters before `start` or after `end` (byte offsets of the
/// candidate in `text`). The window is widened by the longest word, so a
/// word that reaches into it still counts whole.
pub fn word_near(text: &str, start: usize, end: usize, words: &[&str]) -> bool {
    let reach = WINDOW + words.iter().map(|w| w.chars().count()).max().unwrap_or(0);
    let before = text[..start]
        .char_indices()
        .rev()
        .nth(reach - 1)
        .map_or(0, |(i, _)| i);
    let after = text[end..]
        .char_indices()
        .nth(reach)
        .map_or(text.len(), |(i, _)| end + i);
    let window = text[before..after].to_lowercase();
    words.iter().any(|word| contains_word(&window, word))
}

/// Whether `word` (lower case) appears in `haystack` (lower case) with no
/// letter or digit on either side.
pub fn contains_word(haystack: &str, word: &str) -> bool {
    haystack.match_indices(word).any(|(i, _)| {
        let before_ok = haystack[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack[i + word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        before_ok && after_ok
    })
}

/// Whether the match at `start..end` stands alone: no digit or letter
/// directly before or after it, so `123-45-6789` isn't found inside a
/// longer run of digits.
pub fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
}

/// The ASCII digits of `s`.
pub fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_whole_and_near() {
        let text = "Your passport number is X1234567, thanks";
        let start = text.find("X123").unwrap();
        assert!(word_near(text, start, start + 8, &["passport"]));
        assert!(!word_near(text, start, start + 8, &["pass"]));
        let far = format!("passport{}X1234567", " ".repeat(60));
        let start = far.find("X123").unwrap();
        assert!(!word_near(&far, start, start + 8, &["passport"]));
    }

    #[test]
    fn near_counts_characters_not_bytes() {
        // 45 two-byte characters between the word and the candidate: within
        // 50 characters, though over 50 bytes
        let text = format!("passport {} X1234567", "é".repeat(45));
        let start = text.find("X123").unwrap();
        assert!(word_near(&text, start, start + 8, &["passport"]));
    }

    #[test]
    fn ids_are_unique() {
        let mut seen = AHashSet::new();
        for detector in all() {
            assert!(seen.insert(detector.id), "duplicate id {}", detector.id);
            assert!(by_id(detector.id).is_some());
        }
    }
}
