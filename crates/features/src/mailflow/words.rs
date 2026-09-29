/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! An organization's own word lists and patterns (§2.3). Both count
//! occurrences, not distinct values: "confidential" three times is three.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::{Regex, RegexBuilder};

/// How large a compiled pattern may grow. Keeps a rule someone writes from
/// making every message slow to send.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// Words and phrases, matched whole and ignoring case.
#[derive(Debug, Clone)]
pub struct WordList {
    matcher: AhoCorasick,
}

impl WordList {
    /// Builds a list from words or phrases; empty entries are skipped.
    pub fn new<I, S>(words: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let words: Vec<String> = words
            .into_iter()
            .map(|w| w.as_ref().trim().to_lowercase())
            .filter(|w| !w.is_empty())
            .collect();
        if words.is_empty() {
            return Err("The list has no words".into());
        }
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&words)
            .map(|matcher| Self { matcher })
            .map_err(|err| err.to_string())
    }

    /// How many times any word of the list appears in `text`.
    pub fn count(&self, text: &str) -> usize {
        let text = text.to_lowercase();
        self.matcher
            .find_iter(&text)
            .filter(|m| super::detectors::stands_alone(&text, m.start(), m.end()))
            .count()
    }
}

/// An organization's regular expression.
#[derive(Debug, Clone)]
pub struct Pattern {
    regex: Regex,
}

impl Pattern {
    /// Compiles `pattern`, or says why it can't be used. Matching ignores
    /// case unless the pattern turns that off with `(?-i)`.
    pub fn new(pattern: &str) -> Result<Self, String> {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map(|regex| Self { regex })
            .map_err(|err| err.to_string())
    }

    /// How many times the pattern matches in `text`.
    pub fn count(&self, text: &str) -> usize {
        self.regex.find_iter(text).filter(|m| !m.is_empty()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_whole_and_any_case() {
        let list = WordList::new(["Project Falcon", "confidential", " "]).unwrap();
        assert_eq!(
            list.count(
                "CONFIDENTIAL: project falcon notes. Not confidentiality, not projectfalcon."
            ),
            2
        );
        assert_eq!(list.count("Confidential, confidential and confidential"), 3);
        // Non-ASCII case folding
        let list = WordList::new(["GEHEIM", "Straße"]).unwrap();
        assert_eq!(list.count("streng geheim, STRASSE ist nicht Straße"), 2);
        assert!(WordList::new(["", "  "]).is_err());
    }

    #[test]
    fn patterns() {
        let pattern = Pattern::new(r"\bPRJ-\d{4}\b").unwrap();
        assert_eq!(pattern.count("prj-1234 and PRJ-5678, not PRJ-12"), 2);
        assert!(Pattern::new("(unclosed").is_err());
        // Too large to compile within the limit
        assert!(Pattern::new(r"\w{1000}\w{1000}\w{1000}").is_err());
        // Empty matches don't count
        assert_eq!(Pattern::new("x*").unwrap().count("abc"), 0);
    }
}
