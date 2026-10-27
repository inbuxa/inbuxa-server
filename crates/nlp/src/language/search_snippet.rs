/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Language;
use std::collections::VecDeque;

fn escape_char(c: char, string: &mut String) {
    match c {
        '&' => string.push_str("&amp;"),
        '<' => string.push_str("&lt;"),
        '>' => string.push_str("&gt;"),
        '"' => string.push_str("&quot;"),
        '\n' | '\r' => string.push(' '),
        _ => string.push(c),
    }
}

fn escape_char_len(c: char) -> usize {
    match c {
        '&' => "&amp;".len(),
        '<' => "&lt;".len(),
        '>' => "&gt;".len(),
        '"' => "&quot;".len(),
        '\r' | '\n' => 1,
        _ => c.len_utf8(),
    }
}

const MAX_SNIPPET_LEN: usize = 255;
const MARK_LEN: usize = "<mark>".len() * 2;
const LEADING_CONTEXT_THRESHOLD: usize = 240;
const LEADING_CONTEXT_CHARS: usize = 40;
const LEADING_CONTEXT_WORDS: usize = 3;
const MAX_TOKEN_LEN: usize = 200;
const MAX_WINDOW_CAPACITY: usize = 64;

struct Term {
    offset: usize,
    len: usize,
}

struct SnippetWriter<'x> {
    text: &'x str,
    snippet: String,
    last_end: Option<usize>,
    stop_offset: usize,
}

enum Flow {
    Continue,
    Full,
}

pub fn generate_snippet(
    text: &str,
    needles: &[impl AsRef<str>],
    language: Language,
    is_exact: bool,
) -> Option<String> {
    let mut writer = SnippetWriter {
        text,
        snippet: String::new(),
        last_end: None,
        stop_offset: usize::MAX,
    };
    let tokens = language.tokenize_text(text, MAX_TOKEN_LEN);

    if is_exact {
        if needles.is_empty() {
            return None;
        }
        let mut window = VecDeque::with_capacity(needles.len().min(MAX_WINDOW_CAPACITY));
        for token in tokens {
            if window.len() == needles.len() {
                window.pop_front();
            }
            window.push_back(token);
            if window.len() < needles.len() {
                continue;
            }
            if window
                .front()
                .is_some_and(|first| first.from >= writer.stop_offset)
            {
                break;
            }
            if needles
                .iter()
                .zip(&window)
                .all(|(needle, token)| needle.as_ref() == token.word.as_ref())
            {
                for token in &window {
                    if let Flow::Full = writer.push(Term {
                        offset: token.from,
                        len: token.to - token.from,
                    })? {
                        return Some(writer.snippet);
                    }
                }
            }
        }
    } else {
        for token in tokens {
            if token.from >= writer.stop_offset {
                break;
            }
            if needles.iter().any(|needle| {
                let needle = needle.as_ref();
                needle == token.word.as_ref() || needle.len() > 2 && token.word.contains(needle)
            }) && let Flow::Full = writer.push(Term {
                offset: token.from,
                len: token.to - token.from,
            })? {
                return Some(writer.snippet);
            }
        }
    }

    writer.finish()
}

impl SnippetWriter<'_> {
    fn push(&mut self, term: Term) -> Option<Flow> {
        match self.last_end {
            Some(end) => {
                if let Flow::Full = self.write_gap(end, term.offset)? {
                    return Some(Flow::Full);
                }
            }
            None => self.write_leading_context(term.offset)?,
        }

        if self.snippet.len() + MARK_LEN + term.len + 1 > MAX_SNIPPET_LEN {
            return Some(Flow::Full);
        }

        let end = term.offset + term.len;
        self.snippet.push_str("<mark>");
        self.snippet.push_str(self.text.get(term.offset..end)?);
        self.snippet.push_str("</mark>");
        self.last_end = Some(end);
        self.stop_offset = self.overflow_offset(end);

        Some(Flow::Continue)
    }

    fn finish(mut self) -> Option<String> {
        let end = self.last_end?;
        self.write_gap(end, self.text.len())?;
        Some(self.snippet)
    }

    fn write_leading_context(&mut self, start_offset: usize) -> Option<()> {
        self.snippet
            .reserve(self.text.len().min(MAX_SNIPPET_LEN + 1));

        if start_offset > 0 {
            let mut word_count = 0;
            let mut from_offset = 0;
            let mut last_is_space = false;

            if self.text.len() > LEADING_CONTEXT_THRESHOLD {
                for (pos, char) in self.text.get(0..start_offset)?.char_indices().rev() {
                    if char.is_whitespace() {
                        if !last_is_space {
                            word_count += 1;
                            if word_count == LEADING_CONTEXT_WORDS {
                                break;
                            }
                            last_is_space = true;
                        }
                    } else {
                        last_is_space = false;
                    }
                    from_offset = pos;
                    if start_offset - from_offset >= LEADING_CONTEXT_CHARS {
                        break;
                    }
                }
            }

            last_is_space = false;
            for char in self.text.get(from_offset..start_offset)?.chars() {
                if !char.is_whitespace() {
                    last_is_space = false;
                } else {
                    if last_is_space {
                        continue;
                    }
                    last_is_space = true;
                }
                escape_char(char, &mut self.snippet);
            }
        }

        Some(())
    }

    fn write_gap(&mut self, from: usize, to: usize) -> Option<Flow> {
        let mut last_is_space = false;
        for char in self.text.get(from..to)?.chars() {
            if !char.is_whitespace() {
                last_is_space = false;
            } else {
                if last_is_space {
                    continue;
                }
                last_is_space = true;
            }

            if self.snippet.len() + escape_char_len(char) <= MAX_SNIPPET_LEN {
                escape_char(char, &mut self.snippet);
            } else {
                return Some(Flow::Full);
            }
        }

        Some(Flow::Continue)
    }

    fn overflow_offset(&self, from: usize) -> usize {
        let Some(rest) = self.text.get(from..) else {
            return usize::MAX;
        };
        let mut len = self.snippet.len();
        let mut last_is_space = false;
        for (pos, char) in rest.char_indices() {
            if !char.is_whitespace() {
                last_is_space = false;
            } else {
                if last_is_space {
                    continue;
                }
                last_is_space = true;
            }
            len += escape_char_len(char);
            if len > MAX_SNIPPET_LEN {
                return from + pos;
            }
        }
        usize::MAX
    }
}

