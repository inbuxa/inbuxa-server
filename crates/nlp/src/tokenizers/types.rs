/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{Token, unicode::is_alphabetic};

mod scan;

const ASCII_SPACE: [bool; 256] = {
    let mut table = [false; 256];
    let mut byte = 0x09u8;
    while byte <= 0x0d {
        table[byte as usize] = true;
        byte += 1;
    }
    table[0x20] = true;
    table
};

#[cfg(inbuxa_tests)]
pub static TOKENIZED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const QUEUE_COMPACTION_HEAD: usize = 1024;
const CLASS_ALPHA: u8 = 1;
const CLASS_DIGIT: u8 = 2;

const ASCII_ALNUM: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = CLASS_ALPHA;
        table[(byte + 32) as usize] = CLASS_ALPHA;
        byte += 1;
    }
    let mut byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = CLASS_DIGIT;
        byte += 1;
    }
    table
};

type StopChar<'x> = (TokenType<&'x str, &'x str, &'x str, &'x str>, usize, bool);

#[inline(always)]
fn char_at(text: &str, pos: usize) -> Option<char> {
    text.get(pos..).and_then(|rest| rest.chars().next())
}

#[cfg(all(test, inbuxa_tests))]
pub(super) fn ascii_alnum_class(byte: u8) -> u8 {
    ASCII_ALNUM[byte as usize]
}

#[cfg(all(test, inbuxa_tests))]
pub(super) fn ascii_space_class(byte: u8) -> bool {
    ASCII_SPACE[byte as usize]
}

#[derive(Debug)]
pub struct TypesTokenizer<'x> {
    text: &'x str,
    pos: usize,
    tokens: Vec<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>>,
    head: usize,
    peek_pos: usize,
    last_ch_is_space: bool,
    last_token_is_dot: bool,
    next_at: NextByte,
    next_dot: NextByte,
    eof: bool,
    tokenize_urls: bool,
    tokenize_urls_without_scheme: bool,
    tokenize_emails: bool,
    tokenize_numbers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType<T, E, U, I> {
    Alphabetic(T),
    Alphanumeric(T),
    Integer(T),
    Other(char),
    Punctuation(char),
    Space,

    // Detected types
    Url(U),
    UrlNoScheme(U),
    UrlNoHost(T),
    IpAddr(I),
    Email(E),
    Float(T),
}

impl Copy for Token<TokenType<&'_ str, &'_ str, &'_ str, &'_ str>> {}

impl<'x> Iterator for TypesTokenizer<'x> {
    type Item = Token<TokenType<&'x str, &'x str, &'x str, &'x str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.peek()?;
        let last_is_dot = self.last_token_is_dot;
        self.last_token_is_dot = matches!(token.word, TokenType::Punctuation('.'));

        // Try parsing URL with scheme
        if self.tokenize_urls
            && let TokenType::Alphabetic(scheme) | TokenType::Alphanumeric(scheme) = token.word
            && scheme_may_follow(self.text, token.to)
            && scheme.len() <= 8
            && scheme.is_ascii()
            && self.try_skip_url_scheme()
        {
            if let Some(url) = self.try_parse_url(token.into()) {
                self.peek_advance();
                return Some(url);
            } else {
                self.peek_rewind();
            }
        }

        // Try parsing email
        if self.tokenize_emails
            && token.word.is_email_atom()
            && email_may_follow(self.text, token.to)
            && self
                .next_at
                .reachable(self.text, token.from, token.to, FOLLOW_EMAILISH)
        {
            self.peek_rewind();
            if let Some(email) = self.try_parse_email() {
                self.peek_advance();
                return Some(email);
            }
            self.peek_rewind();
        }

        // Try parsing URL without scheme
        if self.tokenize_urls_without_scheme
            && token.word.is_domain_atom(true)
            && host_may_follow(self.text, token.to)
            && self
                .next_dot
                .reachable(self.text, token.from, token.to, FOLLOW_HOSTISH)
        {
            self.peek_rewind();
            if let Some(url) = self.try_parse_url(None) {
                self.peek_advance();
                return Some(url);
            }
            self.peek_rewind();
        }

        // Try parsing currencies and floating point numbers
        if self.tokenize_numbers
            && !last_is_dot
            && let Some(num) = self.try_parse_number()
        {
            self.peek_advance();
            return Some(num);
        }

        self.peek_rewind();
        self.next_()
    }
}

impl<'x> TypesTokenizer<'x> {
    pub fn new(text: &'x str) -> Self {
        #[cfg(inbuxa_tests)]
        TOKENIZED_BYTES.fetch_add(text.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Self {
            text,
            pos: 0,
            tokens: Vec::new(),
            eof: false,
            head: 0,
            peek_pos: 0,
            last_ch_is_space: false,
            last_token_is_dot: false,
            next_at: NextByte::new(b'@'),
            next_dot: NextByte::new(b'.'),
            tokenize_urls: true,
            tokenize_urls_without_scheme: true,
            tokenize_emails: true,
            tokenize_numbers: true,
        }
    }

    pub fn tokenize_urls(mut self, tokenize: bool) -> Self {
        self.tokenize_urls = tokenize;
        self
    }

    pub fn tokenize_urls_without_scheme(mut self, tokenize: bool) -> Self {
        self.tokenize_urls_without_scheme = tokenize;
        self
    }

    pub fn tokenize_emails(mut self, tokenize: bool) -> Self {
        self.tokenize_emails = tokenize;
        self
    }

    pub fn tokenize_numbers(mut self, tokenize: bool) -> Self {
        self.tokenize_numbers = tokenize;
        self
    }

    fn consume(&mut self) -> bool {
        if self.head == self.tokens.len() {
            self.tokens.clear();
            self.head = 0;
        } else if self.head >= QUEUE_COMPACTION_HEAD {
            self.tokens.drain(..self.head);
            self.head = 0;
        }

        let bytes = self.text.as_bytes();
        let mut pos = self.pos;

        if self.last_ch_is_space {
            while let Some(&byte) = bytes.get(pos) {
                if byte < 0x80 {
                    if !ASCII_SPACE[byte as usize] {
                        break;
                    }
                    pos += 1;
                } else {
                    match char_at(self.text, pos) {
                        Some(ch) if ch.is_whitespace() => pos += ch.len_utf8(),
                        _ => break,
                    }
                }
            }
        }

        let start_pos = pos;
        let (end_pos, classes, stop_char) = scan::scan_word(self.text, pos);
        pos = end_pos;

        if end_pos != start_pos {
            self.last_ch_is_space = false;
        }

        let stop_char = stop_char.map(|(word, len, is_space)| {
            let from = pos;
            pos += len;
            self.last_ch_is_space = is_space;
            Token {
                word,
                from,
                to: from + len,
            }
        });
        self.pos = pos;

        if end_pos != start_pos {
            let text = &self.text[start_pos..end_pos];

            self.tokens.push(Token {
                word: if classes == CLASS_ALPHA | CLASS_DIGIT {
                    TokenType::Alphanumeric(text)
                } else if classes == CLASS_ALPHA {
                    TokenType::Alphabetic(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            });
            if let Some(stop_char) = stop_char {
                self.tokens.push(stop_char);
            }
            true
        } else if let Some(stop_char) = stop_char {
            self.tokens.push(stop_char);
            true
        } else {
            self.eof = true;
            false
        }
    }

    fn next_(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        if self.head == self.tokens.len() && !self.eof {
            self.consume();
        }
        match self.tokens.get(self.head) {
            Some(&token) => {
                self.head += 1;
                Some(token)
            }
            None => None,
        }
    }

    fn peek(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        while self.tokens.len() - self.head <= self.peek_pos && !self.eof {
            self.consume();
        }
        debug_assert!(self.head + self.peek_pos <= self.tokens.len());
        match self.tokens.get(self.head + self.peek_pos) {
            Some(&token) => {
                self.peek_pos += 1;
                Some(token)
            }
            None => None,
        }
    }

    fn peek_advance(&mut self) {
        debug_assert!(self.head + self.peek_pos <= self.tokens.len());
        self.head += self.peek_pos;
        self.peek_pos = 0;
    }

    #[inline(always)]
    fn peek_rewind(&mut self) {
        self.peek_pos = 0;
    }

    fn try_parse_url(
        &mut self,
        scheme_token: Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>>,
    ) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        let (has_scheme, allow_blank_host) = scheme_token.as_ref().map_or((false, false), |t| {
            (
                true,
                matches!(t.word, TokenType::Alphabetic(s) if s.eq_ignore_ascii_case("file")),
            )
        });
        if has_scheme {
            let restore_pos = self.peek_pos;
            let mut has_user_info = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Punctuation('@') => {
                        has_user_info = true;
                        break;
                    }
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Punctuation(
                        '-' | '.' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+'
                        | ',' | ';' | '=' | ':',
                    ) => (),
                    _ => break,
                }
            }

            if !has_user_info {
                self.peek_pos = restore_pos;
            }
        }

        // Try parsing hostname
        let mut is_valid_host = true;
        let (host_start_pos, mut end_pos, is_ip) = if has_scheme {
            let mut start_pos = usize::MAX;
            let mut end_pos = usize::MAX;
            let mut restore_pos = self.peek_pos;

            let mut text_count = 0;
            let mut int_count = 0;
            let mut dot_count = 0;
            let mut is_ipv6 = false;

            let mut last_label = None;

            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) => {
                        last_label = Some(text);
                        text_count += 1;
                    }
                    TokenType::Integer(text) => {
                        if text.len() <= 3 {
                            int_count += 1;
                        }
                    }
                    TokenType::Punctuation('.') => {
                        dot_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') if start_pos == usize::MAX => {
                        let (_, to) = self.try_parse_ipv6(token.from)?;
                        start_pos = token.from;
                        end_pos = to;
                        restore_pos = self.peek_pos;
                        is_ipv6 = true;
                        break;
                    }
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ','
                        | ';' | '=' | ':' | '%',
                    ) => {
                        continue;
                    }
                    TokenType::Punctuation('/') if allow_blank_host => {
                        // Allow file://../ urls
                        end_pos = token.from;
                        restore_pos = self.peek_pos - 1;
                        break;
                    }
                    _ => break,
                }

                if start_pos == usize::MAX {
                    start_pos = token.from;
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }

            self.peek_pos = restore_pos;
            let is_ip = is_ipv6 || (int_count == 4 && dot_count == 3 && text_count == 0);
            if end_pos != usize::MAX {
                is_valid_host = is_ip
                    || (dot_count >= 1
                        && (text_count + int_count) >= 2
                        && last_label_is_tld(last_label));
                (start_pos, end_pos, is_ip)
            } else {
                return None;
            }
        } else {
            // Strict hostname parsing
            self.try_parse_hostname()?
        };

        // Try parsing port
        let start_pos = scheme_token.map(|t| t.from).unwrap_or(host_start_pos);
        let mut restore_pos = self.peek_pos;
        let mut has_port = false;
        let mut last_is_colon = false;
        let mut found_query_start = false;
        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation(':') if !last_is_colon && !has_port => {
                    last_is_colon = true;
                }
                TokenType::Integer(_) if last_is_colon => {
                    has_port = true;
                    last_is_colon = false;
                    restore_pos = self.peek_pos;
                    end_pos = token.to;
                }
                TokenType::Punctuation('/' | '?') if !last_is_colon => {
                    found_query_start = true;
                    end_pos = token.to;
                    break;
                }
                _ => {
                    self.peek_pos = restore_pos;
                    break;
                }
            }
        }

        // Try parsing query
        if found_query_start {
            restore_pos = self.peek_pos;
            let mut p_count = 0;
            let mut b_count = 0;
            let mut c_count = 0;
            let mut seen_quote = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Other(_) => {}
                    TokenType::Punctuation('(') => {
                        p_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') => {
                        b_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('{') => {
                        c_count += 1;
                        continue;
                    }
                    TokenType::Punctuation(')') if p_count > 0 => {
                        p_count -= 1;
                    }
                    TokenType::Punctuation(']') if b_count > 0 => {
                        b_count -= 1;
                    }
                    TokenType::Punctuation('}') if c_count > 0 => {
                        c_count -= 1;
                    }
                    TokenType::Punctuation('\'') => {
                        if !seen_quote {
                            seen_quote = true;
                            continue;
                        } else {
                            seen_quote = false;
                        }
                    }
                    TokenType::Punctuation('/') => {}
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '*' | '+' | ',' | ';' | '=' | ':' | '%'
                        | '?' | '.' | '@',
                    ) => {
                        continue;
                    }
                    _ => break,
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }
            self.peek_pos = restore_pos;
        }

        let word = &self.text[start_pos..end_pos];
        Token {
            word: if has_scheme {
                if is_valid_host {
                    TokenType::Url(word)
                } else {
                    TokenType::UrlNoHost(word)
                }
            } else if is_ip && !found_query_start {
                TokenType::IpAddr(word)
            } else {
                TokenType::UrlNoScheme(word)
            },
            from: start_pos,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_email(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        // Start token is a valid local part atom
        let start_token = self.peek()?;
        let mut last_is_dot = false;

        // Find local part
        loop {
            let token = self.peek()?;
            if token.to - start_token.from > 255 {
                return None;
            }
            match token.word {
                word if word.is_email_atom() => {
                    last_is_dot = false;
                }
                TokenType::Punctuation('@') if !last_is_dot => {
                    break;
                }
                TokenType::Punctuation('.') if !last_is_dot => {
                    last_is_dot = true;
                }
                _ => {
                    return None;
                }
            }
        }

        // Obtain domain part
        let (_, end_pos, _) = self.try_parse_hostname()?;

        Token {
            word: TokenType::Email(&self.text[start_token.from..end_pos]),
            from: start_token.from,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_hostname(&mut self) -> Option<(usize, usize, bool)> {
        let mut last_ch = u8::MAX;
        let mut has_int = false;
        let mut has_alpha = false;
        let mut last_label = None;

        let mut dot_count = 0;
        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('.') if last_ch == 0 && start_pos != usize::MAX => {
                    last_ch = b'.';
                    dot_count += 1;
                    continue;
                }
                TokenType::Punctuation('-') if last_ch == 0 || last_ch == b'-' => {
                    last_ch = b'-';
                    continue;
                }
                TokenType::Punctuation('[') if start_pos == usize::MAX => {
                    return self
                        .try_parse_ipv6(token.from)
                        .map(|(from, to)| (from, to, true));
                }
                TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) if text.len() <= 63 => {
                    last_label = Some(text);
                    has_alpha = true;
                    last_ch = 0;
                }
                TokenType::Other(_) => {
                    has_alpha = true;
                    last_label = None;
                    last_ch = 0;
                }
                TokenType::Integer(text) => {
                    if text.len() <= 3 {
                        has_int = true;
                    }
                    last_label = None;
                    last_ch = 0;
                }
                _ => {
                    break;
                }
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;

            if end_pos - start_pos > 255 {
                return None;
            }
        }
        self.peek_pos = restore_pos;

        if last_ch == b'.' {
            dot_count -= 1;
        }

        let is_ipv4 = has_int && !has_alpha && dot_count == 3;
        if end_pos != usize::MAX && dot_count >= 1 && (is_ipv4 || last_label_is_tld(last_label)) {
            (start_pos, end_pos, is_ipv4).into()
        } else {
            None
        }
    }

    fn try_parse_ipv6(&mut self, start_pos: usize) -> Option<(usize, usize)> {
        let mut found_colon = false;
        let mut last_ch = u8::MAX;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Integer(_) | TokenType::Alphanumeric(_) => {
                    last_ch = 0;
                }
                TokenType::Punctuation(':') if last_ch != b'.' => {
                    found_colon = true;
                    last_ch = b':';
                }
                TokenType::Punctuation('.') if last_ch == 0 => {
                    last_ch = b'.';
                }
                TokenType::Punctuation(']') if found_colon && last_ch == 0 => {
                    return (start_pos, token.to).into();
                }
                _ => return None,
            }
        }

        None
    }

    fn try_parse_number(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        self.peek_rewind();
        if let Some(token) = self.tokens.get(self.head)
            && !matches!(
                token.word,
                TokenType::Integer(_) | TokenType::Punctuation('-')
            )
        {
            return None;
        }

        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        let mut seen_integer = 0;
        let mut seen_dot = false;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('-') if start_pos == usize::MAX => {}
                TokenType::Integer(_) if seen_integer == 0 || seen_dot => {
                    seen_integer += 1;
                }
                TokenType::Punctuation('.') if seen_integer != 0 => {
                    if !seen_dot {
                        seen_dot = true;
                        continue;
                    } else {
                        // Avoid parsing num.num.num as floats
                        return None;
                    }
                }
                _ => break,
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;
        }

        self.peek_pos = restore_pos;

        if seen_integer > 0 {
            let text = &self.text[start_pos..end_pos];

            Token {
                word: if seen_integer == 2 {
                    TokenType::Float(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            }
            .into()
        } else {
            None
        }
    }

    fn try_skip_url_scheme(&mut self) -> bool {
        if let Some(token) = self.tokens.get(self.head + self.peek_pos)
            && !matches!(token.word, TokenType::Punctuation(':' | '+'))
        {
            self.peek_pos = 0;
            return false;
        }

        enum State {
            None,
            PlusAlpha,
            Colon,
            Slash1,
            Slash2,
        }
        let mut state = State::None;

        while let Some(token) = self.peek() {
            state = match (token.word, state) {
                (TokenType::Punctuation(':'), State::None | State::Colon) => State::Slash1,
                (TokenType::Punctuation('/'), State::Slash1) => State::Slash2,
                (TokenType::Punctuation('/'), State::Slash2) => return true,
                (TokenType::Punctuation('+'), State::None) => State::PlusAlpha,
                (TokenType::Alphabetic(t) | TokenType::Alphanumeric(t), State::PlusAlpha)
                    if t.is_ascii() =>
                {
                    State::Colon
                }
                _ => break,
            };
        }
        self.peek_rewind();
        false
    }
}

const FOLLOW_RUN: u8 = 1 << 0;
const FOLLOW_EMAIL_PUNCT: u8 = 1 << 1;
const FOLLOW_DOT: u8 = 1 << 2;
const FOLLOW_AT: u8 = 1 << 3;
const FOLLOW_HYPHEN: u8 = 1 << 4;
const FOLLOW_NON_ASCII: u8 = 1 << 5;

const FOLLOW_CLASS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        let byte = index as u8;
        let mut class = 0;
        if byte.is_ascii_alphanumeric() {
            class |= FOLLOW_RUN;
        }
        if matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        ) {
            class |= FOLLOW_EMAIL_PUNCT;
        }
        if byte == b'.' {
            class |= FOLLOW_DOT;
        }
        if byte == b'@' {
            class |= FOLLOW_AT;
        }
        if byte == b'-' {
            class |= FOLLOW_HYPHEN;
        }
        if byte >= 0x80 {
            class |= FOLLOW_NON_ASCII;
        }
        table[index] = class;
        index += 1;
    }
    table
};

#[inline(always)]
fn follow_class(text: &str, at: usize) -> u8 {
    match text.as_bytes().get(at) {
        Some(&byte) => FOLLOW_CLASS[byte as usize],
        None => 0,
    }
}

const FOLLOW_EMAILISH: u8 = FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_DOT | FOLLOW_NON_ASCII;
const FOLLOW_HOSTISH: u8 = FOLLOW_RUN | FOLLOW_DOT | FOLLOW_HYPHEN | FOLLOW_NON_ASCII;

const REACH_SCAN: usize = 8;
const REACH_LIMIT: usize = 255;

#[derive(Debug, Clone, Copy)]
struct NextByte {
    byte: u8,
    searched_from: usize,
    found: usize,
}

impl NextByte {
    const fn new(byte: u8) -> Self {
        NextByte {
            byte,
            searched_from: usize::MAX,
            found: 0,
        }
    }

    #[inline(always)]
    fn reachable(&mut self, text: &str, from: usize, at: usize, allowed: u8) -> bool {
        let bytes = text.as_bytes();
        let limit = bytes.len().min(from.saturating_add(REACH_LIMIT));
        let Some(window) = bytes.get(at..limit) else {
            return false;
        };
        for &byte in window.iter().take(REACH_SCAN) {
            if byte == self.byte {
                return true;
            }
            if FOLLOW_CLASS[byte as usize] & allowed == 0 {
                return false;
            }
        }
        window.len() > REACH_SCAN
            && self.reachable_beyond_scan(bytes, at + REACH_SCAN, limit, allowed)
    }

    #[inline(never)]
    fn reachable_beyond_scan(
        &mut self,
        bytes: &[u8],
        at: usize,
        limit: usize,
        allowed: u8,
    ) -> bool {
        if at < self.searched_from || at > self.found {
            self.searched_from = at;
            self.found = bytes
                .get(at..)
                .and_then(|rest| memchr::memchr(self.byte, rest))
                .map_or(bytes.len(), |offset| at + offset);
        }
        self.found < limit
            && bytes.get(at..self.found).is_some_and(|between| {
                between
                    .iter()
                    .all(|&byte| FOLLOW_CLASS[byte as usize] & allowed != 0)
            })
    }
}

#[inline(always)]
fn scheme_may_follow(text: &str, at: usize) -> bool {
    matches!(text.as_bytes().get(at), Some(b':' | b'+'))
}

#[inline(always)]
fn email_may_follow(text: &str, at: usize) -> bool {
    let class = follow_class(text, at);
    if class & (FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_AT | FOLLOW_NON_ASCII) != 0 {
        true
    } else {
        class & FOLLOW_DOT != 0
            && follow_class(text, at + 1) & (FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_NON_ASCII)
                != 0
    }
}

#[inline(always)]
fn host_may_follow(text: &str, at: usize) -> bool {
    let class = follow_class(text, at);
    if class & (FOLLOW_RUN | FOLLOW_HYPHEN | FOLLOW_NON_ASCII) != 0 {
        true
    } else {
        class & FOLLOW_DOT != 0 && follow_class(text, at + 1) & (FOLLOW_RUN | FOLLOW_NON_ASCII) != 0
    }
}

#[inline(always)]
fn last_label_is_tld(label: Option<&str>) -> bool {
    match label {
        Some(text) if text.len() >= 2 => is_public_suffix(text),
        _ => false,
    }
}

#[inline(never)]
fn is_public_suffix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if !bytes.iter().any(u8::is_ascii_uppercase) {
        return has_suffix_type(bytes);
    }
    let mut buf = [0u8; 64];
    match buf.get_mut(..bytes.len()) {
        Some(lowered) => {
            for (dst, src) in lowered.iter_mut().zip(bytes) {
                *dst = src.to_ascii_lowercase();
            }
            has_suffix_type(lowered)
        }
        None => has_suffix_type(text.to_ascii_lowercase().as_bytes()),
    }
}

#[inline(always)]
fn has_suffix_type(label: &[u8]) -> bool {
    psl::Psl::find(&psl::List, [label].into_iter())
        .typ
        .is_some()
}

impl<T, E, U, I> TokenType<T, E, U, I> {
    fn is_email_atom(&self) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
                | TokenType::Punctuation(
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~',
                )
        )
    }

    fn is_domain_atom(&self, is_start: bool) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
        ) || (!is_start && matches!(self, TokenType::Punctuation('-')))
    }
}

