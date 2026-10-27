/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{functions::lookup_function, *};
use registry::{schema::enums::ExpressionConstant, types::EnumImpl};
use trc::MetricType;

pub struct Tokenizer<'x> {
    input: &'x str,
    pos: usize,
    word_start: usize,
    word_end: usize,
    token_map: &'x TokenMap,
    depth: u32,
    next_token: Option<Token>,
    has_number: bool,
    has_dot: bool,
    has_alpha: bool,
    is_start: bool,
    is_eof: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TokenMap {
    variables: IdSet<{ ExpressionVariable::COUNT.div_ceil(64) }>,
    constants: IdSet<{ ExpressionConstant::COUNT.div_ceil(64) }>,
}

#[derive(Debug, Clone, Copy)]
struct IdSet<const WORDS: usize>([u64; WORDS]);

impl<'x> Tokenizer<'x> {
    #[allow(clippy::should_implement_trait)]
    pub fn new(expr: &'x str, token_map: &'x TokenMap) -> Self {
        Self {
            input: expr,
            pos: 0,
            word_start: 0,
            word_end: 0,
            depth: 0,
            next_token: None,
            has_number: false,
            has_dot: false,
            has_alpha: false,
            is_start: true,
            is_eof: false,
            token_map,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Token>, String> {
        if let Some(token) = self.next_token.take() {
            return Ok(Some(token));
        } else if self.is_eof {
            return Ok(None);
        }

        while let Some(ch) = self.next_byte() {
            match ch {
                b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$' | b'0'..=b'9' | b'.' => {
                    self.push_word();
                    self.scan_word(ch);
                }
                b'}' => {
                    self.is_eof = true;
                    break;
                }
                b'-' if self.word().last().is_some_and(|c| *c == b'[') => {
                    self.push_word();
                }
                b':' if self.has_dot => {
                    self.push_word();
                }
                b']' if self.word().contains(&b'[') => {
                    self.push_word();
                }
                b'*' if self.word().last().is_some_and(|&c| c == b'[' || c == b'.') => {
                    self.push_word();
                }
                _ => {
                    let (prev_token, ch) = if ch == b'(' && !self.word().is_empty() {
                        hashify::fnc_map!(self.word(),
                            "matches" => {
                                let stop_ch = self.find_char(b"\"'")?;
                                let regex_str = self.parse_string(stop_ch)?;
                                let regex = CaptureRegex::new(&regex_str)?;
                                self.has_alpha = false;
                                self.clear_word();
                                self.find_char(b",")?;
                                (Token::Regex(regex).into(), b'(')
                            },
                            "metric" => {
                                let stop_ch = self.find_char(b"\"'")?;
                                let metric_str = self.parse_string(stop_ch)?;
                                let metric = MetricType::parse(&metric_str).ok_or_else(|| {
                                    format!("Invalid metric name {:?}", metric_str)
                                })?;
                                self.has_alpha = false;
                                self.clear_word();
                                (Token::System(SystemVariable::Metric(metric)).into(), b'(')
                            },
                            "system" => {
                                let stop_ch = self.find_char(b"\"'")?;
                                let name = self.parse_string(stop_ch)?;
                                let var = SystemVariable::parse(&name).ok_or_else(|| {
                                    format!("Invalid system variable name {:?}", name)
                                })?;
                                self.has_alpha = false;
                                self.clear_word();
                                (Token::System(var).into(), b'(')
                            },
                            _ => {
                                self.is_start = false;
                                (self.parse_word()?.into(), ch)
                            }
                        )
                    } else if !self.word().is_empty() {
                        self.is_start = false;
                        (self.parse_word()?.into(), ch)
                    } else {
                        (None, ch)
                    };
                    let token = match ch {
                        b'&' => {
                            if self.peek_byte() == Some(b'&') {
                                self.pos += 1;
                            }
                            Token::BinaryOperator(BinaryOperator::And)
                        }
                        b'|' => {
                            if self.peek_byte() == Some(b'|') {
                                self.pos += 1;
                            }
                            Token::BinaryOperator(BinaryOperator::Or)
                        }
                        b'!' => {
                            if self.peek_byte() == Some(b'=') {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Ne)
                            } else {
                                Token::UnaryOperator(UnaryOperator::Not)
                            }
                        }
                        b'^' => Token::BinaryOperator(BinaryOperator::Xor),
                        b'(' => {
                            self.depth += 1;
                            Token::OpenParen
                        }
                        b')' => {
                            if self.depth == 0 {
                                return Err("Unmatched close parenthesis".to_string());
                            }
                            self.depth -= 1;
                            Token::CloseParen
                        }
                        b'+' => Token::BinaryOperator(BinaryOperator::Add),
                        b'*' => Token::BinaryOperator(BinaryOperator::Multiply),
                        b'/' => Token::BinaryOperator(BinaryOperator::Divide),
                        b'-' => {
                            if self.is_start {
                                Token::UnaryOperator(UnaryOperator::Minus)
                            } else {
                                Token::BinaryOperator(BinaryOperator::Subtract)
                            }
                        }
                        b'=' => match self.peek_byte() {
                            Some(b'=') => {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Eq)
                            }
                            Some(b'>') => {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Ge)
                            }
                            Some(b'<') => {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Le)
                            }
                            _ => Token::BinaryOperator(BinaryOperator::Eq),
                        },
                        b'>' => match self.peek_byte() {
                            Some(b'=') => {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Ge)
                            }
                            _ => Token::BinaryOperator(BinaryOperator::Gt),
                        },
                        b'<' => match self.peek_byte() {
                            Some(b'=') => {
                                self.pos += 1;
                                Token::BinaryOperator(BinaryOperator::Le)
                            }
                            _ => Token::BinaryOperator(BinaryOperator::Lt),
                        },
                        b',' => Token::Comma,
                        b'[' => Token::OpenBracket,
                        b']' => Token::CloseBracket,
                        b' ' | b'\r' | b'\n' => {
                            if prev_token.is_some() {
                                return Ok(prev_token);
                            } else {
                                continue;
                            }
                        }
                        b'\"' | b'\'' => Token::Constant(Constant::String(self.parse_string(ch)?)),
                        _ => {
                            return Err(format!("Invalid character {:?}", char::from(ch),));
                        }
                    };
                    self.is_start = matches!(
                        token,
                        Token::OpenParen | Token::Comma | Token::BinaryOperator(_)
                    );

                    return if prev_token.is_some() {
                        self.next_token = Some(token);
                        Ok(prev_token)
                    } else {
                        Ok(Some(token))
                    };
                }
            }
        }

        if self.depth > 0 {
            Err("Unmatched open parenthesis".to_string())
        } else if !self.word().is_empty() {
            self.parse_word().map(Some)
        } else {
            Ok(None)
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let ch = *self.input.as_bytes().get(self.pos)?;
        self.pos += 1;
        Some(ch)
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn word(&self) -> &'x [u8] {
        self.input
            .as_bytes()
            .get(self.word_start..self.word_end)
            .unwrap_or_default()
    }

    fn push_word(&mut self) {
        if self.word_start == self.word_end {
            self.word_start = self.pos - 1;
        }
        self.word_end = self.pos;
    }

    fn scan_word(&mut self, first: u8) {
        self.mark_word_class(first);
        while let Some(&ch) = self.input.as_bytes().get(self.pos) {
            if !self.mark_word_class(ch) {
                break;
            }
            self.pos += 1;
        }
        self.word_end = self.pos;
    }

    fn mark_word_class(&mut self, ch: u8) -> bool {
        match ch {
            b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$' => self.has_alpha = true,
            b'0'..=b'9' => self.has_number = true,
            b'.' => self.has_dot = true,
            _ => return false,
        }
        true
    }

    fn clear_word(&mut self) {
        self.word_end = self.word_start;
    }

    fn find_char(&mut self, chars: &[u8]) -> Result<u8, String> {
        while let Some(ch) = self.next_byte() {
            if !ch.is_ascii_whitespace() {
                return if chars.contains(&ch) {
                    Ok(ch)
                } else {
                    Err(format!(
                        "Expected {:?}, found invalid character {:?}",
                        char::from(chars.first().copied().unwrap_or_default()),
                        char::from(ch),
                    ))
                };
            }
        }

        Err("Unexpected end of expression".to_string())
    }

    fn parse_string(&mut self, stop_ch: u8) -> Result<CompactString, String> {
        let start = self.pos;
        let mut last_ch = 0;
        let mut translate = false;

        while let Some(ch) = self.next_byte() {
            if last_ch != b'\\' {
                if ch == stop_ch {
                    let raw = self.input.get(start..self.pos - 1);
                    return match raw {
                        Some(raw) if !translate => Ok(CompactString::from(raw)),
                        Some(raw) => CompactString::from_utf8(unescape(raw.as_bytes()))
                            .map_err(|_| "Invalid UTF-8".into()),
                        None => Err("Invalid UTF-8".into()),
                    };
                }
            } else if matches!(ch, b'n' | b'r' | b't') {
                translate = true;
            }
            last_ch = ch;
        }

        Err("Unterminated string".to_string())
    }

    fn parse_word(&mut self) -> Result<Token, String> {
        let word = self
            .input
            .get(self.word_start..self.word_end)
            .unwrap_or_default();
        let has_number = self.has_number;
        let has_alpha = self.has_alpha;
        let has_dot = self.has_dot;
        self.clear_word();
        self.has_alpha = false;
        self.has_number = false;
        self.has_dot = false;

        if has_number && !has_alpha {
            if has_dot {
                word.parse::<f64>()
                    .map(|f| Token::Constant(Constant::Float(f)))
                    .map_err(|_| format!("Invalid float value {}", word,))
            } else {
                word.parse::<i64>()
                    .map(|i| Token::Constant(Constant::Integer(i)))
                    .map_err(|_| format!("Invalid integer value {}", word,))
            }
        } else if let Some(value) = hashify::map!(word.as_bytes(), i64, "true" => 1, "false" => 0) {
            Ok(Token::Constant(Constant::Integer(*value)))
        } else if let Some(variable) = word.strip_prefix('$').filter(|s| !s.is_empty()) {
            if variable.chars().all(|c| c.is_ascii_digit()) {
                Ok(variable
                    .parse::<u32>()
                    .map(Token::Capture)
                    .unwrap_or_else(|_| Token::Global(variable.into())))
            } else {
                Ok(Token::Global(variable.into()))
            }
        } else if let Some(function) = lookup_function(word) {
            Ok(Token::Function {
                name: function.name,
                id: function.id,
                num_args: function.num_args,
            })
        } else if let Some(variable) = ExpressionVariable::parse(word) {
            if self.token_map.variables.allows(variable.to_id()) {
                Ok(Token::Variable(variable))
            } else {
                Err(format!("Variable {:?} not allowed in this context", word))
            }
        } else if let Some(constant) = ExpressionConstant::parse(word) {
            if self.token_map.constants.allows(constant.to_id()) {
                Ok(Token::Constant(Constant::Static(constant)))
            } else {
                Err(format!("Constant {:?} not allowed in this context", word))
            }
        } else if let Ok(duration) = registry::types::duration::Duration::from_str(word) {
            Ok(Token::Constant(Constant::Integer(
                duration.as_millis() as i64
            )))
        } else {
            Err(format!("Invalid variable or constant {word:?}"))
        }
    }
}

fn unescape(raw: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(raw.len());
    let mut last_ch = 0;
    for &ch in raw {
        if last_ch != b'\\' {
            buf.push(ch);
        } else {
            buf.push(match ch {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                _ => ch,
            });
        }
        last_ch = ch;
    }
    buf
}

impl TokenMap {
    pub fn with_variables(mut self, variables: &[ExpressionVariable]) -> Self {
        for variable in variables {
            self.variables.insert(variable.to_id());
        }
        self
    }

    pub fn with_constants(mut self, constants: &[ExpressionConstant]) -> Self {
        for constant in constants {
            self.constants.insert(constant.to_id());
        }
        self
    }
}

impl<const WORDS: usize> IdSet<WORDS> {
    const BITS: usize = u64::BITS as usize;

    fn insert(&mut self, id: u16) {
        let id = id as usize;
        if let Some(word) = self.0.get_mut(id / Self::BITS) {
            *word |= 1 << (id % Self::BITS);
        }
    }

    fn allows(&self, id: u16) -> bool {
        let id = id as usize;
        self.0.iter().all(|word| *word == 0)
            || self
                .0
                .get(id / Self::BITS)
                .is_some_and(|word| word & (1 << (id % Self::BITS)) != 0)
    }
}

impl<const WORDS: usize> Default for IdSet<WORDS> {
    fn default() -> Self {
        IdSet([0; WORDS])
    }
}

