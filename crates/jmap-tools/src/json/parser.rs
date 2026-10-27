/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::json::key::Key;
use crate::json::object_vec::ObjectAsVec;
use crate::json::value::Value;
use crate::{Element, Property};
use std::borrow::Cow;

const MAX_DEPTH: u8 = 128;
const ONES: u64 = u64::MAX / 255;
const HIGH: u64 = ONES << 7;
const QUOTES: u64 = ONES * b'"' as u64;
const BACKSLASHES: u64 = ONES * b'\\' as u64;
const CONTROLS: u64 = ONES * 0x20;
const SWAR_LIMIT: usize = 128;
const BLOCK: usize = 128;

#[derive(Clone, Copy)]
enum Code {
    EofWhileParsingList,
    EofWhileParsingObject,
    EofWhileParsingString,
    EofWhileParsingValue,
    ExpectedColon,
    ExpectedListCommaOrEnd,
    ExpectedObjectCommaOrEnd,
    ExpectedSomeIdent,
    ExpectedSomeValue,
    InvalidEscape,
    InvalidNumber,
    NumberOutOfRange,
    ControlCharacterWhileParsingString,
    KeyMustBeAString,
    LoneLeadingSurrogateInHexEscape,
    TrailingComma,
    TrailingCharacters,
    UnexpectedEndOfHexEscape,
    RecursionLimitExceeded,
}

impl Code {
    fn as_str(self) -> &'static str {
        match self {
            Code::EofWhileParsingList => "EOF while parsing a list",
            Code::EofWhileParsingObject => "EOF while parsing an object",
            Code::EofWhileParsingString => "EOF while parsing a string",
            Code::EofWhileParsingValue => "EOF while parsing a value",
            Code::ExpectedColon => "expected `:`",
            Code::ExpectedListCommaOrEnd => "expected `,` or `]`",
            Code::ExpectedObjectCommaOrEnd => "expected `,` or `}`",
            Code::ExpectedSomeIdent => "expected ident",
            Code::ExpectedSomeValue => "expected value",
            Code::InvalidEscape => "invalid escape",
            Code::InvalidNumber => "invalid number",
            Code::NumberOutOfRange => "number out of range",
            Code::ControlCharacterWhileParsingString => {
                "control character (\\u0000-\\u001F) found while parsing a string"
            }
            Code::KeyMustBeAString => "key must be a string",
            Code::LoneLeadingSurrogateInHexEscape => "lone leading surrogate in hex escape",
            Code::TrailingComma => "trailing comma",
            Code::TrailingCharacters => "trailing characters",
            Code::UnexpectedEndOfHexEscape => "unexpected end of hex escape",
            Code::RecursionLimitExceeded => "recursion limit exceeded",
        }
    }
}

struct Failure {
    code: Code,
    index: usize,
}

impl Failure {
    #[cold]
    fn message(self, bytes: &[u8]) -> String {
        let head = bytes.get(..self.index).unwrap_or(bytes);
        let mut lines = head.rsplit(|&byte| byte == b'\n');
        let column = lines.next().map_or(0, <[u8]>::len);
        let line = 1 + lines.count();
        format!("{} at line {line} column {column}", self.code.as_str())
    }
}

type Parsed<T> = Result<T, Failure>;

enum Text<'x> {
    Borrowed(&'x str),
    Copied,
}

#[derive(Clone, Copy)]
struct Unscanned<'x>(&'x [u8]);

pub(crate) struct Parser<'x, P: Property, E: Element> {
    text: &'x str,
    bytes: &'x [u8],
    index: usize,
    depth: u8,
    opaque: bool,
    scratch: String,
    members: Vec<(Key<'x, P>, Value<'x, P, E>)>,
    items: Vec<Value<'x, P, E>>,
}

impl<'x, P: Property, E: Element<Property = P>> Parser<'x, P, E> {
    pub(crate) fn parse(json: &'x str) -> Result<Value<'x, P, E>, String> {
        Parser::new(json)
            .document()
            .map_err(|failure| failure.message(json.as_bytes()))
    }

    fn new(json: &'x str) -> Self {
        Parser {
            text: json,
            bytes: json.as_bytes(),
            index: 0,
            depth: MAX_DEPTH,
            opaque: false,
            scratch: String::new(),
            members: Vec::new(),
            items: Vec::new(),
        }
    }

    fn document(&mut self) -> Parsed<Value<'x, P, E>> {
        let value = self.value(None)?;
        match self.whitespace() {
            Some(_) => Err(self.peek_error(Code::TrailingCharacters)),
            None => Ok(value),
        }
    }

    #[inline(always)]
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    #[inline(always)]
    fn peek_or_null(&self) -> u8 {
        self.bytes.get(self.index).copied().unwrap_or(0)
    }

    #[inline(always)]
    fn next_char(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.index).copied();
        if byte.is_some() {
            self.index += 1;
        }
        byte
    }

    #[inline(always)]
    fn eat_char(&mut self) {
        self.index += 1;
    }

    #[cold]
    fn error(&self, code: Code) -> Failure {
        Failure {
            code,
            index: self.index,
        }
    }

    #[cold]
    fn peek_error(&self, code: Code) -> Failure {
        Failure {
            code,
            index: self.bytes.len().min(self.index + 1),
        }
    }

    #[inline(always)]
    fn whitespace(&mut self) -> Option<u8> {
        loop {
            match self.peek() {
                Some(b' ' | b'\n' | b'\t' | b'\r') => self.eat_char(),
                other => return other,
            }
        }
    }

    fn value(&mut self, parent: Option<&Key<'_, P>>) -> Parsed<Value<'x, P, E>> {
        let Some(peek) = self.whitespace() else {
            return Err(self.peek_error(Code::EofWhileParsingValue));
        };
        match peek {
            b'"' => {
                self.eat_char();
                Ok(match self.string()? {
                    Text::Borrowed(text) => match Self::element(parent, text) {
                        Some(element) => Value::Element(element),
                        None => Value::Str(Cow::Borrowed(text)),
                    },
                    Text::Copied => match Self::element(parent, &self.scratch) {
                        Some(element) => Value::Element(element),
                        None => Value::Str(Cow::Owned(self.scratch.as_str().to_owned())),
                    },
                })
            }
            b'{' => {
                self.enter()?;
                let object = self.object(parent);
                self.depth += 1;
                let object = object?;
                self.eat_char();
                Ok(object)
            }
            b'[' => {
                self.enter()?;
                let array = self.array(parent);
                self.depth += 1;
                let array = array?;
                self.eat_char();
                Ok(array)
            }
            b'-' => {
                self.eat_char();
                self.integer(false)
            }
            b'0'..=b'9' => self.integer(true),
            b'n' => {
                self.eat_char();
                self.ident(b"ull").map(|_| Value::Null)
            }
            b't' => {
                self.eat_char();
                self.ident(b"rue").map(|_| Value::Bool(true))
            }
            b'f' => {
                self.eat_char();
                self.ident(b"alse").map(|_| Value::Bool(false))
            }
            _ => Err(self.peek_error(Code::ExpectedSomeValue)),
        }
    }

    #[inline(always)]
    fn element(parent: Option<&Key<'_, P>>, text: &str) -> Option<E> {
        parent
            .filter(|key| !key.is_opaque())
            .and_then(|key| E::try_parse::<P>(key, text))
    }

    #[inline(always)]
    fn enter(&mut self) -> Parsed<()> {
        self.depth -= 1;
        if self.depth == 0 {
            return Err(self.peek_error(Code::RecursionLimitExceeded));
        }
        self.eat_char();
        Ok(())
    }

    fn object(&mut self, parent: Option<&Key<'_, P>>) -> Parsed<Value<'x, P, E>> {
        let outer = self.opaque;
        let opaque = outer || parent.is_some_and(Key::is_opaque);
        self.opaque = opaque;
        let start = self.members.len();
        let mut first = true;
        loop {
            let Some(peek) = self.whitespace() else {
                return Err(self.peek_error(Code::EofWhileParsingObject));
            };
            if peek == b'}' {
                break;
            }
            if first {
                first = false;
                if peek != b'"' {
                    return Err(self.peek_error(Code::KeyMustBeAString));
                }
            } else if peek == b',' {
                self.eat_char();
                match self.whitespace() {
                    Some(b'"') => {}
                    Some(b'}') => return Err(self.peek_error(Code::TrailingComma)),
                    Some(_) => return Err(self.peek_error(Code::KeyMustBeAString)),
                    None => return Err(self.peek_error(Code::EofWhileParsingValue)),
                }
            } else {
                return Err(self.peek_error(Code::ExpectedObjectCommaOrEnd));
            }
            self.eat_char();
            let key = match self.string()? {
                Text::Borrowed(text) if opaque => Key::Borrowed(text),
                Text::Copied if opaque => Key::Owned(self.scratch.as_str().to_owned()),
                Text::Borrowed(text) => match P::try_parse(parent, text) {
                    Some(property) => Key::Property(property),
                    None => Key::Borrowed(text),
                },
                Text::Copied => match P::try_parse(parent, &self.scratch) {
                    Some(property) => Key::Property(property),
                    None => Key::Owned(self.scratch.as_str().to_owned()),
                },
            };
            match self.whitespace() {
                Some(b':') => self.eat_char(),
                Some(_) => return Err(self.peek_error(Code::ExpectedColon)),
                None => return Err(self.peek_error(Code::EofWhileParsingObject)),
            }
            let value = self.value(if opaque { None } else { Some(&key) })?;
            self.members.push((key, value));
        }
        self.opaque = outer;
        Ok(Value::Object(ObjectAsVec(self.members.split_off(start))))
    }

    fn array(&mut self, parent: Option<&Key<'_, P>>) -> Parsed<Value<'x, P, E>> {
        let outer = self.opaque;
        let opaque = outer || parent.is_some_and(Key::is_opaque);
        self.opaque = opaque;
        let start = self.items.len();
        let mut first = true;
        loop {
            let Some(peek) = self.whitespace() else {
                return Err(self.peek_error(Code::EofWhileParsingList));
            };
            if peek == b']' {
                break;
            }
            if first {
                first = false;
            } else if peek == b',' {
                self.eat_char();
                match self.whitespace() {
                    Some(b']') => return Err(self.peek_error(Code::TrailingComma)),
                    Some(_) => {}
                    None => return Err(self.peek_error(Code::EofWhileParsingValue)),
                }
            } else {
                return Err(self.peek_error(Code::ExpectedListCommaOrEnd));
            }
            let item = self.value(if opaque { None } else { parent })?;
            self.items.push(item);
        }
        self.opaque = outer;
        Ok(Value::Array(self.items.split_off(start)))
    }

    fn ident(&mut self, ident: &[u8]) -> Parsed<()> {
        for expected in ident {
            match self.next_char() {
                None => return Err(self.error(Code::EofWhileParsingValue)),
                Some(next) if next != *expected => return Err(self.error(Code::ExpectedSomeIdent)),
                Some(_) => {}
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn skip_to_escape(&mut self) {
        let rest = self.bytes.get(self.index..).unwrap_or_default();
        let Some((&first, tail)) = rest.split_first() else {
            return;
        };
        if Unscanned::is_escape(first) {
            return;
        }
        let (head, long) = tail.split_at(tail.len().min(SWAR_LIMIT));
        let mut offset = self.index + 1;
        let (chunks, remainder) = head.as_chunks::<8>();
        for chunk in chunks {
            let word = u64::from_le_bytes(*chunk);
            let controls = word.wrapping_sub(CONTROLS) & !word;
            let quotes = word ^ QUOTES;
            let quotes = quotes.wrapping_sub(ONES) & !quotes;
            let backslashes = word ^ BACKSLASHES;
            let backslashes = backslashes.wrapping_sub(ONES) & !backslashes;
            let found = (controls | quotes | backslashes) & HIGH;
            if found != 0 {
                self.index = offset + found.trailing_zeros() as usize / 8;
                return;
            }
            offset += 8;
        }
        self.index = offset
            + if long.is_empty() {
                Unscanned(remainder).plain_len()
            } else {
                Unscanned(long).blockwise_plain_len()
            };
    }

    fn string(&mut self) -> Parsed<Text<'x>> {
        let mut start = self.index;
        let mut copied = false;
        loop {
            self.skip_to_escape();
            match self.peek() {
                Some(b'"') => {
                    let run = self.text.get(start..self.index).unwrap_or_default();
                    self.eat_char();
                    return Ok(if copied {
                        self.scratch.push_str(run);
                        Text::Copied
                    } else {
                        Text::Borrowed(run)
                    });
                }
                Some(b'\\') => {
                    if !copied {
                        copied = true;
                        self.scratch.clear();
                    }
                    let run = self.text.get(start..self.index).unwrap_or_default();
                    self.scratch.push_str(run);
                    self.eat_char();
                    self.escape()?;
                    start = self.index;
                }
                Some(_) => {
                    self.eat_char();
                    return Err(self.error(Code::ControlCharacterWhileParsingString));
                }
                None => return Err(self.error(Code::EofWhileParsingString)),
            }
        }
    }

    fn escape(&mut self) -> Parsed<()> {
        let Some(byte) = self.next_char() else {
            return Err(self.error(Code::EofWhileParsingString));
        };
        let decoded = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\x08',
            b'f' => '\x0c',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(),
            _ => return Err(self.error(Code::InvalidEscape)),
        };
        self.scratch.push(decoded);
        Ok(())
    }

    fn hex_escape(&mut self) -> Parsed<u16> {
        match self.bytes.get(self.index..) {
            Some([a, b, c, d, ..]) => {
                self.index += 4;
                match (
                    Self::hex_digit(*a),
                    Self::hex_digit(*b),
                    Self::hex_digit(*c),
                    Self::hex_digit(*d),
                ) {
                    (Some(a), Some(b), Some(c), Some(d)) => Ok((a << 12) | (b << 8) | (c << 4) | d),
                    _ => Err(self.error(Code::InvalidEscape)),
                }
            }
            _ => {
                self.index = self.bytes.len();
                Err(self.error(Code::EofWhileParsingString))
            }
        }
    }

    fn hex_digit(byte: u8) -> Option<u16> {
        match byte {
            b'0'..=b'9' => Some(u16::from(byte - b'0')),
            b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
            b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
            _ => None,
        }
    }

    fn unicode_escape(&mut self) -> Parsed<()> {
        let high = self.hex_escape()?;
        if (0xDC00..=0xDFFF).contains(&high) {
            return Err(self.error(Code::LoneLeadingSurrogateInHexEscape));
        }
        if !(0xD800..=0xDBFF).contains(&high) {
            self.push_code_point(u32::from(high));
            return Ok(());
        }
        for expected in *b"\\u" {
            match self.peek() {
                Some(byte) if byte == expected => self.eat_char(),
                Some(_) => {
                    self.eat_char();
                    return Err(self.error(Code::UnexpectedEndOfHexEscape));
                }
                None => return Err(self.error(Code::EofWhileParsingString)),
            }
        }
        let low = self.hex_escape()?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(self.error(Code::LoneLeadingSurrogateInHexEscape));
        }
        self.push_code_point(
            (((u32::from(high) - 0xD800) << 10) | (u32::from(low) - 0xDC00)) + 0x1_0000,
        );
        Ok(())
    }

    fn push_code_point(&mut self, code: u32) {
        if let Some(ch) = char::from_u32(code) {
            self.scratch.push(ch);
        }
    }

    fn integer(&mut self, positive: bool) -> Parsed<Value<'x, P, E>> {
        let Some(next) = self.next_char() else {
            return Err(self.error(Code::EofWhileParsingValue));
        };
        match next {
            b'0' => match self.peek_or_null() {
                b'0'..=b'9' => Err(self.peek_error(Code::InvalidNumber)),
                _ => self.number(positive, 0),
            },
            b'1'..=b'9' => {
                let mut significand = u64::from(next - b'0');
                loop {
                    match self.peek_or_null() {
                        byte @ b'0'..=b'9' => {
                            let Some(next) = Self::append_digit(significand, byte) else {
                                return self
                                    .long_integer(positive, significand)
                                    .map(|value| Value::Number(value.into()));
                            };
                            self.eat_char();
                            significand = next;
                        }
                        _ => return self.number(positive, significand),
                    }
                }
            }
            _ => Err(self.error(Code::InvalidNumber)),
        }
    }

    #[inline(always)]
    fn append_digit(significand: u64, digit: u8) -> Option<u64> {
        significand
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
    }

    fn number(&mut self, positive: bool, significand: u64) -> Parsed<Value<'x, P, E>> {
        Ok(Value::Number(match self.peek_or_null() {
            b'.' => self.decimal(positive, significand, 0)?.into(),
            b'e' | b'E' => self.exponent(positive, significand, 0)?.into(),
            _ if positive => significand.into(),
            _ => {
                let negative = (significand as i64).wrapping_neg();
                if negative >= 0 {
                    (-(significand as f64)).into()
                } else {
                    negative.into()
                }
            }
        }))
    }

    fn decimal(&mut self, positive: bool, mut significand: u64, before: i32) -> Parsed<f64> {
        self.eat_char();
        let mut after = 0;
        while let byte @ b'0'..=b'9' = self.peek_or_null() {
            let Some(next) = Self::append_digit(significand, byte) else {
                return self.decimal_overflow(positive, significand, before + after);
            };
            self.eat_char();
            significand = next;
            after -= 1;
        }
        if after == 0 {
            return Err(match self.peek() {
                Some(_) => self.peek_error(Code::InvalidNumber),
                None => self.peek_error(Code::EofWhileParsingValue),
            });
        }
        match self.peek_or_null() {
            b'e' | b'E' => self.exponent(positive, significand, before + after),
            _ => self.float(positive, significand, before + after),
        }
    }

    fn exponent(&mut self, positive: bool, significand: u64, starting: i32) -> Parsed<f64> {
        self.eat_char();
        let positive_exponent = match self.peek_or_null() {
            b'+' => {
                self.eat_char();
                true
            }
            b'-' => {
                self.eat_char();
                false
            }
            _ => true,
        };
        let mut exponent = match self.next_char() {
            Some(byte @ b'0'..=b'9') => i32::from(byte - b'0'),
            Some(_) => return Err(self.error(Code::InvalidNumber)),
            None => return Err(self.error(Code::EofWhileParsingValue)),
        };
        while let byte @ b'0'..=b'9' = self.peek_or_null() {
            self.eat_char();
            let Some(next) = exponent
                .checked_mul(10)
                .and_then(|value| value.checked_add(i32::from(byte - b'0')))
            else {
                return self.exponent_overflow(positive, significand == 0, positive_exponent);
            };
            exponent = next;
        }
        let exponent = if positive_exponent {
            starting.saturating_add(exponent)
        } else {
            starting.saturating_sub(exponent)
        };
        self.float(positive, significand, exponent)
    }

    fn float(&self, positive: bool, significand: u64, mut exponent: i32) -> Parsed<f64> {
        let mut value = significand as f64;
        loop {
            match POW10.get(exponent.wrapping_abs() as usize) {
                Some(&power) => {
                    if exponent >= 0 {
                        value *= power;
                        if value.is_infinite() {
                            return Err(self.error(Code::NumberOutOfRange));
                        }
                    } else {
                        value /= power;
                    }
                    break;
                }
                None => {
                    if value == 0.0 {
                        break;
                    }
                    if exponent >= 0 {
                        return Err(self.error(Code::NumberOutOfRange));
                    }
                    value /= 1e308;
                    exponent += 308;
                }
            }
        }
        Ok(if positive { value } else { -value })
    }

    #[cold]
    fn long_integer(&mut self, positive: bool, significand: u64) -> Parsed<f64> {
        let mut exponent = 0;
        loop {
            match self.peek_or_null() {
                b'0'..=b'9' => {
                    self.eat_char();
                    exponent += 1;
                }
                b'.' => return self.decimal(positive, significand, exponent),
                b'e' | b'E' => return self.exponent(positive, significand, exponent),
                _ => return self.float(positive, significand, exponent),
            }
        }
    }

    #[cold]
    fn decimal_overflow(&mut self, positive: bool, significand: u64, exponent: i32) -> Parsed<f64> {
        while let b'0'..=b'9' = self.peek_or_null() {
            self.eat_char();
        }
        match self.peek_or_null() {
            b'e' | b'E' => self.exponent(positive, significand, exponent),
            _ => self.float(positive, significand, exponent),
        }
    }

    #[cold]
    fn exponent_overflow(
        &mut self,
        positive: bool,
        zero_significand: bool,
        positive_exponent: bool,
    ) -> Parsed<f64> {
        if !zero_significand && positive_exponent {
            return Err(self.error(Code::NumberOutOfRange));
        }
        while let b'0'..=b'9' = self.peek_or_null() {
            self.eat_char();
        }
        Ok(if positive { 0.0 } else { -0.0 })
    }
}

impl Unscanned<'_> {
    #[inline(always)]
    fn is_escape(byte: u8) -> bool {
        (byte == b'"') | (byte == b'\\') | (byte < 0x20)
    }

    #[inline(always)]
    fn plain_len(self) -> usize {
        self.0
            .iter()
            .position(|&byte| Self::is_escape(byte))
            .unwrap_or(self.0.len())
    }

    #[inline(never)]
    fn blockwise_plain_len(self) -> usize {
        let mut offset = 0;
        let (blocks, remainder) = self.0.as_chunks::<BLOCK>();
        for block in blocks {
            if block
                .iter()
                .fold(false, |found, &byte| found | Self::is_escape(byte))
            {
                return offset + Unscanned(block).plain_len();
            }
            offset += BLOCK;
        }
        offset + Unscanned(remainder).plain_len()
    }
}

static POW10: [f64; 309] = [
    1e000, 1e001, 1e002, 1e003, 1e004, 1e005, 1e006, 1e007, 1e008, 1e009, 1e010, 1e011, 1e012,
    1e013, 1e014, 1e015, 1e016, 1e017, 1e018, 1e019, 1e020, 1e021, 1e022, 1e023, 1e024, 1e025,
    1e026, 1e027, 1e028, 1e029, 1e030, 1e031, 1e032, 1e033, 1e034, 1e035, 1e036, 1e037, 1e038,
    1e039, 1e040, 1e041, 1e042, 1e043, 1e044, 1e045, 1e046, 1e047, 1e048, 1e049, 1e050, 1e051,
    1e052, 1e053, 1e054, 1e055, 1e056, 1e057, 1e058, 1e059, 1e060, 1e061, 1e062, 1e063, 1e064,
    1e065, 1e066, 1e067, 1e068, 1e069, 1e070, 1e071, 1e072, 1e073, 1e074, 1e075, 1e076, 1e077,
    1e078, 1e079, 1e080, 1e081, 1e082, 1e083, 1e084, 1e085, 1e086, 1e087, 1e088, 1e089, 1e090,
    1e091, 1e092, 1e093, 1e094, 1e095, 1e096, 1e097, 1e098, 1e099, 1e100, 1e101, 1e102, 1e103,
    1e104, 1e105, 1e106, 1e107, 1e108, 1e109, 1e110, 1e111, 1e112, 1e113, 1e114, 1e115, 1e116,
    1e117, 1e118, 1e119, 1e120, 1e121, 1e122, 1e123, 1e124, 1e125, 1e126, 1e127, 1e128, 1e129,
    1e130, 1e131, 1e132, 1e133, 1e134, 1e135, 1e136, 1e137, 1e138, 1e139, 1e140, 1e141, 1e142,
    1e143, 1e144, 1e145, 1e146, 1e147, 1e148, 1e149, 1e150, 1e151, 1e152, 1e153, 1e154, 1e155,
    1e156, 1e157, 1e158, 1e159, 1e160, 1e161, 1e162, 1e163, 1e164, 1e165, 1e166, 1e167, 1e168,
    1e169, 1e170, 1e171, 1e172, 1e173, 1e174, 1e175, 1e176, 1e177, 1e178, 1e179, 1e180, 1e181,
    1e182, 1e183, 1e184, 1e185, 1e186, 1e187, 1e188, 1e189, 1e190, 1e191, 1e192, 1e193, 1e194,
    1e195, 1e196, 1e197, 1e198, 1e199, 1e200, 1e201, 1e202, 1e203, 1e204, 1e205, 1e206, 1e207,
    1e208, 1e209, 1e210, 1e211, 1e212, 1e213, 1e214, 1e215, 1e216, 1e217, 1e218, 1e219, 1e220,
    1e221, 1e222, 1e223, 1e224, 1e225, 1e226, 1e227, 1e228, 1e229, 1e230, 1e231, 1e232, 1e233,
    1e234, 1e235, 1e236, 1e237, 1e238, 1e239, 1e240, 1e241, 1e242, 1e243, 1e244, 1e245, 1e246,
    1e247, 1e248, 1e249, 1e250, 1e251, 1e252, 1e253, 1e254, 1e255, 1e256, 1e257, 1e258, 1e259,
    1e260, 1e261, 1e262, 1e263, 1e264, 1e265, 1e266, 1e267, 1e268, 1e269, 1e270, 1e271, 1e272,
    1e273, 1e274, 1e275, 1e276, 1e277, 1e278, 1e279, 1e280, 1e281, 1e282, 1e283, 1e284, 1e285,
    1e286, 1e287, 1e288, 1e289, 1e290, 1e291, 1e292, 1e293, 1e294, 1e295, 1e296, 1e297, 1e298,
    1e299, 1e300, 1e301, 1e302, 1e303, 1e304, 1e305, 1e306, 1e307, 1e308,
];

