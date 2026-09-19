/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The filter grammar of RFC 7644 §3.4.2.2, parsed in full so that a server
//! supporting only part of it can name the construct it refuses.
//! Precedence: `not` and grouping, then `and`, then `or`.

use crate::ScimError;
use serde_json::Value;

/// `[URN ":"] name ["." sub]`. Names keep the case sent; compare them with
/// [`AttrPath::is`].
#[derive(Debug, Clone, PartialEq)]
pub struct AttrPath {
    pub urn: Option<String>,
    pub name: String,
    pub sub: Option<String>,
}

impl AttrPath {
    /// Parses `urn:…:Schema:name.sub`, `name.sub` or `name`.
    pub fn parse(text: &str) -> Option<AttrPath> {
        let (urn, rest) = if text.len() > 4 && text[..4].eq_ignore_ascii_case("urn:") {
            let at = text.rfind(':')?;
            (Some(text[..at].to_string()), &text[at + 1..])
        } else {
            (None, text)
        };
        let (name, sub) = match rest.split_once('.') {
            Some((name, sub)) => (name, Some(sub)),
            None => (rest, None),
        };
        if !is_attr_name(name) || sub.is_some_and(|sub| !is_attr_name(sub)) {
            return None;
        }
        Some(AttrPath {
            urn,
            name: name.to_string(),
            sub: sub.map(str::to_string),
        })
    }

    /// Whether this is `name` (and `sub`, when given), in any case.
    pub fn is(&self, name: &str, sub: Option<&str>) -> bool {
        self.name.eq_ignore_ascii_case(name)
            && match (sub, &self.sub) {
                (None, None) => true,
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            }
    }
}

impl std::fmt::Display for AttrPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(urn) = &self.urn {
            write!(f, "{urn}:")?;
        }
        write!(f, "{}", self.name)?;
        if let Some(sub) = &self.sub {
            write!(f, ".{sub}")?;
        }
        Ok(())
    }
}

/// ATTRNAME = ALPHA *(nameChar), nameChar = "-" / "_" / DIGIT / ALPHA, and
/// `$ref`.
fn is_attr_name(name: &str) -> bool {
    name == "$ref"
        || name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

impl CompareOp {
    fn parse(word: &str) -> Option<CompareOp> {
        Some(match word.to_ascii_lowercase().as_str() {
            "eq" => CompareOp::Eq,
            "ne" => CompareOp::Ne,
            "co" => CompareOp::Co,
            "sw" => CompareOp::Sw,
            "ew" => CompareOp::Ew,
            "gt" => CompareOp::Gt,
            "ge" => CompareOp::Ge,
            "lt" => CompareOp::Lt,
            "le" => CompareOp::Le,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CompareOp::Eq => "eq",
            CompareOp::Ne => "ne",
            CompareOp::Co => "co",
            CompareOp::Sw => "sw",
            CompareOp::Ew => "ew",
            CompareOp::Gt => "gt",
            CompareOp::Ge => "ge",
            CompareOp::Lt => "lt",
            CompareOp::Le => "le",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Compare {
        path: AttrPath,
        op: CompareOp,
        value: Value,
    },
    Present(AttrPath),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    /// `attr[filter]`, with the inner filter's paths relative to `attr`.
    ValuePath {
        path: AttrPath,
        filter: Box<Filter>,
    },
}

impl Filter {
    pub fn parse(text: &str) -> Result<Filter, ScimError> {
        let tokens = tokenize(text)?;
        let mut parser = Parser { tokens, pos: 0 };
        let filter = parser.or()?;
        match parser.peek() {
            None => Ok(filter),
            Some(token) => Err(ScimError::invalid_filter(format!(
                "Unexpected {} in the filter",
                token.describe()
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Str(String),
    Open,
    Close,
    OpenBracket,
    CloseBracket,
}

impl Token {
    fn describe(&self) -> String {
        match self {
            Token::Word(word) => format!("'{word}'"),
            Token::Str(text) => format!("\"{text}\""),
            Token::Open => "'('".to_string(),
            Token::Close => "')'".to_string(),
            Token::OpenBracket => "'['".to_string(),
            Token::CloseBracket => "']'".to_string(),
        }
    }
}

fn tokenize(text: &str) -> Result<Vec<Token>, ScimError> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::Open);
            }
            ')' => {
                chars.next();
                tokens.push(Token::Close);
            }
            '[' => {
                chars.next();
                tokens.push(Token::OpenBracket);
            }
            ']' => {
                chars.next();
                tokens.push(Token::CloseBracket);
            }
            '"' => {
                // A JSON string, escapes and all
                chars.next();
                let mut end = None;
                let mut escaped = false;
                for (at, c) in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        end = Some(at);
                        break;
                    }
                }
                let end = end.ok_or_else(|| {
                    ScimError::invalid_filter("An unterminated string in the filter")
                })?;
                let value = serde_json::from_str::<String>(&text[start..=end])
                    .map_err(|_| ScimError::invalid_filter("A malformed string in the filter"))?;
                tokens.push(Token::Str(value));
            }
            _ => {
                let mut end = text.len();
                while let Some(&(at, c)) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '"') {
                        end = at;
                        break;
                    }
                    chars.next();
                }
                tokens.push(Token::Word(text[start..end].to_string()));
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn is_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w.eq_ignore_ascii_case(word))
    }

    fn or(&mut self) -> Result<Filter, ScimError> {
        let mut left = self.and()?;
        while self.is_word("or") {
            self.pos += 1;
            let right = self.and()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Filter, ScimError> {
        let mut left = self.unary()?;
        while self.is_word("and") {
            self.pos += 1;
            let right = self.unary()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn group(&mut self) -> Result<Filter, ScimError> {
        let inner = self.or()?;
        match self.next() {
            Some(Token::Close) => Ok(inner),
            _ => Err(ScimError::invalid_filter(
                "A '(' without its ')' in the filter",
            )),
        }
    }

    fn unary(&mut self) -> Result<Filter, ScimError> {
        match self.next() {
            Some(Token::Word(word)) if word.eq_ignore_ascii_case("not") => match self.next() {
                Some(Token::Open) => Ok(Filter::Not(Box::new(self.group()?))),
                _ => Err(ScimError::invalid_filter("'not' must be followed by '('")),
            },
            Some(Token::Open) => self.group(),
            Some(Token::Word(word)) => {
                let path = AttrPath::parse(&word).ok_or_else(|| {
                    ScimError::invalid_filter(format!("'{word}' isn't an attribute path"))
                })?;
                if self.peek() == Some(&Token::OpenBracket) {
                    self.pos += 1;
                    let inner = self.or()?;
                    return match self.next() {
                        Some(Token::CloseBracket) => Ok(Filter::ValuePath {
                            path,
                            filter: Box::new(inner),
                        }),
                        _ => Err(ScimError::invalid_filter(
                            "A '[' without its ']' in the filter",
                        )),
                    };
                }
                match self.next() {
                    Some(Token::Word(op)) if op.eq_ignore_ascii_case("pr") => {
                        Ok(Filter::Present(path))
                    }
                    Some(Token::Word(op)) => {
                        let op = CompareOp::parse(&op).ok_or_else(|| {
                            ScimError::invalid_filter(format!("'{op}' isn't a filter operator"))
                        })?;
                        let value = match self.next() {
                            Some(Token::Str(text)) => Value::String(text),
                            Some(Token::Word(word)) => match word.as_str() {
                                "true" => Value::Bool(true),
                                "false" => Value::Bool(false),
                                "null" => Value::Null,
                                number => serde_json::from_str::<serde_json::Number>(number)
                                    .map(Value::Number)
                                    .map_err(|_| {
                                        ScimError::invalid_filter(format!(
                                            "'{number}' isn't a filter value"
                                        ))
                                    })?,
                            },
                            _ => {
                                return Err(ScimError::invalid_filter(format!(
                                    "'{path} {}' needs a value",
                                    op.as_str()
                                )));
                            }
                        };
                        Ok(Filter::Compare { path, op, value })
                    }
                    _ => Err(ScimError::invalid_filter(format!(
                        "'{path}' needs an operator"
                    ))),
                }
            }
            Some(token) => Err(ScimError::invalid_filter(format!(
                "Unexpected {} in the filter",
                token.describe()
            ))),
            None => Err(ScimError::invalid_filter("The filter ends too soon")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eq(name: &str, value: Value) -> Filter {
        Filter::Compare {
            path: AttrPath::parse(name).unwrap(),
            op: CompareOp::Eq,
            value,
        }
    }

    #[test]
    fn parses_the_supported_subset() {
        assert_eq!(
            Filter::parse("userName eq \"bjensen@example.com\"").unwrap(),
            eq("userName", json!("bjensen@example.com"))
        );
        assert_eq!(
            Filter::parse("USERNAME EQ \"a\" AND active eq false").unwrap(),
            Filter::And(
                Box::new(eq("USERNAME", json!("a"))),
                Box::new(eq("active", json!(false)))
            )
        );
        assert_eq!(
            Filter::parse("emails.value eq \"a\\\"b\"").unwrap(),
            eq("emails.value", json!("a\"b"))
        );
        let urn =
            Filter::parse("urn:ietf:params:scim:schemas:core:2.0:User:userName eq \"x\"").unwrap();
        match urn {
            Filter::Compare { path, .. } => {
                assert_eq!(
                    path.urn.as_deref(),
                    Some("urn:ietf:params:scim:schemas:core:2.0:User")
                );
                assert!(path.is("username", None));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_the_rest_of_the_grammar() {
        assert!(matches!(
            Filter::parse("title pr or not (a co \"b\")").unwrap(),
            Filter::Or(..)
        ));
        assert!(matches!(
            Filter::parse("emails[type eq \"work\" and value co \"@\"]").unwrap(),
            Filter::ValuePath { .. }
        ));
        // and binds tighter than or
        match Filter::parse("a eq 1 or b eq 2 and c eq 3").unwrap() {
            Filter::Or(_, right) => assert!(matches!(*right, Filter::And(..))),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refuses_malformed_filters() {
        for text in [
            "",
            "userName",
            "userName eq",
            "userName xx \"a\"",
            "(userName eq \"a\"",
            "userName eq \"a",
            "userName eq \"a\" extra",
            "1abc eq \"a\"",
        ] {
            let err = Filter::parse(text).unwrap_err();
            assert_eq!(
                err.scim_type,
                Some(crate::ScimType::InvalidFilter),
                "{text}"
            );
        }
    }
}
