/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ContextToken, Recipient, SpamFilterInput, SpamFilterOutput, TextPart, analysis::url::UrlParts,
};
use common::{
    config::mailstore::spamfilter::Location,
    expr::{
        Bump, Variable,
        bumpalo::collections::String as BumpString,
        functions::ResolveVariable,
        kernels::{to_lowercase, utf8_lossy},
    },
};
use compact_str::CompactString;
use mail_parser::{DateTime, Header, HeaderValue};
use nlp::tokenizers::types::TokenType;
use registry::schema::enums::ExpressionVariable;
use std::fmt::Write;
use store::ahash::AHashSet;

pub(crate) const HEADER_NAME_INLINE: usize = 64;

const RFC3339_LEN: usize = 25;
const IP_TEXT_MAX_LEN: usize = 39;

pub(crate) struct SpamFilterResolver<'x, T: ResolveVariable> {
    pub input: &'x SpamFilterInput<'x>,
    pub output: &'x SpamFilterOutput<'x>,
    pub tags: &'x AHashSet<CompactString>,
    pub item: &'x T,
    pub location: Location,
    pub scores: ScoreVariables,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreVariables {
    pub score: f32,
    pub probability: f32,
    pub threshold: f32,
}

pub(crate) const NO_PROBABILITY: f32 = -1.0;

impl Default for ScoreVariables {
    fn default() -> Self {
        ScoreVariables {
            score: 0.0,
            probability: NO_PROBABILITY,
            threshold: 0.0,
        }
    }
}

impl ScoreVariables {
    pub fn for_rules(probability: Option<f32>) -> Self {
        ScoreVariables {
            probability: probability.unwrap_or(NO_PROBABILITY),
            ..Default::default()
        }
    }
}

pub(crate) struct EmailHeader<'h> {
    pub header: Header<'h>,
    pub name: &'h str,
    pub name_lower: &'h str,
}

pub struct StringResolver<'x>(pub &'x str);

#[derive(Clone, Copy)]
enum RecipientPart {
    Address,
    Name,
    Local,
    Domain,
}

impl<'x, T: ResolveVariable> SpamFilterResolver<'x, T> {
    pub fn new(
        input: &'x SpamFilterInput<'x>,
        output: &'x SpamFilterOutput<'x>,
        tags: &'x AHashSet<CompactString>,
        item: &'x T,
        location: Location,
    ) -> Self {
        Self {
            input,
            output,
            tags,
            item,
            location,
            scores: ScoreVariables::default(),
        }
    }

    pub fn with_scores(mut self, scores: ScoreVariables) -> Self {
        self.scores = scores;
        self
    }

    fn list<'a>(&'a self, variable: ExpressionVariable, arena: &'a Bump) -> &'a [Variable<'a>] {
        let output = self.output;
        match variable {
            ExpressionVariable::To => {
                recipients(arena, &output.recipients_to, RecipientPart::Address)
            }
            ExpressionVariable::ToName => {
                recipients(arena, &output.recipients_to, RecipientPart::Name)
            }
            ExpressionVariable::ToLocal => {
                recipients(arena, &output.recipients_to, RecipientPart::Local)
            }
            ExpressionVariable::ToDomain => {
                recipients(arena, &output.recipients_to, RecipientPart::Domain)
            }
            ExpressionVariable::Cc => {
                recipients(arena, &output.recipients_cc, RecipientPart::Address)
            }
            ExpressionVariable::CcName => {
                recipients(arena, &output.recipients_cc, RecipientPart::Name)
            }
            ExpressionVariable::CcLocal => {
                recipients(arena, &output.recipients_cc, RecipientPart::Local)
            }
            ExpressionVariable::CcDomain => {
                recipients(arena, &output.recipients_cc, RecipientPart::Domain)
            }
            ExpressionVariable::Bcc => {
                recipients(arena, &output.recipients_bcc, RecipientPart::Address)
            }
            ExpressionVariable::BccName => {
                recipients(arena, &output.recipients_bcc, RecipientPart::Name)
            }
            ExpressionVariable::BccLocal => {
                recipients(arena, &output.recipients_bcc, RecipientPart::Local)
            }
            ExpressionVariable::BccDomain => {
                recipients(arena, &output.recipients_bcc, RecipientPart::Domain)
            }
            ExpressionVariable::EnvTo => strs(
                arena,
                output.env_to_orig_addr.iter().map(|e| e.address.as_str()),
            ),
            ExpressionVariable::SubjectWords => words(arena, &output.subject_tokens),
            ExpressionVariable::BodyWords => self
                .input
                .message
                .html_body()
                .next()
                .and_then(|part| output.text_parts.get(part.id() as usize))
                .map(|part| match part {
                    TextPart::Plain { tokens, .. } | TextPart::Html { tokens, .. } => {
                        words(arena, tokens)
                    }
                    TextPart::None => &[],
                })
                .unwrap_or_default(),
            _ => &[],
        }
    }
}

impl<T: ResolveVariable> ResolveVariable for SpamFilterResolver<'_, T> {
    fn resolve_variable<'a>(
        &'a self,
        variable: ExpressionVariable,
        arena: &'a Bump,
    ) -> Variable<'a> {
        let (input, output) = (self.input, self.output);
        match variable {
            ExpressionVariable::RemoteIp => {
                let mut ip = BumpString::with_capacity_in(IP_TEXT_MAX_LEN, arena);
                let _ = write!(ip, "{}", input.remote_ip);
                ip.into_bump_str().into()
            }
            ExpressionVariable::RemoteIpPtr => {
                output.iprev_ptr.as_deref().unwrap_or_default().into()
            }
            ExpressionVariable::HeloDomain => output.ehlo_host.fqdn.as_str().into(),
            ExpressionVariable::AuthenticatedAs => {
                input.authenticated_as.unwrap_or_default().into()
            }
            ExpressionVariable::Asn => input.asn.unwrap_or_default().into(),
            ExpressionVariable::Country => input.country.unwrap_or_default().into(),
            ExpressionVariable::IsTls => input.is_tls.into(),
            ExpressionVariable::EnvFrom => output.env_from_addr.address.as_str().into(),
            ExpressionVariable::EnvFromLocal => output.env_from_addr.local_part.as_str().into(),
            ExpressionVariable::EnvFromDomain => {
                output.env_from_addr.domain_part.fqdn.as_str().into()
            }
            ExpressionVariable::From => output.from.email.address.as_str().into(),
            ExpressionVariable::FromName => output.from.name.as_deref().unwrap_or_default().into(),
            ExpressionVariable::FromLocal => output.from.email.local_part.as_str().into(),
            ExpressionVariable::FromDomain => output.from.email.domain_part.fqdn.as_str().into(),
            ExpressionVariable::ReplyTo => output
                .reply_to
                .as_ref()
                .map(|r| r.email.address.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToName => output
                .reply_to
                .as_ref()
                .and_then(|r| r.name.as_deref())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToLocal => output
                .reply_to
                .as_ref()
                .map(|r| r.email.local_part.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToDomain => output
                .reply_to
                .as_ref()
                .map(|r| r.email.domain_part.fqdn.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::EnvTo
            | ExpressionVariable::To
            | ExpressionVariable::ToName
            | ExpressionVariable::ToLocal
            | ExpressionVariable::ToDomain
            | ExpressionVariable::Cc
            | ExpressionVariable::CcName
            | ExpressionVariable::CcLocal
            | ExpressionVariable::CcDomain
            | ExpressionVariable::Bcc
            | ExpressionVariable::BccName
            | ExpressionVariable::BccLocal
            | ExpressionVariable::BccDomain
            | ExpressionVariable::SubjectWords
            | ExpressionVariable::BodyWords => Variable::Array(self.list(variable, arena)),
            ExpressionVariable::Body | ExpressionVariable::BodyText => {
                output.text_body(input).unwrap_or_default().into()
            }
            ExpressionVariable::BodyHtml => input
                .message
                .html_body()
                .next()
                .and_then(|part| output.text_parts.get(part.id() as usize))
                .map(|part| {
                    if let TextPart::Html { text_body, .. } = part {
                        *text_body
                    } else {
                        ""
                    }
                })
                .unwrap_or_default()
                .into(),
            ExpressionVariable::BodyRaw => utf8_lossy(input.message.raw(), arena).into(),
            ExpressionVariable::Subject => output.subject_lc.as_str().into(),
            ExpressionVariable::SubjectThread => output.subject_thread_lc.as_str().into(),
            ExpressionVariable::Location => self.location.as_str().into(),
            ExpressionVariable::SpamScore => Variable::Float(f64::from(self.scores.score)),
            ExpressionVariable::SpamProbability => {
                Variable::Float(f64::from(self.scores.probability))
            }
            ExpressionVariable::SpamThreshold => Variable::Float(f64::from(self.scores.threshold)),
            variable => self.item.resolve_variable(variable, arena),
        }
    }

    fn resolve_global<'a>(&'a self, variable: &str, _: &'a Bump) -> Variable<'a> {
        Variable::Integer(self.tags.contains(variable).into())
    }
}

impl ResolveVariable for EmailHeader<'_> {
    fn resolve_variable<'a>(
        &'a self,
        variable: ExpressionVariable,
        arena: &'a Bump,
    ) -> Variable<'a> {
        match variable {
            ExpressionVariable::Name => self.name.into(),
            ExpressionVariable::NameLower => self.name_lower.into(),
            ExpressionVariable::Value
            | ExpressionVariable::ValueLower
            | ExpressionVariable::Attributes => header_value(self.header, variable, arena),
            ExpressionVariable::Raw => utf8_lossy(self.header.raw_value(), arena).into(),
            ExpressionVariable::RawLower => {
                to_lowercase(utf8_lossy(self.header.raw_value(), arena), arena).into()
            }
            _ => Variable::Integer(0),
        }
    }
}

pub(crate) fn lower_header_name<'b>(
    name: &'b str,
    inline: &'b mut [u8; HEADER_NAME_INLINE],
    arena: &'b Bump,
) -> &'b str {
    if name.is_ascii()
        && name.bytes().any(|b| b.is_ascii_uppercase())
        && let Some(out) = inline.get_mut(..name.len())
    {
        out.copy_from_slice(name.as_bytes());
        out.make_ascii_lowercase();
        if let Ok(lower) = std::str::from_utf8(out) {
            return lower;
        }
    }
    to_lowercase(name, arena)
}

fn rfc3339<'a>(date: &DateTime, arena: &'a Bump) -> &'a str {
    let mut out = BumpString::with_capacity_in(RFC3339_LEN, arena);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        date.year, date.month, date.day, date.hour, date.minute, date.second
    );
    let _ = if date.tz_hour != 0 || date.tz_minute != 0 {
        let sign = if date.tz_before_gmt { '-' } else { '+' };
        write!(out, "{sign}{:02}:{:02}", date.tz_hour, date.tz_minute)
    } else {
        out.write_char('Z')
    };
    out.into_bump_str()
}

fn header_value<'a>(
    header: Header<'a>,
    variable: ExpressionVariable,
    arena: &'a Bump,
) -> Variable<'a> {
    let lower = variable == ExpressionVariable::ValueLower;
    let text = |text: &'a str| -> &'a str {
        if lower {
            to_lowercase(text, arena)
        } else {
            text
        }
    };
    match header.value() {
        HeaderValue::Text(value) => text(value).into(),
        HeaderValue::TextList(list) if list.len() == 1 => {
            text(list.first().unwrap_or_default()).into()
        }
        HeaderValue::TextList(list) => Variable::Array(strs(arena, list.iter().map(&text))),
        HeaderValue::Address(address) => {
            Variable::Array(if variable != ExpressionVariable::Attributes {
                let addresses = || address.mailboxes().filter_map(|mailbox| mailbox.address());
                fill_strs(arena, addresses().count(), addresses().map(&text))
            } else {
                filtered_strs(arena, || {
                    address.mailboxes().filter_map(|mailbox| mailbox.name())
                })
            })
        }
        HeaderValue::DateTime(date_time) => Variable::String(rfc3339(&date_time, arena)),
        HeaderValue::ContentType(ct) => {
            if variable != ExpressionVariable::Attributes {
                if let Some(st) = ct.subtype() {
                    let mut out =
                        BumpString::with_capacity_in(ct.ctype().len() + st.len() + 1, arena);
                    out.push_str(ct.ctype());
                    out.push('/');
                    out.push_str(st);
                    Variable::String(out.into_bump_str())
                } else {
                    ct.ctype().into()
                }
            } else {
                Variable::Array(arena.alloc_slice_fill_iter(ct.attributes().map(
                    |(name, value)| {
                        let mut out =
                            BumpString::with_capacity_in(name.len() + value.len() + 1, arena);
                        out.push_str(name);
                        out.push('=');
                        out.push_str(value);
                        Variable::String(out.into_bump_str())
                    },
                )))
            }
        }
        HeaderValue::Received(_) => text(utf8_lossy(header.raw_value(), arena).trim()).into(),
        HeaderValue::Empty => "".into(),
    }
}

fn strs<'a, I>(arena: &'a Bump, items: I) -> &'a [Variable<'a>]
where
    I: IntoIterator<Item = &'a str>,
    I::IntoIter: ExactSizeIterator,
{
    arena.alloc_slice_fill_iter(items.into_iter().map(Variable::String))
}

fn filtered_strs<'a, I>(arena: &'a Bump, items: impl Fn() -> I) -> &'a [Variable<'a>]
where
    I: Iterator<Item = &'a str>,
{
    fill_strs(arena, items().count(), items())
}

fn fill_strs<'a>(
    arena: &'a Bump,
    len: usize,
    items: impl Iterator<Item = &'a str>,
) -> &'a [Variable<'a>] {
    let out = arena.alloc_slice_fill_copy(len, Variable::default());
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = Variable::String(item);
    }
    out
}

fn words<'a>(arena: &'a Bump, tokens: &'a [ContextToken<'_>]) -> &'a [Variable<'a>] {
    filtered_strs(arena, || {
        tokens.iter().filter_map(|token| match token {
            TokenType::Alphabetic(word)
            | TokenType::Alphanumeric(word)
            | TokenType::Integer(word)
            | TokenType::Float(word) => Some(word.as_ref()),
            _ => None,
        })
    })
}

fn recipients<'a>(
    arena: &'a Bump,
    list: &'a [Recipient],
    part: RecipientPart,
) -> &'a [Variable<'a>] {
    match part {
        RecipientPart::Address => strs(arena, list.iter().map(|r| r.email.address.as_str())),
        RecipientPart::Name => {
            filtered_strs(arena, || list.iter().filter_map(|r| r.name.as_deref()))
        }
        RecipientPart::Local => strs(arena, list.iter().map(|r| r.email.local_part.as_str())),
        RecipientPart::Domain => strs(
            arena,
            list.iter().map(|r| r.email.domain_part.fqdn.as_str()),
        ),
    }
}

impl ResolveVariable for Recipient {
    fn resolve_variable<'a>(&'a self, variable: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        match variable {
            ExpressionVariable::Email | ExpressionVariable::Value => {
                Variable::from(self.email.address.as_str())
            }
            ExpressionVariable::Name => Variable::from(self.name.as_deref().unwrap_or_default()),
            ExpressionVariable::Local => Variable::from(self.email.local_part.as_str()),
            ExpressionVariable::Domain => Variable::from(self.email.domain_part.fqdn.as_str()),
            ExpressionVariable::Sld => Variable::from(self.email.domain_part.sld_or_default()),
            _ => Variable::Integer(0),
        }
    }
}

impl ResolveVariable for UrlParts<'_> {
    fn resolve_variable<'a>(&'a self, variable: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        match variable {
            ExpressionVariable::Url | ExpressionVariable::Value => {
                Variable::from(self.url.as_str())
            }
            ExpressionVariable::UrlOriginal => Variable::from(self.url_original.as_ref()),
            ExpressionVariable::PathQuery => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.path_and_query().map(|p| p.as_str()))
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Path => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.parts.path())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Query => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.query())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Scheme => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.scheme_str())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Authority => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.authority().map(|a| a.as_str()))
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Host => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.fqdn.as_str())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Sld => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.sld_or_default())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Port => Variable::Integer(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.port_u16())
                    .unwrap_or(0) as _,
            ),
            _ => Variable::Integer(0),
        }
    }
}

impl ResolveVariable for StringResolver<'_> {
    fn resolve_variable<'a>(&'a self, _: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        Variable::from(self.0)
    }
}

