/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::borrow::Cow;

use mail_parser::{Header, HeaderName, HeaderValue};

use crate::{
    Context,
    compiler::grammar::{
        MatchType,
        actions::{
            action_editheader::{AddHeader, DeleteHeader},
            action_mime::MimeOpts,
        },
    },
};

impl AddHeader {
    pub(crate) fn exec(&self, ctx: &mut Context) {
        let header_name__ = ctx.eval_value(&self.field_name);
        let header_name_ = header_name__.to_string();
        let mut header_name = String::with_capacity(header_name_.len());

        for ch in header_name_.chars() {
            if ch.is_alphanumeric() || ch == '-' {
                header_name.push(ch);
            }
        }

        if !header_name.is_empty()
            && let Some(header_name) = HeaderName::parse(header_name)
            && !ctx.runtime.protected_headers.contains(&header_name)
        {
            ctx.has_changes = true;
            ctx.insert_header(
                ctx.part,
                header_name,
                ctx.eval_value(&self.value)
                    .to_string()
                    .as_ref()
                    .remove_crlf(ctx.runtime.max_header_size),
                self.last,
            )
        }
    }
}

impl DeleteHeader {
    pub(crate) fn exec(&self, ctx: &mut Context) {
        let header_name__ = ctx.eval_value(&self.field_name);
        let header_name_ = header_name__.to_string();
        let header_name = if let Some(header_name) = HeaderName::parse(header_name_.as_ref()) {
            header_name
        } else {
            return;
        };
        let value_patterns = ctx.eval_values(&self.value_patterns);
        let mut deleted_headers = Vec::new();
        let mut deleted_bytes = 0;

        if ctx.runtime.protected_headers.contains(&header_name) {
            return;
        }

        ctx.find_headers(
            &[header_name],
            self.index,
            self.mime_anychild,
            |header, part_id, header_pos| {
                if ctx.is_over_cpu_limit() {
                    return true;
                }
                if !value_patterns.is_empty() {
                    let did_match = ctx.find_header_values(header, &MimeOpts::None, |value| {
                        // inbuxa: charged like the header test; past the limit,
                        // nothing is deleted and the run stops
                        if ctx.charge_scan(value.len() * value_patterns.len()) {
                            return false;
                        }
                        for (pattern_expr, pattern) in
                            value_patterns.iter().zip(self.value_patterns.iter())
                        {
                            if match &self.match_type {
                                MatchType::Is => self.comparator.is(&value, pattern_expr),
                                MatchType::Contains => self
                                    .comparator
                                    .contains(value, pattern_expr.to_string().as_ref()),
                                MatchType::Value(rel_match) => {
                                    self.comparator.relational(rel_match, &value, pattern_expr)
                                }
                                MatchType::Matches(_) => self.comparator.matches(
                                    value,
                                    pattern_expr.to_string().as_ref(),
                                    0,
                                    &mut Vec::new(),
                                ),
                                MatchType::Regex(_) => self.comparator.regex(
                                    &ctx.regex_cache,
                                    pattern,
                                    pattern_expr,
                                    value,
                                    0,
                                    &mut Vec::new(),
                                ),
                                MatchType::Count(_) => false,
                                MatchType::List => false,
                            } {
                                return true;
                            }
                        }
                        false
                    });

                    if !did_match {
                        return false;
                    }
                }

                if header.offset_end != 0 {
                    deleted_bytes += (header.offset_end - header.offset_field) as usize;
                } else {
                    deleted_bytes += header.name.as_str().len() + header.value.len() + 4;
                }
                deleted_headers.push((part_id, header_pos));

                false
            },
        );

        if ctx.is_over_cpu_limit() {
            return;
        }

        if !deleted_headers.is_empty() {
            ctx.has_changes = true;
            for (part_id, header_pos) in deleted_headers.iter().rev() {
                if let Some(part) = ctx.message.parts.get_mut(*part_id as usize)
                    && *header_pos < part.headers.len()
                {
                    part.headers.remove(*header_pos);
                }
            }
        }

        ctx.message_size = ctx.message_size.saturating_sub(deleted_bytes);
    }
}

// inbuxa: every header value the runtime writes into a message goes through
// this, wherever the value came from: CR, LF and the other control
// characters but tab are dropped, so a value can't start a header line
pub(crate) trait RemoveCrLf {
    fn remove_crlf(&self, max_len: usize) -> String;
}

impl RemoveCrLf for &str {
    fn remove_crlf(&self, max_len: usize) -> String {
        let mut header_value = String::with_capacity(self.len());
        for ch in self.chars() {
            if ch == '\t' || ch >= ' ' {
                if header_value.len() + ch.len_utf8() <= max_len {
                    header_value.push(ch);
                } else {
                    return header_value;
                }
            }
        }
        header_value
    }
}

impl<'x> Context<'x> {
    pub(crate) fn insert_header(
        &mut self,
        part_id: u32,
        header_name: HeaderName<'x>,
        header_value: impl Into<Cow<'static, str>>,
        last: bool,
    ) {
        // inbuxa: a part that is gone gets no header, rather than a panic
        let Some(part) = self.message.parts.get_mut(part_id as usize) else {
            return;
        };
        let header_value = header_value.into();
        self.message_size += header_name.len() + header_value.len() + 4;
        let header = Header {
            name: header_name,
            value: HeaderValue::Text(header_value),
            offset_start: 0,
            offset_end: 0,
            offset_field: 0,
        };

        if !last {
            part.headers.insert(0, header);
        } else {
            part.headers.push(header);
        }
    }
}

// inbuxa: header values that reach a message the runtime writes (vacation,
// notify, enclose) come from the inbound message and from scripts; a CR or
// LF in one must not start a new header line in that message
#[cfg(test)]
mod header_injection_tests {
    use mail_parser::MessageParser;

    use crate::{Compiler, Context, Envelope, Event, Input, Runtime};

    // "x\r\nBcc: victim@example.com", RFC 2047 encoded
    const INJECTED: &str = "=?utf-8?b?eA0KQmNjOiB2aWN0aW1AZXhhbXBsZS5jb20=?=";

    fn messages(script: &str, extra_headers: &str, full_name: &str) -> Vec<String> {
        let script = std::sync::Arc::new(Compiler::new().compile(script.as_bytes()).unwrap());
        let raw = format!(
            "From: sender@example.org\r\nTo: john@example.com\r\n{extra_headers}\
             Subject: {INJECTED}\r\n\r\nbody\r\n"
        );
        let runtime = Runtime::new();
        let mut ctx = Context::new(
            &runtime,
            MessageParser::new().parse(raw.as_bytes()).unwrap(),
        )
        .with_envelope(Envelope::From, "sender@example.org")
        .with_envelope(Envelope::To, "john@example.com")
        .with_user_address("john@example.com");
        if !full_name.is_empty() {
            ctx.set_user_full_name(full_name);
        }
        let mut input = Input::script("test", script);
        let mut created = Vec::new();
        while let Some(event) = ctx.run(input) {
            input = match event.unwrap() {
                Event::CreatedMessage { message, .. } => {
                    created.push(String::from_utf8(message).unwrap());
                    Input::True
                }
                Event::DuplicateId { .. } => Input::False,
                _ => Input::True,
            };
        }
        created
    }

    // every line of the top-level header block is a "name: value" field or a
    // folded continuation, and none of them is a Bcc
    fn header_problem(message: &str) -> Option<String> {
        let headers = message.split("\r\n\r\n").next().unwrap();
        for line in headers.split("\r\n") {
            if line.contains(['\r', '\n']) {
                return Some(format!("bare CR or LF in {line:?}"));
            }
            if line.starts_with([' ', '\t']) {
                continue;
            }
            let Some((name, _)) = line.split_once(':') else {
                return Some(format!("not a header line {line:?}"));
            };
            if name.is_empty() || !name.bytes().all(|b| (33..=126).contains(&b)) {
                return Some(format!("bad field name in {line:?}"));
            }
            if name.eq_ignore_ascii_case("bcc") {
                return Some(format!("injected header {line:?}"));
            }
        }
        None
    }

    #[test]
    fn generated_messages_have_no_injected_headers() {
        // ${1} is the inbound Subject, decoded
        let matched = |action: &str| {
            format!(
                "require [\"variables\", \"vacation\", \"enotify\", \"enclose\"];\n\
                 if header :matches \"subject\" \"*\" {{ {action} }}\n"
            )
        };
        let plain = |script: &str| script.to_string();
        // a URI the compiler can't check: it's in a variable
        let mailto = |uri: &str| {
            format!(
                "require [\"variables\", \"enotify\"];\nset \"u\" \"mailto:{uri}\";\n\
                 notify :message \"hi\" \"${{u}}\";\n"
            )
        };
        let away = "require \"vacation\";\nvacation :subject \"hi\" \"away\";\n";
        let cases = [
            (
                "vacation, inbound subject",
                plain("require \"vacation\";\nvacation \"away\";\n"),
            ),
            (
                "vacation :subject",
                matched("vacation :subject \"${1}\" \"away\";"),
            ),
            (
                "vacation :from",
                matched("vacation :subject \"hi\" :from \"${1} <john@example.com>\" \"away\";"),
            ),
            (
                "enclose, inbound subject",
                plain("require \"enclose\";\nenclose \"body\";\nkeep;\n"),
            ),
            (
                "enclose :subject",
                matched("enclose :subject \"${1}\" \"body\"; keep;"),
            ),
            (
                "enclose :headers",
                matched("enclose :subject \"hi\" :headers \"X-Note: ${1}\" \"body\"; keep;"),
            ),
            (
                "notify, inbound subject",
                plain("require \"enotify\";\nnotify \"mailto:john@example.net\";\n"),
            ),
            (
                "notify :message",
                matched("notify :message \"${1}\" \"mailto:john@example.net\";"),
            ),
            (
                "notify :from",
                matched(
                    "notify :message \"hi\" :from \"${1} <john@example.com>\" \"mailto:john@example.net\";",
                ),
            ),
            (
                "notify mailto subject",
                mailto("john@example.net?subject=a%0D%0ABcc:%20victim@example.com"),
            ),
            (
                "notify mailto header",
                mailto("john@example.net?subject=hi&x-note=a%0D%0ABcc:%20victim@example.com"),
            ),
            (
                "notify mailto param name",
                mailto("john@example.net?x%0D%0ABcc=victim%40example.com"),
            ),
            (
                "notify mailto trailing name",
                mailto("john@example.net?subject=hi&x%0D%0ABcc%3A%20victim%40example%2Ecom"),
            ),
            (
                "notify mailto address",
                mailto("a%0D%0ABcc%3A%20victim@example.net"),
            ),
        ];
        let mut problems = Vec::new();
        let mut check = |case: &str, script: &str, extra_headers: &str, full_name: &str| {
            for message in messages(script, extra_headers, full_name) {
                if let Some(problem) = header_problem(&message) {
                    problems.push(format!("{case}: {problem}"));
                }
            }
        };
        for (case, script) in &cases {
            check(case, script, "", "");
        }
        check(
            "vacation, user name",
            away,
            "",
            "John\r\nBcc: victim@example.com",
        );
        check(
            "vacation, message id",
            away,
            "Message-ID: <a\rBcc: victim@example.com>\r\n",
            "",
        );
        assert!(problems.is_empty(), "{problems:#?}");

        // the inbound subject still makes the vacation reply's subject
        let reply = &messages(&cases[0].1, "", "")[0];
        assert!(
            reply.contains("\r\nSubject: Auto: xBcc: victim@example.com\r\n"),
            "{reply}"
        );
    }
}
