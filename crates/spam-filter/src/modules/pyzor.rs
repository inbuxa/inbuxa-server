/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::SpamFilterInput;
use common::config::mailstore::spamfilter::PyzorConfig;
use mail_parser::PartKind;
use nlp::tokenizers::types::{TokenType, TypesTokenizer};

use super::html::{TEXT_STOP, byte_table, push_span, scan_until};
use sha1::{Digest, Sha1};
use std::{
    borrow::Cow,
    net::SocketAddr,
    ops::Range,
    time::{Duration, SystemTime},
};
use tokio::net::UdpSocket;
use utils::HexEncode;

static TAG_STOP: [bool; 256] = byte_table(b"<>/! \t\r\n");
static STYLE_STOP: [bool; 256] = byte_table(b"< \t\r\n");
static COMMENT_MARK: [bool; 256] = byte_table(b"->");

pub(crate) const MIN_LINE_LENGTH: usize = 8;
pub(crate) const ATOMIC_NUM_LINES: usize = 4;
pub(crate) const DIGEST_SPEC: &[(usize, usize)] = &[(20, 3), (60, 3)];

#[derive(Default, Debug, PartialEq, Eq)]
pub struct PyzorResponse {
    pub code: u32,
    pub count: u64,
    pub wl_count: u64,
}

/// inbuxa: the answers tests get, by digest, instead of a public server's,
/// whose counts change and which a test may not be able to reach. Upstream
/// answers the first three here and sends every other digest to the network.
#[cfg(inbuxa_tests)]
fn test_response(request: &str) -> PyzorResponse {
    let (count, wl_count) = if request.contains("b5b476f0b5ba6e1c038361d3ded5818dd39c90a2")
        // The digest of an empty body, as an HTML-only message with no text
        // to hash produces; public servers report it widely.
        || request.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    {
        (1000, 0)
    } else if request.contains("d67d4b8bfc3860449e3418bb6017e2612f3e2a99") {
        (60, 10)
    } else if request.contains("81763547012b75e57a20d18ce0b93014208cdfdb") {
        (50, 20)
    } else {
        (0, 0)
    };
    PyzorResponse {
        code: 200,
        count,
        wl_count,
    }
}

#[cfg_attr(inbuxa_tests, allow(dead_code))]
async fn pyzor_send_message(
    addr: SocketAddr,
    timeout: Duration,
    message: &str,
) -> std::io::Result<PyzorResponse> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tokio::time::timeout(timeout, socket.send_to(message.as_bytes(), addr)).await??;

    let mut buffer = vec![0u8; 1024];
    let (size, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer)).await??;

    let raw_response = std::str::from_utf8(&buffer[..size])
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut response = PyzorResponse {
        code: u32::MAX,
        count: u64::MAX,
        wl_count: u64::MAX,
    };

    for line in raw_response.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("code") {
                response.code = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            } else if k.eq_ignore_ascii_case("count") {
                response.count = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            } else if k.eq_ignore_ascii_case("wl-count") {
                response.wl_count = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            }
        }
    }

    if response.code != u32::MAX && response.count != u64::MAX && response.wl_count != u64::MAX {
        Ok(response)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid response: {raw_response}"),
        ))
    }
}

pub trait PyzorWrite {
    fn write_all(&mut self, data: &[u8]);
}

impl PyzorWrite for Vec<u8> {
    fn write_all(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

impl PyzorWrite for Sha1 {
    fn write_all(&mut self, data: &[u8]) {
        self.update(data);
    }
}

impl SpamFilterInput<'_> {
    pub(crate) async fn pyzor_check(
        &self,
        config: &PyzorConfig,
    ) -> trc::Result<Option<PyzorResponse>> {
        let Some(request) = self.pyzor_check_message() else {
            return Ok(None);
        };

        // Send message to address. inbuxa: in tests, a fixed table answers
        // instead of a public server (test_response).
        #[cfg(not(inbuxa_tests))]
        let response = match tokio::time::timeout(config.timeout, config.address()).await {
            Ok(Ok(address)) => pyzor_send_message(address, config.timeout, &request).await,
            Ok(Err(err)) => Err(err),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timed out resolving the Pyzor server",
            )),
        };
        #[cfg(inbuxa_tests)]
        let response = std::io::Result::Ok(test_response(&request));

        response.map(Into::into).map_err(|err| {
            trc::SpamEvent::PyzorError
                .into_err()
                .ctx(trc::Key::Url, format!("{}:{}", config.host, config.port))
                .reason(err)
                .details("Pyzor failed")
        })
    }

    pub fn pyzor_digest<W: PyzorWrite>(&self, writer: W) -> Option<W> {
        let texts = self.texts;
        let parts = self
            .message
            .root()
            .parts()
            .filter_map(|part| match part.kind() {
                PartKind::Text => texts.get(part.id()).map(Cow::Borrowed),
                PartKind::Html => Some(Cow::Owned(html_to_text(texts.get(part.id())?))),
                _ => None,
            })
            .collect::<Vec<_>>();

        pyzor_digest(writer, parts.iter().flat_map(|text| text.lines()))
    }

    pub fn pyzor_check_message(&self) -> Option<String> {
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        self.pyzor_create_message(
            time,
            (time & 0xFFFF) as u16 ^ ((time >> 16) & 0xFFFF) as u16,
        )
    }

    fn pyzor_create_message(&self, time: u64, thread: u16) -> Option<String> {
        let hash = self.pyzor_digest(Sha1::new())?.finalize().hex_encode();
        let mut hash_key = Sha1::new();
        hash_key.update("anonymous:".as_bytes());
        let hash_key = hash_key.finalize().hex_encode();

        let message = format!(
            "Op: check\nOp-Digest: {hash}\nThread: {thread}\nPV: 2.1\nUser: anonymous\nTime: {time}"
        );
        let mut msg_hash = Sha1::new();
        msg_hash.update(message.as_bytes());
        let msg_hash = msg_hash.finalize();

        let mut sig = Sha1::new();
        sig.update(msg_hash);
        sig.update(format!(":{time}:{hash_key}"));
        let sig = sig.finalize().hex_encode();

        Some(format!("{message}\nSig: {sig}\n"))
    }
}

pub fn pyzor_digest<'x, I, W>(mut writer: W, lines: I) -> Option<W>
where
    I: Iterator<Item = &'x str>,
    W: PyzorWrite,
{
    let mut buffer = String::new();
    let mut kept: Vec<Range<usize>> = Vec::with_capacity(16);

    for line in lines {
        if line.len() < MIN_LINE_LENGTH {
            continue;
        }
        buffer.reserve(line.len());
        let line_start = buffer.len();
        let mut token_start = usize::MAX;
        let mut token_end = usize::MAX;

        for token in TypesTokenizer::new(line) {
            match token.word {
                TokenType::Alphabetic(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Integer(_)
                | TokenType::Float(_)
                | TokenType::Other(_)
                | TokenType::Punctuation(_) => {
                    if token_start == usize::MAX {
                        token_start = token.from;
                    }
                    token_end = token.to;
                }
                TokenType::Space
                | TokenType::Url(_)
                | TokenType::UrlNoScheme(_)
                | TokenType::UrlNoHost(_)
                | TokenType::IpAddr(_)
                | TokenType::Email(_) => {
                    if token_start != usize::MAX {
                        add_span(&mut buffer, &line[token_start..token_end]);
                        token_start = usize::MAX;
                        token_end = usize::MAX;
                    }
                }
            }
        }

        if token_start != usize::MAX {
            add_span(&mut buffer, &line[token_start..token_end]);
        }

        if buffer.len() - line_start >= MIN_LINE_LENGTH {
            kept.push(line_start..buffer.len());
        } else {
            buffer.truncate(line_start);
        }
    }

    if kept.is_empty() {
        return None;
    }

    if kept.len() > ATOMIC_NUM_LINES {
        for (offset, length) in DIGEST_SPEC {
            for i in 0..*length {
                if let Some(line) = kept.get((*offset * kept.len() / 100) + i) {
                    writer.write_all(buffer[line.clone()].as_bytes());
                }
            }
        }
    } else {
        for line in kept {
            writer.write_all(buffer[line].as_bytes());
        }
    }

    Some(writer)
}

#[inline(always)]
fn add_span(line: &mut String, span: &str) {
    if !span.as_bytes().contains(&0) {
        if span.len() < 10 {
            line.push_str(span);
        }
    } else if span.len() - span.as_bytes().iter().filter(|&&ch| ch == 0).count() < 10 {
        for part in span.split('\0') {
            line.push_str(part);
        }
    }
}

pub fn html_to_text(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();

    let mut in_tag = false;
    let mut in_comment = false;
    let mut in_style = false;
    let mut in_script = false;

    let mut is_token_start = true;
    let mut is_after_space = false;
    let mut is_tag_close = false;

    let mut token_start = 0;
    let mut token_end = 0;

    let mut tag_token_pos = 0;
    let mut comment_pos = 0;

    let mut pos = 0;

    while let Some(&ch) = bytes.get(pos) {
        if in_comment {
            let stop = scan_until(bytes, pos, &COMMENT_MARK);
            if stop > pos {
                comment_pos = 0;
            }
            pos = stop;
            match bytes.get(pos) {
                None => break,
                Some(b'-') => {
                    comment_pos += 1;
                }
                Some(_) => {
                    if comment_pos == 2 {
                        in_comment = false;
                        in_tag = false;
                        is_token_start = true;
                    }
                    comment_pos = 0;
                }
            }
            pos += 1;
            continue;
        }

        match ch {
            b'<' => {
                if !(in_tag || in_style || in_script || is_token_start) {
                    push_span(
                        &mut result,
                        input,
                        token_start,
                        token_end + 1,
                        is_after_space,
                    );
                    is_after_space = false;
                }

                tag_token_pos = 0;
                in_tag = true;
                is_token_start = true;
                is_tag_close = false;
                pos += 1;
                continue;
            }
            b'>' if in_tag => {
                if tag_token_pos == 1
                    && let Some(tag) = bytes.get(token_start..token_end + 1)
                {
                    if tag.eq_ignore_ascii_case(b"style") {
                        in_style = !is_tag_close;
                    } else if tag.eq_ignore_ascii_case(b"script") {
                        in_script = !is_tag_close;
                    }
                }

                in_tag = false;
                is_token_start = true;
                is_after_space = !result.is_empty();
                pos += 1;
                continue;
            }
            b'/' if in_tag => {
                if tag_token_pos == 0 {
                    is_tag_close = true;
                }
                pos += 1;
                continue;
            }
            b'!' if in_tag && tag_token_pos == 0 => {
                if let Some(b"--") = bytes.get(pos + 1..pos + 3) {
                    in_comment = true;
                    pos += 1;
                    continue;
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                if !(in_tag || in_style || in_script) {
                    if !is_token_start {
                        push_span(
                            &mut result,
                            input,
                            token_start,
                            token_end + 1,
                            is_after_space,
                        );
                    }
                    is_after_space = true;
                }

                is_token_start = true;
                pos += 1;
                while matches!(bytes.get(pos), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    pos += 1;
                }
                continue;
            }
            b'&' if !(in_tag || is_token_start || in_style || in_script) => {
                push_span(
                    &mut result,
                    input,
                    token_start,
                    token_end + 1,
                    is_after_space,
                );
                is_token_start = true;
                is_after_space = false;
            }
            b';' if !(in_tag || is_token_start || in_style || in_script) => {
                push_span(&mut result, input, token_start, pos + 1, is_after_space);
                is_token_start = true;
                is_after_space = false;
                pos += 1;
                continue;
            }
            _ => (),
        }

        if is_token_start {
            token_start = pos;
            is_token_start = false;
            if in_tag {
                tag_token_pos += 1;
            }
        }
        let stop = if in_tag {
            scan_until(bytes, pos + 1, &TAG_STOP)
        } else if in_style || in_script {
            scan_until(bytes, pos + 1, &STYLE_STOP)
        } else {
            scan_until(bytes, pos + 1, &TEXT_STOP)
        };
        token_end = stop - 1;
        pos = stop;
    }

    if !(in_tag || is_token_start || in_style || in_script) {
        push_span(
            &mut result,
            input,
            token_start,
            token_end + 1,
            is_after_space,
        );
    }

    result.shrink_to_fit();
    result
}

