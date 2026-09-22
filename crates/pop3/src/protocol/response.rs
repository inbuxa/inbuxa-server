/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Mechanism;
use std::{borrow::Cow, fmt::Display};
use utils::chained_bytes::SliceRange;

pub enum Response<'x, T> {
    Ok(Cow<'static, str>),
    Err(Cow<'static, str>),
    List(Vec<T>),
    Message {
        bytes: SliceRange<'x>,
        lines: Option<u32>,
    },
    Capability {
        mechanisms: Vec<Mechanism>,
        stls: bool,
    },
}

impl<'x, T: Display> Response<'x, T> {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Ok(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::Err(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"-ERR ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::List(octets) => {
                let mut buf = Vec::with_capacity(octets.len() * 8 + 10);
                buf.extend_from_slice(format!("+OK {} messages\r\n", octets.len()).as_bytes());
                for (num, octet) in octets.iter().enumerate() {
                    buf.extend_from_slice((num + 1).to_string().as_bytes());
                    buf.extend_from_slice(b" ");
                    buf.extend_from_slice(octet.to_string().as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                buf.extend_from_slice(b".\r\n");
                buf
            }
            Response::Message { bytes, lines } => {
                let lines = *lines;
                let mut message = Vec::with_capacity(bytes.len() + 16);
                let mut octets = 0;
                let mut last_byte = b'\n';
                let mut in_headers = lines.is_some();
                let mut is_blank_line = true;
                let mut body_lines = 0;

                // Transparency procedure
                for &byte in bytes.into_iter() {
                    // POP3 requires that lines end with CRLF, do this check to ensure that
                    if byte == b'\n' && last_byte != b'\r' {
                        message.push(b'\r');
                        octets += 1;
                    }

                    if byte == b'.' && last_byte == b'\n' {
                        message.push(b'.');
                    }
                    message.push(byte);
                    octets += 1;
                    last_byte = byte;

                    match byte {
                        b'\n' => {
                            if in_headers {
                                in_headers = !is_blank_line;
                            } else {
                                body_lines += 1;
                            }
                            if !in_headers && lines.is_some_and(|lines| body_lines >= lines) {
                                break;
                            }
                            is_blank_line = true;
                        }
                        b'\r' => {}
                        _ => {
                            is_blank_line = false;
                        }
                    }
                }

                if last_byte != b'\n' {
                    message.extend_from_slice(b"\r\n");
                    octets += 2;
                }

                if in_headers {
                    message.extend_from_slice(b"\r\n");
                    octets += 2;
                }

                message.extend_from_slice(b".\r\n");

                let mut buf = Vec::with_capacity(message.len() + 24);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(octets.to_string().as_bytes());
                buf.extend_from_slice(b" octets\r\n");
                buf.extend_from_slice(&message);
                buf
            }
            Response::Capability { mechanisms, stls } => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(b"+OK Capability list follows\r\n");
                if !mechanisms.is_empty() {
                    if mechanisms.contains(&Mechanism::Plain) {
                        buf.extend_from_slice(b"USER\r\n");
                    }
                    buf.extend_from_slice(b"SASL");
                    for mechanism in mechanisms {
                        buf.extend_from_slice(b" ");
                        buf.extend_from_slice(mechanism.as_str().as_bytes());
                    }
                    buf.extend_from_slice(b"\r\n");
                }

                if *stls {
                    buf.extend_from_slice(b"STLS\r\n");
                }

                for capa in [
                    "TOP",
                    "RESP-CODES",
                    "PIPELINING",
                    "EXPIRE NEVER",
                    "UIDL",
                    "UTF8",
                    "IMPLEMENTATION Stalwart Server",
                ] {
                    buf.extend_from_slice(capa.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }

                buf.extend_from_slice(b".\r\n");
                buf
            }
        }
    }
}

impl Mechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Plain => "PLAIN",
            Mechanism::CramMd5 => "CRAM-MD5",
            Mechanism::DigestMd5 => "DIGEST-MD5",
            Mechanism::ScramSha1 => "SCRAM-SHA-1",
            Mechanism::ScramSha256 => "SCRAM-SHA-256",
            Mechanism::Apop => "APOP",
            Mechanism::Ntlm => "NTLM",
            Mechanism::Gssapi => "GSSAPI",
            Mechanism::Anonymous => "ANONYMOUS",
            Mechanism::External => "EXTERNAL",
            Mechanism::OAuthBearer => "OAUTHBEARER",
            Mechanism::XOauth2 => "XOAUTH2",
        }
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let message = self
            .value_as_str(trc::Key::Details)
            .unwrap_or_else(|| self.as_ref().message());
        let mut buf = Vec::with_capacity(message.len() + 6);
        buf.extend_from_slice(b"-ERR ");
        buf.extend_from_slice(message.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::Response;
    use crate::protocol::Mechanism;
    use utils::chained_bytes::SliceRange;

    #[test]
    fn serialize_response() {
        for (cmd, expected) in [
            (
                Response::Ok("message 1 deleted".into()),
                "+OK message 1 deleted\r\n",
            ),
            (
                Response::Err("permission denied".into()),
                "-ERR permission denied\r\n",
            ),
            (
                Response::List(vec![100, 200, 300]),
                "+OK 3 messages\r\n1 100\r\n2 200\r\n3 300\r\n.\r\n",
            ),
            (
                Response::Capability {
                    mechanisms: vec![Mechanism::Plain, Mechanism::CramMd5],
                    stls: true,
                },
                concat!(
                    "+OK Capability list follows\r\n",
                    "USER\r\n",
                    "SASL PLAIN CRAM-MD5\r\n",
                    "STLS\r\n",
                    "TOP\r\n",
                    "RESP-CODES\r\n",
                    "PIPELINING\r\n",
                    "EXPIRE NEVER\r\n",
                    "UIDL\r\n",
                    "UTF8\r\n",
                    "IMPLEMENTATION Stalwart Server\r\n.\r\n"
                ),
            ),
            (
                Response::Message {
                    bytes: SliceRange::Split(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    lines: None,
                },
                "+OK 37 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Split(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    lines: Some(0),
                },
                "+OK 17 octets\r\nSubject: test\r\n\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Split(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    lines: Some(2),
                },
                "+OK 27 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Split(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    lines: Some(100),
                },
                "+OK 37 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Single(b"Subject: test\n\nbody\n"),
                    lines: None,
                },
                "+OK 23 octets\r\nSubject: test\r\n\r\nbody\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Single(b"Subject: test\n\n.leading dot\n"),
                    lines: Some(1),
                },
                "+OK 31 octets\r\nSubject: test\r\n\r\n..leading dot\r\n.\r\n",
            ),
            (
                Response::Message {
                    bytes: SliceRange::Single(b".dot\r\nSubject: test\r\n"),
                    lines: Some(3),
                },
                "+OK 23 octets\r\n..dot\r\nSubject: test\r\n\r\n.\r\n",
            ),
        ] {
            assert_eq!(expected, String::from_utf8(cmd.serialize()).unwrap());
        }
    }
}
