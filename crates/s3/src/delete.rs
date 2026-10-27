/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Error, Result,
    error::{ErrorBody, ErrorField, push_entity},
};
use bytes::Bytes;
use quick_xml::{Reader, events::Event};
use std::fmt::Write;

pub const MAX_DELETE_KEYS: usize = 1000;

const BODY_START: &str = "<Delete>";
const BODY_END: &str = "<Quiet>true</Quiet></Delete>";
const OBJECT_START: &str = "<Object><Key>";
const OBJECT_END: &str = "</Key></Object>";
const NO_SUCH_KEY: &str = "NoSuchKey";

#[derive(Debug, Clone)]
pub struct DeleteBatch {
    body: String,
    len: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeleteFailure {
    pub key: String,
    pub code: String,
    pub message: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeleteResponse {
    Deleted,
    Failed(Vec<DeleteFailure>),
    Rejected {
        code: Option<String>,
        message: Option<String>,
    },
    Malformed,
}

impl DeleteBatch {
    pub fn with_capacity(keys: usize, key_len: usize) -> Self {
        let keys = keys.min(MAX_DELETE_KEYS);
        DeleteBatch {
            body: String::with_capacity(
                BODY_START.len()
                    + keys * (OBJECT_START.len() + key_len + OBJECT_END.len())
                    + BODY_END.len(),
            ),
            len: 0,
        }
    }

    pub fn push(&mut self, key: &str) -> Result<()> {
        if key.is_empty() || self.len == MAX_DELETE_KEYS {
            return Err(Error::InvalidKey(key.into()));
        }
        if self.body.is_empty() {
            self.body.push_str(BODY_START);
        }
        self.body.push_str(OBJECT_START);
        push_escaped(&mut self.body, key);
        self.body.push_str(OBJECT_END);
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == MAX_DELETE_KEYS
    }

    pub(crate) fn into_body(mut self) -> Bytes {
        if self.body.is_empty() {
            self.body.push_str(BODY_START);
        }
        self.body.push_str(BODY_END);
        Bytes::from(self.body)
    }
}

fn push_escaped(out: &mut String, key: &str) {
    for ch in key.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            ch if ch.is_ascii_control() => {
                let _ = write!(out, "&#{};", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
}

impl DeleteResponse {
    pub(crate) fn parse(body: &[u8], content_length: Option<u64>) -> Self {
        if body.is_empty() && content_length == Some(0) {
            return DeleteResponse::Deleted;
        }
        let mut reader = Reader::from_reader(body);
        loop {
            match reader.read_event() {
                Ok(Event::Start(tag)) => {
                    return match tag.local_name().as_ref() {
                        "DeleteResult" => Self::parse_result(&mut reader),
                        "Error" => {
                            let error = ErrorBody::parse(body);
                            DeleteResponse::Rejected {
                                code: error.code,
                                message: error.message,
                            }
                        }
                        _ => DeleteResponse::Malformed,
                    };
                }
                Ok(Event::Empty(tag)) => {
                    return if tag.local_name().as_ref() == "DeleteResult" {
                        DeleteResponse::Deleted
                    } else {
                        DeleteResponse::Malformed
                    };
                }
                Ok(Event::Eof | Event::End(_)) | Err(_) => return DeleteResponse::Malformed,
                Ok(_) => {}
            }
        }
    }

    fn parse_result(reader: &mut Reader<&[u8]>) -> Self {
        let mut failures = Vec::new();
        let mut current: Option<DeleteFailure> = None;
        let mut field = ErrorField::Other;
        let mut text = String::new();
        let mut depth = 0u32;

        loop {
            match reader.read_event() {
                Ok(Event::Start(tag)) => {
                    depth += 1;
                    if current.is_some() {
                        field = ErrorField::parse(tag.local_name().as_ref());
                        text.clear();
                    } else if depth == 1 && tag.local_name().as_ref() == "Error" {
                        current = Some(DeleteFailure::default());
                    }
                }
                Ok(Event::Text(chunk)) if field != ErrorField::Other => {
                    text.push_str(&chunk.xml10_content());
                }
                Ok(Event::GeneralRef(entity)) if field != ErrorField::Other => {
                    push_entity(&entity, &mut text);
                }
                Ok(Event::End(_)) => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    if let Some(failure) = current.as_mut() {
                        if depth == 0 {
                            if let Some(failure) = current.take()
                                && failure.code != NO_SUCH_KEY
                            {
                                failures.push(failure);
                            }
                        } else {
                            let value = std::mem::take(&mut text);
                            match field {
                                ErrorField::Key => failure.key = value,
                                ErrorField::Code => failure.code = value,
                                ErrorField::Message => failure.message = Some(value),
                                ErrorField::Other => {}
                            }
                            field = ErrorField::Other;
                        }
                    }
                }
                Ok(Event::Eof) | Err(_) => return DeleteResponse::Malformed,
                Ok(_) => {}
            }
        }

        if failures.is_empty() {
            DeleteResponse::Deleted
        } else {
            DeleteResponse::Failed(failures)
        }
    }
}

