/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use quick_xml::{
    Reader,
    escape::resolve_predefined_entity,
    events::{BytesRef, Event},
};
use reqwest::{Response, StatusCode};
use std::fmt::{self, Display};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Transport(reqwest::Error),
    Status {
        status: u16,
        code: Option<Box<str>>,
        message: Option<Box<str>>,
    },
    DeleteFailed {
        key: Box<str>,
        code: Box<str>,
        message: Option<Box<str>>,
    },
    NotVisible,
    InvalidResponse(&'static str),
    InvalidKey(Box<str>),
    InvalidConfig(Box<str>),
    Credentials(Box<str>),
}

const MAX_ERROR_BODY: usize = 64 * 1024;
const CHECKSUM_HEADER_PREFIX: &str = "x-amz-checksum-";

impl Error {
    #[cold]
    pub(crate) async fn from_response(response: Response) -> Self {
        let status = response.status().as_u16();
        let body = read_capped(response, MAX_ERROR_BODY)
            .await
            .unwrap_or_default();
        let (code, message) = ErrorBody::parse(&body).into_parts();
        Error::Status {
            status,
            code,
            message,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Status { status, .. } => Some(*status),
            Error::NotVisible => Some(StatusCode::NOT_FOUND.as_u16()),
            _ => None,
        }
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Status { code, .. } => code.as_deref(),
            Error::DeleteFailed { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn is_not_implemented(&self) -> bool {
        matches!(self, Error::Status { status, .. } if *status == StatusCode::NOT_IMPLEMENTED.as_u16())
    }

    #[cold]
    pub(crate) fn rejects_checksum(&self) -> bool {
        let Error::Status {
            status,
            code,
            message,
        } = self
        else {
            return false;
        };
        if *status == StatusCode::NOT_IMPLEMENTED.as_u16() {
            return true;
        }
        if *status != StatusCode::BAD_REQUEST.as_u16() {
            return false;
        }
        let Some(message) = message.as_deref().map(str::to_ascii_lowercase) else {
            return false;
        };
        match code.as_deref().map(str::as_bytes) {
            Some(code)
                if hashify::set!(
                    code,
                    "BadDigest",
                    "InvalidDigest",
                    "XAmzContentChecksumMismatch",
                    "XAmzContentSHA256Mismatch"
                ) =>
            {
                false
            }
            Some(code)
                if hashify::set!(
                    code,
                    "InvalidArgument",
                    "InvalidRequest",
                    "NotImplemented",
                    "UnsupportedHeader"
                ) =>
            {
                message.contains("checksum")
            }
            _ => message.contains(CHECKSUM_HEADER_PREFIX),
        }
    }
}

pub(crate) async fn read_capped(
    mut response: Response,
    max_len: usize,
) -> std::result::Result<Vec<u8>, reqwest::Error> {
    let mut body = Vec::with_capacity(response.content_length().map_or(0, |len| {
        usize::try_from(len).unwrap_or(max_len).min(max_len)
    }));
    while let Some(chunk) = response.chunk().await? {
        let room = max_len - body.len();
        if chunk.len() >= room {
            body.extend_from_slice(chunk.get(..room).unwrap_or_default());
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Default)]
pub(crate) struct ErrorBody {
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorField {
    Code,
    Message,
    Key,
    Other,
}

impl ErrorField {
    pub(crate) fn parse(name: &str) -> Self {
        hashify::map!(name.as_bytes(), ErrorField,
            "Code" => ErrorField::Code,
            "Message" => ErrorField::Message,
            "Key" => ErrorField::Key,
        )
        .copied()
        .unwrap_or(ErrorField::Other)
    }
}

impl ErrorBody {
    pub(crate) fn parse(body: &[u8]) -> Self {
        let mut reader = Reader::from_reader(body);
        let mut error = ErrorBody::default();
        let mut field = ErrorField::Other;
        let mut text = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(tag)) => {
                    field = ErrorField::parse(tag.local_name().as_ref());
                    text.clear();
                }
                Ok(Event::Text(chunk)) if field != ErrorField::Other => {
                    text.push_str(&chunk.xml10_content());
                }
                Ok(Event::GeneralRef(entity)) if field != ErrorField::Other => {
                    push_entity(&entity, &mut text);
                }
                Ok(Event::End(_)) => {
                    match field {
                        ErrorField::Code => error.code = Some(std::mem::take(&mut text)),
                        ErrorField::Message => error.message = Some(std::mem::take(&mut text)),
                        ErrorField::Key | ErrorField::Other => {}
                    }
                    field = ErrorField::Other;
                }
                Ok(Event::Eof) | Err(_) => break,
                Ok(_) => {}
            }
        }
        error
    }

    fn into_parts(self) -> (Option<Box<str>>, Option<Box<str>>) {
        (
            self.code.map(String::into_boxed_str),
            self.message.map(String::into_boxed_str),
        )
    }
}

pub(crate) fn push_entity(entity: &BytesRef<'_>, out: &mut String) {
    if let Ok(Some(ch)) = entity.resolve_char_ref() {
        out.push(ch);
    } else if let Some(text) = resolve_predefined_entity(entity) {
        out.push_str(text);
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(err) => {
                write!(f, "S3 request failed: {err}")?;
                let mut source = std::error::Error::source(err);
                while let Some(err) = source {
                    write!(f, ": {err}")?;
                    source = err.source();
                }
                Ok(())
            }
            Error::Status {
                status,
                code,
                message,
            } => {
                write!(f, "S3 returned status {status}")?;
                if let Some(code) = code {
                    write!(f, " {code}")?;
                }
                if let Some(message) = message {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            Error::DeleteFailed { key, code, message } => {
                write!(f, "S3 failed to delete {key:?}: {code}")?;
                if let Some(message) = message {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            Error::NotVisible => f.write_str(concat!(
                "PUT acknowledged with 2xx but object not visible to read path; ",
                "backend may be silently losing writes"
            )),
            Error::InvalidResponse(reason) => write!(f, "Invalid S3 response: {reason}"),
            Error::InvalidKey(key) => write!(f, "Invalid S3 object key {key:?}"),
            Error::InvalidConfig(reason) => write!(f, "Invalid S3 configuration: {reason}"),
            Error::Credentials(reason) => write!(f, "S3 credentials: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Transport(err)
    }
}

