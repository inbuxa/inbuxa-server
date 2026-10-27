/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod file;
pub mod hierarchy;
pub mod paths;
pub mod presence;
pub mod resource;
pub mod store;

pub use file::{
    FILE_DEFAULT_MEDIA_TYPE, FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK,
    MAX_FILE_EXTRA_LEN,
};
pub use presence::{DISPLAY_NAME_PROPERTY, FilePresence, PresenceBits};
pub use store::ResourceChunkBuilder;

use ::store::blake3;
use percent_encoding::{
    AsciiSet, CONTROLS, percent_decode_str, percent_encode, utf8_percent_encode,
};
use std::{borrow::Cow, convert::Infallible};
use utils::text::hex_encode_into;

pub(crate) const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const CONTAINER_FLAG: u32 = 1 << 31;
pub const MAX_CACHED_UID_LEN: usize = 255;
const HASHED_UID_MARKER: u8 = 0;
const HASHED_UID_DIGEST_LEN: usize = 16;
const HASHED_UID_SUFFIX_LEN: usize = 1 + 2 * HASHED_UID_DIGEST_LEN;
const HASHED_UID_PREFIX_LEN: usize = MAX_CACHED_UID_LEN - HASHED_UID_SUFFIX_LEN;

pub trait CachedUid {
    fn cached_uid(&self) -> Cow<'_, str>;
    fn is_hashed_uid(&self) -> bool;
}

impl CachedUid for str {
    fn cached_uid(&self) -> Cow<'_, str> {
        if self.len() <= MAX_CACHED_UID_LEN && !self.as_bytes().contains(&HASHED_UID_MARKER) {
            Cow::Borrowed(self)
        } else {
            Cow::Owned(hashed_uid(self))
        }
    }

    #[inline(always)]
    fn is_hashed_uid(&self) -> bool {
        matches!(
            self.as_bytes().split_last_chunk::<HASHED_UID_SUFFIX_LEN>(),
            Some((_, [HASHED_UID_MARKER, ..]))
        )
    }
}

#[cold]
#[inline(never)]
fn hashed_uid(uid: &str) -> String {
    let prefix = uid
        .get(..uid.floor_char_boundary(HASHED_UID_PREFIX_LEN))
        .unwrap_or_default();
    let digest = blake3::hash(uid.as_bytes());
    let mut hex = [0u8; 2 * HASHED_UID_DIGEST_LEN];
    let mut cached = String::with_capacity(prefix.len() + HASHED_UID_SUFFIX_LEN);
    cached.push_str(prefix);
    cached.push(char::from(HASHED_UID_MARKER));
    cached.push_str(hex_encode_into(
        &digest.as_bytes()[..HASHED_UID_DIGEST_LEN],
        &mut hex,
    ));
    cached
}
pub const MAX_FILE_NODE_DEPTH: usize = 64;

pub const RFC_3986: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub const FILE_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub const MAX_DAV_FILE_NAME_LEN: usize = 255;
pub const FORBIDDEN_FILE_NAME_CHARS: &str = "/<>:\"\\|?*";
pub const FORBIDDEN_FILE_NODE_NAMES: &[&str] = &[
    ".", "..", "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
    "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavFileNameError {
    Empty,
    TooLong,
    InvalidCharacter,
    ReservedName,
}

pub fn canonical_path_segment(name: &str) -> Cow<'_, str> {
    utf8_percent_encode(name, FILE_SEGMENT).into()
}

pub fn canonical_uri_path(path: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    canonicalize_path(path, push_file_segment)
}

pub fn canonical_dav_resource_uri(uri: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    canonicalize_resource_uri(uri, push_file_segment)
}

pub fn canonical_calcard_segment(segment: &str) -> Cow<'_, str> {
    if segment.bytes().all(is_pchar) {
        return Cow::Borrowed(segment);
    }
    let mut canonical = String::with_capacity(segment.len() + 8);
    let Ok(()) = push_calcard_segment(&mut canonical, segment);
    Cow::Owned(canonical)
}

pub fn canonical_calcard_uri(uri: &str) -> Cow<'_, str> {
    let Ok(uri) = canonicalize_resource_uri(uri, push_calcard_segment);
    uri
}

fn canonicalize_path<E>(
    path: &str,
    push_segment: impl Fn(&mut String, &str) -> Result<(), E>,
) -> Result<Cow<'_, str>, E> {
    if path.bytes().all(|byte| is_pchar(byte) || byte == b'/') {
        return Ok(Cow::Borrowed(path));
    }
    let mut canonical = String::with_capacity(path.len() + 8);
    for (idx, segment) in path.split('/').enumerate() {
        if idx > 0 {
            canonical.push('/');
        }
        push_segment(&mut canonical, segment)?;
    }
    Ok(Cow::Owned(canonical))
}

fn canonicalize_resource_uri<E>(
    uri: &str,
    push_segment: impl Fn(&mut String, &str) -> Result<(), E>,
) -> Result<Cow<'_, str>, E> {
    let Some((base, (collection, (account, resource)))) =
        uri.split_once("/dav/").and_then(|(base, path)| {
            path.split_once('/').and_then(|(collection, rest)| {
                rest.split_once('/')
                    .map(|account| (base, (collection, account)))
            })
        })
    else {
        return Ok(Cow::Borrowed(uri));
    };
    Ok(match canonicalize_path(resource, push_segment)? {
        Cow::Borrowed(_) => Cow::Borrowed(uri),
        Cow::Owned(resource) => Cow::Owned(format!("{base}/dav/{collection}/{account}/{resource}")),
    })
}

fn push_file_segment(canonical: &mut String, segment: &str) -> Result<(), DavFileNameError> {
    canonical.extend(utf8_percent_encode(&decode_segment(segment)?, FILE_SEGMENT));
    Ok(())
}

fn push_calcard_segment(canonical: &mut String, segment: &str) -> Result<(), Infallible> {
    let decoded: Cow<'_, [u8]> = percent_decode_str(segment).into();
    canonical.extend(percent_encode(&decoded, FILE_SEGMENT));
    Ok(())
}

pub fn dav_file_name(segment: &str) -> Result<String, DavFileNameError> {
    let name = decode_segment(segment)?;
    if name.is_empty() {
        Err(DavFileNameError::Empty)
    } else if name.len() > MAX_DAV_FILE_NAME_LEN {
        Err(DavFileNameError::TooLong)
    } else if matches!(name.as_ref(), "." | "..") {
        Err(DavFileNameError::ReservedName)
    } else if name.contains(char::is_control)
        || percent_decode_str(segment).any(|byte| byte.is_ascii_control())
    {
        Err(DavFileNameError::InvalidCharacter)
    } else {
        Ok(name.into_owned())
    }
}

fn decode_segment(segment: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    let decoded: Cow<'_, [u8]> = percent_decode_str(segment).into();
    if decoded.iter().any(|byte| matches!(byte, b'/' | b'\0')) {
        return Err(DavFileNameError::InvalidCharacter);
    }
    Ok(match decoded {
        Cow::Borrowed(_) => Cow::Borrowed(segment),
        Cow::Owned(bytes) => match String::from_utf8(bytes) {
            Ok(decoded) => Cow::Owned(decoded),
            Err(err) => Cow::Owned(escape_invalid_utf8(err.as_bytes())),
        },
    })
}

fn escape_invalid_utf8(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut name = String::with_capacity(bytes.len() * 3);
    for chunk in bytes.utf8_chunks() {
        name.push_str(chunk.valid());
        for byte in chunk.invalid() {
            let _ = write!(name, "%{byte:02X}");
        }
    }
    name
}

fn is_pchar(byte: u8) -> bool {
    matches!(byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@')
}

