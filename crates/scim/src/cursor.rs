/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Cursor pagination (RFC 9865, SCIM-49). A cursor carries its own state,
//! sealed with an HMAC under the server's key: the position, the page size,
//! when it expires, and a hash of what produced it (principal, query and
//! sort). Nothing is kept on the server.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use scim_proto::{ScimError, ScimType};
use sha2::Sha256;

const VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const BODY_LEN: usize = 1 + 8 + 8 + 8 + 8;

/// What a cursor is bound to.
pub fn binding(parts: &[&str]) -> u64 {
    let mut text = String::new();
    for part in parts {
        text.push_str(part);
        text.push('\u{0}');
    }
    xxhash_rust::xxh3::xxh3_64(text.as_bytes())
}

fn tag(key: &[u8], body: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(b"inbuxa-scim-cursor");
    mac.update(body);
    mac.finalize().into_bytes()[..TAG_LEN].to_vec()
}

pub fn encode(key: &[u8], offset: u64, count: u64, expires: u64, binding: u64) -> String {
    let mut body = Vec::with_capacity(BODY_LEN + TAG_LEN);
    body.push(VERSION);
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(&expires.to_be_bytes());
    body.extend_from_slice(&binding.to_be_bytes());
    let tag = tag(key, &body);
    body.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(body)
}

/// The position a cursor points at, if it's genuine, unexpired, and was
/// issued for this binding and page size.
pub fn decode(
    key: &[u8],
    cursor: &str,
    count: u64,
    now: u64,
    binding: u64,
) -> Result<u64, ScimError> {
    let invalid = || ScimError::bad_request(ScimType::InvalidCursor, "The cursor isn't valid");
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor.trim())
        .map_err(|_| invalid())?;
    if bytes.len() != BODY_LEN + TAG_LEN || bytes[0] != VERSION {
        return Err(invalid());
    }
    let (body, sent) = bytes.split_at(BODY_LEN);
    let expected = tag(key, body);
    // Constant-time comparison
    if sent
        .iter()
        .zip(&expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        != 0
    {
        return Err(invalid());
    }
    let read = |at: usize| u64::from_be_bytes(body[at..at + 8].try_into().unwrap());
    let (offset, issued_count, expires, bound) = (read(1), read(9), read(17), read(25));
    if bound != binding {
        return Err(invalid());
    }
    if expires < now {
        return Err(ScimError::bad_request(
            ScimType::ExpiredCursor,
            "The cursor has expired",
        ));
    }
    if issued_count != count {
        return Err(ScimError::bad_request(
            ScimType::InvalidCount,
            "The count differs from the one the cursor was issued for",
        ));
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_changes() {
        let key = b"a server key";
        let bind = binding(&["principal", "userName eq \"a\""]);
        let cursor = encode(key, 200, 200, 1000, bind);
        assert_eq!(decode(key, &cursor, 200, 999, bind).unwrap(), 200);

        let err = |r: Result<u64, ScimError>| r.unwrap_err().scim_type.unwrap();
        assert_eq!(
            err(decode(key, &cursor, 100, 999, bind)),
            ScimType::InvalidCount
        );
        assert_eq!(
            err(decode(key, &cursor, 200, 1001, bind)),
            ScimType::ExpiredCursor
        );
        assert_eq!(
            err(decode(key, &cursor, 200, 999, bind + 1)),
            ScimType::InvalidCursor
        );
        assert_eq!(
            err(decode(b"other key", &cursor, 200, 999, bind)),
            ScimType::InvalidCursor
        );

        let mut tampered = URL_SAFE_NO_PAD.decode(&cursor).unwrap();
        tampered[8] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(tampered);
        assert_eq!(
            err(decode(key, &tampered, 200, 999, bind)),
            ScimType::InvalidCursor
        );
        assert_eq!(
            err(decode(key, "garbage", 200, 999, bind)),
            ScimType::InvalidCursor
        );
    }
}
