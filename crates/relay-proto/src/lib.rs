/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The link between inbuxa-relay and its downstream server or cluster
//! (docs/spec/features/relay.md).
//!
//! The relay is a small JMAP server; the downstream is a JMAP client that
//! dials out to it. Both sides use this crate, so the wire types, the join
//! proof, recipient hashing and the sealed spool format are defined once.

pub mod jmap;
pub mod pin;
pub mod recipient;
pub mod release;
pub mod seal;
pub mod time;
pub mod token;
pub mod types;

/// The relay's JMAP capability.
pub const CAPABILITY: &str = "urn:inbuxa:jmap:relay";

/// The link protocol's version. A downstream refuses a relay with a higher
/// major version than it knows (RL-28).
pub const PROTOCOL_VERSION: u32 = 1;

/// The JMAP core capability, which every request also uses.
pub const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

/// Base64url without padding, for every byte field on the wire.
pub mod b64 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(text).ok()
    }

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| D::Error::custom(format!("expected {N} bytes in base64url")))
    }

    /// The same, for an optional field.
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer, const N: usize>(
            bytes: &Option<[u8; N]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match bytes {
                Some(bytes) => super::serialize(bytes, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
            deserializer: D,
        ) -> Result<Option<[u8; N]>, D::Error> {
            #[derive(Deserialize)]
            struct Wrap<const N: usize>(#[serde(with = "super")] [u8; N]);
            Ok(Option::<Wrap<N>>::deserialize(deserializer)?.map(|Wrap(bytes)| bytes))
        }
    }
}
