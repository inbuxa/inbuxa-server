/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:RelayMessage` ids (relay spec, "Registry objects"): a relay's
//! `Inbound` and `Outbound` messages, as this server names them. Nothing
//! is stored: the relay keeps its queues, and each id is made from the
//! relay's id and the relay's own message id, so every node names a
//! message the same way. The top 16 bits are the relay, the rest a hash
//! of the message's id at the relay, which a lookup checks against the
//! relay's queues.

use xxhash_rust::xxh3::xxh3_64;

const HASH_BITS: u32 = 48;
const HASH_MASK: u64 = (1 << HASH_BITS) - 1;

/// Relays numbered above this have no message ids. Relays are numbered
/// from 1, one more for each made, so there are never that many.
pub const MAX_RELAY_ID: u32 = u16::MAX as u32;

/// The id of a relay's message, from its id at the relay.
pub fn message_id(relay_id: u32, relay_message_id: &str) -> Option<u64> {
    (relay_id <= MAX_RELAY_ID).then(|| {
        (u64::from(relay_id) << HASH_BITS) | (xxh3_64(relay_message_id.as_bytes()) & HASH_MASK)
    })
}

/// The relay a message id is at.
pub fn relay_of(id: u64) -> u32 {
    (id >> HASH_BITS) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_name_their_relay() {
        let id = message_id(7, "o0123456789abcdef01234567").unwrap();
        assert_eq!(relay_of(id), 7);
        assert_eq!(message_id(7, "o0123456789abcdef01234567"), Some(id));
        assert_ne!(message_id(8, "o0123456789abcdef01234567"), Some(id));
        assert_ne!(message_id(7, "i0123456789abcdef01234567"), Some(id));
        assert_eq!(
            relay_of(message_id(MAX_RELAY_ID, "x").unwrap()),
            MAX_RELAY_ID
        );
        assert_eq!(message_id(MAX_RELAY_ID + 1, "x"), None);
    }
}
