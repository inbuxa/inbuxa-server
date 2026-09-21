/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! When each account last signed in over each legacy protocol, for the
//! impact panel (legacy-protocols spec, LP-15, "Last use per protocol").
//!
//! One timestamp per account per protocol, and nothing else: no address, no
//! IP, no client. It is written at most once an hour per account and
//! protocol, so a mail app polling every minute costs one read per sign-in
//! and one write an hour. Stored under `P` `u`, the account id and a protocol
//! byte, in the fork's subspace.

use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// How long a recorded use stands before the next sign-in rewrites it.
pub const WRITE_EVERY_SECS: u64 = 3600;

/// How far back the impact panel looks (LP-15).
pub const RECENT_SECS: u64 = 30 * 24 * 3600;

/// The protocols the panel names, as they are spelled over JMAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyUse {
    Imap,
    Pop3,
    ManageSieve,
    Submission,
}

impl LegacyUse {
    pub fn as_str(&self) -> &'static str {
        match self {
            LegacyUse::Imap => "imap",
            LegacyUse::Pop3 => "pop3",
            LegacyUse::ManageSieve => "manageSieve",
            LegacyUse::Submission => "submission",
        }
    }

    fn byte(&self) -> u8 {
        match self {
            LegacyUse::Imap => b'i',
            LegacyUse::Pop3 => b'p',
            LegacyUse::ManageSieve => b's',
            LegacyUse::Submission => b'm',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'i' => Some(LegacyUse::Imap),
            b'p' => Some(LegacyUse::Pop3),
            b's' => Some(LegacyUse::ManageSieve),
            b'm' => Some(LegacyUse::Submission),
            _ => None,
        }
    }
}

/// One account's last use of one protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Use {
    pub account_id: u32,
    pub protocol: LegacyUse,
    /// Seconds since the epoch.
    pub at: u64,
}

fn key(account_id: u32, protocol: Option<LegacyUse>) -> ValueKey<ValueClass> {
    let mut key = Vec::with_capacity(7);
    key.extend_from_slice(b"Pu");
    key.extend_from_slice(&account_id.to_be_bytes());
    key.push(protocol.map_or(0, |p| p.byte()));
    ValueKey::from(ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    }))
}

/// Reads a stored key back into who and what, if it is one of ours.
fn parse_key(key: &[u8]) -> Option<(u32, LegacyUse)> {
    // The iterator may or may not hand back the subspace byte; the tail is
    // what identifies an entry: two bytes of prefix, four of account id and
    // one of protocol.
    let tail = key.get(key.len().checked_sub(7)?..)?;
    (tail[..2] == *b"Pu").then_some(())?;
    let account_id = u32::from_be_bytes(tail[2..6].try_into().ok()?);
    Some((account_id, LegacyUse::from_byte(tail[6])?))
}

struct At(u64);

impl Deserialize for At {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .try_into()
            .map(|bytes| At(u64::from_be_bytes(bytes)))
            .map_err(|_| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))
    }
}

/// Whether a use at `at` is recent enough for the panel at `now` (LP-15).
pub fn is_recent(at: u64, now: u64) -> bool {
    at >= now.saturating_sub(RECENT_SECS)
}

/// Whether a use at `now` should be written over one stored at `stored`.
fn due(stored: Option<u64>, now: u64) -> bool {
    stored.is_none_or(|stored| now.saturating_sub(stored) >= WRITE_EVERY_SECS)
}

/// Records a successful sign-in, unless one was recorded within the hour.
pub async fn record(
    data: &Store,
    account_id: u32,
    protocol: LegacyUse,
    now: u64,
) -> trc::Result<()> {
    let stored = data
        .get_value::<At>(key(account_id, Some(protocol)))
        .await
        .caused_by(trc::location!())?
        .map(|At(at)| at);
    if !due(stored, now) {
        return Ok(());
    }
    let mut batch = BatchBuilder::new();
    batch.set(
        key(account_id, Some(protocol)).class,
        now.to_be_bytes().to_vec(),
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Every use recent at `now` (LP-15), across all accounts.
pub async fn recent(data: &Store, now: u64) -> trc::Result<Vec<Use>> {
    let mut uses = Vec::new();
    data.iterate(
        IterateParams::new(key(0, None), key(u32::MAX, Some(LegacyUse::Submission))).ascending(),
        |key, value| {
            if let Some((account_id, protocol)) = parse_key(key)
                && let Ok(At(at)) = At::deserialize(value)
                && is_recent(at, now)
            {
                uses.push(Use {
                    account_id,
                    protocol,
                    at,
                });
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(uses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_at_most_once_an_hour() {
        assert!(due(None, 100));
        assert!(!due(Some(100), 100 + WRITE_EVERY_SECS - 1));
        assert!(due(Some(100), 100 + WRITE_EVERY_SECS));
        // A clock that went backwards doesn't write.
        assert!(!due(Some(100), 50));
    }

    #[test]
    fn the_panel_looks_back_thirty_days() {
        // Acceptance test 11: three days ago is listed, forty days ago isn't.
        let now = 1_800_000_000;
        let day = 24 * 3600;
        assert!(is_recent(now - 3 * day, now));
        assert!(is_recent(now - 30 * day, now));
        assert!(!is_recent(now - 30 * day - 1, now));
        assert!(!is_recent(now - 40 * day, now));
    }

    #[test]
    fn keys_read_back() {
        for protocol in [
            LegacyUse::Imap,
            LegacyUse::Pop3,
            LegacyUse::ManageSieve,
            LegacyUse::Submission,
        ] {
            let ValueClass::Any(any) = key(42, Some(protocol)).class else {
                panic!()
            };
            assert_eq!(parse_key(&any.key), Some((42, protocol)));
            // With the subspace byte in front, too.
            let mut with_subspace = vec![SUBSPACE_INBUXA];
            with_subspace.extend_from_slice(&any.key);
            assert_eq!(parse_key(&with_subspace), Some((42, protocol)));
        }
        assert_eq!(parse_key(b"Pp"), None);
        assert_eq!(parse_key(b"Xx\0\0\0\x2ai"), None);
    }

    #[test]
    fn only_protocols_are_recorded() {
        // Nothing but the four legacy protocols has a byte of its own.
        assert_eq!(LegacyUse::from_byte(0), None);
        assert_eq!(LegacyUse::from_byte(b'x'), None);
    }
}
