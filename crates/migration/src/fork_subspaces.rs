/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: store layout step 2 -> 3 (store-layout spec SL-16, SL-17, SL-20).
//! The audit log, the journal, holds and undelete notes move out of the
//! fork's `_` subspace into subspaces of their own, each key without the
//! letter that named its feature. Their settings stay in `_`, where a
//! configuration export carries them. RocksDB's legacy `v` and `c` go.
//!
//! Every key in `_` belongs to a feature, by its first byte, listed in
//! [`OWNERS`]. A key nobody claims stops the step before it changes
//! anything: it would mean a feature this step doesn't know about.

use store::{
    IterateParams, SUBSPACE_AUDIT, SUBSPACE_HOLDS, SUBSPACE_INBUXA, SUBSPACE_JOURNAL,
    SUBSPACE_UNDELETE, Store, ValueKey,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// Set once every copy has been checked, before the first original is
/// deleted, so a run that stops while deleting doesn't check again against
/// originals it already deleted. Cleared at the end.
pub const CHECKED_KEY: &[u8] = b"Vt";

/// Rows copied at a time where the backend can't copy on the server.
const COPY_CHUNK: usize = 10_000;

/// What happens to the keys under one first byte of `_`.
pub enum Owner {
    /// They stay in `_`.
    Stays(&'static str),
    /// They move to `to`, without the first byte. `kinds` are the second
    /// bytes that move and `stays` those that stay; any other stops the step.
    Moves {
        what: &'static str,
        to: u8,
        kinds: &'static [u8],
        stays: &'static [u8],
        /// Kinds whose values are compared row for row after the copy, not
        /// only counted: the chain heads and floors.
        compared: &'static [u8],
    },
}

/// SL-16: every first byte in use in `_`, and its owner.
pub const OWNERS: &[(u8, Owner)] = &[
    (b'A', Owner::Stays("AI limits")),
    (b'B', Owner::Stays("first boot defaults")),
    (b'C', Owner::Stays("account snapshots")),
    (b'D', Owner::Stays("deliverability reports")),
    (b'E', Owner::Stays("inbuxa relay")),
    (b'F', Owner::Stays("front ends")),
    (b'G', Owner::Stays("scheduled reports")),
    (
        b'H',
        Owner::Moves {
            what: "legal holds",
            to: SUBSPACE_HOLDS,
            kinds: b"hoe",
            stays: b"",
            compared: b"h",
        },
    ),
    (b'I', Owner::Stays("migrations")),
    (
        b'J',
        Owner::Moves {
            what: "journal",
            to: SUBSPACE_JOURNAL,
            kinds: b"ecptxhfow",
            stays: b"j",
            compared: b"hf",
        },
    ),
    (b'K', Owner::Stays("account locks")),
    (
        b'L',
        Owner::Moves {
            what: "audit log",
            to: SUBSPACE_AUDIT,
            kinds: b"etohf",
            stays: b"s",
            compared: b"hf",
        },
    ),
    (b'M', Owner::Stays("masked email")),
    (b'P', Owner::Stays("permissions and protocol policies")),
    (b'Q', Owner::Stays("acceptance records")),
    (b'R', Owner::Stays("mail flow rules")),
    (
        b'S',
        Owner::Stays("spam rules, scale-out storage and earlier scheduled reports"),
    ),
    (b'T', Owner::Stays("log files")),
    (
        b'U',
        Owner::Moves {
            what: "undelete notes",
            to: SUBSPACE_UNDELETE,
            kinds: b"nxbrckag",
            stays: b"",
            compared: b"",
        },
    ),
    (b'V', Owner::Stays("store checks and the store layout")),
    (
        b'W',
        Owner::Stays("blob store changes and the sharing policy"),
    ),
];

/// Step 2 -> 3. Returns how many rows moved.
pub async fn fork_data_own_subspaces(store: &Store) -> trc::Result<u64> {
    let moving = moving_prefixes(store).await?;

    // Always copy, even after a run that stopped while deleting: whatever
    // is left of the originals is copied again before it goes
    for prefix in &moving {
        copy(store, prefix).await?;
    }

    let checked = store
        .key_exists(inbuxa_key(CHECKED_KEY))
        .await
        .caused_by(trc::location!())?;
    let mut moved = 0;
    if !checked {
        for prefix in &moving {
            moved += check(store, prefix).await?;
        }
        let mut batch = BatchBuilder::new();
        batch.set(inbuxa_class(CHECKED_KEY), vec![1]);
        store
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    for prefix in &moving {
        store
            .delete_range(
                AnyKey {
                    subspace: SUBSPACE_INBUXA,
                    key: prefix.from.clone(),
                },
                AnyKey {
                    subspace: SUBSPACE_INBUXA,
                    key: prefix.to.clone(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    let dropped = store
        .drop_legacy_subspaces()
        .await
        .caused_by(trc::location!())?;
    if dropped > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = "Dropped the legacy v and c column families",
            Total = dropped,
        );
    }

    let mut batch = BatchBuilder::new();
    batch.clear(inbuxa_class(CHECKED_KEY));
    store
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(moved)
}

/// One second byte under a moving feature: its range in `_` and where it
/// goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    what: &'static str,
    /// The two bytes in `_`.
    from: Vec<u8>,
    /// The first key after them in `_`.
    to: Vec<u8>,
    dest: u8,
    compared: bool,
}

/// SL-16: lists the two-byte prefixes in `_` by skipping from one to the
/// next, so it reads one key per prefix, not every key. Stops on any key
/// nobody claims, before anything is written.
pub async fn moving_prefixes(store: &Store) -> trc::Result<Vec<Prefix>> {
    let mut begin = Vec::new();
    let mut unclaimed = Vec::new();
    let mut moving = Vec::new();

    loop {
        let mut first = None;
        store
            .iterate(
                IterateParams::new(inbuxa_key(&begin), inbuxa_key(&[u8::MAX; 64]))
                    .no_values()
                    .only_first(),
                |key, _| {
                    first = Some(key.to_vec());
                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;
        let Some(key) = first else {
            break;
        };

        let prefix = &key[..key.len().min(2)];
        match claim(prefix) {
            Claim::Stays => {}
            Claim::Moves(found) => moving.push(found),
            Claim::Nobody => unclaimed.push(printable(prefix)),
        }

        // A one-byte key is followed by the longer keys under it
        begin = if key.len() == 1 {
            vec![key[0], 0]
        } else {
            match next_prefix(prefix) {
                Some(next) => next,
                None => break,
            }
        };
    }

    if unclaimed.is_empty() {
        Ok(moving)
    } else {
        Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details(format!(
                "Store layout step 2 to 3 found keys in the _ subspace that no feature claims ({}). Nothing was changed",
                unclaimed.join(", ")
            ))
            .caused_by(trc::location!()))
    }
}

enum Claim {
    Stays,
    Moves(Prefix),
    Nobody,
}

fn claim(prefix: &[u8]) -> Claim {
    let Some((_, owner)) = OWNERS.iter().find(|(byte, _)| Some(byte) == prefix.first()) else {
        return Claim::Nobody;
    };
    match owner {
        Owner::Stays(_) => Claim::Stays,
        Owner::Moves {
            what,
            to,
            kinds,
            stays,
            compared,
        } => match prefix.get(1) {
            Some(kind) if stays.contains(kind) => Claim::Stays,
            Some(kind) if kinds.contains(kind) => Claim::Moves(Prefix {
                what,
                from: prefix.to_vec(),
                to: next_prefix(prefix).unwrap_or_else(|| vec![u8::MAX; 64]),
                dest: *to,
                compared: compared.contains(kind),
            }),
            _ => Claim::Nobody,
        },
    }
}

/// The first byte string after every key that starts with `prefix`.
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next = prefix.to_vec();
    while let Some(last) = next.pop() {
        if last < u8::MAX {
            next.push(last + 1);
            return Some(next);
        }
    }
    None
}

fn printable(prefix: &[u8]) -> String {
    prefix
        .iter()
        .map(|&byte| {
            if byte.is_ascii_graphic() {
                (byte as char).to_string()
            } else {
                format!("\\x{byte:02x}")
            }
        })
        .collect()
}

/// SL-17: on SQL in one statement on the server, elsewhere a row at a
/// time. A row already copied is written again, unchanged.
async fn copy(store: &Store, prefix: &Prefix) -> trc::Result<()> {
    let copied = store
        .copy_range(
            AnyKey {
                subspace: SUBSPACE_INBUXA,
                key: prefix.from.clone(),
            },
            AnyKey {
                subspace: SUBSPACE_INBUXA,
                key: prefix.to.clone(),
            },
            prefix.dest,
            1,
        )
        .await
        .caused_by(trc::location!())?;
    if copied.is_some() {
        return Ok(());
    }

    // A chunk at a time, so a large journal isn't held in memory
    let mut begin = prefix.from.clone();
    loop {
        let mut rows = Vec::new();
        store
            .iterate(
                IterateParams::new(inbuxa_key(&begin), inbuxa_key(&prefix.to)),
                |key, value| {
                    if key.starts_with(&prefix.from) {
                        rows.push((key.to_vec(), value.to_vec()));
                    }
                    Ok(rows.len() < COPY_CHUNK)
                },
            )
            .await
            .caused_by(trc::location!())?;
        let Some((last, _)) = rows.last() else {
            return Ok(());
        };
        let full = rows.len() == COPY_CHUNK;
        // The next chunk starts right after the last key of this one
        begin = last.clone();
        begin.push(0);

        let mut batch = BatchBuilder::new();
        for (key, value) in rows {
            batch.set(
                ValueClass::Any(AnyClass {
                    subspace: prefix.dest,
                    key: key[1..].to_vec(),
                }),
                value,
            );
            if batch.is_large_batch() {
                store
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            store
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }
        if !full {
            return Ok(());
        }
    }
}

/// SL-17: the copy has as many rows as the originals, and the chain heads
/// and floors are the same, byte for byte. Returns the rows checked.
async fn check(store: &Store, prefix: &Prefix) -> trc::Result<u64> {
    let dest_from = prefix.from[1..].to_vec();
    let dest_to = next_prefix(&dest_from).unwrap_or_else(|| vec![u8::MAX; 64]);
    let originals = rows(
        store,
        SUBSPACE_INBUXA,
        &prefix.from,
        &prefix.to,
        prefix.compared,
    )
    .await?;
    let copies = rows(store, prefix.dest, &dest_from, &dest_to, prefix.compared).await?;

    let matches = if prefix.compared {
        originals.values == copies.values
    } else {
        originals.count == copies.count
    };
    if !matches {
        return Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details(format!(
                "Store layout step 2 to 3: the copy of the {} ({}) doesn't match its originals: {} rows were copied of {}. Nothing was deleted",
                prefix.what,
                printable(&prefix.from),
                copies.count,
                originals.count
            ))
            .caused_by(trc::location!()));
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!(
            "Copied the {} ({}) to its own subspace",
            prefix.what,
            printable(&prefix.from)
        ),
        Total = originals.count,
    );
    Ok(originals.count)
}

struct Rows {
    count: u64,
    /// The keys as they are in the feature's own subspace, when compared.
    values: Vec<(Vec<u8>, Vec<u8>)>,
}

async fn rows(
    store: &Store,
    subspace: u8,
    from: &[u8],
    to: &[u8],
    with_values: bool,
) -> trc::Result<Rows> {
    let mut rows = Rows {
        count: 0,
        values: Vec::new(),
    };
    // In `_`, the feature's letter comes first
    let skip = usize::from(subspace == SUBSPACE_INBUXA);
    store
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: from.to_vec(),
                },
                AnyKey {
                    subspace,
                    key: to.to_vec(),
                },
            )
            .set_values(with_values),
            |key, value| {
                if key.starts_with(from) {
                    rows.count += 1;
                    if with_values {
                        rows.values.push((key[skip..].to_vec(), value.to_vec()));
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    Ok(rows)
}

fn inbuxa_key(key: &[u8]) -> ValueKey<ValueClass> {
    ValueKey::from(inbuxa_class(key))
}

fn inbuxa_class(key: &[u8]) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: key.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_owner_is_listed_once() {
        for (i, (byte, _)) in OWNERS.iter().enumerate() {
            assert!(
                OWNERS[i + 1..].iter().all(|(other, _)| other != byte),
                "{} is listed twice",
                *byte as char
            );
        }
    }

    #[test]
    fn claims() {
        assert!(matches!(claim(b"Vs"), Claim::Stays));
        assert!(matches!(claim(b"Ls"), Claim::Stays));
        assert!(matches!(claim(b"Jj"), Claim::Stays));
        assert!(matches!(claim(b"Lz"), Claim::Nobody));
        assert!(matches!(claim(b"L"), Claim::Nobody));
        assert!(matches!(claim(b"Zz"), Claim::Nobody));
        assert!(matches!(claim(b"\x00"), Claim::Nobody));
        let Claim::Moves(prefix) = claim(b"Le") else {
            panic!()
        };
        assert_eq!(prefix.dest, SUBSPACE_AUDIT);
        assert_eq!(prefix.to, b"Lf");
        assert!(!prefix.compared);
        let Claim::Moves(prefix) = claim(b"Jh") else {
            panic!()
        };
        assert_eq!(prefix.dest, SUBSPACE_JOURNAL);
        assert!(prefix.compared);
        let Claim::Moves(prefix) = claim(b"Ug") else {
            panic!()
        };
        assert_eq!(prefix.dest, SUBSPACE_UNDELETE);
    }

    // The two-byte prefixes on prod's `_` on 2026-11-11, all claimed
    #[test]
    fn prod_prefixes_are_claimed() {
        for prefix in [
            "Al", "Ci", "Dr", "Gr", "Gs", "Kd", "Kl", "Le", "Lh", "Lo", "Lt", "Mi", "Pc", "Pg",
            "Pu", "Sf", "Sr", "Vs", "Wl", "Wn",
        ] {
            assert!(
                !matches!(claim(prefix.as_bytes()), Claim::Nobody),
                "{prefix}"
            );
        }
    }

    #[test]
    fn next_prefixes() {
        assert_eq!(next_prefix(b"Le"), Some(b"Lf".to_vec()));
        assert_eq!(next_prefix(&[b'L', 0xff]), Some(b"M".to_vec()));
        assert_eq!(next_prefix(&[0xff, 0xff]), None);
    }
}
