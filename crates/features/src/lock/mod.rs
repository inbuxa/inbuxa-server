/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Account lock with delegation (audit-hold-lock spec, AL-1 to AL-12).
//!
//! A locked account keeps receiving mail but can't sign in, by any means,
//! and sends nothing on its own. Delegates open it as a separate account,
//! through real ACL grants on its containers (the sharing every protocol
//! already honors), at a level the administrator chose.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `K`, then one byte for the kind:
//!
//! - `l` + account: the lock, as JSON.
//! - `d` + delegate + account: an index, so a delegate's access token can
//!   find the accounts delegated to it with one scan.
//!
//! Numbers are big-endian. Nothing is cached in memory: the access token is
//! the cache, built from these keys and invalidated on every change.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
};
use utils::map::bitmap::Bitmap;

/// Rung when a lock is written, so this node's expiry timer re-reads the
/// `until` dates (AL-5): a delegation ends at its time, not at a sweep.
pub static UNTIL_CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// The soonest `until` still ahead of `now`, across every lock.
pub fn next_until(locks: &[Lock], now: u64) -> Option<u64> {
    locks
        .iter()
        .flat_map(|lock| &lock.delegates)
        .filter_map(|delegate| delegate.until)
        .filter(|until| *until > now)
        .min()
}

/// Locks with a delegation that ended in `(after, now]`.
pub fn ended_between(locks: &[Lock], after: u64, now: u64) -> impl Iterator<Item = u32> + '_ {
    locks
        .iter()
        .filter(move |lock| {
            lock.delegates
                .iter()
                .any(|d| d.until.is_some_and(|until| until > after && until <= now))
        })
        .map(|lock| lock.account_id)
}

const FEATURE: u8 = b'K';
const KIND_LOCK: u8 = b'l';
const KIND_DELEGATE: u8 = b'd';

/// Most delegates one lock may have (AL-5).
pub const MAX_DELEGATES: usize = 10;

/// Most people one shared mailbox may have (MA-S): a help desk is bigger
/// than the handful a departed colleague's mail is handed to.
pub const MAX_SHARED_MAILBOX_DELEGATES: usize = 100;

/// What a lock is for (multi-account spec, MA-S).
///
/// Both kinds keep receiving mail, can't be signed in to, and are opened by
/// delegates through real grants. A shared mailbox is a role address such
/// as support@: it needs no reason, holds more people, runs its own Sieve
/// replies (an automatic acknowledgement), records only what is sent as it,
/// and may only send as its own addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    #[default]
    Lock,
    SharedMailbox,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Lock => "lock",
            Kind::SharedMailbox => "sharedMailbox",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "lock" => Some(Kind::Lock),
            "sharedMailbox" => Some(Kind::SharedMailbox),
            _ => None,
        }
    }

    pub fn is_lock(&self) -> bool {
        matches!(self, Kind::Lock)
    }

    pub fn max_delegates(&self) -> usize {
        match self {
            Kind::Lock => MAX_DELEGATES,
            Kind::SharedMailbox => MAX_SHARED_MAILBOX_DELEGATES,
        }
    }
}

/// What a delegate may do in the locked account (AL-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Access {
    /// See and download everything; change nothing, not even `$seen`.
    Read,
    /// Read, set keywords, move mail and create and rename folders; never
    /// destroy.
    Organize,
    /// Everything the owner could do. Deletions are still kept under a hold.
    Full,
}

impl Access {
    pub fn as_str(&self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Organize => "organize",
            Access::Full => "full",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Access::Read),
            "organize" => Some(Access::Organize),
            "full" => Some(Access::Full),
            _ => None,
        }
    }

    /// Whether a delegate at this level may destroy anything.
    pub fn may_destroy(&self) -> bool {
        matches!(self, Access::Full)
    }

    /// The rights granted on one container. `is_trash` marks a mailbox with
    /// the Trash or Junk role: an organizing delegate may read it, but not
    /// move mail into it, since mail there is destroyed in time.
    pub fn grants(&self, collection: Collection, is_trash: bool) -> Bitmap<Acl> {
        let read = [Acl::Read, Acl::ReadItems];
        let rights: &[Acl] = match (self, collection) {
            (Access::Read, _) => &read,
            (Access::Organize, Collection::Mailbox) if is_trash => &read,
            (Access::Organize, Collection::Mailbox) => &[
                Acl::Read,
                Acl::ReadItems,
                Acl::Modify,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::RemoveItems,
                Acl::CreateChild,
            ],
            // Calendars, address books and files have no "move": organizing
            // there is adding and changing, never removing
            (Access::Organize, _) => &[
                Acl::Read,
                Acl::ReadItems,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::CreateChild,
            ],
            (Access::Full, _) => &[
                Acl::Read,
                Acl::Modify,
                Acl::Delete,
                Acl::ReadItems,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::RemoveItems,
                Acl::CreateChild,
                Acl::Submit,
                Acl::ModifyItemsOwn,
                Acl::ModifyPrivateProperties,
                Acl::ModifyRSVP,
                Acl::SchedulingReadFreeBusy,
                Acl::SchedulingInvite,
                Acl::SchedulingReply,
            ],
        };
        Bitmap::from_iter(rights.iter().copied())
    }
}

/// One person the locked account is handed to (AL-5).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delegate {
    pub account_id: u32,
    pub access: Access,
    /// May send from the locked account's identities (AL-8). Needs
    /// `organize` or `full`: a message is made in its Drafts first.
    #[serde(default)]
    pub send_as: bool,
    /// Seconds since the epoch; the delegation ends then on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

impl Delegate {
    pub fn is_current(&self, now: u64) -> bool {
        self.until.is_none_or(|until| until > now)
    }
}

/// A delegate's rights a lock replaced on one container, put back when the
/// lock or that delegation ends (AL-10). A container with no entry had no
/// grant for that delegate before.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Replaced {
    pub collection: u8,
    pub document_id: u32,
    pub delegate: u32,
    /// The rights as a bitmap's raw value.
    pub rights: u64,
}

/// An account's lock (AL-1).
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lock {
    pub account_id: u32,
    /// Absent on locks written before shared mailboxes existed: a lock.
    #[serde(default, skip_serializing_if = "Kind::is_lock")]
    pub kind: Kind,
    pub reason: String,
    /// Seconds since the epoch.
    pub locked_at: u64,
    pub locked_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_by_id: Option<u32>,
    #[serde(default)]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced: Vec<Replaced>,
}

impl Lock {
    pub fn delegate(&self, account_id: u32) -> Option<&Delegate> {
        self.delegates.iter().find(|d| d.account_id == account_id)
    }

    /// The grants a new container of this account gets: one per current
    /// delegate (AL-7, containers made later).
    pub fn grants_for_new(
        &self,
        collection: Collection,
        is_trash: bool,
        now: u64,
    ) -> Vec<(u32, Bitmap<Acl>)> {
        self.delegates
            .iter()
            .filter(|d| d.is_current(now))
            .map(|d| (d.account_id, d.access.grants(collection, is_trash)))
            .collect()
    }
}

/// One container's ACL as a lock change leaves it (AL-7, AL-10).
///
/// Delegates in `new` get their level's rights. The first time a delegate
/// is given a container, whatever it had there before is noted in
/// `replaced`; entries `old` already noted are carried over. Delegates only
/// in `old` get back what they had before, or nothing. Returns the new ACL
/// when it differs from `current`.
pub fn merge_grants(
    current: &[AclGrant],
    collection: Collection,
    document_id: u32,
    is_trash: bool,
    old: Option<&Lock>,
    new: Option<&Lock>,
    now: u64,
    replaced: &mut Vec<Replaced>,
) -> Option<Vec<AclGrant>> {
    let mut acls = current.to_vec();
    let collection_id = collection as u8;
    let noted = |lock: &Lock, delegate: u32| {
        lock.replaced
            .iter()
            .find(|r| {
                r.collection == collection_id && r.document_id == document_id && r.delegate == delegate
            })
            .cloned()
    };
    let is_current = |lock: Option<&Lock>, delegate: u32| {
        lock.and_then(|lock| lock.delegate(delegate))
            .is_some_and(|d| d.is_current(now))
    };
    let set = |acls: &mut Vec<AclGrant>, account_id: u32, grants: Bitmap<Acl>| {
        acls.retain(|a| a.account_id != account_id);
        if !grants.is_empty() {
            acls.push(AclGrant { account_id, grants });
        }
    };

    // Delegations that ended get back what they had
    if let Some(old) = old {
        for delegate in &old.delegates {
            if is_current(new, delegate.account_id) {
                continue;
            }
            let note = noted(old, delegate.account_id);
            let before = note
                .as_ref()
                .map(|r| Bitmap::from(r.rights))
                .unwrap_or_default();
            set(&mut acls, delegate.account_id, before);
            // Still listed but past its `until`: keep the note, so running
            // this again puts back the same share instead of removing it
            if let Some(note) = note
                && new.is_some_and(|new| new.delegate(delegate.account_id).is_some())
            {
                replaced.push(note);
            }
        }
    }

    // Current delegations get their level
    if let Some(new) = new {
        for delegate in new.delegates.iter().filter(|d| d.is_current(now)) {
            let had = old.and_then(|old| {
                is_current(Some(old), delegate.account_id)
                    .then(|| noted(old, delegate.account_id))
                    .flatten()
            });
            match had {
                Some(entry) => replaced.push(entry),
                None if !is_current(old, delegate.account_id) => {
                    if let Some(existing) = current.iter().find(|a| a.account_id == delegate.account_id) {
                        replaced.push(Replaced {
                            collection: collection_id,
                            document_id,
                            delegate: delegate.account_id,
                            rights: existing.grants.into(),
                        });
                    }
                }
                None => {}
            }
            set(
                &mut acls,
                delegate.account_id,
                delegate.access.grants(collection, is_trash),
            );
        }
    }

    let sorted = |acls: &[AclGrant]| {
        let mut v = acls.iter().map(|a| (a.account_id, u64::from(a.grants))).collect::<Vec<_>>();
        v.sort();
        v
    };
    (sorted(&acls) != sorted(current)).then_some(acls)
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize account lock")
                .reason(err)
        })
    }
}

impl<T: serde::de::DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid account lock")
                .reason(err)
        })
    }
}

fn class(kind: u8, parts: &[u32]) -> ValueClass {
    let mut key = Vec::with_capacity(2 + parts.len() * 4);
    key.push(FEATURE);
    key.push(kind);
    for part in parts {
        key.extend_from_slice(&part.to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(kind: u8, parts: &[u32]) -> ValueKey<ValueClass> {
    ValueKey::from(class(kind, parts))
}

/// The numbers after the kind byte, from the key's tail (the iterator may or
/// may not hand back the subspace byte).
fn parse_key(key: &[u8], kind: u8, parts: usize) -> Option<Vec<u32>> {
    let len = 2 + parts * 4;
    let tail = key.get(key.len().checked_sub(len)?..)?;
    (tail[0] == FEATURE && tail[1] == kind).then_some(())?;
    Some(
        tail[2..]
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect(),
    )
}

/// An account's lock, if it is locked.
pub async fn get(data: &Store, account_id: u32) -> trc::Result<Option<Lock>> {
    Ok(data
        .get_value::<Json<Lock>>(key(KIND_LOCK, &[account_id]))
        .await
        .caused_by(trc::location!())?
        .map(|Json(lock)| lock))
}

/// Every lock, for the console's list.
pub async fn all(data: &Store) -> trc::Result<Vec<Lock>> {
    let mut locks = Vec::new();
    data.iterate(
        IterateParams::new(key(KIND_LOCK, &[0]), key(KIND_LOCK, &[u32::MAX])),
        |_, value| {
            if let Ok(Json(lock)) = Json::<Lock>::deserialize(value) {
                locks.push(lock);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(locks)
}

/// The accounts delegated to `delegate`, with its delegation in each and
/// the kind of lock it is in.
pub async fn delegated_to(data: &Store, delegate: u32) -> trc::Result<Vec<(u32, Delegate, Kind)>> {
    let mut locked = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_DELEGATE, &[delegate, 0]),
            key(KIND_DELEGATE, &[delegate, u32::MAX]),
        )
        .no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_DELEGATE, 2) {
                locked.push(parts[1]);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;

    let mut delegations = Vec::with_capacity(locked.len());
    for account_id in locked {
        if let Some(lock) = get(data, account_id).await?
            && let Some(delegation) = lock.delegate(delegate)
        {
            delegations.push((account_id, delegation.clone(), lock.kind));
        }
    }
    Ok(delegations)
}

/// Writes a lock, keeping the delegate index in step with `previous`.
pub async fn set(data: &Store, lock: &Lock, previous: Option<&Lock>) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    if let Some(previous) = previous {
        for delegate in &previous.delegates {
            if lock.delegate(delegate.account_id).is_none() {
                batch.clear(class(KIND_DELEGATE, &[delegate.account_id, lock.account_id]));
            }
        }
    }
    for delegate in &lock.delegates {
        batch.set(
            class(KIND_DELEGATE, &[delegate.account_id, lock.account_id]),
            vec![],
        );
    }
    batch.set(class(KIND_LOCK, &[lock.account_id]), Json(lock).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    UNTIL_CHANGED.notify_one();
    Ok(())
}

/// Removes a lock and its delegate index.
pub async fn remove(data: &Store, lock: &Lock) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    for delegate in &lock.delegates {
        batch.clear(class(KIND_DELEGATE, &[delegate.account_id, lock.account_id]));
    }
    batch.clear(class(KIND_LOCK, &[lock.account_id]));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_reads_back_and_defaults_to_lock() {
        // MA-S: a lock stored before shared mailboxes existed has no kind
        let stored = r#"{"accountId":1,"reason":"r","lockedAt":0,"lockedBy":"admin","delegates":[]}"#;
        let lock: Lock = serde_json::from_str(stored).unwrap();
        assert_eq!(lock.kind, Kind::Lock);
        assert!(!serde_json::to_string(&lock).unwrap().contains("kind"), "a lock is written as before");

        let shared = Lock { kind: Kind::SharedMailbox, ..lock };
        let written = serde_json::to_string(&shared).unwrap();
        assert!(written.contains(r#""kind":"sharedMailbox""#), "{written}");
        assert_eq!(serde_json::from_str::<Lock>(&written).unwrap().kind, Kind::SharedMailbox);
        assert_eq!(Kind::parse("sharedMailbox"), Some(Kind::SharedMailbox));
        assert_eq!(Kind::SharedMailbox.max_delegates(), MAX_SHARED_MAILBOX_DELEGATES);
    }

    #[test]
    fn keys_read_back() {
        let ValueClass::Any(any) = class(KIND_DELEGATE, &[7, 9]) else {
            panic!()
        };
        assert_eq!(parse_key(&any.key, KIND_DELEGATE, 2), Some(vec![7, 9]));
        let mut with_subspace = vec![SUBSPACE_INBUXA];
        with_subspace.extend_from_slice(&any.key);
        assert_eq!(parse_key(&with_subspace, KIND_DELEGATE, 2), Some(vec![7, 9]));
        assert_eq!(parse_key(&any.key, KIND_LOCK, 2), None);
    }

    #[test]
    fn levels_grant_what_they_say() {
        let read = Access::Read.grants(Collection::Mailbox, false);
        assert!(read.contains(Acl::ReadItems));
        assert!(!read.contains(Acl::ModifyItems), "read can't set $seen");
        assert!(!read.contains(Acl::RemoveItems));

        let organize = Access::Organize.grants(Collection::Mailbox, false);
        assert!(organize.contains(Acl::RemoveItems), "moving needs it");
        assert!(!organize.contains(Acl::Delete));
        assert!(!organize.contains(Acl::Submit));
        let trash = Access::Organize.grants(Collection::Mailbox, true);
        assert!(!trash.contains(Acl::AddItems), "nothing moved into Trash");
        let calendar = Access::Organize.grants(Collection::Calendar, false);
        assert!(!calendar.contains(Acl::RemoveItems));

        let full = Access::Full.grants(Collection::Mailbox, false);
        assert!(full.contains(Acl::Delete) && full.contains(Acl::RemoveItems));
        assert!(!full.contains(Acl::Share), "a delegate can't pass it on");
        assert!(Access::Full.may_destroy() && !Access::Organize.may_destroy());
    }

    fn lock_with(delegates: Vec<Delegate>, replaced: Vec<Replaced>) -> Lock {
        Lock {
            account_id: 1,
            kind: Kind::Lock,
            reason: "r".into(),
            locked_at: 0,
            locked_by: "admin".into(),
            locked_by_id: None,
            delegates,
            replaced,
        }
    }

    fn delegate(account_id: u32, access: Access) -> Delegate {
        Delegate {
            account_id,
            access,
            send_as: false,
            until: None,
        }
    }

    #[test]
    fn grants_are_added_and_restored() {
        let read = Access::Read.grants(Collection::Mailbox, false);
        let full = Access::Full.grants(Collection::Mailbox, false);
        // Delegate 2 already had a share here; delegate 3 had nothing
        let earlier: Bitmap<Acl> = Bitmap::from_iter([Acl::Read]);
        let current = vec![AclGrant {
            account_id: 2,
            grants: earlier,
        }];
        let lock = lock_with(
            vec![delegate(2, Access::Full), delegate(3, Access::Read)],
            vec![],
        );
        let mut replaced = Vec::new();
        let acls = merge_grants(&current, Collection::Mailbox, 5, false, None, Some(&lock), 0, &mut replaced)
            .unwrap();
        assert!(acls.contains(&AclGrant { account_id: 2, grants: full }));
        assert!(acls.contains(&AclGrant { account_id: 3, grants: read }));
        assert_eq!(replaced.len(), 1, "only 2 had rights to put back");
        assert_eq!(replaced[0].rights, u64::from(earlier));

        // Running it again changes nothing and keeps the note
        let locked = Lock { replaced: replaced.clone(), ..lock.clone() };
        let mut again = Vec::new();
        assert!(merge_grants(&acls, Collection::Mailbox, 5, false, Some(&locked), Some(&locked), 0, &mut again).is_none());
        assert_eq!(again, replaced);

        // Unlocking puts 2's share back and removes 3
        let mut none = Vec::new();
        let back = merge_grants(&acls, Collection::Mailbox, 5, false, Some(&locked), None, 0, &mut none).unwrap();
        assert_eq!(back, vec![AclGrant { account_id: 2, grants: earlier }]);

        // Ending one delegation keeps the other
        let fewer = lock_with(vec![delegate(3, Access::Read)], vec![]);
        let mut kept = Vec::new();
        let after = merge_grants(&acls, Collection::Mailbox, 5, false, Some(&locked), Some(&fewer), 0, &mut kept).unwrap();
        assert!(after.contains(&AclGrant { account_id: 2, grants: earlier }));
        assert!(after.contains(&AclGrant { account_id: 3, grants: read }));
    }

    #[test]
    fn an_expired_delegation_gives_back_its_share_every_time() {
        let earlier: Bitmap<Acl> = Bitmap::from_iter([Acl::Read]);
        let note = Replaced {
            collection: Collection::Mailbox as u8,
            document_id: 5,
            delegate: 2,
            rights: u64::from(earlier),
        };
        let mut ending = delegate(2, Access::Full);
        ending.until = Some(200);
        let lock = lock_with(vec![ending], vec![note.clone()]);
        let during = vec![AclGrant {
            account_id: 2,
            grants: Access::Full.grants(Collection::Mailbox, false),
        }];

        // At its `until`, the share it had before comes back, and the note stays
        let mut replaced = Vec::new();
        let after = merge_grants(&during, Collection::Mailbox, 5, false, Some(&lock), Some(&lock), 300, &mut replaced)
            .unwrap();
        assert_eq!(after, vec![AclGrant { account_id: 2, grants: earlier }]);
        assert_eq!(replaced, vec![note.clone()]);

        // The next sweep changes nothing, rather than removing that share
        let swept = Lock { replaced: replaced.clone(), ..lock };
        let mut again = Vec::new();
        assert!(
            merge_grants(&after, Collection::Mailbox, 5, false, Some(&swept), Some(&swept), 400, &mut again).is_none()
        );
        assert_eq!(again, vec![note]);
    }

    #[test]
    fn the_timer_finds_the_next_end() {
        let ends_at = |account_id, until| {
            let mut d = delegate(account_id, Access::Read);
            d.until = until;
            d
        };
        let a = Lock { account_id: 10, ..lock_with(vec![ends_at(2, Some(500)), ends_at(3, None)], vec![]) };
        let b = Lock { account_id: 11, ..lock_with(vec![ends_at(4, Some(300))], vec![]) };
        let locks = vec![a, b];
        assert_eq!(next_until(&locks, 100), Some(300));
        assert_eq!(next_until(&locks, 300), Some(500));
        assert_eq!(next_until(&locks, 500), None);
        assert_eq!(ended_between(&locks, 100, 300).collect::<Vec<_>>(), vec![11]);
        assert_eq!(ended_between(&locks, 300, 600).collect::<Vec<_>>(), vec![10]);
        assert!(ended_between(&locks, 600, 900).next().is_none());
    }

    #[test]
    fn expired_delegations_grant_nothing() {
        let lock = Lock {
            account_id: 1,
            kind: Kind::Lock,
            reason: "Left the company".into(),
            locked_at: 100,
            locked_by: "admin".into(),
            locked_by_id: None,
            delegates: vec![
                Delegate {
                    account_id: 2,
                    access: Access::Read,
                    send_as: false,
                    until: Some(200),
                },
                Delegate {
                    account_id: 3,
                    access: Access::Full,
                    send_as: true,
                    until: None,
                },
            ],
            replaced: vec![],
        };
        let grants = lock.grants_for_new(Collection::Mailbox, false, 300);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].0, 3);
        let json = serde_json::to_string(&lock).unwrap();
        assert_eq!(serde_json::from_str::<Lock>(&json).unwrap(), lock);
        assert!(json.contains("\"access\":\"full\""));
    }
}
