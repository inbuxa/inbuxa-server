/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Legal holds (audit-hold-lock spec, LH-1 to LH-14).
//!
//! A hold names a case and what it covers: accounts, groups, domains,
//! tenants or the whole server, optionally only items dated inside a range.
//! While any active hold covers an item, nothing may destroy it. A hold is
//! never deleted: releasing it keeps it, read-only, for the audit trail.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `H`, then one byte for the kind:
//!
//! - `h` + hold id (u32): the hold, as JSON.
//!
//! Numbers are big-endian. There are few holds, so they're read whole.

use registry::schema::{prelude::ObjectInner, structs::Account};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

/// The deadline a held archived item carries: the last second of 9999. It
/// never passes, so every expiry check keeps the item without knowing about
/// holds (LH-4, LH-5); releasing a hold gives it a real deadline (LH-10).
pub const HELD_UNTIL: u64 = 253_402_300_799;

/// Whether an archived item's deadline marks it as held. Anything past the
/// year 9000 counts, so a deadline computed from a hold a moment earlier or
/// later still reads as held.
pub fn is_held_until(until: u64) -> bool {
    until >= 221_845_392_000
}

/// A day, in seconds: the slack either side of a range for an event's start,
/// whose time zone isn't known here.
const DAY: u64 = 86_400;

/// How an account's deleted items are kept: its holds' ranges, and the
/// undelete period for whatever no hold covers (LH-3, LH-4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keeping {
    /// `archiveDeletedItemsFor`, in seconds, if undelete is on.
    pub retention: Option<u64>,
    /// Each active hold's range on this account; `(None, None)` is a whole
    /// account. Empty when nothing holds it.
    pub ranges: Vec<(Option<u64>, Option<u64>)>,
}

impl Keeping {
    pub fn new(retention: Option<u64>, holds: &[Hold]) -> Keeping {
        Keeping {
            retention,
            ranges: holds.iter().map(|h| (h.from, h.to)).collect(),
        }
    }

    /// Whether any hold reaches the account at all.
    pub fn is_held(&self) -> bool {
        !self.ranges.is_empty()
    }

    /// Whether deleted items need noting: something may keep them.
    pub fn keeps_anything(&self) -> bool {
        self.is_held() || self.retention.is_some()
    }

    /// Whether a hold covers an item dated `date`. No date means the item is
    /// held whole, whatever the range (LH-3).
    pub fn covers(&self, date: Option<u64>) -> bool {
        self.ranges.iter().any(|(from, to)| match date {
            None => true,
            Some(at) => {
                from.is_none_or(|from| at >= from) && to.is_none_or(|to| at <= to)
            }
        })
    }

    /// Like `covers`, for an event's start: a day of slack either side, since
    /// its time zone isn't known here.
    pub fn covers_event(&self, start: Option<u64>) -> bool {
        self.ranges.iter().any(|(from, to)| match start {
            None => true,
            Some(at) => {
                from.is_none_or(|from| at + DAY >= from)
                    && to.is_none_or(|to| at <= to.saturating_add(DAY))
            }
        })
    }

    /// Until when an item deleted at `now` is kept: held, the undelete
    /// period, or not at all.
    pub fn until(&self, now: u64, held: bool) -> Option<u64> {
        if held {
            Some(HELD_UNTIL)
        } else {
            self.retention.map(|retention| now + retention)
        }
    }
}

const FEATURE: u8 = b'H';
const KIND_HOLD: u8 = b'h';

/// How many times creating a hold retries when another node took its id.
const CREATE_ATTEMPTS: usize = 5;

/// What a hold covers (LH-1, LH-2). Domains and tenants are resolved live,
/// so an account added to one later is held too.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    /// Every account on the server.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tenants: Vec<u32>,
}

impl Scope {
    pub fn is_empty(&self) -> bool {
        !self.server
            && self.accounts.is_empty()
            && self.groups.is_empty()
            && self.domains.is_empty()
            && self.tenants.is_empty()
    }

    /// Whether this scope covers everything `other` does, entry by entry.
    /// A scope may only grow (LH-3's rule for ranges, applied to scope):
    /// taking something out would free what it held.
    pub fn contains(&self, other: &Scope) -> bool {
        let all = |mine: &[u32], theirs: &[u32]| theirs.iter().all(|id| mine.contains(id));
        (self.server || !other.server)
            && all(&self.accounts, &other.accounts)
            && all(&self.groups, &other.groups)
            && all(&self.domains, &other.domains)
            && all(&self.tenants, &other.tenants)
    }

    fn normalize(&mut self) {
        for list in [
            &mut self.accounts,
            &mut self.groups,
            &mut self.domains,
            &mut self.tenants,
        ] {
            list.sort_unstable();
            list.dedup();
        }
    }
}

/// What decides whether a hold's scope reaches an account: the domains of
/// its addresses, its groups and its tenant (LH-2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Member {
    pub account: u32,
    pub domains: Vec<u32>,
    pub groups: Vec<u32>,
    pub tenant: Option<u32>,
}

impl Member {
    /// A person's account as the registry stores it; `None` for a group,
    /// whose own data is held through its members.
    pub fn of(account_id: u32, object: &ObjectInner) -> Option<Member> {
        let ObjectInner::Account(Account::User(user)) = object else {
            return None;
        };
        let mut domains = vec![user.domain_id.document_id()];
        domains.extend(user.aliases.iter().map(|alias| alias.domain_id.document_id()));
        domains.sort_unstable();
        domains.dedup();
        Some(Member {
            account: account_id,
            domains,
            groups: user.member_group_ids.iter().map(|id| id.document_id()).collect(),
            tenant: user.member_tenant_id.map(|id| id.document_id()),
        })
    }
}

impl Scope {
    /// Whether this scope reaches `member`, directly or through its domains,
    /// groups or tenant, as they are now (LH-2).
    pub fn covers(&self, member: &Member) -> bool {
        self.server
            || self.accounts.contains(&member.account)
            || member.domains.iter().any(|d| self.domains.contains(d))
            || member.groups.iter().any(|g| self.groups.contains(g))
            || member.tenant.is_some_and(|t| self.tenants.contains(&t))
    }
}

/// When and why a hold was released (LH-10).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub at: u64,
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_id: Option<u32>,
    pub reason: String,
}

/// A legal hold (LH-1).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hold {
    pub id: u32,
    /// The case name.
    pub name: String,
    /// A matter or ticket number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub scope: Scope,
    /// Seconds since the epoch. Items dated before aren't held (LH-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// Seconds since the epoch. Items dated after aren't held (LH-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    pub placed_at: u64,
    pub placed_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placed_by_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released: Option<Release>,
}

/// Why a change to a hold is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A released hold is read-only (LH-1).
    Released,
    /// The range may only widen (LH-3).
    Narrowed,
    /// The scope may only grow.
    ScopeShrunk,
    /// A hold has to cover something.
    EmptyScope,
    /// `from` after `to`.
    Backwards,
}

impl Refusal {
    pub fn describe(self) -> &'static str {
        match self {
            Refusal::Released => "A released hold can't be changed; place a new one instead.",
            Refusal::Narrowed => {
                "A hold's date range can only be widened. To hold less, release it and place a new hold."
            }
            Refusal::ScopeShrunk => {
                "Nothing can be taken out of a hold's scope. To hold less, release it and place a new hold."
            }
            Refusal::EmptyScope => "A hold has to cover at least one account, group, domain or tenant, or the whole server.",
            Refusal::Backwards => "The range starts after it ends.",
        }
    }
}

impl Hold {
    pub fn is_active(&self) -> bool {
        self.released.is_none()
    }

    /// Whether an item dated `at` (seconds) falls in the hold's range. With
    /// no range, everything does (LH-3).
    pub fn covers_date(&self, at: u64) -> bool {
        self.from.is_none_or(|from| at >= from) && self.to.is_none_or(|to| at <= to)
    }

    /// Checks a new hold, and tidies its scope.
    pub fn check_new(&mut self) -> Result<(), Refusal> {
        self.scope.normalize();
        if self.scope.is_empty() {
            return Err(Refusal::EmptyScope);
        }
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from > to
        {
            return Err(Refusal::Backwards);
        }
        Ok(())
    }

    /// Checks that `next` is an allowed change of `self`: names and notes
    /// may change, the range may only widen, the scope may only grow, and a
    /// released hold may not change at all.
    pub fn check_update(&self, next: &mut Hold) -> Result<(), Refusal> {
        if !self.is_active() {
            return Err(Refusal::Released);
        }
        next.check_new()?;
        // An open end can't be closed, and a set end can only move outward
        let from_ok = match (self.from, next.from) {
            (None, Some(_)) => false,
            (Some(old), Some(new)) => new <= old,
            (_, None) => true,
        };
        let to_ok = match (self.to, next.to) {
            (None, Some(_)) => false,
            (Some(old), Some(new)) => new >= old,
            (_, None) => true,
        };
        if !from_ok || !to_ok {
            return Err(Refusal::Narrowed);
        }
        if !next.scope.contains(&self.scope) {
            return Err(Refusal::ScopeShrunk);
        }
        Ok(())
    }
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize legal hold")
                .reason(err)
        })
    }
}

impl<T: serde::de::DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid legal hold")
                .reason(err)
        })
    }
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_HOLD);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(class(id))
}

/// One hold, released or not.
pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Hold>> {
    Ok(data
        .get_value::<Json<Hold>>(key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(hold)| hold))
}

/// Every hold, released ones included, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Hold>> {
    let mut holds = Vec::new();
    data.iterate(IterateParams::new(key(0), key(u32::MAX)), |_, value| {
        if let Ok(Json(hold)) = Json::<Hold>::deserialize(value) {
            holds.push(hold);
        }
        Ok(true)
    })
    .await
    .caused_by(trc::location!())?;
    Ok(holds)
}

/// The holds still in force.
pub async fn active(data: &Store) -> trc::Result<Vec<Hold>> {
    Ok(all(data).await?.into_iter().filter(Hold::is_active).collect())
}

/// Writes a new hold under the next free id, which it returns. Two nodes
/// placing holds at once can't take the same id: the key must be absent.
pub async fn create(data: &Store, hold: &Hold) -> trc::Result<u32> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = all(data).await?.iter().map(|h| h.id).max().unwrap_or(0) + 1;
        let stored = Hold {
            id,
            ..hold.clone()
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(id),
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// The active holds that reach `member` (LH-2, LH-11).
pub async fn covering(data: &Store, member: &Member) -> trc::Result<Vec<Hold>> {
    Ok(active(data)
        .await?
        .into_iter()
        .filter(|hold| hold.scope.covers(member))
        .collect())
}

/// LH-2: an account a hold reached through its domain, group or tenant stays
/// held when it leaves them: it is added to the hold by name. Called for
/// every change to an account, so no move escapes a hold.
pub async fn keep_moved(data: &Store, before: &Member, after: &Member) -> trc::Result<()> {
    if before == after {
        return Ok(());
    }
    for mut hold in active(data).await? {
        if hold.scope.covers(before) && !hold.scope.covers(after) {
            hold.scope.accounts.push(after.account);
            hold.scope.accounts.sort_unstable();
            hold.scope.accounts.dedup();
            update(data, &hold).await?;
        }
    }
    Ok(())
}

/// Replaces a hold that `check_update` allowed.
pub async fn update(data: &Store, hold: &Hold) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(hold.id), Json(hold).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hold(scope: Scope, from: Option<u64>, to: Option<u64>) -> Hold {
        Hold {
            id: 1,
            name: "Matter 4411".into(),
            reference: Some("4411".into()),
            description: None,
            scope,
            from,
            to,
            placed_at: 10,
            placed_by: "admin".into(),
            placed_by_id: None,
            released: None,
        }
    }

    fn accounts(ids: &[u32]) -> Scope {
        Scope {
            accounts: ids.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn a_hold_needs_a_scope_and_a_forward_range() {
        assert_eq!(hold(Scope::default(), None, None).check_new(), Err(Refusal::EmptyScope));
        assert_eq!(hold(accounts(&[2]), Some(20), Some(10)).check_new(), Err(Refusal::Backwards));
        let mut ok = hold(accounts(&[3, 2, 3]), None, None);
        assert_eq!(ok.check_new(), Ok(()));
        assert_eq!(ok.scope.accounts, vec![2, 3], "sorted, once each");
    }

    #[test]
    fn the_range_only_widens() {
        let current = hold(accounts(&[2]), Some(100), Some(200));
        let widened = |from, to| {
            let mut next = hold(accounts(&[2]), from, to);
            current.check_update(&mut next)
        };
        assert_eq!(widened(Some(50), Some(300)), Ok(()));
        assert_eq!(widened(None, None), Ok(()), "opening both ends widens");
        assert_eq!(widened(Some(150), Some(200)), Err(Refusal::Narrowed));
        assert_eq!(widened(Some(100), Some(150)), Err(Refusal::Narrowed));

        let open = hold(accounts(&[2]), None, None);
        let mut closed = hold(accounts(&[2]), Some(1), None);
        assert_eq!(open.check_update(&mut closed), Err(Refusal::Narrowed), "an open end stays open");
    }

    #[test]
    fn the_scope_only_grows() {
        let current = hold(
            Scope {
                accounts: vec![2],
                domains: vec![7],
                ..Default::default()
            },
            None,
            None,
        );
        let mut grown = hold(
            Scope {
                accounts: vec![2, 3],
                domains: vec![7],
                tenants: vec![1],
                ..Default::default()
            },
            None,
            None,
        );
        assert_eq!(current.check_update(&mut grown), Ok(()));
        let mut shrunk = hold(accounts(&[2, 3]), None, None);
        assert_eq!(current.check_update(&mut shrunk), Err(Refusal::ScopeShrunk));

        let server = hold(Scope { server: true, ..Default::default() }, None, None);
        let mut less = hold(accounts(&[2]), None, None);
        assert_eq!(server.check_update(&mut less), Err(Refusal::ScopeShrunk));
    }

    #[test]
    fn a_released_hold_is_read_only() {
        let mut released = hold(accounts(&[2]), None, None);
        released.released = Some(Release {
            at: 50,
            by: "admin".into(),
            by_id: None,
            reason: "Settled".into(),
        });
        let mut next = released.clone();
        next.name = "Renamed".into();
        assert_eq!(released.check_update(&mut next), Err(Refusal::Released));
        assert!(!released.is_active());
    }

    #[test]
    fn dates_in_range() {
        let whole = hold(accounts(&[2]), None, None);
        assert!(whole.covers_date(0) && whole.covers_date(u64::MAX));
        let ranged = hold(accounts(&[2]), Some(100), Some(200));
        assert!(ranged.covers_date(100) && ranged.covers_date(200));
        assert!(!ranged.covers_date(99) && !ranged.covers_date(201));
        let open_ended = hold(accounts(&[2]), Some(100), None);
        assert!(open_ended.covers_date(u64::MAX), "no `to` also catches mail still to come");
    }

    #[test]
    fn a_scope_reaches_members_through_domain_group_and_tenant() {
        let member = Member {
            account: 9,
            domains: vec![3, 4],
            groups: vec![20],
            tenant: Some(7),
        };
        let reaches = |scope: Scope| scope.covers(&member);
        assert!(reaches(accounts(&[9])));
        assert!(reaches(Scope { domains: vec![4], ..Default::default() }), "an alias's domain counts");
        assert!(reaches(Scope { groups: vec![20], ..Default::default() }));
        assert!(reaches(Scope { tenants: vec![7], ..Default::default() }));
        assert!(reaches(Scope { server: true, ..Default::default() }));
        assert!(!reaches(Scope { domains: vec![5], tenants: vec![8], ..Default::default() }));

        // LH-2: leaving the held domain would free it, so the hold must name it
        let held = hold(Scope { domains: vec![3], ..Default::default() }, None, None);
        let moved = Member { domains: vec![6], ..member.clone() };
        assert!(held.scope.covers(&member) && !held.scope.covers(&moved));
    }

    #[test]
    fn keeping_deleted_items() {
        let whole = Keeping::new(None, &[hold(accounts(&[2]), None, None)]);
        assert!(whole.covers(Some(5)) && whole.covers(None));
        assert_eq!(whole.until(100, whole.covers(Some(5))), Some(HELD_UNTIL));
        assert!(is_held_until(whole.until(100, true).unwrap()));

        // LH-3: a range holds only what's inside it; outside, undelete's rules
        let ranged = Keeping::new(Some(30), &[hold(accounts(&[2]), Some(1_000), Some(2_000))]);
        assert!(ranged.covers(Some(1_500)) && !ranged.covers(Some(2_500)));
        assert!(ranged.covers(None), "contacts, files and scripts are held whole");
        assert_eq!(ranged.until(100, ranged.covers(Some(2_500))), Some(130));
        assert!(ranged.covers_event(Some(2_000 + 3_600)), "a day of slack for an event");

        // Neither held nor undelete: nothing is kept
        let none = Keeping::new(None, &[]);
        assert!(!none.keeps_anything());
        assert_eq!(none.until(100, false), None);
        assert!(!is_held_until(100 + 30 * 365 * 86_400));
    }

    #[test]
    fn stored_as_json() {
        let current = hold(accounts(&[2]), Some(100), None);
        let json = serde_json::to_string(&current).unwrap();
        assert_eq!(serde_json::from_str::<Hold>(&json).unwrap(), current);
        assert!(json.contains("\"scope\":{\"accounts\":[2]}"), "{json}");
    }
}
