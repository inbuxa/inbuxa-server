/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod blob;
pub mod blob_hash;
pub mod collation;
pub mod collection;
pub mod field;
pub mod id;
pub mod keyword;
pub mod media_type;
pub mod metadata;
pub mod semver;
pub mod special_use;
pub mod text;
pub mod type_state;

pub type DocumentId = u32;
pub type ChangeId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(stalwart_tests, derive(serde::Serialize, serde::Deserialize))]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapRule {
    CalDav,
    Jmap,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OverlapCondition {
    #[default]
    Event,
    TodoStartDuration,
    TodoStartDue,
    TodoStart,
    TodoDue,
    TodoCreatedCompleted,
    TodoCompleted,
    TodoCreated,
}

impl OverlapCondition {
    pub const ALL: [OverlapCondition; 8] = [
        OverlapCondition::Event,
        OverlapCondition::TodoStartDuration,
        OverlapCondition::TodoStartDue,
        OverlapCondition::TodoStart,
        OverlapCondition::TodoDue,
        OverlapCondition::TodoCreatedCompleted,
        OverlapCondition::TodoCompleted,
        OverlapCondition::TodoCreated,
    ];

    pub fn for_instance(self, start: i64, end: i64) -> Self {
        match self {
            OverlapCondition::TodoStart if start != end => OverlapCondition::TodoStartDuration,
            condition => condition,
        }
    }
}

impl TimeRange {
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    pub fn is_in_range(&self, condition: OverlapCondition, start: i64, end: i64) -> bool {
        match condition {
            OverlapCondition::Event if start == end => self.start <= start && self.end > start,
            // RFC4791#9.9: (start <  DTEND AND end > DTSTART)
            OverlapCondition::Event => self.start < end && self.end > start,
            OverlapCondition::TodoStartDuration => {
                self.start <= end && (self.end > start || self.end >= end)
            }
            // RFC4791#9.9: ((start <  DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))
            OverlapCondition::TodoStartDue => {
                (self.start < end || self.start <= start) && (self.end > start || self.end >= end)
            }
            OverlapCondition::TodoStart => self.start <= start && self.end > start,
            OverlapCondition::TodoDue => self.start < start && self.end >= start,
            OverlapCondition::TodoCreatedCompleted => {
                (self.start <= start || self.start <= end) && (self.end >= start || self.end >= end)
            }
            OverlapCondition::TodoCompleted => self.start <= start && self.end >= start,
            OverlapCondition::TodoCreated => self.end > start,
        }
    }

    pub fn overlaps(&self, start: i64, end: i64) -> bool {
        self.start < end && self.end > start
    }

    pub fn union(self, other: TimeRange) -> Self {
        TimeRange {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    pub fn touches(&self, start: i64, end: i64) -> bool {
        self.start <= end && self.end >= start
    }

    pub fn matches(
        &self,
        rule: OverlapRule,
        condition: OverlapCondition,
        start: i64,
        end: i64,
    ) -> bool {
        match rule {
            OverlapRule::CalDav => self.is_in_range(condition, start, end),
            OverlapRule::Jmap => self.overlaps(start, end),
        }
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        Self {
            start: i64::MIN,
            end: i64::MAX,
        }
    }
}

