/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! One state per mask, shown by each API in its own terms (ME-1, ME-2,
//! ME-6a).

/// A mask's state. The order of the discriminants is stored, so it never
/// changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum State {
    /// Created by a password manager, not yet used: delivered, and becomes
    /// `Enabled` on the first message (ME-7). Removed after 24 hours
    /// without mail (ME-8).
    Pending = 0,
    /// Delivered normally.
    Enabled = 1,
    /// Accepted, and filed straight to Trash (ME-5).
    Disabled = 2,
    /// Refused (ME-6).
    Deleted = 3,
}

impl State {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(State::Pending),
            1 => Some(State::Enabled),
            2 => Some(State::Disabled),
            3 => Some(State::Deleted),
            _ => None,
        }
    }

    /// The state of a mask written before the fork, from upstream's
    /// `enabled` flag.
    pub fn from_upstream(enabled: bool) -> Self {
        if enabled {
            State::Enabled
        } else {
            State::Deleted
        }
    }

    /// Whether mail to the mask is accepted (ME-4).
    pub fn is_live(self) -> bool {
        self != State::Deleted
    }

    /// The Fastmail API's name for the state.
    pub fn as_fastmail(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Enabled => "enabled",
            State::Disabled => "disabled",
            State::Deleted => "deleted",
        }
    }

    pub fn parse_fastmail(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(State::Pending),
            "enabled" => Some(State::Enabled),
            "disabled" => Some(State::Disabled),
            "deleted" => Some(State::Deleted),
            _ => None,
        }
    }

    /// Upstream's `enabled`: whether mail is accepted. `disabled` masks
    /// accept mail (into Trash), so they read `true`. An expired mask reads
    /// `false` whatever its state (ME-6a).
    pub fn as_upstream_enabled(self, expired: bool) -> bool {
        self.is_live() && !expired
    }

    /// The state an upstream `enabled` write sets (ME-2).
    pub fn from_upstream_write(enabled: bool) -> Self {
        State::from_upstream(enabled)
    }

    /// Whether a Fastmail write may move a mask from `self` to `to` (ME-1):
    /// `pending` can't be set once a mask has left it.
    pub fn can_become(self, to: State) -> bool {
        to != State::Pending || self == State::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_apis_read_one_state() {
        // The table in "One state, two APIs"
        for (state, fastmail, enabled) in [
            (State::Pending, "pending", true),
            (State::Enabled, "enabled", true),
            (State::Disabled, "disabled", true),
            (State::Deleted, "deleted", false),
        ] {
            assert_eq!(state.as_fastmail(), fastmail);
            assert_eq!(State::parse_fastmail(fastmail), Some(state));
            assert_eq!(state.as_upstream_enabled(false), enabled);
            assert!(!state.as_upstream_enabled(true), "expired reads false");
            assert_eq!(State::from_u8(state as u8), Some(state));
        }
    }

    #[test]
    fn upstream_writes() {
        // ME-2: enabled false is deleted, enabled true is enabled
        assert_eq!(State::from_upstream_write(false), State::Deleted);
        assert_eq!(State::from_upstream_write(true), State::Enabled);
    }

    #[test]
    fn pending_is_one_way() {
        // ME-1
        assert!(State::Pending.can_become(State::Pending));
        assert!(State::Pending.can_become(State::Enabled));
        assert!(!State::Enabled.can_become(State::Pending));
        assert!(!State::Deleted.can_become(State::Pending));
        assert!(State::Deleted.can_become(State::Enabled));
    }
}
