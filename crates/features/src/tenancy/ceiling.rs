/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The permission ceiling (MT-13, MT-14, MT-15).
//!
//! A principal in a tenant keeps only those of its permissions the tenant
//! allows. What the tenant allows starts from its roles, is adjusted by its
//! own permission lists, and anything the tenant disables is never allowed.

use trc::ipc::bitset::Bitset;

/// How a tenant's own permission lists adjust the permissions of its roles
/// (MT-14, step 2).
#[derive(Debug, Clone, Copy)]
pub enum Policy<'x, const N: usize> {
    /// The roles' permissions, unchanged.
    Inherit,
    /// The roles' permissions plus `enabled`, less `disabled`.
    Merge {
        enabled: &'x Bitset<N>,
        disabled: &'x Bitset<N>,
    },
    /// Only `enabled`, less `disabled`. The roles are ignored.
    Replace {
        enabled: &'x Bitset<N>,
        disabled: &'x Bitset<N>,
    },
}

/// What a tenant allows its people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling<const N: usize> {
    /// Permissions the tenant allows. A principal's permission outside this
    /// set has no effect (MT-13).
    pub allowed: Bitset<N>,
    /// Permissions the tenant disables. These are removed last, whatever
    /// granted them (MT-14, step 3).
    pub denied: Bitset<N>,
}

/// Computes a tenant's ceiling (MT-14).
///
/// `base` is the permissions of all the tenant's roles taken together, with
/// each role's own disabled permissions already removed (MT-14, step 1).
pub fn ceiling<const N: usize>(base: Bitset<N>, policy: Policy<'_, N>) -> Ceiling<N> {
    match policy {
        Policy::Inherit => Ceiling {
            allowed: base,
            denied: Bitset::new(),
        },
        Policy::Merge { enabled, disabled } => {
            let mut allowed = base;
            allowed.union(enabled);
            allowed.difference(disabled);
            Ceiling {
                allowed,
                denied: disabled.clone(),
            }
        }
        Policy::Replace { enabled, disabled } => {
            let mut allowed = enabled.clone();
            allowed.difference(disabled);
            Ceiling {
                allowed,
                denied: disabled.clone(),
            }
        }
    }
}

impl<const N: usize> Ceiling<N> {
    /// Cuts a principal's permissions down to the ceiling (MT-13).
    ///
    /// `enabled` and `disabled` are the principal's own, before its disabled
    /// permissions are removed. The ceiling only ever removes: a principal
    /// never gains a permission from its tenant, so no tenant setting can
    /// undo one the server disabled for it (MT-15).
    pub fn apply(&self, enabled: &mut Bitset<N>, disabled: &mut Bitset<N>) {
        enabled.intersection(&self.allowed);
        disabled.union(&self.denied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Set = Bitset<1>;

    fn set(bits: &[usize]) -> Set {
        let mut s = Set::new();
        for &bit in bits {
            s.set(bit);
        }
        s
    }

    fn effective(ceiling: &Ceiling<1>, enabled: &[usize], disabled: &[usize]) -> Set {
        let mut enabled = set(enabled);
        let mut disabled = set(disabled);
        ceiling.apply(&mut enabled, &mut disabled);
        enabled.difference(&disabled);
        enabled
    }

    #[test]
    fn inherit_uses_the_roles() {
        let c = ceiling(set(&[1, 2]), Policy::Inherit);
        assert_eq!(c.allowed, set(&[1, 2]));
        assert!(c.denied.is_empty());
        // MT-13: a permission the tenant lacks has no effect, however granted.
        assert_eq!(effective(&c, &[1, 3], &[]), set(&[1]));
    }

    #[test]
    fn merge_adds_then_disables() {
        let enabled = set(&[3, 4]);
        let disabled = set(&[1, 4]);
        let c = ceiling(
            set(&[1, 2]),
            Policy::Merge {
                enabled: &enabled,
                disabled: &disabled,
            },
        );
        assert_eq!(c.allowed, set(&[2, 3]));
        assert_eq!(effective(&c, &[1, 2, 3, 4], &[]), set(&[2, 3]));
    }

    #[test]
    fn replace_ignores_the_roles() {
        let enabled = set(&[3]);
        let disabled = Set::new();
        let c = ceiling(
            set(&[1, 2]),
            Policy::Replace {
                enabled: &enabled,
                disabled: &disabled,
            },
        );
        assert_eq!(c.allowed, set(&[3]));
        assert_eq!(effective(&c, &[1, 2, 3], &[]), set(&[3]));
    }

    #[test]
    fn disabled_wins_in_replace() {
        // Acceptance test 10: enabled and disabled at once is not allowed.
        let enabled = set(&[3, 5]);
        let disabled = set(&[5]);
        let c = ceiling(
            Set::new(),
            Policy::Replace {
                enabled: &enabled,
                disabled: &disabled,
            },
        );
        assert!(!c.allowed.get(5usize));
        assert_eq!(effective(&c, &[3, 5], &[]), set(&[3]));
    }

    #[test]
    fn server_disabled_stays_disabled() {
        // MT-15: the principal's own disabled permission survives any ceiling.
        let enabled = set(&[1, 2]);
        let disabled = Set::new();
        let c = ceiling(
            Set::new(),
            Policy::Merge {
                enabled: &enabled,
                disabled: &disabled,
            },
        );
        assert_eq!(effective(&c, &[1, 2], &[2]), set(&[1]));
    }
}
