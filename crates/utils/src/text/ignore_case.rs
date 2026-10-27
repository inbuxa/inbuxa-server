/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{case::lowercase, rank::BYTE_RANK};
use memchr::{memchr_iter, memchr2_iter, memmem::Finder};

const KELVIN_SIGN: [u8; 3] = [0xE2, 0x84, 0xAA];
const CAPITAL_I_WITH_DOT: [u8; 2] = [0xC4, 0xB0];
const MAX_INLINE_NEEDLE_LEN: usize = 64;
const CANDIDATE_COST: usize = 8;
const EITHER_CASE_RANK: [u8; 256] = {
    let mut ranks = [0u8; 256];
    let mut index = 0;
    while index < ranks.len() {
        let byte = index as u8;
        let lower = BYTE_RANK[byte.to_ascii_lowercase() as usize];
        let upper = BYTE_RANK[byte.to_ascii_uppercase() as usize];
        ranks[index] = if lower > upper { lower } else { upper };
        index += 1;
    }
    ranks
};

pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let Some(plan) = AsciiPlan::new(needle.as_bytes()) else {
        return haystack.to_lowercase().contains(&needle.to_lowercase());
    };
    let found = if haystack.len() < IgnoreCaseNeedle::LONG_HAYSTACK_LEN {
        contains_ascii(haystack.as_bytes(), needle.as_bytes(), plan)
    } else {
        contains_long(haystack.as_bytes(), needle.as_bytes())
    };
    plan.settle(found, haystack)
        .unwrap_or_else(|| lowercase(haystack).contains(needle.to_ascii_lowercase().as_str()))
}

fn contains_long(haystack: &[u8], needle: &[u8]) -> Option<bool> {
    let mut buffer = [0u8; MAX_INLINE_NEEDLE_LEN];
    let lowered = buffer.get_mut(..needle.len())?;
    for (out, byte) in lowered.iter_mut().zip(needle) {
        *out = byte.to_ascii_lowercase();
    }
    contains_windowed(haystack, &Finder::new(lowered))
}

#[derive(Debug, Clone)]
pub struct IgnoreCaseNeedle {
    lowered: Box<str>,
    plan: Option<AsciiPlan>,
    finder: Option<Finder<'static>>,
}

impl IgnoreCaseNeedle {
    pub const LONG_HAYSTACK_LEN: usize = 256;
    pub const SHORT_WINDOW_LEN: usize = 1024;
    pub const WINDOW_LEN: usize = 4096;
    pub const MAX_WINDOW_NEEDLE_LEN: usize = Self::WINDOW_LEN / 2;

    pub fn new(needle: &str) -> Self {
        let lowered = needle.to_lowercase().into_boxed_str();
        let plan = AsciiPlan::new(needle.as_bytes());
        let finder = (plan.is_some() && lowered.len() <= Self::MAX_WINDOW_NEEDLE_LEN)
            .then(|| Finder::new(lowered.as_bytes()).into_owned());
        Self {
            lowered,
            plan,
            finder,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.lowered
    }

    pub fn contains(&self, haystack: &str) -> bool {
        self.contains_with(haystack, lowercase)
    }

    pub fn contains_with<'h, L: AsRef<str>>(
        &self,
        haystack: &'h str,
        lower: impl FnOnce(&'h str) -> L,
    ) -> bool {
        let Some(plan) = self.plan else {
            return !(haystack.is_ascii() && !self.lowered.is_ascii())
                && lower(haystack).as_ref().contains(self.lowered.as_ref());
        };
        let found = if haystack.len() < Self::LONG_HAYSTACK_LEN {
            contains_ascii(haystack.as_bytes(), self.lowered.as_bytes(), plan)
        } else {
            self.finder
                .as_ref()
                .and_then(|finder| contains_windowed(haystack.as_bytes(), finder))
        };
        plan.settle(found, haystack)
            .unwrap_or_else(|| lower(haystack).as_ref().contains(self.lowered.as_ref()))
    }
}

#[derive(Debug, Clone, Copy)]
struct AsciiPlan {
    offset: usize,
    lower: u8,
    upper: u8,
    has_joinable: bool,
}

impl AsciiPlan {
    #[inline]
    fn new(needle: &[u8]) -> Option<Self> {
        if !needle.is_ascii() {
            return None;
        }
        let mut anchor_rank = u8::MAX;
        let mut offset = 0;
        let mut has_joinable = false;
        for (position, &byte) in needle.iter().enumerate() {
            let rank = either_case_rank(byte);
            if rank < anchor_rank {
                anchor_rank = rank;
                offset = position;
            }
            has_joinable |= matches!(byte, b'i' | b'I' | b'k' | b'K');
        }
        let anchor = needle.get(offset).copied().unwrap_or_default();
        Some(Self {
            offset,
            lower: anchor.to_ascii_lowercase(),
            upper: anchor.to_ascii_uppercase(),
            has_joinable,
        })
    }

    fn settle(self, found: Option<bool>, haystack: &str) -> Option<bool> {
        match found {
            Some(true) => Some(true),
            Some(false) if !self.may_join(haystack) => Some(false),
            _ => None,
        }
    }

    fn may_join(self, haystack: &str) -> bool {
        self.has_joinable && has_ascii_lowering_char(haystack.as_bytes())
    }
}

fn either_case_rank(byte: u8) -> u8 {
    EITHER_CASE_RANK[usize::from(byte)]
}

fn contains_ascii(haystack: &[u8], needle: &[u8], plan: AsciiPlan) -> Option<bool> {
    if needle.is_empty() {
        return Some(true);
    }
    let Some(last_start) = haystack.len().checked_sub(needle.len()) else {
        return Some(false);
    };
    let Some(window) = haystack.get(plan.offset..=last_start + plan.offset) else {
        return Some(false);
    };
    if plan.lower == plan.upper {
        verify_candidates(haystack, needle, memchr_iter(plan.lower, window))
    } else {
        verify_candidates(
            haystack,
            needle,
            memchr2_iter(plan.lower, plan.upper, window),
        )
    }
}

fn verify_candidates(
    haystack: &[u8],
    needle: &[u8],
    starts: impl Iterator<Item = usize>,
) -> Option<bool> {
    let mut budget = haystack.len();
    for start in starts {
        let candidate = haystack.get(start..start + needle.len())?;
        let matched = candidate
            .iter()
            .zip(needle)
            .take(budget)
            .take_while(|(left, right)| left.eq_ignore_ascii_case(right))
            .count();
        if matched == needle.len() {
            return Some(true);
        }
        budget = budget.checked_sub(matched + CANDIDATE_COST)?;
    }
    Some(false)
}

fn contains_windowed(haystack: &[u8], finder: &Finder<'_>) -> Option<bool> {
    if haystack.len() <= IgnoreCaseNeedle::SHORT_WINDOW_LEN {
        Some(search_windows::<{ IgnoreCaseNeedle::SHORT_WINDOW_LEN }>(
            haystack, finder,
        ))
    } else if finder.needle().len() <= IgnoreCaseNeedle::MAX_WINDOW_NEEDLE_LEN {
        Some(search_windows::<{ IgnoreCaseNeedle::WINDOW_LEN }>(
            haystack, finder,
        ))
    } else {
        None
    }
}

fn search_windows<const LEN: usize>(haystack: &[u8], finder: &Finder<'_>) -> bool {
    let mut buffer = [0u8; LEN];
    let step = LEN.saturating_sub(finder.needle().len().saturating_sub(1));
    let mut rest = haystack;
    loop {
        let window = rest.get(..LEN).unwrap_or(rest);
        let Some(lowered) = buffer.get_mut(..window.len()) else {
            return false;
        };
        for (out, byte) in lowered.iter_mut().zip(window) {
            *out = byte.to_ascii_lowercase();
        }
        if finder.find(lowered).is_some() {
            return true;
        }
        match rest.get(step..) {
            Some(next) if step > 0 && window.len() < rest.len() => rest = next,
            _ => return false,
        }
    }
}

fn has_ascii_lowering_char(haystack: &[u8]) -> bool {
    memchr2_iter(KELVIN_SIGN[0], CAPITAL_I_WITH_DOT[0], haystack).any(|position| {
        haystack.get(position..).is_some_and(|rest| {
            rest.starts_with(&KELVIN_SIGN) || rest.starts_with(&CAPITAL_I_WITH_DOT)
        })
    })
}

