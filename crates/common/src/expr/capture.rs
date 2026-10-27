/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bumpalo::Bump;
use regex_automata::{
    Input, MatchKind, meta,
    util::{primitives::NonMaxUsize, syntax},
};
use std::{fmt, sync::Arc};

const NFA_SIZE_LIMIT: usize = 10 * (1 << 20);
const HYBRID_CACHE_CAPACITY: usize = 2 * (1 << 20);

pub type Slot = Option<NonMaxUsize>;

#[derive(Clone)]
pub struct CaptureRegex {
    inner: Arc<CompiledRegex>,
}

struct CompiledRegex {
    regex: meta::Regex,
    pattern: Box<str>,
}

#[derive(Default)]
pub(crate) struct Captures<'s> {
    haystack: &'s str,
    matched: bool,
    slots: Option<(u32, &'s mut [Slot])>,
}

impl CaptureRegex {
    pub fn new(pattern: &str) -> Result<Self, String> {
        meta::Builder::new()
            .configure(
                meta::Config::new()
                    .nfa_size_limit(Some(NFA_SIZE_LIMIT))
                    .hybrid_cache_capacity(HYBRID_CACHE_CAPACITY)
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(true),
            )
            .syntax(syntax::Config::new().utf8(true))
            .build(pattern)
            .map(|regex| CaptureRegex {
                inner: Arc::new(CompiledRegex {
                    regex,
                    pattern: pattern.into(),
                }),
            })
            .map_err(|err| {
                let reason = match (err.size_limit(), err.syntax_error()) {
                    (Some(limit), _) => {
                        format!("Compiled regex exceeds size limit of {limit} bytes.")
                    }
                    (None, Some(syntax)) => syntax.to_string(),
                    (None, None) => err.to_string(),
                };
                format!("Invalid regular expression {pattern:?}: {reason}")
            })
    }

    pub fn is_match(&self, haystack: &str) -> bool {
        self.inner.regex.is_match(haystack)
    }

    pub fn slot_len(&self) -> usize {
        self.inner.regex.group_info().slot_len()
    }

    pub fn search(&self, haystack: &str, slots: &mut [Slot]) -> bool {
        self.inner
            .regex
            .search_slots(&Input::new(haystack), slots)
            .is_some()
    }
}

impl fmt::Debug for CaptureRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Regex").field(&self.inner.pattern).finish()
    }
}

impl<'s> Captures<'s> {
    pub(crate) fn read(
        &mut self,
        index: u32,
        regex: &CaptureRegex,
        haystack: &'s str,
        arena: &'s Bump,
    ) -> bool {
        let slots = match &mut self.slots {
            Some((current, slots)) if *current == index => slots,
            slots => {
                &mut slots
                    .insert((index, arena.alloc_slice_fill_copy(regex.slot_len(), None)))
                    .1
            }
        };
        self.matched = regex.search(haystack, slots);
        self.haystack = haystack;
        self.matched
    }

    pub(crate) fn get(&self, group: u32) -> &'s str {
        let Some((_, slots)) = self.slots.as_ref().filter(|_| self.matched) else {
            return "";
        };
        let start = group as usize * 2;
        match slots.get(start..start + 2) {
            Some([Some(start), Some(end)]) => self.haystack.get(start.get()..end.get()),
            _ => None,
        }
        .unwrap_or_default()
    }
}

