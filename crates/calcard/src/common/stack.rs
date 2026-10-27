/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const INLINE_DEPTH: usize = 8;

pub(crate) struct ComponentStack<T> {
    inline: [Option<T>; INLINE_DEPTH],
    len: usize,
    spilled: Vec<T>,
}

impl<T> ComponentStack<T> {
    pub(crate) fn new() -> Self {
        Self {
            inline: [const { None }; INLINE_DEPTH],
            len: 0,
            spilled: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        match self.inline.get_mut(self.len) {
            Some(slot) => *slot = Some(item),
            None => self.spilled.push(item),
        }
        self.len += 1;
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.len = self.len.checked_sub(1)?;
        match self.inline.get_mut(self.len) {
            Some(slot) => slot.take(),
            None => self.spilled.pop(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}
