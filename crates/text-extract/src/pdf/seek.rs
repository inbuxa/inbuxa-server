/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy)]
struct Searched {
    from: usize,
    found: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Seek {
    last: Option<Searched>,
}

impl Seek {
    pub(crate) fn find(
        &mut self,
        pos: usize,
        search: impl FnOnce(usize) -> Option<usize>,
    ) -> Option<usize> {
        if let Some(Searched { from, found }) = self.last
            && from <= pos
            && found.is_none_or(|found| found >= pos)
        {
            return found;
        }
        let found = search(pos);
        self.last = Some(Searched { from: pos, found });
        found
    }
}

