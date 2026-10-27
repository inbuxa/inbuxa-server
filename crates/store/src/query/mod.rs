/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod log;

use crate::{Fetch, IterateParams, Key};

impl<T: Key> IterateParams<T> {
    pub fn new(begin: T, end: T) -> Self {
        IterateParams {
            begin,
            end,
            ascending: true,
            values: true,
            fetch: Fetch::All,
        }
    }

    pub fn expect_rows(mut self, rows: usize) -> Self {
        if !matches!(self.fetch, Fetch::Limit(_)) {
            self.fetch = Fetch::Expect(u32::try_from(rows).unwrap_or(u32::MAX));
        }
        self
    }

    pub fn limit(mut self, rows: usize) -> Self {
        self.fetch = Fetch::Limit(u32::try_from(rows).unwrap_or(u32::MAX));
        self
    }

    pub fn set_ascending(mut self, ascending: bool) -> Self {
        self.ascending = ascending;
        self
    }

    pub fn set_values(mut self, values: bool) -> Self {
        self.values = values;
        self
    }

    pub fn ascending(mut self) -> Self {
        self.ascending = true;
        self
    }

    pub fn descending(mut self) -> Self {
        self.ascending = false;
        self
    }

    pub fn only_first(self) -> Self {
        self.limit(1)
    }

    pub fn no_values(mut self) -> Self {
        self.values = false;
        self
    }
}
