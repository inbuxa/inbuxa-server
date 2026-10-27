/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) type Bounds = (Vec<u8>, Vec<u8>);

pub(crate) enum RangeAttempt {
    Finished,
    TimedOut { delivered: bool },
    BeginTimedOut(trc::Error),
}

pub(crate) enum Timeout<E> {
    Begin(E),
    Statement(E),
}

#[derive(Default)]
pub(crate) struct RangeCursor {
    pub(crate) start: usize,
    pub(crate) resumed: bool,
    pub(crate) last_key: Vec<u8>,
}

impl RangeCursor {
    pub(crate) fn advance(&mut self, bounds: &mut [Bounds], end: usize) {
        let last_key = self.last_key.as_slice();
        self.start = bounds.get(self.start..end).map_or(end, |chunk| {
            self.start + chunk.partition_point(|(_, range_end)| range_end.as_slice() <= last_key)
        });
        self.resumed = match bounds.get_mut(self.start) {
            Some((begin, _)) if begin.as_slice() <= last_key => {
                begin.clone_from(&self.last_key);
                true
            }
            _ => false,
        };
    }

    pub(crate) fn halve(&self, per_statement: usize, total: usize) -> Option<usize> {
        let size = per_statement.min(total.saturating_sub(self.start));
        (size > 1).then_some(size / 2)
    }

    pub(crate) fn remaining<'x>(
        &'x self,
        bounds: &'x [Bounds],
    ) -> impl Iterator<Item = (Vec<u8>, &'x [u8])> + 'x {
        bounds
            .iter()
            .enumerate()
            .skip(self.start)
            .map(|(position, (begin, end))| {
                let mut begin = begin.clone();
                if position == self.start && self.resumed {
                    begin.push(0);
                }
                (begin, end.as_slice())
            })
    }
}

