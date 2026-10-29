/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{Context, compiler::grammar::tests::test_exists::TestExists};

use super::{TestResult, mime::SubpartIterator, test_header::header_bytes};

impl TestExists {
    pub(crate) fn exec(&self, ctx: &mut Context) -> TestResult {
        let header_names = ctx.parse_header_names(&self.header_names);
        let mut header_exists = vec![false; header_names.len()];
        let parts = [ctx.part];
        let mut part_iter = SubpartIterator::new(ctx, &parts, self.mime_anychild);
        let mut result = false;

        while let Some((_, message_part)) = part_iter.next() {
            for (pos, header_name) in header_names.iter().enumerate() {
                // inbuxa: looking for a header scans the part's headers
                if !header_exists[pos] && ctx.charge_scan(header_bytes(message_part)) {
                    return TestResult::Bool(false);
                }
                if !header_exists[pos]
                    && message_part.headers.iter().any(|h| &h.name == header_name)
                {
                    header_exists[pos] = true;
                }
            }

            if header_exists.iter().all(|v| *v) {
                result = true;
                break;
            }
        }

        TestResult::Bool(result ^ self.is_not)
    }
}
