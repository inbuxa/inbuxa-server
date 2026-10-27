/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BatchCursor, Operation, ValueClass, ValueOp};
use crate::WITH_SUBSPACE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NewKeyAsserts {
    CheckedByInsert,
    Read,
}

impl BatchCursor {
    pub(crate) fn is_document_independent(
        &self,
        class: &ValueClass,
        key_buf: &mut Vec<u8>,
    ) -> bool {
        key_buf.clear();
        class.serialize_into(key_buf, self.account_id, self.collection, 0, WITH_SUBSPACE);
        let len = key_buf.len();
        class.serialize_into(
            key_buf,
            self.account_id,
            self.collection,
            u32::MAX,
            WITH_SUBSPACE,
        );
        let independent = key_buf
            .split_at_checked(len)
            .is_some_and(|(first, second)| first == second);
        key_buf.truncate(len);
        independent
    }
}

pub(crate) fn insert_follows(class: &ValueClass, rest: &[Operation]) -> bool {
    rest.iter()
        .find_map(|op| match op {
            Operation::Value { class: next, op } if next == class => {
                Some(matches!(op, ValueOp::Set(_)))
            }
            Operation::AssertValue { class: next, .. } if next == class => Some(false),
            Operation::AccountId { .. }
            | Operation::Collection { .. }
            | Operation::DocumentId { .. } => Some(false),
            _ => None,
        })
        .unwrap_or(false)
}

