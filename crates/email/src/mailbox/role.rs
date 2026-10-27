/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{INBOX_ID, JUNK_ID, TRASH_ID};
use crate::cache::mailbox::MailboxCacheAccess;
use common::MessageStoreCache;
use std::fmt::{self, Display};
use types::special_use::SpecialUse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleChange {
    Create {
        role: SpecialUse,
    },
    Update {
        document_id: u32,
        current: SpecialUse,
        role: SpecialUse,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleChangeError {
    InUse(SpecialUse),
    Protected,
}

impl RoleChange {
    pub fn validate(self, cache: &MessageStoreCache) -> Result<(), RoleChangeError> {
        let role = match self {
            RoleChange::Update { current, role, .. } if current == role => return Ok(()),
            RoleChange::Create { role } | RoleChange::Update { role, .. } => role,
        };

        if role != SpecialUse::None && cache.mailbox_by_role(&role).is_some() {
            Err(RoleChangeError::InUse(role))
        } else if let RoleChange::Update {
            document_id: INBOX_ID | TRASH_ID | JUNK_ID,
            ..
        } = self
        {
            Err(RoleChangeError::Protected)
        } else {
            Ok(())
        }
    }
}

impl Display for RoleChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleChangeError::InUse(role) => write!(
                f,
                "A mailbox with role '{}' already exists.",
                role.as_str().unwrap_or_default()
            ),
            RoleChangeError::Protected => f.write_str(
                "You are not allowed to change the role of Inbox, Junk or Trash folders.",
            ),
        }
    }
}

