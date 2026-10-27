/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{MessageStoreCache, auth::AccessToken, sharing::EffectiveAcl};
use email::cache::mailbox::MailboxCacheAccess;
use imap_proto::protocol::select::PermanentFlags;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

pub enum MailboxRights<'x> {
    Member,
    Shared {
        access_token: &'x AccessToken,
        acls: Vec<(u32, Bitmap<Acl>)>,
    },
}

impl<'x> MailboxRights<'x> {
    pub fn new(access_token: &'x AccessToken, account_id: u32) -> Self {
        if access_token.is_member(account_id) {
            MailboxRights::Member
        } else {
            MailboxRights::Shared {
                access_token,
                acls: Vec::new(),
            }
        }
    }

    pub fn acl(&mut self, cache: &MessageStoreCache, mailbox_id: u32) -> Bitmap<Acl> {
        let MailboxRights::Shared { access_token, acls } = self else {
            return Bitmap::all();
        };
        match acls.binary_search_by_key(&mailbox_id, |(id, _)| *id) {
            Ok(index) => acls[index].1,
            Err(index) => {
                let acl = cache
                    .mailbox_by_id(&mailbox_id)
                    .map_or_else(Bitmap::new, |mailbox| {
                        mailbox.acls.as_slice().effective_acl(access_token)
                    });
                acls.insert(index, (mailbox_id, acl));
                acl
            }
        }
    }

    pub fn permanent_flags(
        &mut self,
        cache: &MessageStoreCache,
        mailbox_ids: impl IntoIterator<Item = u32>,
    ) -> PermanentFlags {
        if matches!(self, MailboxRights::Member) {
            return PermanentFlags::All;
        }
        let mut acl = Bitmap::all();
        for mailbox_id in mailbox_ids {
            acl.intersection(&self.acl(cache, mailbox_id));
        }
        PermanentFlags::from(acl)
    }
}
