/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::acl::{self, ModRights, ModRightsOp, Rights},
    receiver::{Request, bad},
};

use super::PushUnique;

/*

   setacl          = "SETACL" SP mailbox SP identifier
                       SP mod-rights

   deleteacl       = "DELETEACL" SP mailbox SP identifier

   getacl          = "GETACL" SP mailbox

   listrights      = "LISTRIGHTS" SP mailbox SP identifier

   myrights        = "MYRIGHTS" SP mailbox

*/

impl Request<Command> {
    pub fn parse_acl(self, is_utf8: bool) -> trc::Result<acl::Arguments> {
        let (has_identifier, has_mod_rights) = match self.command {
            Command::SetAcl => (true, true),
            Command::DeleteAcl | Command::ListRights => (true, false),
            Command::GetAcl | Command::MyRights => (false, false),
            _ => unreachable!(),
        };
        let mut tokens = self.tokens.into_iter();
        let mailbox_name = tokens
            .next()
            .ok_or_else(|| bad(self.tag.clone(), "Missing mailbox name."))?
            .unwrap_mailbox_name(is_utf8)
            .map_err(|v| bad(self.tag.clone(), v))?;
        let identifier = if has_identifier {
            tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing identifier."))?
                .unwrap_string()
                .map_err(|v| bad(self.tag.clone(), v))?
                .into()
        } else {
            None
        };
        let mod_rights = if has_mod_rights {
            ModRights::parse(
                &tokens
                    .next()
                    .ok_or_else(|| bad(self.tag.clone(), "Missing rights."))?
                    .unwrap_bytes(),
            )
            .map_err(|v| bad(self.tag.clone(), v))?
            .into()
        } else {
            None
        };

        Ok(acl::Arguments {
            tag: self.tag,
            mailbox_name,
            identifier,
            mod_rights,
        })
    }
}

impl ModRights {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        let mut op = ModRightsOp::Replace;
        let mut rights = Vec::with_capacity(value.len());
        for (pos, ch) in value.iter().enumerate() {
            rights.push_unique(match ch {
                b'l' => Rights::Lookup,
                b'r' => Rights::Read,
                b's' => Rights::Seen,
                b'w' => Rights::Write,
                b'i' => Rights::Insert,
                b'p' => Rights::Post,
                b'k' => Rights::CreateMailbox,
                b'x' => Rights::DeleteMailbox,
                b't' => Rights::DeleteMessages,
                b'e' => Rights::Expunge,
                b'n' => Rights::Annotate,
                b'a' => Rights::Administer,
                // RFC2086
                b'd' => Rights::DeleteMessages,
                b'c' => Rights::CreateMailbox,
                b'+' if pos == 0 => {
                    op = ModRightsOp::Add;
                    continue;
                }
                b'-' if pos == 0 => {
                    op = ModRightsOp::Remove;
                    continue;
                }
                _ => {
                    return Err(
                        format!("Invalid character {:?} in rights.", char::from(*ch)).into(),
                    );
                }
            })
        }

        if !rights.is_empty() {
            Ok(ModRights { op, rights })
        } else {
            Err("At least one right has to be specified.".into())
        }
    }
}

