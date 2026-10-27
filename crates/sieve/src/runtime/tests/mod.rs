/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RuntimeError,
    handler::{Handler, Mailbox, Reply},
};
use crate::{Context, Sieve, bytecode::ops, compiler::grammar::Capability};
use mail_parser::MessagePart;
use smallvec::SmallVec;

pub mod comparator;
pub mod glob;
pub mod matching;
pub mod mime;
pub mod test_address;
pub mod test_body;
pub mod test_date;
pub mod test_duplicate;
pub mod test_envelope;
pub mod test_exists;
pub mod test_extlists;
pub mod test_hasflag;
pub mod test_header;
pub mod test_metadata;
pub mod test_notify;
pub mod test_size;
pub mod test_spamtest;
pub mod test_string;

const MAX_SCAN_BYTES: usize = 192 << 20;
const PART_VISIT_BYTES: usize = 512;

pub(crate) struct ScanMeter {
    budget: usize,
    spent: usize,
    weight: usize,
}

impl ScanMeter {
    pub(crate) fn charge(&mut self, bytes: usize) -> bool {
        self.spent = self.weight.saturating_mul(bytes).saturating_add(self.spent);
        self.spent <= self.budget
    }

    pub(crate) fn charge_visit(&mut self) -> bool {
        self.spent = self.spent.saturating_add(PART_VISIT_BYTES);
        self.spent <= self.budget
    }

    pub(crate) fn charge_headers(&mut self, part: MessagePart<'_>) -> bool {
        let headers = part.offset_body().saturating_sub(part.offset_header()) as usize;
        self.charge_visit() && self.charge(headers)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestResult {
    Bool(bool),
    Pending { is_not: bool },
}

impl TestResult {
    #[inline(always)]
    pub(crate) fn from_reply(reply: Reply<bool>, is_not: bool) -> Result<TestResult, RuntimeError> {
        match reply {
            Reply::Ready(result) => Ok(TestResult::Bool(result ^ is_not)),
            Reply::Pending => Ok(TestResult::Pending { is_not }),
            Reply::Error(err) => Err(err),
        }
    }
}

impl<'x> Context<'x> {
    pub(crate) fn scan_meter(&self, keys: usize) -> ScanMeter {
        ScanMeter {
            budget: MAX_SCAN_BYTES.saturating_sub(self.num_scanned_bytes),
            spent: 0,
            weight: keys.max(1),
        }
    }

    pub(crate) fn settle_scan(&mut self, meter: ScanMeter) -> Result<(), RuntimeError> {
        self.num_scanned_bytes = self.num_scanned_bytes.saturating_add(meter.spent);
        if meter.spent <= meter.budget {
            Ok(())
        } else {
            Err(RuntimeError::CPULimitReached)
        }
    }

    pub(crate) fn charge_scan(&mut self, keys: usize, bytes: usize) -> Result<(), RuntimeError> {
        let mut meter = self.scan_meter(keys);
        meter.charge(bytes);
        self.settle_scan(meter)
    }

    pub(crate) fn test_ihave(
        &self,
        script: &'x Sieve<'x>,
        test: &ops::TestIhave,
    ) -> Result<TestResult, RuntimeError> {
        let mut result = true;
        for rec in script.recs(test.capabilities)? {
            let capability = Capability::from_rec(script, rec)?;
            if [Capability::Variables, Capability::EncodedCharacter].contains(&capability)
                || !self.runtime.allowed_capabilities.contains(&capability)
            {
                result = false;
                break;
            }
        }
        Ok(TestResult::Bool(result ^ test.is_not))
    }

    pub(crate) fn test_mailbox_exists<H: Handler<'x>>(
        &self,
        script: &'x Sieve<'x>,
        test: &ops::TestMailboxExists,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let names = self.eval_strings(script, test.mailbox_names)?;
        let mailboxes: SmallVec<[Mailbox<'_>; 4]> =
            names.iter().map(|name| Mailbox::Name(name)).collect();
        TestResult::from_reply(handler.mailbox_exists(self, &mailboxes, &[]), test.is_not)
    }

    pub(crate) fn test_mailbox_id_exists<H: Handler<'x>>(
        &self,
        script: &'x Sieve<'x>,
        test: &ops::TestMailboxIdExists,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let ids = self.eval_strings(script, test.mailbox_ids)?;
        let mailboxes: SmallVec<[Mailbox<'_>; 4]> = ids.iter().map(|id| Mailbox::Id(id)).collect();
        TestResult::from_reply(handler.mailbox_exists(self, &mailboxes, &[]), test.is_not)
    }

    pub(crate) fn test_special_use_exists<H: Handler<'x>>(
        &self,
        script: &'x Sieve<'x>,
        test: &ops::TestSpecialUseExists,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let mailbox = self.eval_opt_str(script, test.mailbox)?;
        let attributes = self.eval_strings(script, test.attributes)?;
        let mailboxes: SmallVec<[Mailbox<'_>; 1]> =
            mailbox.map(Mailbox::Name).into_iter().collect();
        TestResult::from_reply(
            handler.mailbox_exists(self, &mailboxes, &attributes),
            test.is_not,
        )
    }
}
