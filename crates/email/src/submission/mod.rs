/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    ValueKey,
    write::{ArchiveCompression, BatchBuilder, Compression, IndexPropertyClass, ValueClass},
};
use types::{collection::Collection, field::EmailSubmissionField};
use utils::map::vec_map::VecMap;

pub mod index;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EmailSubmission {
    pub email_id: u32,
    pub thread_id: u32,
    pub identity_id: u32,
    pub send_at: u64,
    pub queue_id: Option<u64>,
    pub undo_status: UndoStatus,
    pub envelope: Envelope,
    pub delivery_status: VecMap<String, DeliveryStatus>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Envelope {
    pub mail_from: Address,
    pub rcpt_to: Vec<Address>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Address {
    pub email: String,
    pub parameters: Option<VecMap<String, Option<String>>>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct DeliveryStatus {
    pub smtp_reply: String,
    pub delivered: Delivered,
    pub displayed: bool,
}

pub const QUEUED_REPLY: &str = "250 2.1.5 Queued";

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResults(pub Box<[DeliveryResult]>);

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    pub address: Box<str>,
    pub delivered: Delivered,
    pub smtp_reply: Box<str>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub enum Delivered {
    Queued,
    Yes,
    No,
    #[default]
    Unknown,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub enum UndoStatus {
    #[default]
    Pending,
    Final,
    Canceled,
}

impl UndoStatus {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::fnc_map!(s.as_bytes(),
            "pending" => Some(UndoStatus::Pending),
            "final" => Some(UndoStatus::Final),
            "canceled" => Some(UndoStatus::Canceled),
            "cancelled" => Some(UndoStatus::Canceled),
            _ => None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UndoStatus::Pending => "pending",
            UndoStatus::Final => "final",
            UndoStatus::Canceled => "canceled",
        }
    }

    pub fn as_index(&self) -> u8 {
        match self {
            UndoStatus::Pending => b'p',
            UndoStatus::Final => b'f',
            UndoStatus::Canceled => b'c',
        }
    }
}

impl ArchivedUndoStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArchivedUndoStatus::Pending => "pending",
            ArchivedUndoStatus::Final => "final",
            ArchivedUndoStatus::Canceled => "canceled",
        }
    }

    pub fn as_index(&self) -> u8 {
        match self {
            ArchivedUndoStatus::Pending => b'p',
            ArchivedUndoStatus::Final => b'f',
            ArchivedUndoStatus::Canceled => b'c',
        }
    }
}

impl DeliveryResults {
    pub fn key(account_id: u32, queue_id: u64) -> ValueKey<ValueClass> {
        Self::key_at(account_id, queue_id, 0)
    }

    pub fn write(batch: &mut BatchBuilder, account_id: u32, queue_id: u64, value: Vec<u8>) {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::EmailSubmission)
            .with_document(0)
            .set(Self::class(queue_id), value);
    }

    pub fn clear(batch: &mut BatchBuilder, account_id: u32, queue_id: u64) {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::EmailSubmission)
            .with_document(0)
            .clear(Self::class(queue_id));
    }

    pub fn range(
        account_id: u32,
        max_queue_id: u64,
    ) -> (ValueKey<ValueClass>, ValueKey<ValueClass>) {
        (
            Self::key_at(account_id, 0, 0),
            Self::key_at(account_id, max_queue_id, u32::MAX),
        )
    }

    fn key_at(account_id: u32, queue_id: u64, document_id: u32) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: Collection::EmailSubmission.into(),
            document_id,
            class: Self::class(queue_id),
        }
    }

    fn class(queue_id: u64) -> ValueClass {
        ValueClass::IndexProperty(IndexPropertyClass::Integer {
            property: EmailSubmissionField::DeliveryResult.into(),
            value: queue_id,
        })
    }
}

impl ArchiveCompression for DeliveryResults {
    const COMPRESSION: Compression = Compression::None;
}

impl From<&ArchivedDeliveryResult> for DeliveryStatus {
    fn from(value: &ArchivedDeliveryResult) -> Self {
        DeliveryStatus {
            smtp_reply: value.smtp_reply.to_string(),
            delivered: Delivered::from(&value.delivered),
            displayed: false,
        }
    }
}

impl From<&ArchivedDelivered> for Delivered {
    fn from(value: &ArchivedDelivered) -> Self {
        match value {
            ArchivedDelivered::Queued => Delivered::Queued,
            ArchivedDelivered::Yes => Delivered::Yes,
            ArchivedDelivered::No => Delivered::No,
            ArchivedDelivered::Unknown => Delivered::Unknown,
        }
    }
}

impl From<&ArchivedDeliveryStatus> for DeliveryStatus {
    fn from(value: &ArchivedDeliveryStatus) -> Self {
        DeliveryStatus {
            smtp_reply: value.smtp_reply.to_string(),
            delivered: Delivered::from(&value.delivered),
            displayed: value.displayed,
        }
    }
}

impl Delivered {
    pub fn as_str(&self) -> &'static str {
        match self {
            Delivered::Queued => "queued",
            Delivered::Yes => "yes",
            Delivered::No => "no",
            Delivered::Unknown => "unknown",
        }
    }
}

impl ArchivedDelivered {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArchivedDelivered::Queued => "queued",
            ArchivedDelivered::Yes => "yes",
            ArchivedDelivered::No => "no",
            ArchivedDelivered::Unknown => "unknown",
        }
    }
}
