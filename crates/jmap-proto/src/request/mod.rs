/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod capability;
pub mod deserialize;
pub mod method;
pub mod parser;
pub mod reference;
pub mod websocket;

use self::method::MethodName;
use crate::{
    method::{
        availability::GetAvailabilityRequest,
        changes::ChangesRequest,
        copy::{CopyBlobRequest, CopyRequest},
        get::GetRequest,
        import::ImportEmailRequest,
        lookup::BlobLookupRequest,
        parse::ParseRequest,
        query::QueryRequest,
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::SetRequest,
        upload::BlobUploadRequest,
        validate::ValidateSieveScriptRequest,
    },
    object::{
        AnyId, addressbook::AddressBook, blob::Blob, calendar::Calendar,
        calendar_event::CalendarEvent, calendar_event_notification::CalendarEventNotification,
        contact::ContactCard, email::Email, email_submission::EmailSubmission, file_node::FileNode,
        identity::Identity, mailbox::Mailbox, participant_identity::ParticipantIdentity,
        principal::Principal, push_subscription::PushSubscription, quota::Quota,
        registry::Registry, share_notification::ShareNotification, sieve::Sieve, thread::Thread,
        vacation_response::VacationResponse,
    },
    request::{capability::CapabilityIds, reference::MaybeIdReference},
};
use jmap_tools::{Null, Value};
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use types::id::Id;
use utils::map::vec_map::VecMap;

pub const INVALID_ACCOUNT_ID: u64 = u64::MAX - 1;

pub fn deserialize_account_id<'de, A>(map: &mut A) -> Result<Id, A::Error>
where
    A: serde::de::MapAccess<'de>,
{
    Ok(map
        .next_value::<MaybeInvalid<Id>>()?
        .try_unwrap()
        .unwrap_or_else(|| Id::from(INVALID_ACCOUNT_ID)))
}

#[derive(Debug)]
pub struct Request<'x> {
    pub using: CapabilityIds,
    pub method_calls: Vec<Call<RequestMethod<'x>>>,
    pub created_ids: Option<HashMap<String, AnyId>>,
}

#[derive(Debug)]
pub struct Call<T> {
    pub id: String,
    pub name: MethodName,
    pub method: T,
}

#[derive(Debug)]
pub enum RequestMethod<'x> {
    Get(GetRequestMethod),
    Set(SetRequestMethod<'x>),
    Changes(Box<ChangesRequest>),
    Copy(CopyRequestMethod<'x>),
    ImportEmail(Box<ImportEmailRequest>),
    Parse(ParseRequestMethod),
    Query(QueryRequestMethod),
    QueryChanges(QueryChangesRequestMethod),
    SearchSnippet(Box<GetSearchSnippetRequest>),
    ValidateScript(Box<ValidateSieveScriptRequest>),
    LookupBlob(Box<BlobLookupRequest>),
    UploadBlob(Box<BlobUploadRequest>),
    Echo(Value<'x, Null, Null>),
    Error(trc::Error),
}

#[derive(Debug)]
pub enum GetRequestMethod {
    Email(Box<GetRequest<Email>>),
    Mailbox(Box<GetRequest<Mailbox>>),
    Thread(Box<GetRequest<Thread>>),
    Identity(Box<GetRequest<Identity>>),
    EmailSubmission(Box<GetRequest<EmailSubmission>>),
    PushSubscription(Box<GetRequest<PushSubscription>>),
    Sieve(Box<GetRequest<Sieve>>),
    VacationResponse(Box<GetRequest<VacationResponse>>),
    Principal(Box<GetRequest<Principal>>),
    PrincipalAvailability(Box<GetAvailabilityRequest>),
    Quota(Box<GetRequest<Quota>>),
    Blob(Box<GetRequest<Blob>>),
    AddressBook(Box<GetRequest<AddressBook>>),
    ContactCard(Box<GetRequest<ContactCard>>),
    FileNode(Box<GetRequest<FileNode>>),
    Calendar(Box<GetRequest<Calendar>>),
    CalendarEvent(Box<GetRequest<CalendarEvent>>),
    CalendarEventNotification(Box<GetRequest<CalendarEventNotification>>),
    ParticipantIdentity(Box<GetRequest<ParticipantIdentity>>),
    ShareNotification(Box<GetRequest<ShareNotification>>),
    Registry(Box<GetRequest<Registry>>),
    MaskedEmail(Box<GetRequest<crate::object::fastmail_masked_email::FastmailMaskedEmail>>),
    DeletedAccount(Box<GetRequest<crate::object::inbuxa_deleted_account::DeletedAccount>>),
    AiLimits(Box<GetRequest<crate::object::inbuxa_ai_limits::AiLimits>>),
    LogSettings(Box<GetRequest<crate::object::inbuxa_log_settings::LogSettings>>),
    DlpSettings(Box<GetRequest<crate::object::inbuxa_dlp_settings::DlpSettings>>),
    DataInventory(Box<GetRequest<crate::object::inbuxa_data_inventory::DataInventory>>),
    InventorySnapshot(Box<GetRequest<crate::object::inbuxa_inventory_snapshot::InventorySnapshot>>),
    AuditEvent(Box<GetRequest<crate::object::inbuxa_audit::AuditEvent>>),
    AuditSettings(Box<GetRequest<crate::object::inbuxa_audit::AuditSettings>>),
    AccountLock(Box<GetRequest<crate::object::inbuxa_account_lock::AccountLock>>),
    LegalHold(Box<GetRequest<crate::object::inbuxa_legal_hold::LegalHold>>),
    MailRule(Box<GetRequest<crate::object::inbuxa_mail_rule::MailRule>>),
    SecurityAcceptance(Box<GetRequest<crate::object::inbuxa_security_acceptance::SecurityAcceptance>>),
    DeliverabilityReport(Box<GetRequest<crate::object::inbuxa_deliverability_report::DeliverabilityReport>>),
    DeliverabilitySettings(Box<GetRequest<crate::object::inbuxa_deliverability_settings::DeliverabilitySettings>>),
    Journal(Box<GetRequest<crate::object::inbuxa_journal::Journal>>),
    JournalEntry(Box<GetRequest<crate::object::inbuxa_journal_entry::JournalEntry>>),
    HeldMessage(Box<GetRequest<crate::object::inbuxa_held_message::HeldMessage>>),
    HoldExport(Box<GetRequest<crate::object::inbuxa_hold_export::HoldExport>>),
    ProtocolPolicy(Box<GetRequest<crate::object::inbuxa_protocol_policy::ProtocolPolicy>>),
    TenantProtocolPolicy(
        Box<GetRequest<crate::object::inbuxa_tenant_protocol_policy::TenantProtocolPolicy>>,
    ),
    SharingPolicy(
        Box<GetRequest<crate::object::inbuxa_sharing_policy::SharingPolicy>>,
    ),
}

#[derive(Debug)]
pub enum SetRequestMethod<'x> {
    Email(Box<SetRequest<'x, Email>>),
    Mailbox(Box<SetRequest<'x, Mailbox>>),
    Identity(Box<SetRequest<'x, Identity>>),
    EmailSubmission(Box<SetRequest<'x, EmailSubmission>>),
    PushSubscription(Box<SetRequest<'x, PushSubscription>>),
    Sieve(Box<SetRequest<'x, Sieve>>),
    VacationResponse(Box<SetRequest<'x, VacationResponse>>),
    AddressBook(Box<SetRequest<'x, AddressBook>>),
    ContactCard(Box<SetRequest<'x, ContactCard>>),
    FileNode(Box<SetRequest<'x, FileNode>>),
    ShareNotification(Box<SetRequest<'x, ShareNotification>>),
    Calendar(Box<SetRequest<'x, Calendar>>),
    CalendarEvent(Box<SetRequest<'x, CalendarEvent>>),
    CalendarEventNotification(Box<SetRequest<'x, CalendarEventNotification>>),
    ParticipantIdentity(Box<SetRequest<'x, ParticipantIdentity>>),
    Registry(Box<SetRequest<'x, Registry>>),
    MaskedEmail(Box<SetRequest<'x, crate::object::fastmail_masked_email::FastmailMaskedEmail>>),
    DeletedAccount(Box<SetRequest<'x, crate::object::inbuxa_deleted_account::DeletedAccount>>),
    AiLimits(Box<SetRequest<'x, crate::object::inbuxa_ai_limits::AiLimits>>),
    LogSettings(Box<SetRequest<'x, crate::object::inbuxa_log_settings::LogSettings>>),
    DlpSettings(Box<SetRequest<'x, crate::object::inbuxa_dlp_settings::DlpSettings>>),
    Explanation(Box<SetRequest<'x, crate::object::inbuxa_explanation::Explanation>>),
    AuditSettings(Box<SetRequest<'x, crate::object::inbuxa_audit::AuditSettings>>),
    AuditExport(Box<SetRequest<'x, crate::object::inbuxa_audit::AuditExport>>),
    AuditVerification(Box<SetRequest<'x, crate::object::inbuxa_audit::AuditVerification>>),
    AccountLock(Box<SetRequest<'x, crate::object::inbuxa_account_lock::AccountLock>>),
    LegalHold(Box<SetRequest<'x, crate::object::inbuxa_legal_hold::LegalHold>>),
    MailRule(Box<SetRequest<'x, crate::object::inbuxa_mail_rule::MailRule>>),
    SecurityAcceptance(
        Box<SetRequest<'x, crate::object::inbuxa_security_acceptance::SecurityAcceptance>>,
    ),
    DeliverabilityReport(Box<SetRequest<'x, crate::object::inbuxa_deliverability_report::DeliverabilityReport>>),
    DeliverabilitySettings(Box<SetRequest<'x, crate::object::inbuxa_deliverability_settings::DeliverabilitySettings>>),
    Journal(Box<SetRequest<'x, crate::object::inbuxa_journal::Journal>>),
    JournalExport(Box<SetRequest<'x, crate::object::inbuxa_journal_entry::JournalExport>>),
    JournalVerification(Box<SetRequest<'x, crate::object::inbuxa_journal_entry::JournalVerification>>),
    HeldMessage(Box<SetRequest<'x, crate::object::inbuxa_held_message::HeldMessage>>),
    HoldExport(Box<SetRequest<'x, crate::object::inbuxa_hold_export::HoldExport>>),
    ProtocolPolicy(Box<SetRequest<'x, crate::object::inbuxa_protocol_policy::ProtocolPolicy>>),
    TenantProtocolPolicy(
        Box<SetRequest<'x, crate::object::inbuxa_tenant_protocol_policy::TenantProtocolPolicy>>,
    ),
    SharingPolicy(
        Box<SetRequest<'x, crate::object::inbuxa_sharing_policy::SharingPolicy>>,
    ),
}

#[derive(Debug)]
pub enum CopyRequestMethod<'x> {
    Email(Box<CopyRequest<'x, Email>>),
    ContactCard(Box<CopyRequest<'x, ContactCard>>),
    CalendarEvent(Box<CopyRequest<'x, CalendarEvent>>),
    FileNode(Box<CopyRequest<'x, FileNode>>),
    Blob(Box<CopyBlobRequest>),
}

#[derive(Debug)]
pub enum QueryRequestMethod {
    Email(Box<QueryRequest<Email>>),
    Mailbox(Box<QueryRequest<Mailbox>>),
    EmailSubmission(Box<QueryRequest<EmailSubmission>>),
    Sieve(Box<QueryRequest<Sieve>>),
    Principal(Box<QueryRequest<Principal>>),
    Quota(Box<QueryRequest<Quota>>),
    AddressBook(Box<QueryRequest<AddressBook>>),
    ContactCard(Box<QueryRequest<ContactCard>>),
    FileNode(Box<QueryRequest<FileNode>>),
    Calendar(Box<QueryRequest<Calendar>>),
    CalendarEvent(Box<QueryRequest<CalendarEvent>>),
    CalendarEventNotification(Box<QueryRequest<CalendarEventNotification>>),
    ShareNotification(Box<QueryRequest<ShareNotification>>),
    Registry(Box<QueryRequest<Registry>>),
    AuditEvent(Box<QueryRequest<crate::object::inbuxa_audit::AuditEvent>>),
    JournalEntry(Box<QueryRequest<crate::object::inbuxa_journal_entry::JournalEntry>>),
}

#[derive(Debug)]
pub enum QueryChangesRequestMethod {
    Email(Box<QueryChangesRequest<Email>>),
    Mailbox(Box<QueryChangesRequest<Mailbox>>),
    EmailSubmission(Box<QueryChangesRequest<EmailSubmission>>),
    Principal(Box<QueryChangesRequest<Principal>>),
    Quota(Box<QueryChangesRequest<Quota>>),
    ContactCard(Box<QueryChangesRequest<ContactCard>>),
    FileNode(Box<QueryChangesRequest<FileNode>>),
    CalendarEvent(Box<QueryChangesRequest<CalendarEvent>>),
    CalendarEventNotification(Box<QueryChangesRequest<CalendarEventNotification>>),
    ShareNotification(Box<QueryChangesRequest<ShareNotification>>),
}

#[derive(Debug)]
pub enum ParseRequestMethod {
    Email(Box<ParseRequest<Email>>),
    ContactCard(Box<ParseRequest<ContactCard>>),
    CalendarEvent(Box<ParseRequest<CalendarEvent>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeInvalid<V: FromStr> {
    Value(V),
    Invalid(String),
}

impl<'de, V: FromStr> serde::Deserialize<'de> for MaybeInvalid<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;

        if let Ok(id) = V::from_str(value) {
            Ok(MaybeInvalid::Value(id))
        } else {
            Ok(MaybeInvalid::Invalid(value.to_string()))
        }
    }
}

impl<V: FromStr + serde::Serialize> serde::Serialize for MaybeInvalid<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MaybeInvalid::Value(v) => v.serialize(serializer),
            MaybeInvalid::Invalid(s) => serializer.serialize_str(s),
        }
    }
}

impl<V: FromStr> From<V> for MaybeInvalid<V> {
    fn from(value: V) -> Self {
        MaybeInvalid::Value(value)
    }
}

impl<V: FromStr> Default for MaybeInvalid<V> {
    fn default() -> Self {
        MaybeInvalid::Invalid("".to_string())
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Request<'_> {
    fn default() -> Self {
        Request {
            using: CapabilityIds::default(),
            method_calls: Vec::new(),
            created_ids: None,
        }
    }
}

impl<T> MaybeInvalid<T>
where
    T: FromStr,
{
    pub fn try_unwrap(self) -> Option<T> {
        match self {
            MaybeInvalid::Value(id) => Some(id),
            MaybeInvalid::Invalid(_) => None,
        }
    }
}

pub trait IntoValid {
    type Item;

    fn into_valid(self) -> impl Iterator<Item = Self::Item>;
}

impl<T: FromStr> IntoValid for Vec<MaybeInvalid<T>> {
    type Item = T;

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter().filter_map(|v| v.try_unwrap())
    }
}

impl<T: FromStr> IntoValid for Vec<MaybeIdReference<T>> {
    type Item = T;

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter().filter_map(|v| v.try_unwrap())
    }
}

impl<T: FromStr + Eq, V> IntoValid for VecMap<MaybeInvalid<T>, V> {
    type Item = (T, V);

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter()
            .filter_map(|(k, v)| k.try_unwrap().map(|k| (k, v)))
    }
}

impl<T: FromStr + Eq, V> IntoValid for VecMap<MaybeIdReference<T>, V> {
    type Item = (T, V);

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter()
            .filter_map(|(k, v)| k.try_unwrap().map(|k| (k, v)))
    }
}
