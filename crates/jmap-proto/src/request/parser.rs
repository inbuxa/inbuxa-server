/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{
    Call, Request, RequestMethod,
    method::{MethodFunction, MethodName, MethodObject},
};
use crate::request::{
    CopyRequestMethod, GetRequestMethod, ParseRequestMethod, QueryChangesRequestMethod,
    QueryRequestMethod, SetRequestMethod, capability::Using, deserialize::DeserializeArguments,
};
use compact_str::{CompactString, ToCompactString};
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use simdutf8::basic::from_utf8;
use std::{
    borrow::Cow,
    fmt::{self, Display},
    marker::PhantomData,
};
use utils::text::utf8_lossy;

const MAX_ERROR_EXCERPT: usize = 1024;

impl<'x> Request<'x> {
    pub fn parse(json: &'x [u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            let request = match from_utf8(json) {
                Ok(text) => serde_json::from_str::<Request>(text)
                    .or_else(|err| Self::parse_lenient(text, err)),
                Err(err) => Err(err.to_compact_string()),
            };
            match request {
                // inbuxa: RFC 8620 section 3.6.1, a capability the server
                // doesn't know fails the request with unknownCapability
                Ok(Request {
                    unknown_capability: Some(capability),
                    ..
                }) => Err(trc::JmapEvent::UnknownCapability
                    .into_err()
                    .details(capability)),
                Ok(request) => {
                    if request.method_calls.len() <= max_calls {
                        Ok(request)
                    } else {
                        Err(trc::LimitEvent::CallsIn.into_err())
                    }
                }
                Err(err) => Err(trc::JmapEvent::NotRequest.into_err().reason(err).details(
                    CompactString::from(utf8_lossy(json.get(..MAX_ERROR_EXCERPT).unwrap_or(json))),
                )),
            }
        } else {
            Err(trc::LimitEvent::SizeRequest.into_err())
        }
    }

    #[cold]
    #[inline(never)]
    fn parse_lenient(text: &'x str, err: serde_json::Error) -> Result<Self, CompactString> {
        serde_json::from_str::<LenientRequest>(text)
            .map(|request| request.0)
            .map_err(|_| err.to_compact_string())
    }

    pub(crate) fn deserialize_field<A, C>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'x>,
        C: CallList<'x>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"using" => {
                // inbuxa: an unknown capability is kept, not a parse error
                let using = map.next_value::<Using>()?;
                self.using = using.ids;
                self.unknown_capability = using.unknown;
            },
            b"methodCalls" => {
                self.method_calls = map.next_value::<C>()?.into_calls();
            },
            b"createdIds" => {
                self.created_ids = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

pub(crate) trait CallList<'de>: Deserialize<'de> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>>;
}

impl<'de> CallList<'de> for Vec<Call<RequestMethod<'de>>> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>> {
        self
    }
}

impl<'de> CallList<'de> for Vec<LenientCall<'de>> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>> {
        self.into_iter().map(|call| call.0).collect()
    }
}

impl<'de> DeserializeArguments<'de> for Request<'de> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        self.deserialize_field::<A, Vec<Call<RequestMethod<'de>>>>(key, map)
    }
}

pub(crate) struct LenientRequest<'x>(pub Request<'x>);

#[repr(transparent)]
pub(crate) struct LenientCall<'x>(Call<RequestMethod<'x>>);

struct MethodArguments(MethodName);

impl<'de> DeserializeSeed<'de> for MethodArguments {
    type Value = RequestMethod<'de>;

    #[inline(always)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match (self.0.fnc, self.0.obj) {
            (MethodFunction::Get, MethodObject::Email) => RequestMethod::Get(
                GetRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Mailbox) => RequestMethod::Get(
                GetRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Thread) => RequestMethod::Get(
                GetRequestMethod::Thread(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Identity) => RequestMethod::Get(
                GetRequestMethod::Identity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::EmailSubmission) => RequestMethod::Get(
                GetRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::PushSubscription) => RequestMethod::Get(
                GetRequestMethod::PushSubscription(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::VacationResponse) => RequestMethod::Get(
                GetRequestMethod::VacationResponse(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SieveScript) => RequestMethod::Get(
                GetRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Principal) => RequestMethod::Get(
                GetRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Quota) => RequestMethod::Get(
                GetRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Blob) => RequestMethod::Get(
                GetRequestMethod::Blob(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Calendar) => RequestMethod::Get(
                GetRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::CalendarEvent) => RequestMethod::Get(
                GetRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::CalendarEventNotification) => {
                RequestMethod::Get(GetRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Get, MethodObject::ParticipantIdentity) => RequestMethod::Get(
                GetRequestMethod::ParticipantIdentity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AddressBook) => RequestMethod::Get(
                GetRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ContactCard) => RequestMethod::Get(
                GetRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::FileNode) => RequestMethod::Get(
                GetRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ShareNotification) => RequestMethod::Get(
                GetRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SearchSnippet) => {
                RequestMethod::SearchSnippet(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Get, MethodObject::Registry(_)) => RequestMethod::Get(
                GetRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Email) => RequestMethod::Set(
                SetRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Mailbox) => RequestMethod::Set(
                SetRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Identity) => RequestMethod::Set(
                SetRequestMethod::Identity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::EmailSubmission) => RequestMethod::Set(
                SetRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::PushSubscription) => RequestMethod::Set(
                SetRequestMethod::PushSubscription(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::VacationResponse) => RequestMethod::Set(
                SetRequestMethod::VacationResponse(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::SieveScript) => RequestMethod::Set(
                SetRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Calendar) => RequestMethod::Set(
                SetRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::CalendarEvent) => RequestMethod::Set(
                SetRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::CalendarEventNotification) => {
                RequestMethod::Set(SetRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Set, MethodObject::ParticipantIdentity) => RequestMethod::Set(
                SetRequestMethod::ParticipantIdentity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AddressBook) => RequestMethod::Set(
                SetRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ContactCard) => RequestMethod::Set(
                SetRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::FileNode) => RequestMethod::Set(
                SetRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ShareNotification) => RequestMethod::Set(
                SetRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Registry(_)) => RequestMethod::Set(
                SetRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Email) => RequestMethod::Query(
                QueryRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Mailbox) => RequestMethod::Query(
                QueryRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::EmailSubmission) => RequestMethod::Query(
                QueryRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::SieveScript) => RequestMethod::Query(
                QueryRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Principal) => RequestMethod::Query(
                QueryRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Quota) => RequestMethod::Query(
                QueryRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Calendar) => RequestMethod::Query(
                QueryRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::CalendarEvent) => RequestMethod::Query(
                QueryRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::CalendarEventNotification) => {
                RequestMethod::Query(QueryRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Query, MethodObject::AddressBook) => RequestMethod::Query(
                QueryRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::ContactCard) => RequestMethod::Query(
                QueryRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::FileNode) => RequestMethod::Query(
                QueryRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::ShareNotification) => RequestMethod::Query(
                QueryRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Registry(_)) => RequestMethod::Query(
                QueryRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Email) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Mailbox) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::EmailSubmission) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::EmailSubmission(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::Principal) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Quota) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::CalendarEvent) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::CalendarEvent(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::CalendarEventNotification) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::ContactCard) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::ContactCard(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::FileNode) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::ShareNotification) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::ShareNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Changes, _) => {
                RequestMethod::Changes(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Copy, MethodObject::Email) => RequestMethod::Copy(
                CopyRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::Blob) => RequestMethod::Copy(
                CopyRequestMethod::Blob(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::CalendarEvent) => RequestMethod::Copy(
                CopyRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::ContactCard) => RequestMethod::Copy(
                CopyRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::FileNode) => RequestMethod::Copy(
                CopyRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Lookup, MethodObject::Blob) => {
                RequestMethod::LookupBlob(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Upload, MethodObject::Blob) => {
                RequestMethod::UploadBlob(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Import, MethodObject::Email) => {
                RequestMethod::ImportEmail(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Parse, MethodObject::Email) => RequestMethod::Parse(
                ParseRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Parse, MethodObject::CalendarEvent) => RequestMethod::Parse(
                ParseRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Parse, MethodObject::ContactCard) => RequestMethod::Parse(
                ParseRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::GetAvailability, MethodObject::Principal) => RequestMethod::Get(
                GetRequestMethod::PrincipalAvailability(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Validate, MethodObject::SieveScript) => {
                RequestMethod::ValidateScript(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Echo, MethodObject::Core) => {
                RequestMethod::Echo(Deserialize::deserialize(deserializer)?)
            }
            // inbuxa: the fork's own objects
            (MethodFunction::Get, MethodObject::MaskedEmail) => RequestMethod::Get(
                GetRequestMethod::MaskedEmail(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::DeletedAccount) => RequestMethod::Get(
                GetRequestMethod::DeletedAccount(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AiLimits) => RequestMethod::Get(
                GetRequestMethod::AiLimits(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::LogSettings) => RequestMethod::Get(
                GetRequestMethod::LogSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::DlpSettings) => RequestMethod::Get(
                GetRequestMethod::DlpSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::DataInventory) => RequestMethod::Get(
                GetRequestMethod::DataInventory(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::InventorySnapshot) => RequestMethod::Get(
                GetRequestMethod::InventorySnapshot(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ProtocolPolicy) => RequestMethod::Get(
                GetRequestMethod::ProtocolPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::TenantProtocolPolicy) => RequestMethod::Get(
                GetRequestMethod::TenantProtocolPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SharingPolicy) => RequestMethod::Get(
                GetRequestMethod::SharingPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::FrontEnds) => RequestMethod::Get(
                GetRequestMethod::FrontEnds(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::MaskedEmail) => RequestMethod::Set(
                SetRequestMethod::MaskedEmail(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::DeletedAccount) => RequestMethod::Set(
                SetRequestMethod::DeletedAccount(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AiLimits) => RequestMethod::Set(
                SetRequestMethod::AiLimits(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::LogSettings) => RequestMethod::Set(
                SetRequestMethod::LogSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::DlpSettings) => RequestMethod::Set(
                SetRequestMethod::DlpSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Explanation) => RequestMethod::Set(
                SetRequestMethod::Explanation(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ProtocolPolicy) => RequestMethod::Set(
                SetRequestMethod::ProtocolPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::TenantProtocolPolicy) => RequestMethod::Set(
                SetRequestMethod::TenantProtocolPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::SharingPolicy) => RequestMethod::Set(
                SetRequestMethod::SharingPolicy(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::FrontEnds) => RequestMethod::Set(
                SetRequestMethod::FrontEnds(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AccountLock) => RequestMethod::Get(
                GetRequestMethod::AccountLock(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AccountLock) => RequestMethod::Set(
                SetRequestMethod::AccountLock(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::HoldExport) => RequestMethod::Get(
                GetRequestMethod::HoldExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::HoldExport) => RequestMethod::Set(
                SetRequestMethod::HoldExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::HeldMessage) => RequestMethod::Get(
                GetRequestMethod::HeldMessage(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::HeldMessage) => RequestMethod::Set(
                SetRequestMethod::HeldMessage(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::MailRule) => RequestMethod::Get(
                GetRequestMethod::MailRule(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::MailRule) => RequestMethod::Set(
                SetRequestMethod::MailRule(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SecurityAcceptance) => RequestMethod::Get(
                GetRequestMethod::SecurityAcceptance(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::SecurityAcceptance) => RequestMethod::Set(
                SetRequestMethod::SecurityAcceptance(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::DeliverabilityReport) => RequestMethod::Get(
                GetRequestMethod::DeliverabilityReport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::DeliverabilityReport) => RequestMethod::Set(
                SetRequestMethod::DeliverabilityReport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::DeliverabilitySettings) => RequestMethod::Get(
                GetRequestMethod::DeliverabilitySettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::DeliverabilitySettings) => RequestMethod::Set(
                SetRequestMethod::DeliverabilitySettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ScheduledReport) => RequestMethod::Get(
                GetRequestMethod::ScheduledReport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ScheduledReport) => RequestMethod::Set(
                SetRequestMethod::ScheduledReport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ScheduledReportSettings) => RequestMethod::Get(
                GetRequestMethod::ScheduledReportSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ScheduledReportSettings) => RequestMethod::Set(
                SetRequestMethod::ScheduledReportSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ReportExport) => RequestMethod::Get(
                GetRequestMethod::ReportExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ReportExport) => RequestMethod::Set(
                SetRequestMethod::ReportExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::JournalEntry) => RequestMethod::Get(
                GetRequestMethod::JournalEntry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::JournalEntry) => RequestMethod::Query(
                QueryRequestMethod::JournalEntry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::JournalExport) => RequestMethod::Set(
                SetRequestMethod::JournalExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::JournalVerification) => RequestMethod::Set(
                SetRequestMethod::JournalVerification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Journal) => RequestMethod::Get(
                GetRequestMethod::Journal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Journal) => RequestMethod::Set(
                SetRequestMethod::Journal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::LegalHold) => RequestMethod::Get(
                GetRequestMethod::LegalHold(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::LegalHold) => RequestMethod::Set(
                SetRequestMethod::LegalHold(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AuditEvent) => RequestMethod::Get(
                GetRequestMethod::AuditEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::AuditEvent) => RequestMethod::Query(
                QueryRequestMethod::AuditEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AuditSettings) => RequestMethod::Get(
                GetRequestMethod::AuditSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AuditSettings) => RequestMethod::Set(
                SetRequestMethod::AuditSettings(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AuditExport) => RequestMethod::Set(
                SetRequestMethod::AuditExport(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AuditVerification) => RequestMethod::Set(
                SetRequestMethod::AuditVerification(Deserialize::deserialize(deserializer)?),
            ),
            _ => {
                IgnoredAny::deserialize(deserializer)?;
                RequestMethod::Error(
                    trc::JmapEvent::UnknownMethod
                        .into_err()
                        .details(self.0.as_str()),
                )
            }
        })
    }
}

struct CallVisitor;

impl<'de> Visitor<'de> for CallVisitor {
    type Value = Call<RequestMethod<'de>>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array with 3 elements")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Call<RequestMethod<'de>>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let method_name = seq
            .next_element::<Cow<str>>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let (name, method) = match MethodName::parse(method_name.as_ref()) {
            Some(name) => match seq.next_element_seed(MethodArguments(name)) {
                Ok(Some(method)) => (name, method),
                Err(err) => (name, RequestMethod::invalid(err)),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            None => {
                seq.next_element::<IgnoredAny>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                (MethodName::error(), RequestMethod::unknown(method_name))
            }
        };

        let id = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

        Ok(Call { id, method, name })
    }
}

struct LenientCallVisitor;

impl<'de> Visitor<'de> for LenientCallVisitor {
    type Value = LenientCall<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array with 3 elements")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<LenientCall<'de>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let method_name = seq
            .next_element::<Cow<str>>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let arguments = seq
            .next_element::<&'de RawValue>()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let id = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let (name, method) = match MethodName::parse(method_name.as_ref()) {
            Some(name) => {
                let mut deserializer = serde_json::Deserializer::from_str(arguments.get());
                match MethodArguments(name).deserialize(&mut deserializer) {
                    Ok(method) => (name, method),
                    Err(err) => (name, RequestMethod::invalid(err)),
                }
            }
            None => (MethodName::error(), RequestMethod::unknown(method_name)),
        };

        Ok(LenientCall(Call { id, method, name }))
    }
}

impl<'de> Deserialize<'de> for LenientCall<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LenientCallVisitor)
    }
}

impl RequestMethod<'_> {
    fn invalid(err: impl Display) -> Self {
        RequestMethod::Error(
            trc::JmapEvent::InvalidArguments
                .into_err()
                .details(err.to_compact_string()),
        )
    }

    fn unknown(method_name: Cow<'_, str>) -> Self {
        RequestMethod::Error(
            trc::JmapEvent::UnknownMethod
                .into_err()
                .details(method_name.into_owned()),
        )
    }
}

struct RequestVisitor<C> {
    _calls: PhantomData<C>,
}

impl<'de, C: CallList<'de>> Visitor<'de> for RequestVisitor<C> {
    type Value = Request<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JMAP request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut target = Request::default();
        let mut has_using = false;
        let mut has_method_calls = false;

        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "using" => has_using = true,
                "methodCalls" => has_method_calls = true,
                _ => {}
            }
            target.deserialize_field::<A, C>(key, &mut map)?;
        }

        if !has_using || !has_method_calls {
            return Err(de::Error::custom(
                "Request is missing the \"using\" or \"methodCalls\" property.",
            ));
        }

        Ok(target)
    }
}

impl<'de> Deserialize<'de> for Request<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RequestVisitor::<Vec<Call<RequestMethod<'de>>>> {
            _calls: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for LenientRequest<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_map(RequestVisitor::<Vec<LenientCall<'de>>> {
                _calls: PhantomData,
            })
            .map(LenientRequest)
    }
}

impl<'de> Deserialize<'de> for Call<RequestMethod<'de>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(CallVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::request::Request;

    const TEST: &str = r#"
    {
        "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail" ],
        "methodCalls": [
          [ "method1", {
            "arg1": "arg1data",
            "arg2": "arg2data"
          }, "c1" ],
          [ "Core/echo", {
            "hello": true,
            "high": 5
          }, "c2" ],
          [ "method3", {"hello": [{"a": {"b": true}}]}, "c3" ]
        ],
        "createdIds": {
            "c1": "m1",
            "c2": "m2"
        }
      }
    "#;

    const TEST1: &str = r#"
    {
    "using": [
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail"
    ],
    "methodCalls": [
        [
        "Email/query",
        {
            "accountId": "0",
            "filter": { "conditions": [ { "hasKeyword": "music", "maxSize": 455 }, { "hasKeyword": "video" }, { "operator": "AND", "conditions": [ { "subject": "test" }, { "minSize": 100 } ] } ], "operator": "OR" },
            "sort": [
            {
                "property": "subject",
                "isAscending": true
            },
            {
                "property": "allInThreadHaveKeyword",
                "isAscending": false,
                "keyword": "$seen"
            },
            {
                "keyword": "$junk",
                "property": "someInThreadHaveKeyword",
                "collation": "i;octet",
                "isAscending": false
            }
            ],
            "position": 0,
            "limit": 10
        },
        "c1"
        ]
    ],
    "createdIds": {}
    }
    "#;

    const TEST2: &str = r##"
    {
        "using": [
          "urn:ietf:params:jmap:submission",
          "urn:ietf:params:jmap:mail",
          "urn:ietf:params:jmap:core"
        ],
        "methodCalls": [
          [
            "Email/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds": {
                    "9": true
                  },
                  "subject": "test",
                  "from": [
                    {
                      "name": "Foo",
                      "email": "foo@bar.com"
                    }
                  ],
                  "to": [
                    {
                      "name": null,
                      "email": "bar@foo.com"
                    }
                  ],
                  "cc": [],
                  "bcc": [],
                  "replyTo": [
                    {
                      "name": null,
                      "email": "foo@bar.com"
                    }
                  ],
                  "htmlBody": [
                    {
                      "partId": "c37ee58b-e224-4799-88e6-1d7484e3b782",
                      "type": "text/html"
                    }
                  ],
                  "bodyValues": {
                    "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                      "value": "<p>test email<br></p>",
                      "isEncodingProblem": false,
                      "isTruncated": false
                    }
                  },
                  "header:User-Agent:asText": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
                }
              }
            },
            "c0"
          ],
          [
            "EmailSubmission/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "identityId": "a",
                  "emailId": "#c37ee58b-e224-4799-88e6-1d7484e3b782",
                  "envelope": {
                    "mailFrom": {
                      "email": "foo@bar.com"
                    },
                    "rcptTo": [
                      {
                        "email": "bar@foo.com"
                      }
                    ]
                  }
                }
              },
              "onSuccessUpdateEmail": {
                "#c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds/d": true,
                  "mailboxIds/9": null,
                  "keywords/$seen": true,
                  "keywords/$draft": null
                }
              }
            },
            "c1"
          ]
        ]
      }
    "##;

    const TEST_ESCAPED_SOLIDUS: &str = r#"
    {
        "using": [ "urn:ietf:params:jmap:core" ],
        "methodCalls": [
          [ "Core\/echo", { "hello": true }, "c1" ]
        ]
      }
    "#;

    #[test]
    fn parse_request() {
        println!("{:#?}", Request::parse(TEST.as_bytes(), 10, 10240));
        println!("{:#?}", Request::parse(TEST1.as_bytes(), 10, 10240));
        println!("{:#?}", Request::parse(TEST2.as_bytes(), 10, 10240));
    }

    // inbuxa: an unknown capability fails the request as unknownCapability,
    // naming it, and a known one parses as before.
    #[test]
    fn unknown_capability_is_named() {
        let request = r#"{"using": ["urn:ietf:params:jmap:core", "urn:example:nope", "urn:example:other"],
                          "methodCalls": [["Core/echo", {}, "0"]]}"#;
        let err = Request::parse(request.as_bytes(), 10, 10240).unwrap_err();
        assert_eq!(
            *err.as_ref(),
            trc::EventType::Jmap(trc::JmapEvent::UnknownCapability)
        );
        assert_eq!(
            err.value(trc::Key::Details).and_then(|v| v.as_str()),
            Some("urn:example:nope")
        );

        let request = r#"{"using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry"],
                          "methodCalls": [["Core/echo", {}, "0"]]}"#;
        let request = Request::parse(request.as_bytes(), 10, 10240).unwrap();
        assert!(
            request
                .using
                .contains(crate::request::capability::Capability::Stalwart)
        );
        assert!(request.unknown_capability.is_none());
    }

    #[test]
    fn unknown_capability_over_websocket_is_named() {
        let message = r#"{"@type": "Request", "id": "r1", "using": ["urn:example:nope"],
                          "methodCalls": [["Core/echo", {}, "0"]]}"#;
        let err = crate::request::websocket::WebSocketMessage::parse(message.as_bytes(), 10, 10240)
            .unwrap_err();
        assert_eq!(
            *err.as_ref(),
            trc::EventType::Jmap(trc::JmapEvent::UnknownCapability)
        );
    }

    #[test]
    fn parse_method_name_with_escaped_solidus() {
        let request = Request::parse(TEST_ESCAPED_SOLIDUS.as_bytes(), 10, 10240)
            .expect("escaped solidus in method name must parse");
        assert_eq!(request.method_calls.len(), 1);
        assert!(matches!(
            request.method_calls[0].method,
            super::RequestMethod::Echo(_)
        ));
    }
}
