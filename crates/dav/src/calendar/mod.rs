/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod copy_move;
pub mod delete;
pub mod freebusy;
pub mod get;
pub mod mkcol;
pub mod privacy; // inbuxa: what sharees see of events
pub mod proppatch;
pub mod query;
pub mod scheduling;
pub mod update;

use crate::{DavError, DavErrorCondition};
use common::{DavResources, Server};
use dav_proto::schema::{
    property::{CalDavProperty, CalendarData, DavProperty, WebDavProperty},
    response::CalCondition,
};
use groupware::scheduling::ItipError;
use hyper::StatusCode;
use store::{ValueKey, write::ValueClass};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, PrincipalField},
};

pub(crate) static CALENDAR_CONTAINER_PROPS: [DavProperty; 31] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
    DavProperty::CalDav(CalDavProperty::CalendarDescription),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarData),
    DavProperty::CalDav(CalDavProperty::SupportedCollationSet),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
    DavProperty::CalDav(CalDavProperty::CalendarTimezone),
    DavProperty::CalDav(CalDavProperty::MaxResourceSize),
    DavProperty::CalDav(CalDavProperty::MinDateTime),
    DavProperty::CalDav(CalDavProperty::MaxDateTime),
    DavProperty::CalDav(CalDavProperty::MaxInstances),
    DavProperty::CalDav(CalDavProperty::MaxAttendeesPerInstance),
    DavProperty::CalDav(CalDavProperty::TimezoneServiceSet),
    DavProperty::CalDav(CalDavProperty::TimezoneId),
];

pub(crate) static CALENDAR_ITEM_PROPS: [DavProperty; 20] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::CalDav(CalDavProperty::CalendarData(CalendarData {
        properties: vec![],
        expand: None,
        limit_recurrence: None,
        limit_freebusy: None,
    })),
];

pub(crate) async fn assert_is_unique_uid(
    server: &Server,
    resources: &DavResources,
    account_id: u32,
    calendar_id: u32,
    uid: Option<&str>,
) -> crate::Result<()> {
    if let Some(uid) = uid {
        let hits = server
            .document_ids_matching(
                account_id,
                Collection::CalendarEvent,
                CalendarEventField::Uid,
                uid.as_bytes(),
            )
            .await
            .caused_by(trc::location!())?;

        if !hits.is_empty() {
            for path in resources.children(calendar_id) {
                if hits.contains(path.document_id()) {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CalCondition::NoUidConflict(resources.format_resource(path).into()),
                    )));
                }
            }
        }
    }

    Ok(())
}

// inbuxa: the account's default calendar as CalDAV sees it. This is the one chosen
// over JMAP while it exists, else the calendar at the configured default name.
pub(crate) async fn default_calendar_id(
    server: &Server,
    resources: &DavResources,
    account_id: u32,
) -> trc::Result<Option<u32>> {
    if let Some(document_id) = server
        .store()
        .get_value::<u32>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
        })
        .await
        .caused_by(trc::location!())?
        && resources.has_container_id(&document_id)
    {
        return Ok(Some(document_id));
    }

    Ok(server
        .core
        .groupware
        .default_calendar_name
        .as_ref()
        .and_then(|name| resources.by_path(name))
        .filter(|resource| resource.is_container())
        .map(|resource| resource.document_id()))
}

pub(crate) trait ItipPrecondition {
    fn failed_precondition(&self) -> Option<CalCondition>;
}

impl ItipPrecondition for ItipError {
    fn failed_precondition(&self) -> Option<CalCondition> {
        match self {
            ItipError::MultipleOrganizer => Some(CalCondition::SameOrganizerInAllComponents),
            ItipError::OrganizerIsLocalAddress
            | ItipError::SenderIsNotParticipant(_)
            | ItipError::SenderIsNotOrganizer(_)
            | ItipError::OrganizerMismatch => Some(CalCondition::ValidOrganizer),
            ItipError::CannotModifyProperty(_)
            | ItipError::CannotModifyInstance
            | ItipError::CannotModifyAddress => Some(CalCondition::AllowedAttendeeObjectChange),
            ItipError::MissingUid
            | ItipError::MultipleUid
            | ItipError::MultipleObjectTypes
            | ItipError::MultipleObjectInstances
            | ItipError::MissingMethod
            | ItipError::InvalidComponentType
            | ItipError::OutOfSequence
            | ItipError::UnknownParticipant(_)
            | ItipError::UnsupportedMethod(_) => Some(CalCondition::ValidSchedulingMessage),
            _ => None,
        }
    }
}
