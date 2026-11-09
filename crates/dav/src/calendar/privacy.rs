/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What a reader who isn't a calendar's owner gets of its events over CalDAV:
//! what JMAP shows it. The time only of a private or confidential event, and
//! only the owners and the reader among the attendees of an event that hides
//! them, unless the reader may change it.

use crate::DavError;
use calcard::common::timezone::Tz;
use common::{EVENT_VIEW_HIDE_ATTENDEES, EVENT_VIEW_PRIVATE, Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventData,
        privacy::{event_view, hide_attendees, redact_private_event},
    },
};
use hyper::StatusCode;
use store::{
    Deserialize, Serialize,
    write::{AlignedBytes, Archive, Archiver},
};
use trc::AddContext;
use types::{acl::Acl, collection::SyncCollection};

#[derive(Debug, Clone, Copy)]
pub(crate) struct ShareeView {
    pub private: bool,
    pub hide_attendees: bool,
}

impl ShareeView {
    /// The view of an event with these EVENT_VIEW_* flags, or None when the
    /// reader may see all of it. `may_modify` tells whether the reader may
    /// change the event.
    pub fn new(view: u8, may_modify: impl FnOnce() -> bool) -> Option<Self> {
        let private = view & EVENT_VIEW_PRIVATE != 0;
        let hide_attendees = view & EVENT_VIEW_HIDE_ATTENDEES != 0 && !may_modify();
        (private || hide_attendees).then_some(ShareeView {
            private,
            hide_attendees,
        })
    }

    /// Leaves of `event` what the reader, at `addresses`, may see
    pub fn apply(&self, event: &mut CalendarEvent, addresses: &[String], max_expansions: usize) {
        if self.private {
            redact_private_event(&mut event.data.event);
            // Alarms and overrides may be gone, so the dates are worked out
            // again for what is left
            event.data = CalendarEventData::new(
                std::mem::take(&mut event.data.event),
                Tz::Floating,
                max_expansions,
                &mut None,
            );
        }
        if self.hide_attendees {
            hide_attendees(&mut event.data.event, addresses);
        }
    }

    /// A stored event as the reader may see it, under the stored one's ETag
    pub fn apply_archive(
        &self,
        archive: &Archive<AlignedBytes>,
        addresses: &[String],
        max_expansions: usize,
    ) -> trc::Result<Archive<AlignedBytes>> {
        let mut event = archive
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        self.apply(&mut event, addresses, max_expansions);
        event.size = event.data.event.to_string().len() as u32;
        let mut result = Archive::<AlignedBytes>::deserialize_owned(
            Archiver::new(event)
                .serialize()
                .caused_by(trc::location!())?,
        )
        .caused_by(trc::location!())?;
        result.version = archive.version;
        Ok(result)
    }
}

/// An event copied or moved out of its account by a reader who isn't the
/// calendar's owner takes what JMAP's CalendarEvent/copy lets it take: a
/// private or confidential event can't leave, and one that hides its
/// attendees leaves without those the reader may not see.
pub(crate) async fn check_copy_out(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    event: &mut CalendarEvent,
) -> crate::Result<()> {
    if access_token.reads_as_owner(from_account_id) {
        return Ok(());
    }
    let resources = server
        .fetch_dav_resources(
            access_token.account_id(),
            from_account_id,
            SyncCollection::Calendar,
        )
        .await
        .caused_by(trc::location!())?;
    if let Some(view) = ShareeView::new(event_view(event), || {
        resources
            .shared_items(access_token, [Acl::ModifyItems], true)
            .contains(from_document_id)
    }) {
        if view.private {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        let reader = server
            .account_info(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        view.apply(
            event,
            reader.addresses(),
            server.core.groupware.max_ical_instances,
        );
    }
    Ok(())
}
