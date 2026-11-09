/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    DavError, DavMethod,
    calendar::privacy::ShareeView,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEvent, privacy::archived_event_view},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait CalendarGetRequestHandler: Sync + Send {
    fn handle_calendar_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarGetRequestHandler for Server {
    async fn handle_calendar_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .by_path(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate ACL
        if !access_token.is_member(account_id)
            && !resources.has_access_to_container(
                access_token,
                resource.parent_id().unwrap(),
                Acl::ReadItems,
            )
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Fetch event
        let event_ = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEvent,
                resource.document_id(),
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let event = event_
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?;

        // Validate headers
        let etag = event_.etag();
        let schedule_tag = event.schedule_tag.as_ref().map(|tag| tag.to_native());
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: Collection::CalendarEvent,
                document_id: resource.document_id().into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type("text/calendar; charset=utf-8")
            .with_etag(etag)
            .with_schedule_tag_opt(schedule_tag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(event.modified)).to_string());

        // inbuxa: a reader who isn't the calendar's owner gets the event as
        // JMAP shows it
        let view = if !access_token.reads_as_owner(account_id) {
            ShareeView::new(archived_event_view(event), || {
                resources
                    .shared_items(access_token, [Acl::ModifyItems], true)
                    .contains(resource.document_id())
            })
        } else {
            None
        };
        let ical = if let Some(view) = view {
            let mut event = event_
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let reader = if view.hide_attendees {
                Some(
                    self.account_info(access_token.account_id())
                        .await
                        .caused_by(trc::location!())?,
                )
            } else {
                None
            };
            view.apply(
                &mut event,
                reader.as_ref().map(|r| r.addresses()).unwrap_or_default(),
                self.core.groupware.max_ical_instances,
            );
            event.data.event.to_string()
        } else {
            event.data.event.to_string()
        };

        if !is_head {
            Ok(response.with_binary_body(ical))
        } else {
            Ok(response.with_content_length(ical.len()))
        }
    }
}
