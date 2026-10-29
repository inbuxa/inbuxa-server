/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    calendar_event::{CalendarSyntheticId, set::CalendarEventSet},
    changes::state::JmapCacheState,
};
use calcard::jscalendar::JSCalendarProperty;
use common::{
    EVENT_VIEW_HIDE_ATTENDEES, EVENT_VIEW_PRIVATE, Server, auth::AccessToken,
    storage::quota::QuotaBudget,
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, limit_component_depth,
        privacy::{event_view, hide_attendees},
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse},
        set::SetRequest,
    },
    object::calendar_event,
    request::{
        Call, IntoValid, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use utils::map::vec_map::VecMap;

pub trait JmapCalendarEventCopy: Sync + Send {
    fn calendar_event_copy<'x>(
        &self,
        request: CopyRequest<'x, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<calendar_event::CalendarEvent>>> + Send;
}

impl JmapCalendarEventCopy for Server {
    async fn calendar_event_copy<'x>(
        &self,
        request: CopyRequest<'x, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        _session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<calendar_event::CalendarEvent>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let old_state = cache.assert_state(false, &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let is_owner = access_token.reads_as_owner(from_account_id);
        let from_calendar_event_ids = if is_owner {
            from_cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            from_cache.shared_events(access_token, [Acl::ReadItems], true, 0)
        };
        let mut writable_ids = None;

        let can_add_calendars = if access_token.is_shared(account_id) {
            cache
                .shared_containers(access_token, [Acl::AddItems], true)
                .into()
        } else {
            None
        };
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();

        // Obtain account info
        let account_info = self
            .account_info(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        // inbuxa: the account copied into is the one whose quota applies
        let mut quota =
            QuotaBudget::new(self.account(account_id).await.caused_by(trc::location!())?);

        // Prepare batch
        let mut batch = BatchBuilder::new();

        'create: for (id, create) in request.create.into_valid() {
            let from_calendar_event_id = id.document_id();
            if !from_calendar_event_ids.contains(from_calendar_event_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }
            if id.is_synthetic() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description(format!(
                            "Item {} is a synthetic id and cannot be copied.",
                            id
                        )),
                );
                continue;
            }

            let Some(_calendar_event) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    from_account_id,
                    Collection::CalendarEvent,
                    from_calendar_event_id,
                ))
                .await?
            else {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            };

            let mut calendar_event = _calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            limit_component_depth(&mut calendar_event.data.event);

            // inbuxa: a sharee can't copy out what it may not see
            if !is_owner {
                let view = event_view(&calendar_event);
                if view & EVENT_VIEW_PRIVATE != 0 {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(
                            "Private events can't be copied from a shared calendar.",
                        ),
                    );
                    continue;
                }
                if view & EVENT_VIEW_HIDE_ATTENDEES != 0
                    && !writable_ids
                        .get_or_insert_with(|| {
                            from_cache.shared_items(access_token, [Acl::ModifyItems], true)
                        })
                        .contains(from_calendar_event_id)
                {
                    hide_attendees(&mut calendar_event.data.event, account_info.addresses());
                }
            }

            match self
                .create_calendar_event(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    &account_info,
                    &mut quota,
                    false,
                    &can_add_calendars,
                    calendar_event.data.event.into_jscalendar(),
                    create,
                )
                .await?
            {
                Ok(document_id) => {
                    response.created(id, document_id);

                    // Add to destroy list
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(id));
                    }
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;
            self.notify_task_queue();

            response.new_state = State::Exact(change_id);
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::CalendarEvent, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::CalendarEvent(Box::new(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}
