/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::{RegistryQueryFilters, with_page_position},
    },
};
use compact_str::format_compact;
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::{Key, Value};
use registry::{
    jmap::IntoValue,
    schema::{
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::Task,
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use services::task_manager::lock::{TaskLock, TaskLockManager};
use smtp::reporting::{
    aggregate::{ReportItem, read_dmarc_records, read_tls_policies},
    index::{ExternalReportIndex, InternalReportIndex},
};
use std::str::FromStr;
use store::{
    U64_LEN, ValueKey,
    registry::{RegistryFilter, RegistryFilterValue, RegistryQuery},
    write::{
        BatchBuilder, RegistryClass, TaskId, TaskQueueClass, ValueClass, assert::AssertValue,
        key::KeySerializer,
    },
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn report_set(
    set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    // inbuxa: task locks taken to reschedule reports are released however
    // the request ends; a held lock is renewed, so a leaked one would keep
    // the report's task from ever running
    let server = set.server;
    let mut locked_tasks = Vec::new();
    let result = report_set_locked(set, &mut locked_tasks).await;
    for lock in locked_tasks {
        server.unlock_task(lock).await;
    }
    result
}

async fn report_set_locked<'x>(
    mut set: RegistrySetResponse<'x>,
    locked_tasks: &mut Vec<TaskLock>,
) -> trc::Result<RegistrySetResponse<'x>> {
    let object_id = set.object_type.to_id();

    // Reports cannot be created
    set.fail_all_create("Reports cannot be created");

    let mut batch = BatchBuilder::new();
    if matches!(
        set.object_type,
        ObjectType::DmarcInternalReport | ObjectType::TlsInternalReport
    ) {
        let now = UTCDateTime::now();
        'outer: for (id, value) in set.update.drain(..) {
            // Extract new deliverAt value
            let mut deliver_at = None;
            for (key, value) in value.into_expanded_object() {
                match (key, value) {
                    (Key::Property(Property::DeliverAt), Value::Str(deliver_at_)) => {
                        deliver_at = UTCDateTime::from_str(deliver_at_.as_ref())
                            .ok()
                            .filter(|da| *da > now);
                        if deliver_at.is_none() {
                            set.response.not_updated.append(
                                id,
                                SetError::invalid_patch()
                                    .with_property(Property::DeliverAt)
                                    .with_description("Invalid value for property"),
                            );
                            continue 'outer;
                        }
                    }
                    (Key::Property(Property::Id), _) => {}
                    (key, _) => {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_properties().with_property(key.into_owned()),
                        );
                        continue 'outer;
                    }
                }
            }
            let Some(deliver_at) = deliver_at else {
                set.response.not_updated.append(
                    id,
                    SetError::invalid_patch()
                        .with_property(Key::Property(Property::DeliverAt))
                        .with_description("Missing required property"),
                );
                continue;
            };

            let item_id = id.id();
            let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
            if let Some(mut report_obj) = set
                .server
                .store()
                .get_value::<Object>(ValueKey::from(key.clone()))
                .await?
            {
                // inbuxa: the report's task shares its id. Hold the task
                // while its queue rows move, as x:Task/set does, and move the
                // row the task is actually queued under
                let Some(lock) = set.server.lock_task(item_id).await else {
                    set.response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(
                            "The report is being sent and cannot be rescheduled".to_string(),
                        ),
                    );
                    continue;
                };
                locked_tasks.push(lock);
                let queued = set
                    .server
                    .store()
                    .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                        TaskQueueClass::Task {
                            id: TaskId::Assigned(item_id),
                        },
                    )))
                    .await?;

                match &mut report_obj.inner {
                    ObjectInner::DmarcInternalReport(report) => {
                        report.reschedule_ops(
                            &mut batch,
                            item_id,
                            report_obj.revision,
                            deliver_at,
                            queued.as_ref(),
                        );
                    }
                    ObjectInner::TlsInternalReport(report) => {
                        report.reschedule_ops(
                            &mut batch,
                            item_id,
                            report_obj.revision,
                            deliver_at,
                            queued.as_ref(),
                        );
                    }
                    _ => {}
                }
                batch.commit_point();

                set.response.updated.append(id, None);
            } else {
                set.response.not_updated.append(id, SetError::not_found());
            }
        }
    } else {
        // External reports cannot be updated
        set.fail_all_update("External reports cannot be updated");
    }

    // Process reports to destroy
    // inbuxa: MT: tenant scoping, kept from 0.16
    let tenant_id = set.access_token.tenant_id().map(Id::from);
    let mut closed = Vec::new();
    for id in set.destroy.drain(..) {
        let item_id = id.id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
        let report = set
            .server
            .store()
            .get_value::<Object>(ValueKey::from(key.clone()))
            .await?
            // inbuxa: MT: tenant scoping, kept from 0.16
            .filter(|report| {
                !set.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            });
        if let Some(report) = report {
            match &report.inner {
                ObjectInner::DmarcExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::TlsExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::ArfExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::DmarcInternalReport(inner) => {
                    let item = ReportItem::new(ObjectType::DmarcInternalReport, item_id);
                    batch.assert_value(key, AssertValue::Hash(report.revision));
                    inner.write_ops(&mut batch, item_id, false);
                    item.clear(&mut batch);
                    closed.push(item);
                }
                ObjectInner::TlsInternalReport(inner) => {
                    let item = ReportItem::new(ObjectType::TlsInternalReport, item_id);
                    batch.assert_value(key, AssertValue::Hash(report.revision));
                    inner.write_ops(&mut batch, item_id, false);
                    item.clear(&mut batch);
                    closed.push(item);
                }
                _ => {}
            }
            batch.commit_point();

            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        // inbuxa: a rescheduled report may now be due sooner than the task
        // manager's next scan
        set.server.notify_task_queue();
    }
    for item in closed {
        if let Err(err) = item.clear_orphans(set.server.store()).await {
            trc::error!(err.details("Failed to clear orphaned report rows"));
        }
    }

    Ok(set)
}

pub(crate) async fn report_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let external_query = RegistryQuery::new(get.object_type);
    // inbuxa: MT: tenant scoping, kept from 0.16
    let external_query = if get.is_tenant_filtered {
        external_query.with_tenant(get.access_token.tenant_id())
    } else {
        external_query.greater_than(Property::ExpiresAt, 0u64)
    };
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else if matches!(
        get.object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    ) {
        get.server
            .registry()
            .query::<Vec<Id>>(external_query.with_limit(get.server.core.jmap.get_max_objects))
            .await?
    } else {
        get.server
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(get.object_type)
                    .filter(RegistryFilter::greater_than(
                        Property::Domain,
                        RegistryFilterValue::Bytes(vec![]),
                        true,
                    ))
                    .with_limit(get.server.core.jmap.get_max_objects),
            )
            .await?
    };

    // inbuxa: MT: tenant scoping, kept from 0.16
    let tenant_id = get.access_token.tenant_id().map(Id::from);
    for id in ids {
        let report = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
            // inbuxa: MT: tenant scoping, kept from 0.16
            .filter(|report| {
                !get.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            });
        if let Some(mut report) = report {
            match &mut report.inner {
                ObjectInner::DmarcInternalReport(report) => {
                    read_dmarc_records(get.server.store(), id.id(), report, usize::MAX).await?;
                }
                ObjectInner::TlsInternalReport(report) => {
                    read_tls_policies(get.server.store(), id.id(), report, usize::MAX).await?;
                }
                _ => {}
            }
            get.insert(id, report.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn report_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    // inbuxa: MT: tenant scoping, kept from 0.16
    let mut query = store::registry::RegistryQuery::new(req.object_type)
        .with_tenant(req.access_token.tenant_id());
    let is_internal = matches!(
        req.object_type,
        ObjectType::DmarcInternalReport | ObjectType::TlsInternalReport
    );

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Domain if is_internal => {
                if let serde_json::Value::String(value) = value {
                    let from = KeySerializer::new(value.len() + 1 + (U64_LEN * 2))
                        .write(value.as_str())
                        .write(0u8)
                        .finalize();
                    let mut to = from.clone();
                    to.extend_from_slice(&[u8::MAX; U64_LEN * 2]);
                    query.filters.push(RegistryFilter::greater_than_or_equal(
                        property,
                        RegistryFilterValue::Bytes(from),
                        true,
                    ));
                    query.filters.push(RegistryFilter::less_than_or_equal(
                        property,
                        RegistryFilterValue::Bytes(to),
                        true,
                    ));
                    true
                } else {
                    false
                }
            }
            Property::Text if !is_internal => {
                if let serde_json::Value::String(value) = value {
                    query.filters.push(RegistryFilter::text(property, value));
                    true
                } else {
                    false
                }
            }
            // inbuxa: MT: tenant scoping, kept from 0.16
            Property::MemberTenantId if !is_internal => {
                if req.access_token.tenant_id().is_none()
                    && let Some(id) = value.as_str().and_then(|s| Id::from_str(s).ok())
                {
                    query
                        .filters
                        .push(RegistryFilter::equal(property, id.id(), false));
                    true
                } else {
                    false
                }
            }
            Property::TotalFailedSessions | Property::TotalSuccessfulSessions if !is_internal => {
                if let Some(value) = value.as_u64() {
                    query.filters.push(store::registry::RegistryFilter {
                        property,
                        op,
                        value: value.into(),
                        is_pk: false,
                    });
                    true
                } else {
                    false
                }
            }
            Property::ExpiresAt if !is_internal => {
                if let Some(value) = value
                    .as_str()
                    .and_then(|value| UTCDateTime::from_str(value).ok())
                {
                    query.filters.push(store::registry::RegistryFilter {
                        property,
                        op,
                        value: (value.timestamp() as u64).into(),
                        is_pk: false,
                    });
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    if !query.has_filters() {
        if is_internal {
            query.filters.push(RegistryFilter::greater_than(
                Property::Domain,
                RegistryFilterValue::Bytes(vec![]),
                true,
            ));
        } else {
            query.filters.push(RegistryFilter::greater_than(
                Property::ExpiresAt,
                0u64,
                false,
            ));
        }
    }
    let page = req
        .server
        .registry()
        .query_page::<Vec<Id>>(params.paged(query))
        .await?;
    let position = params.page_position(page.position)?;
    let matches = page.ids;
    let results = match params.sort_by {
        Property::Id => {
            let mut results = matches;
            if params.needs_reversal() {
                results.sort_unstable_by(|a, b| b.cmp(a));
            }
            results
        }
        Property::Domain if is_internal => {
            if !matches.is_empty() {
                req.server
                    .registry()
                    .sort_by_pk(
                        req.object_type,
                        Property::Domain,
                        Some(matches),
                        params.sort_ascending,
                    )
                    .await?
            } else {
                vec![]
            }
        }
        Property::ExpiresAt if !is_internal => {
            if !matches.is_empty() {
                req.server
                    .registry()
                    .sort_by_index(
                        req.object_type,
                        Property::ExpiresAt,
                        Some(matches),
                        params.sort_ascending,
                    )
                    .await?
            } else {
                vec![]
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(format_compact!(
                    "Property {} is not supported for sorting",
                    property
                )));
        }
    };

    // Build response
    let mut response = with_page_position(
        QueryResponseBuilder::new(
            results.len(),
            req.server.core.jmap.query_max_results,
            State::Initial,
            &req.request,
        ),
        position,
    );

    for id in results {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}
