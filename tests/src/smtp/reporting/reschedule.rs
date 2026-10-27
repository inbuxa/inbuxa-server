/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Rescheduling an internal DMARC or TLS report over JMAP moves its task: the
//! task runs at the new time, x:Task/get shows the new due, and tasks due
//! after it still run. A task queue row that matches no task (a stale due,
//! or no task at all) is removed rather than holding back the tasks due
//! after it.

use crate::{
    smtp::reporting::{TestDmarcRecord, close_report_window},
    utils::server::{TestServer, TestServerBuilder},
};
use common::{
    Server,
    config::smtp::report::AggregateFrequency,
    ipc::{DmarcEvent, PolicyType, TlsEvent},
};
use mail_auth::{dmarc::DmarcRecord, dns::TxtRecordParser, mta_sts::TlsRptRecord};
use registry::{
    schema::{
        enums::{TaskStoreMaintenanceType, TaskType},
        prelude::{ObjectType, Property},
        structs::{
            DmarcInternalReport, DmarcReportSettings, Expression, Task, TaskStatus,
            TaskStoreMaintenance, TlsInternalReport, TlsReportSettings,
        },
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime},
};
use serde_json::json;
use smtp::reporting::{index::InternalReportIndex, send::MtaReportSend};
use smtp_report::dmarc::{Disposition, DmarcStatus, Record};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    SerializeInfallible, ValueKey,
    write::{BatchBuilder, RegistryClass, TaskId, TaskQueueClass, ValueClass, now},
};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn report_reschedule() {
    let mut test = TestServerBuilder::new("smtp_report_reschedule")
        .await
        .with_http_listener(19058)
        .await
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(TlsReportSettings {
            max_report_size: Expression {
                else_: "1024".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(DmarcReportSettings {
            max_aggregate_report_size: Expression {
                else_: "1024".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;
    let admin = test.account("admin");

    // A daily DMARC and TLS report, due a day from now
    schedule_dmarc(&test, "foobar.org").await;
    schedule_tls(&test, "foobar.org").await;
    let dmarc_id = wait_for_report::<DmarcInternalReport>(&test, "foobar.org").await;
    let tls_id = wait_for_report::<TlsInternalReport>(&test, "foobar.org").await;

    // Reschedule both to a few seconds from now, with a task due after them
    let at = now() + 3;
    let later = marker_task(&test.server, at + 3).await;
    for (object, id, task_type) in [
        (
            ObjectType::DmarcInternalReport,
            dmarc_id,
            TaskType::DmarcReport,
        ),
        (ObjectType::TlsInternalReport, tls_id, TaskType::TlsReport),
    ] {
        admin
            .registry_update_object(
                object,
                id,
                json!({
                    Property::DeliverAt: UTCDateTime::from_timestamp(at as i64),
                }),
            )
            .await;

        // x:Task/get shows the new due, and the queue row carries the task's
        // type. Upstream wrote the report's object type there and left the
        // task at its old due
        let task = admin.registry_get::<Task>(id).await;
        assert_eq!(task.object_type(), task_type);
        assert_eq!(
            task.due_timestamp(),
            at,
            "{object:?} task due not moved: {task:?}"
        );
        // inbuxa: 1.0 keys queue rows by task type, so the row being found
        // under the task's type is what carries the type now
        assert!(
            queue_row(&test.server, id.id(), task_type, at)
                .await
                .is_some(),
            "{object:?} queue row"
        );
    }

    // Both reports go out at the new time, and the later task still runs
    wait_until_run(&test.server, &[dmarc_id.id(), tls_id.id(), later]).await;
    assert!(now() >= at, "the reports went out before their new time");
    assert!(
        admin
            .registry_get_all::<DmarcInternalReport>()
            .await
            .is_empty()
    );
    assert!(
        admin
            .registry_get_all::<TlsInternalReport>()
            .await
            .is_empty()
    );

    // Rows that don't match a task: one at a due its task doesn't have, and
    // one with no task behind it. Neither may hold back a task due after
    // them.
    // inbuxa: 0.16 tested here the row its old reschedule wrote (the
    // report's object type in the value, the task left at its old due) and
    // moved the task to that row's time. 1.0 keys queue rows by task type and
    // never reads their value, so that row can't be misread any more; the
    // closest 1.0 case is a stale due: the task manager drops the row and the
    // task keeps its own due and row.
    schedule_dmarc(&test, "foobar.net").await;
    let dmarc_id = wait_for_report::<DmarcInternalReport>(&test, "foobar.net").await;
    let at = now() + 2;
    let task_due = stale_queue_row(&test.server, dmarc_id.id(), at).await;
    let orphan = SnowflakeIdGenerator::global_id().unwrap();
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(orphan),
            typ: TaskType::StoreMaintenance,
            due: at,
        }),
        vec![0xff, 0xff],
    );
    test.server.store().write_batch(&mut batch).await.unwrap();
    let later = marker_task(&test.server, at + 2).await;

    wait_until_run(&test.server, &[later]).await;
    wait_until_gone(&test.server, orphan, TaskType::StoreMaintenance, at).await;
    wait_until_gone(&test.server, dmarc_id.id(), TaskType::DmarcReport, at).await;
    assert!(task_due > at + 3600, "the report's own due is a day away");
    let task = admin.registry_get::<Task>(dmarc_id).await;
    assert_eq!(task.object_type(), TaskType::DmarcReport);
    assert_eq!(task.due_timestamp(), task_due);
    assert!(
        queue_row(&test.server, dmarc_id.id(), TaskType::DmarcReport, task_due)
            .await
            .is_some(),
        "the report's task lost its queue row"
    );
    assert_eq!(
        admin
            .registry_get_all::<DmarcInternalReport>()
            .await
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![dmarc_id]
    );
    admin
        .registry_destroy(ObjectType::DmarcInternalReport, vec![dmarc_id])
        .await
        .assert_destroyed(&[dmarc_id]);
    assert!(!task_exists(&test.server, dmarc_id.id()).await);
    assert_eq!(
        queue_row(&test.server, dmarc_id.id(), TaskType::DmarcReport, task_due).await,
        None
    );

    // x:Task/query by type skips an unreadable row rather than failing
    let mut batch = BatchBuilder::new();
    let due = now() + 3600;
    batch.set(
        ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(orphan),
            typ: TaskType::DmarcReport,
            due,
        }),
        vec![0xff, 0xff],
    );
    test.server.store().write_batch(&mut batch).await.unwrap();
    admin
        .registry_query_ids(
            ObjectType::Task,
            vec![(Property::Type, TaskType::DmarcReport.as_str())],
            Vec::<&str>::new(),
        )
        .await;
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
        id: TaskId::Assigned(orphan),
        typ: TaskType::DmarcReport,
        due,
    }));
    test.server.store().write_batch(&mut batch).await.unwrap();

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn schedule_dmarc(test: &TestServer, domain: &str) {
    test.server
        .schedule_report(DmarcEvent {
            domain: domain.to_string(),
            report_record: Record::default()
                .with_source_ip("192.168.1.2".parse().unwrap())
                .with_action_disposition(Disposition::Pass)
                .with_dmarc_dkim_result(DmarcStatus::Pass)
                .with_dmarc_spf_result(DmarcStatus::Fail)
                .with_envelope_from("hello@example.org")
                .with_envelope_to("other@example.org")
                .with_header_from("bye@example.org"),
            dmarc_record: Arc::new(
                DmarcRecord::parse(
                    format!("v=DMARC1; p=reject; rua=mailto:reports@{domain}").as_bytes(),
                )
                .unwrap(),
            ),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        })
        .await;
}

async fn schedule_tls(test: &TestServer, domain: &str) {
    test.server
        .schedule_report(TlsEvent {
            domain: domain.to_string(),
            policy: PolicyType::None,
            failure: None,
            tls_record: Arc::new(
                TlsRptRecord::parse(format!("v=TLSRPTv1;rua=mailto:reports@{domain}").as_bytes())
                    .unwrap(),
            ),
            interval: AggregateFrequency::Daily,
            span_id: 0,
        })
        .await;
}

trait ReportDomain: ObjectImpl {
    fn report_domain(&self) -> &str;
}

impl ReportDomain for DmarcInternalReport {
    fn report_domain(&self) -> &str {
        &self.domain
    }
}

impl ReportDomain for TlsInternalReport {
    fn report_domain(&self) -> &str {
        &self.domain
    }
}

async fn wait_for_report<T: ReportDomain>(test: &TestServer, domain: &str) -> Id {
    let admin = test.account("admin");
    for _ in 0..100 {
        // inbuxa: 1.0 creates the report when its window closes. The window
        // task may predate this report's rows, so close it until it shows
        close_report_window(&test.server, T::OBJECT, AggregateFrequency::Daily).await;
        if let Some((id, _)) = admin
            .registry_get_all::<T>()
            .await
            .into_iter()
            .find(|(_, report)| report.report_domain() == domain)
        {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("No {} for {domain}", T::OBJECT.as_str());
}

/// A task that succeeds when it runs, due at `due`.
async fn marker_task(server: &Server, due: u64) -> u64 {
    let id = SnowflakeIdGenerator::global_id().unwrap();
    let mut batch = BatchBuilder::new();
    batch.schedule_task_with_id(
        id,
        Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::RemoveLockDav,
            shard_index: Some(0),
            status: TaskStatus::at(due as i64),
        }),
    );
    server.store().write_batch(&mut batch).await.unwrap();
    server.notify_task_queue();
    id
}

/// A queue row for the report's task at `at`, a due the task doesn't have.
/// The value is what 0.16's reschedule wrote there (the report's object
/// type); 1.0 doesn't read it. Returns the task's own due.
async fn stale_queue_row(server: &Server, item_id: u64, at: u64) -> u64 {
    let object_id = ObjectType::DmarcInternalReport.to_id();
    let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
    let report = server
        .store()
        .get_value::<DmarcInternalReport>(ValueKey::from(key))
        .await
        .unwrap()
        .unwrap();
    let task_due = report.deliver_at().timestamp() as u64;
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(item_id),
            typ: TaskType::DmarcReport,
            due: at,
        }),
        object_id.serialize(),
    );
    server.store().write_batch(&mut batch).await.unwrap();
    server.notify_task_queue();
    task_due
}

struct RawValue(Vec<u8>);

impl store::Deserialize for RawValue {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawValue(bytes.to_vec()))
    }
}

async fn queue_row(server: &Server, id: u64, typ: TaskType, due: u64) -> Option<Vec<u8>> {
    server
        .store()
        .get_value::<RawValue>(ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(id),
            typ,
            due,
        })))
        .await
        .unwrap()
        .map(|raw| raw.0)
}

async fn task_exists(server: &Server, id: u64) -> bool {
    server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task {
                id: TaskId::Assigned(id),
            },
        )))
        .await
        .unwrap()
        .is_some()
}

async fn wait_until_gone(server: &Server, id: u64, typ: TaskType, due: u64) {
    let started = Instant::now();
    while queue_row(server, id, typ, due).await.is_some() {
        if started.elapsed() > Duration::from_secs(30) {
            panic!("{typ:?} queue row {id} at {due} never went (now {})", now());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_until_run(server: &Server, ids: &[u64]) {
    let started = Instant::now();
    loop {
        let mut pending = Vec::new();
        for id in ids {
            if task_exists(server, *id).await {
                pending.push(*id);
            }
        }
        if pending.is_empty() {
            return;
        }
        if started.elapsed() > Duration::from_secs(30) {
            let mut tasks = Vec::new();
            for id in &pending {
                tasks.push(
                    server
                        .store()
                        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                            TaskQueueClass::Task {
                                id: TaskId::Assigned(*id),
                            },
                        )))
                        .await
                        .unwrap(),
                );
            }
            panic!("tasks {pending:?} never ran: {tasks:?} (now {})", now());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
