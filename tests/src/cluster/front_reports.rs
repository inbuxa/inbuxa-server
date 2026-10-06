/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! DMARC results recorded on a node without outboundMta reach the aggregate
//! report, which a node with outboundMta builds and sends. Before, a front
//! node's results were dropped (or, before live roles, left in a channel
//! nobody read), so the report covered only the mail the outbound nodes
//! received. Also checks that nodes appending to one report at once lose
//! nothing. Needs a store the nodes can share (STORE=PostgreSql or MySql).

use crate::{smtp::inbound::TestMessage, utils::server::TestServerBuilder};
use common::{Server, config::smtp::report::AggregateFrequency, ipc::DmarcEvent};
use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::Dmarc,
    report::{ActionDisposition, DmarcResult, Record, Report},
};
use registry::{
    schema::{
        enums::ClusterTaskType,
        prelude::{ObjectType, Property},
        structs::{
            ClusterListenerGroup, ClusterRole, ClusterTaskGroup, ClusterTaskGroupProperties,
            DmarcInternalReport, DmarcReportSettings, Expression, Task, TaskDmarcReport,
            TaskStatus,
        },
    },
    types::{EnumImpl, map::Map},
};
use smtp::reporting::{dmarc::DmarcReporting, send::MtaReportSend};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    registry::{RegistryFilter, RegistryFilterValue, RegistryQuery},
    write::{BatchBuilder, RegistryClass, TaskQueueClass, ValueClass, now},
};
use types::id::Id;

const FRONT_ROLE: &str = "front_reports_front";
const MTA_ROLE: &str = "front_reports_mta";
const DOMAIN: &str = "front-reports.example";

#[tokio::test(flavor = "multi_thread")]
pub async fn front_node_report_tests() {
    if matches!(
        std::env::var("STORE").as_deref(),
        Ok("RocksDb" | "Sqlite") | Err(_)
    ) {
        println!("Skipping front node report tests: they need a store the nodes can share.");
        return;
    }
    println!(
        "Running front node report tests on {}...",
        std::env::var("STORE").unwrap_or_default()
    );

    // A front role without outboundMta, an MTA role with it
    let seed = TestServerBuilder::new("front_reports_seed").await;
    seed.insert_object(role(FRONT_ROLE, &[ClusterTaskType::PushNotifications]))
        .await;
    seed.insert_object(role(MTA_ROLE, &[ClusterTaskType::OutboundMta]))
        .await;
    seed.insert_object(DmarcReportSettings {
        aggregate_max_report_size: Expression {
            else_: "1048576".into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let seed = seed.disable_services().build().await;

    // The front node receives mail from two sources: the events its SMTP
    // sessions hand the report scheduler
    let front = TestServerBuilder::new_with_role(
        "front_reports_front",
        "front.front-reports.example".into(),
        Some(FRONT_ROLE.into()),
        false,
    )
    .await
    .build_with_opts(false)
    .await;
    let front_server = front.server.clone();
    assert!(!front_server.core.network.roles.outbound_mta);
    for ip in ["192.0.2.1", "192.0.2.2"] {
        front_server.schedule_report(event(ip)).await;
    }

    // Both are recorded in the shared report. Upstream, and main after live
    // roles, left the front node's results out
    let report_id = wait_for_report(&front_server, 2).await;

    // Make the report due now. The front node leaves it alone: building and
    // sending it is the outbound MTA's
    move_task(&front_server, report_id, TaskStatus::now()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    front_server.notify_task_queue();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        task_exists(&front_server, report_id).await,
        "the front node ran the report task"
    );

    // Several writers append to the report at once, from both nodes: none
    // of their records is lost. The report waits in the future meanwhile, or
    // the MTA node would send it as soon as it starts
    move_task(
        &front_server,
        report_id,
        TaskStatus::at(now() as i64 + 3600),
    )
    .await;
    let mut mta = TestServerBuilder::new_with_role(
        "front_reports_mta",
        "mta.front-reports.example".into(),
        Some(MTA_ROLE.into()),
        false,
    )
    .await
    .capture_queue()
    .build_with_opts(false)
    .await;
    let mta_server = mta.server.clone();
    assert!(mta_server.core.network.roles.outbound_mta);

    let concurrent: Vec<String> = (10..18).map(|n| format!("192.0.2.{n}")).collect();
    let mut handles = Vec::new();
    for (n, ip) in concurrent.iter().enumerate() {
        let server = if n % 2 == 0 {
            front_server.clone()
        } else {
            mta_server.clone()
        };
        let ip = ip.clone();
        handles.push(tokio::spawn(async move {
            server.schedule_dmarc(Box::new(event(&ip))).await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    // Due again, the MTA node sends the report with every record in it
    move_task(&mta_server, report_id, TaskStatus::now()).await;
    let message = mta.expect_message().await;
    let report =
        Report::parse_rfc5322(message.read_message(&mta).await.as_bytes(), usize::MAX).unwrap();
    assert_eq!(report.domain(), DOMAIN);
    let sent: BTreeSet<IpAddr> = report
        .records()
        .iter()
        .map(|r| r.source_ip().unwrap())
        .collect();
    let expected: BTreeSet<IpAddr> = ["192.0.2.1", "192.0.2.2"]
        .into_iter()
        .map(String::from)
        .chain(concurrent)
        .map(|ip| ip.parse().unwrap())
        .collect();
    assert_eq!(sent, expected);
    wait_for(Duration::from_secs(20), "report task to finish", || async {
        !task_exists(&mta_server, report_id).await
    })
    .await;
    assert!(reports(&mta_server).await.is_empty());

    if seed.is_reset() {
        seed.temp_dir.delete();
        front.temp_dir.delete();
        mta.temp_dir.delete();
    }
}

fn role(name: &str, tasks: &[ClusterTaskType]) -> ClusterRole {
    ClusterRole {
        name: name.into(),
        description: None,
        listeners: ClusterListenerGroup::EnableAll,
        tasks: ClusterTaskGroup::EnableSome(ClusterTaskGroupProperties {
            task_types: Map::new(tasks.to_vec()),
        }),
    }
}

fn event(ip: &str) -> DmarcEvent {
    DmarcEvent {
        domain: DOMAIN.to_string(),
        report_record: Record::new()
            .with_source_ip(ip.parse().unwrap())
            .with_action_disposition(ActionDisposition::Pass)
            .with_dmarc_dkim_result(DmarcResult::Pass)
            .with_dmarc_spf_result(DmarcResult::Pass)
            .with_envelope_from("sender.example")
            .with_header_from("sender.example"),
        dmarc_record: Arc::new(
            Dmarc::parse(format!("v=DMARC1; p=reject; rua=mailto:reports@{DOMAIN}").as_bytes())
                .unwrap(),
        ),
        interval: AggregateFrequency::Daily,
        span_id: 0,
    }
}

async fn reports(server: &Server) -> Vec<(u64, DmarcInternalReport)> {
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::DmarcInternalReport).filter(
            RegistryFilter::greater_than(
                Property::Domain,
                RegistryFilterValue::Bytes(vec![]),
                true,
            ),
        ))
        .await
        .unwrap();
    let mut reports = Vec::new();
    for id in ids {
        if let Some(report) = server
            .store()
            .get_value::<DmarcInternalReport>(ValueKey::from(ValueClass::Registry(
                RegistryClass::Item {
                    object_id: ObjectType::DmarcInternalReport.to_id(),
                    item_id: id.id(),
                },
            )))
            .await
            .unwrap()
        {
            reports.push((id.id(), report));
        }
    }
    reports
}

/// Waits for the report for `DOMAIN` to hold `records` records; returns its id.
async fn wait_for_report(server: &Server, records: usize) -> u64 {
    let started = Instant::now();
    loop {
        let found = reports(server)
            .await
            .into_iter()
            .find(|(_, report)| report.domain == DOMAIN);
        if let Some((id, report)) = &found
            && report.report.records.len() == records
        {
            return *id;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no report with {records} records for {DOMAIN}: {found:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reschedules the report's task.
async fn move_task(server: &Server, id: u64, status: TaskStatus) {
    let task = server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task { id },
        )))
        .await
        .unwrap()
        .expect("report task missing");
    let mut batch = BatchBuilder::new();
    batch
        .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            due: task.due_timestamp(),
        }))
        .schedule_task_with_id(
            id,
            Task::DmarcReport(TaskDmarcReport {
                report_id: id.into(),
                status,
            }),
        );
    server.store().write(batch.build_all()).await.unwrap();
    server.notify_task_queue();
}

async fn task_exists(server: &Server, id: u64) -> bool {
    server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task { id },
        )))
        .await
        .unwrap()
        .is_some()
}

async fn wait_for<F, Fut>(within: Duration, what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let started = Instant::now();
    while !check().await {
        assert!(
            started.elapsed() < within,
            "still waiting for the {what} after {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
