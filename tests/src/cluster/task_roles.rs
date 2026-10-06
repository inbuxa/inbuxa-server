/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Two task managers with different cluster roles over one shared store:
//! each runs only the task types its role allows, and a task one node may
//! not run is left for the node that may. Needs a store both nodes can open
//! (STORE=PostgreSql or MySql).

use crate::utils::server::TestServerBuilder;
use common::Server;
use registry::{
    schema::{
        enums::{ClusterTaskType, IndexDocumentType},
        structs::{
            ClusterListenerGroup, ClusterRole, ClusterTaskGroup, ClusterTaskGroupProperties, Task,
            TaskDnsManagement, TaskIndexDocument, TaskStatus, TaskTlsReport,
        },
    },
    types::map::Map,
};
use std::time::{Duration, Instant};
use store::{
    ValueKey,
    write::{BatchBuilder, TaskQueueClass, ValueClass},
};
use utils::snowflake::SnowflakeIdGenerator;

const QUEUE_ROLE: &str = "tasks_queue";
const INDEX_MTA_ROLE: &str = "tasks_index_mta";

#[tokio::test(flavor = "multi_thread")]
pub async fn task_role_tests() {
    if matches!(
        std::env::var("STORE").as_deref(),
        Ok("RocksDb" | "Sqlite") | Err(_)
    ) {
        println!("Skipping task role tests: they need a store both nodes can open.");
        return;
    }
    println!(
        "Running task role tests on {}...",
        std::env::var("STORE").unwrap_or_default()
    );

    // The roles, stored by a node that runs no services of its own (a node
    // looks its role up when it starts)
    let seed = TestServerBuilder::new("task_roles_seed")
        .await
        .with_object(role(QUEUE_ROLE, &[ClusterTaskType::TaskQueueProcessing]))
        .await
        .with_object(role(
            INDEX_MTA_ROLE,
            &[
                ClusterTaskType::SearchIndexing,
                ClusterTaskType::OutboundMta,
            ],
        ))
        .await
        .disable_services()
        .build()
        .await;

    // Node A runs queue tasks (taskQueueProcessing) only
    let node_a = TestServerBuilder::new_with_role(
        "task_roles_a",
        "node-a.example.com".into(),
        Some(QUEUE_ROLE.into()),
        false,
    )
    .await
    .build_with_opts(false)
    .await;
    let server_a = node_a.server.clone();
    let roles = &server_a.core.network.roles;
    assert!(roles.task_manager && !roles.search_indexing && !roles.outbound_mta);

    // A DNS task (taskQueueProcessing), an unindex task (searchIndexing) and
    // a TLS report (outboundMta), all due now
    let [dns, unindex, report] = new_task_ids();
    let mut batch = BatchBuilder::new();
    batch
        .schedule_task_with_id(
            dns,
            Task::DnsManagement(TaskDnsManagement {
                status: TaskStatus::now(),
                ..Default::default()
            }),
        )
        .schedule_task_with_id(
            unindex,
            Task::UnindexDocument(TaskIndexDocument {
                account_id: 0u32.into(),
                document_id: u32::MAX.into(),
                document_type: IndexDocumentType::File,
                status: TaskStatus::now(),
            }),
        )
        .schedule_task_with_id(
            report,
            Task::TlsReport(TaskTlsReport {
                report_id: u64::MAX.into(),
                status: TaskStatus::now(),
            }),
        );
    server_a.store().write(batch.build_all()).await.unwrap();
    server_a.notify_task_queue();

    // Node A runs the DNS task and leaves the other two alone. Upstream ran
    // the TLS report here too: report tasks ran on any node with a task
    // manager.
    wait_until_run(&server_a, &[dns], Duration::from_secs(20)).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    server_a.notify_task_queue();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        is_pending(&server_a, unindex).await,
        "unindex ran on node A"
    );
    assert!(
        is_pending(&server_a, report).await,
        "TLS report ran on node A"
    );

    // Node B (search indexing and outbound MTA) comes up and picks up what
    // node A left
    let node_b = TestServerBuilder::new_with_role(
        "task_roles_b",
        "node-b.example.com".into(),
        Some(INDEX_MTA_ROLE.into()),
        false,
    )
    .await
    .build_with_opts(false)
    .await;
    let server_b = node_b.server.clone();
    let roles = &server_b.core.network.roles;
    assert!(!roles.task_manager && roles.search_indexing && roles.outbound_mta);
    server_b.notify_task_queue();
    wait_until_run(&server_b, &[unindex, report], Duration::from_secs(20)).await;

    // A queue task scheduled now still runs, on node A: node B may not
    // claim it
    let [dns] = new_task_ids();
    let mut batch = BatchBuilder::new();
    batch.schedule_task_with_id(
        dns,
        Task::DnsManagement(TaskDnsManagement {
            status: TaskStatus::now(),
            ..Default::default()
        }),
    );
    server_b.store().write(batch.build_all()).await.unwrap();
    server_b.notify_task_queue();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(is_pending(&server_b, dns).await, "DNS task ran on node B");
    server_a.notify_task_queue();
    wait_until_run(&server_a, &[dns], Duration::from_secs(20)).await;

    if seed.is_reset() {
        seed.temp_dir.delete();
        node_a.temp_dir.delete();
        node_b.temp_dir.delete();
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

fn new_task_ids<const N: usize>() -> [u64; N] {
    std::array::from_fn(|_| SnowflakeIdGenerator::global_id().unwrap())
}

/// Still due and never run: present, and pending.
async fn is_pending(server: &Server, id: u64) -> bool {
    matches!(
        server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id },
            )))
            .await
            .unwrap()
            .map(|task| task.status().clone()),
        Some(TaskStatus::Pending(_))
    )
}

async fn wait_until_run(server: &Server, ids: &[u64], within: Duration) {
    let started = Instant::now();
    loop {
        let mut left = 0;
        for id in ids {
            if is_pending(server, *id).await {
                left += 1;
            }
        }
        if left == 0 {
            return;
        }
        assert!(
            started.elapsed() < within,
            "{left} task(s) still pending after {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
