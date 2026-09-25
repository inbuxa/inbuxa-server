/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A node follows edits to its cluster role without a restart: outbound
//! delivery and report tasks start when the role gains outboundMta and stop
//! when it loses it. Upstream decided at boot whether the queue, report and
//! task managers ran at all. Needs a store the seed and the node can share
//! (STORE=PostgreSql or MySql).

use crate::utils::server::{TestServer, TestServerBuilder};
use common::Server;
use registry::{
    schema::{
        enums::ClusterTaskType,
        prelude::{Object, ObjectType},
        structs::{
            ClusterListenerGroup, ClusterRole, ClusterTaskGroup, ClusterTaskGroupProperties, Task,
            TaskStatus, TaskTlsReport,
        },
    },
    types::{id::ObjectId, map::Map},
};
use smtp::{
    queue::{Message, Status},
    reporting::send::MtaReportSend,
};
use std::time::{Duration, Instant};
use store::{
    Deserialize, IterateParams, ValueKey,
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::{AlignedBytes, Archive, BatchBuilder, QueueClass, TaskQueueClass, ValueClass},
};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

const BUSY_ROLE: &str = "live_role_busy";
const IDLE_ROLE: &str = "live_role_idle";
const WITH: &[ClusterTaskType] = &[
    ClusterTaskType::PushNotifications,
    ClusterTaskType::OutboundMta,
];
const WITHOUT: &[ClusterTaskType] = &[ClusterTaskType::PushNotifications];
const RCPT_DOMAIN: &str = "live-role.invalid";

#[tokio::test(flavor = "multi_thread")]
pub async fn live_role_tests() {
    if matches!(
        std::env::var("STORE").as_deref(),
        Ok("RocksDb" | "Sqlite") | Err(_)
    ) {
        println!("Skipping live role tests: they need a store the nodes can share.");
        return;
    }
    println!(
        "Running live role tests on {}...",
        std::env::var("STORE").unwrap_or_default()
    );

    // Two roles: one with outboundMta, one with no task type at all
    let seed = TestServerBuilder::new("live_roles_seed").await;
    let busy_id = seed.insert_object(role(BUSY_ROLE, WITH)).await;
    let idle_id = seed.insert_object(role(IDLE_ROLE, WITHOUT)).await;
    let seed = seed.disable_services().build().await;
    let registry = seed.server.clone();

    // 1. The rehearsal case: a node started with outboundMta has it taken
    // away. Upstream kept delivering, report messages included, until a
    // restart.
    let node = start_node("live_roles_busy", BUSY_ROLE).await;
    let server = node.server.clone();
    assert!(server.core.network.roles.outbound_mta);
    let (msg, task) = queue_work(&server, "busy-before").await;
    assert_runs(&server, &msg, task).await;

    set_role(&registry, &server, busy_id, role(BUSY_ROLE, WITHOUT)).await;
    let (msg, task) = queue_work(&server, "busy-off").await;
    assert_idle(&server, &msg, task).await;

    // Given back, it takes up the work left waiting
    set_role(&registry, &server, busy_id, role(BUSY_ROLE, WITH)).await;
    assert_runs(&server, &msg, task).await;

    // Off again, so it leaves the next node's work alone
    set_role(&registry, &server, busy_id, role(BUSY_ROLE, WITHOUT)).await;

    // 2. A node started with no task type at all gains outboundMta.
    // Upstream never started its queue, report or task manager, so the
    // role did nothing until a restart.
    let node2 = start_node("live_roles_idle", IDLE_ROLE).await;
    let server2 = node2.server.clone();
    assert!(!server2.core.network.roles.outbound_mta);
    let (msg, task) = queue_work(&server2, "idle-off").await;
    assert_idle(&server2, &msg, task).await;
    set_role(&registry, &server2, idle_id, role(IDLE_ROLE, WITH)).await;
    assert_runs(&server2, &msg, task).await;
    set_role(&registry, &server2, idle_id, role(IDLE_ROLE, WITHOUT)).await;

    if seed.is_reset() {
        seed.temp_dir.delete();
        node.temp_dir.delete();
        node2.temp_dir.delete();
    }
}

async fn start_node(name: &str, role: &str) -> TestServer {
    TestServerBuilder::new_with_role(
        name,
        format!("{name}.example.com").replace('_', "-"),
        Some(role.into()),
        false,
    )
    .await
    .build_with_opts(false)
    .await
}

/// Neither the message nor the report task is touched.
async fn assert_idle(server: &Server, msg: &str, task: u64) {
    tokio::time::sleep(Duration::from_secs(4)).await;
    server.notify_task_queue();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !attempted(server, msg).await,
        "delivery attempted without outboundMta"
    );
    assert!(
        is_pending(server, task).await,
        "report task claimed without outboundMta"
    );
}

/// Delivery of the message is attempted and the report task runs.
async fn assert_runs(server: &Server, msg: &str, task: u64) {
    wait_for(Duration::from_secs(20), "message delivery attempt", || {
        attempted(server, msg)
    })
    .await;
    wait_for(Duration::from_secs(20), "report task to run", || async {
        !is_pending(server, task).await
    })
    .await;
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

/// Stores a new version of a role and reloads the node's settings, as a
/// JMAP write to the role does.
async fn set_role(registry: &Server, node: &Server, id: Id, new: ClusterRole) {
    let enabled = matches!(&new.tasks, ClusterTaskGroup::EnableSome(group)
        if group.task_types.iter().any(|t| *t == ClusterTaskType::OutboundMta));
    let old = registry
        .registry()
        .get(ObjectId::new(ObjectType::ClusterRole, id))
        .await
        .unwrap()
        .expect("role not found");
    let new = Object::from(new);
    let result = registry
        .registry()
        .write(RegistryWrite::update(id, &new, &old))
        .await
        .unwrap();
    assert!(
        matches!(result, RegistryWriteResult::Success(_)),
        "role update refused"
    );
    assert_eq!(
        node.reload_after_write(ObjectType::ClusterRole).await,
        Some(Ok(()))
    );
    assert_eq!(
        node.inner.shared_core.load().network.roles.outbound_mta,
        enabled
    );
}

/// Queues a message to an unreachable domain and schedules a TLS report
/// task, both due now. Returns the recipient's local part and the task id.
async fn queue_work(server: &Server, name: &str) -> (String, u64) {
    let local = format!("{name}-{}", SnowflakeIdGenerator::global_id().unwrap());
    let rcpt = format!("{local}@{RCPT_DOMAIN}");
    server
        .send_autogenerated(
            "postmaster@example.com",
            [rcpt.as_str()].into_iter(),
            format!(
                "From: postmaster@example.com\r\nTo: {rcpt}\r\n\
                 Subject: live role test\r\n\r\nTest\r\n"
            )
            .into_bytes(),
            None,
            0,
        )
        .await;
    assert!(
        queued_recipient(server, &rcpt).await.is_some(),
        "message to {rcpt} was not queued"
    );

    let task = SnowflakeIdGenerator::global_id().unwrap();
    let mut batch = BatchBuilder::new();
    batch.schedule_task_with_id(
        task,
        Task::TlsReport(TaskTlsReport {
            report_id: u64::MAX.into(),
            status: TaskStatus::now(),
        }),
    );
    server.store().write(batch.build_all()).await.unwrap();
    server.notify_task_queue();

    (rcpt, task)
}

/// Whether delivery to `rcpt` was tried: the message is gone, or its
/// recipient is no longer scheduled or has a retry count.
async fn attempted(server: &Server, rcpt: &str) -> bool {
    match queued_recipient(server, rcpt).await {
        None => true,
        Some((status_scheduled, retries)) => !status_scheduled || retries > 0,
    }
}

/// The queued recipient `rcpt`: whether it is still scheduled, and how many
/// times delivery was retried.
async fn queued_recipient(server: &Server, rcpt: &str) -> Option<(bool, u32)> {
    let mut found = None;
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Queue(QueueClass::Message(0))),
                ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX))),
            ),
            |_, value| {
                let message = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?
                    .deserialize::<Message>()?;
                if let Some(recipient) = message
                    .recipients
                    .iter()
                    .find(|recipient| recipient.address.as_ref() == rcpt)
                {
                    found = Some((
                        matches!(recipient.status, Status::Scheduled),
                        recipient.retry.inner,
                    ));
                    return Ok(false);
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    found
}

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
