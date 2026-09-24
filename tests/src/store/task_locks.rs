/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Task locks across nodes: tasks claimed by a node that then disappears
//! run elsewhere once its locks expire, and a node that stops gracefully
//! hands its locks back at once. The other node is played by writing its
//! locks straight into the shared in-memory store, as a node that claimed
//! the tasks and died leaves them.

use crate::utils::server::TestServerBuilder;
use common::{KV_LOCK_TASK, Server};
use registry::schema::{
    enums::IndexDocumentType,
    structs::{Task, TaskIndexDocument, TaskStatus},
};
use services::task_manager::lock::{TaskLockManager, release_task_locks};
use std::time::{Duration, Instant};
use store::{
    ValueKey,
    write::{BatchBuilder, TaskQueueClass, ValueClass},
};
use utils::snowflake::SnowflakeIdGenerator;

// Short enough for a test, long enough that the recheck interval (a twelfth
// of it) is well below it
const LOCK_EXPIRY: u64 = 12;

#[tokio::test(flavor = "multi_thread")]
pub async fn task_lock_tests() {
    let test = TestServerBuilder::new("task_lock_tests")
        .await
        .build()
        .await;
    let server = test.server.clone();
    println!(
        "Running task lock tests on {}...",
        std::env::var("STORE").unwrap_or_default()
    );
    server.inner.ipc.task_locks.set_expiry(LOCK_EXPIRY);

    // 1. Another node claimed the tasks and died. Its locks block them until
    // they expire; then this node runs them, without waiting for anything
    // else to wake it
    let ids = new_task_ids(4);
    for id in &ids {
        assert!(foreign_lock(&server, *id, LOCK_EXPIRY).await);
    }
    schedule(&server, &ids).await;
    let started = Instant::now();
    server.notify_task_queue();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(pending(&server, &ids).await, ids.len(), "held by the other node");
    wait_until_done(&server, &ids, Duration::from_secs(LOCK_EXPIRY + 10)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(LOCK_EXPIRY - 2),
        "ran before the other node's locks expired: {elapsed:?}"
    );

    // 2. The other node's locks outlive what this node expects: claimed just
    // after this node looked, or by a node whose clock runs ahead. This node
    // keeps checking at the recheck interval, so the tasks run soon after
    // those locks expire, not a whole lock lifetime later
    let held_for = LOCK_EXPIRY + LOCK_EXPIRY / 2;
    let ids = new_task_ids(4);
    for id in &ids {
        assert!(foreign_lock(&server, *id, held_for).await);
    }
    schedule(&server, &ids).await;
    let started = Instant::now();
    server.notify_task_queue();
    wait_until_done(&server, &ids, Duration::from_secs(held_for + 8)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(held_for - 2),
        "ran before the other node's locks expired: {elapsed:?}"
    );

    // 3. A graceful stop releases the locks this node holds: another node
    // can claim those tasks at once, and this one claims nothing more
    let ids = new_task_ids(3);
    for id in &ids {
        assert!(server.try_lock_task(*id).await, "claim {id}");
    }
    assert_eq!(server.inner.ipc.task_locks.held(), ids.len());
    for id in &ids {
        assert!(
            !foreign_lock(&server, *id, LOCK_EXPIRY).await,
            "held while this node runs"
        );
    }
    assert_eq!(release_task_locks(&server).await, ids.len());
    assert_eq!(server.inner.ipc.task_locks.held(), 0);
    for id in &ids {
        assert!(
            foreign_lock(&server, *id, LOCK_EXPIRY).await,
            "released on stop: {id}"
        );
    }
    let [id] = new_task_ids(1)[..] else {
        unreachable!()
    };
    assert!(!server.try_lock_task(id).await, "a stopping node claims nothing");

    for id in ids {
        let _ = server
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &id.to_be_bytes())
            .await;
    }
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

fn new_task_ids(count: usize) -> Vec<u64> {
    (0..count)
        .map(|_| SnowflakeIdGenerator::global_id().unwrap())
        .collect()
}

/// The other node's claim on a task, as its task manager takes it.
async fn foreign_lock(server: &Server, id: u64, seconds: u64) -> bool {
    server
        .in_memory_store()
        .try_lock(KV_LOCK_TASK, &id.to_be_bytes(), seconds)
        .await
        .unwrap()
}

/// Unindex tasks for files that don't exist: files aren't search-indexed and
/// there is no undelete note, so running one only drops it from the queue.
async fn schedule(server: &Server, ids: &[u64]) {
    let mut batch = BatchBuilder::new();
    for (n, id) in ids.iter().enumerate() {
        batch.schedule_task_with_id(
            *id,
            Task::UnindexDocument(TaskIndexDocument {
                account_id: 0u32.into(),
                document_id: (u32::MAX - n as u32).into(),
                document_type: IndexDocumentType::File,
                status: TaskStatus::now(),
            }),
        );
    }
    server.store().write(batch.build_all()).await.unwrap();
}

async fn pending(server: &Server, ids: &[u64]) -> usize {
    let mut count = 0;
    for id in ids {
        if server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id: *id },
            )))
            .await
            .unwrap()
            .is_some()
        {
            count += 1;
        }
    }
    count
}

async fn wait_until_done(server: &Server, ids: &[u64], within: Duration) {
    let started = Instant::now();
    loop {
        let left = pending(server, ids).await;
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
