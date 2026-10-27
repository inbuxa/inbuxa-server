/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::StoredTask;
use common::Server;
use registry::schema::structs::{Task, TaskStatus};
use store::{
    ValueKey,
    write::{BatchBuilder, TaskId, TaskQueueClass, ValueClass, assert::AssertValue},
};
use trc::AddContext;

pub(crate) async fn insert_task_if_absent(server: &Server, task: Task) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    if let Some(id) = TaskId::singleton_of(&task) {
        let key = ValueClass::TaskQueue(TaskQueueClass::Task {
            id: TaskId::Assigned(id),
        });
        let current = match server
            .store()
            .get_value::<StoredTask>(ValueKey::from(key.clone()))
            .await
            .caused_by(trc::location!())?
        {
            Some(stored) if matches!(stored.task.status(), TaskStatus::Failed(_)) => {
                AssertValue::Hash(stored.hash)
            }
            Some(_) => return Ok(()),
            None => AssertValue::None,
        };
        batch.assert_value(key, current);
    }

    batch.schedule_task(task);
    let queues = batch.queue_notify();
    match server.store().write_batch(&mut batch).await {
        Ok(_) => {
            server.notify_queues(queues).await;
            Ok(())
        }
        Err(err) if err.is_assertion_failure() => Ok(()),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

pub async fn schedule_replacing(
    server: &Server,
    batch: &mut BatchBuilder,
    task: Task,
) -> trc::Result<()> {
    if let Some(id) = TaskId::singleton_of(&task)
        && let Some(current) = server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(id),
                },
            )))
            .await
            .caused_by(trc::location!())?
    {
        let due = current.due_timestamp();
        if due != task.due_timestamp() {
            batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                id: TaskId::Assigned(id),
                typ: current.object_type(),
                due,
            }));
        }
    }

    batch.schedule_task(task);
    Ok(())
}
