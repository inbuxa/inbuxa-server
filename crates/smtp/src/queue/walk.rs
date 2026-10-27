/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    IterateParams, Store, ValueKey,
    write::{QueueClass, QueueEvent, ValueClass},
};
use trc::AddContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkStep {
    Continue,
    NextQueue,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueWalk {
    pub due_from: u64,
    pub due_to: u64,
    pub ascending: bool,
    pub read_limit: usize,
}

impl QueueWalk {
    pub fn ascending(read_limit: usize) -> Self {
        QueueWalk {
            due_from: 0,
            due_to: u64::MAX,
            ascending: true,
            read_limit,
        }
    }

    fn start(&self) -> QueueEvent {
        self.queue_start(if self.ascending {
            [0; 8]
        } else {
            QueueEvent::LAST_QUEUE
        })
    }

    fn end(&self) -> QueueEvent {
        if self.ascending {
            event(QueueEvent::LAST_QUEUE, u64::MAX, u64::MAX)
        } else {
            event([0; 8], 0, 0)
        }
    }

    fn queue_start(&self, queue_name: [u8; 8]) -> QueueEvent {
        if self.ascending {
            event(queue_name, self.due_from, 0)
        } else {
            event(queue_name, self.due_to, u64::MAX)
        }
    }

    fn next_queue(&self, queue_name: [u8; 8]) -> Option<QueueEvent> {
        let queue_name = u64::from_be_bytes(queue_name);
        if self.ascending {
            queue_name
                .checked_add(1)
                .filter(|&next| next <= u64::from_be_bytes(QueueEvent::LAST_QUEUE))
        } else {
            queue_name.checked_sub(1)
        }
        .map(|queue_name| self.queue_start(queue_name.to_be_bytes()))
    }

    fn outside_window(&self, current: &QueueEvent) -> Option<Option<QueueEvent>> {
        let is_before = if self.ascending {
            current.due < self.due_from
        } else {
            current.due > self.due_to
        };
        if is_before {
            Some(Some(self.queue_start(current.queue_name)))
        } else if (self.due_from..=self.due_to).contains(&current.due) {
            None
        } else {
            Some(self.next_queue(current.queue_name))
        }
    }

    fn after(&self, current: &QueueEvent) -> Option<QueueEvent> {
        if self.ascending {
            match current.queue_id.checked_add(1) {
                Some(queue_id) => Some(event(current.queue_name, current.due, queue_id)),
                None => current
                    .due
                    .checked_add(1)
                    .map(|due| event(current.queue_name, due, 0)),
            }
        } else {
            match current.queue_id.checked_sub(1) {
                Some(queue_id) => Some(event(current.queue_name, current.due, queue_id)),
                None => current
                    .due
                    .checked_sub(1)
                    .map(|due| event(current.queue_name, due, u64::MAX)),
            }
        }
        .or_else(|| self.next_queue(current.queue_name))
    }
}

pub async fn walk_queues(
    store: &Store,
    walk: QueueWalk,
    mut visit: impl FnMut(&QueueEvent) -> WalkStep + Sync + Send,
) -> trc::Result<()> {
    let mut bound = Some(walk.start());
    while let Some(position) = bound.take() {
        let (from, to) = if walk.ascending {
            (position, walk.end())
        } else {
            (walk.end(), position)
        };
        let mut rows = 0;
        let mut last = None;
        let mut next = None;
        let mut is_stopped = false;
        store
            .iterate(
                IterateParams::new(key(from), key(to))
                    .set_ascending(walk.ascending)
                    .no_values()
                    .limit(walk.read_limit),
                |key, _| {
                    let current = QueueEvent::deserialize(key)?;
                    rows += 1;
                    if let Some(skip) = walk.outside_window(&current) {
                        next = Some(skip);
                        return Ok(false);
                    }
                    match visit(&current) {
                        WalkStep::Continue => {
                            last = Some(current);
                            Ok(true)
                        }
                        WalkStep::NextQueue => {
                            next = Some(walk.next_queue(current.queue_name));
                            Ok(false)
                        }
                        WalkStep::Stop => {
                            is_stopped = true;
                            Ok(false)
                        }
                    }
                },
            )
            .await
            .caused_by(trc::location!())?;

        if is_stopped {
            break;
        }
        bound = match next {
            Some(next) => next,
            None if rows >= walk.read_limit => last.and_then(|last| walk.after(&last)),
            None => None,
        };
    }

    Ok(())
}

fn event(queue_name: [u8; 8], due: u64, queue_id: u64) -> QueueEvent {
    QueueEvent {
        due,
        queue_id,
        queue_name,
    }
}

fn key(event: QueueEvent) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(event)))
}

