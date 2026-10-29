/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: bounds how many operations one IMAP session runs at once and
//! keeps commands that change state in order (RFC 9051, section 5.5). A
//! read takes one permit and a write takes all of them, so a write starts
//! once every earlier operation has finished and later ones wait for it.
//! The session loop waits for its permit before it starts the operation
//! and reads no more commands meanwhile.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Operations one session may run at the same time.
pub const MAX_CONCURRENT_OPS: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// Leaves the account and the session as they were
    Read,
    /// Changes the account or the session, so runs on its own
    Write,
}

pub type OpPermit = OwnedSemaphorePermit;

#[derive(Clone)]
pub struct OpGate(Arc<Semaphore>);

impl OpGate {
    pub fn new() -> Self {
        OpGate(Arc::new(Semaphore::new(MAX_CONCURRENT_OPS as usize)))
    }

    /// Waits until an operation of this kind may start. Permits are handed
    /// out in the order they were asked for.
    pub async fn acquire(&self, kind: OpKind) -> OpPermit {
        let permits = match kind {
            OpKind::Read => 1,
            OpKind::Write => MAX_CONCURRENT_OPS,
        };
        self.0
            .clone()
            .acquire_many_owned(permits)
            .await
            .expect("the operation gate is never closed")
    }
}

impl Default for OpGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CONCURRENT_OPS, OpGate, OpKind};
    use parking_lot::Mutex;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    // A permit that can't be had now: nothing else here frees one, so the
    // timeout always expires
    async fn is_blocked(gate: &OpGate, kind: OpKind) -> bool {
        tokio::time::timeout(Duration::from_millis(50), gate.acquire(kind))
            .await
            .is_err()
    }

    #[tokio::test]
    async fn reads_are_bounded() {
        let gate = OpGate::new();
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_OPS {
            held.push(gate.acquire(OpKind::Read).await);
        }
        assert!(is_blocked(&gate, OpKind::Read).await);
        held.pop();
        held.push(gate.acquire(OpKind::Read).await);
    }

    #[tokio::test]
    async fn write_waits_for_reads_and_reads_wait_for_write() {
        let gate = OpGate::new();
        let read = gate.acquire(OpKind::Read).await;
        assert!(is_blocked(&gate, OpKind::Write).await);
        drop(read);

        let write = gate.acquire(OpKind::Write).await;
        assert!(is_blocked(&gate, OpKind::Read).await);
        assert!(is_blocked(&gate, OpKind::Write).await);
        drop(write);
        gate.acquire(OpKind::Read).await;
    }

    // Drives the gate the way the session loop does: permits are taken in
    // command order, then each operation runs in its own task
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelined_operations_keep_order() {
        use OpKind::{Read, Write};
        let commands = [
            Read, Read, Read, Read, Read, Read, Write, Read, Read, Write, Write, Read, Read, Read,
            Read, Read, Read, Read, Write, Read,
        ];
        let gate = OpGate::new();
        let running = Arc::new(AtomicUsize::new(0));
        let most_running = Arc::new(AtomicUsize::new(0));
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();

        for (id, kind) in commands.into_iter().enumerate() {
            let permit = gate.acquire(kind).await;
            let running = running.clone();
            let most_running = most_running.clone();
            let log = log.clone();
            tasks.push(tokio::spawn(async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most_running.fetch_max(now, Ordering::SeqCst);
                log.lock().push((id, true));
                tokio::time::sleep(Duration::from_millis(5)).await;
                log.lock().push((id, false));
                running.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        assert!(most_running.load(Ordering::SeqCst) <= MAX_CONCURRENT_OPS as usize);
        let log = log.lock();
        let position = |id: usize, start: bool| log.iter().position(|e| *e == (id, start)).unwrap();
        for (write, kind) in commands.iter().enumerate() {
            if *kind != Write {
                continue;
            }
            for other in 0..commands.len() {
                if other < write {
                    assert!(
                        position(other, false) < position(write, true),
                        "write {write} started before {other} finished"
                    );
                } else if other > write {
                    assert!(
                        position(write, false) < position(other, true),
                        "{other} started before write {write} finished"
                    );
                }
            }
        }
    }
}
