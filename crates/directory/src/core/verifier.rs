/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::VecDeque,
    fmt::Display,
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread::available_parallelism,
};
use tokio::sync::oneshot;

const FALLBACK_WORKERS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(3);

#[derive(Clone)]
pub struct PasswordVerifier {
    pool: Arc<Pool>,
}

struct Pool {
    max_workers: usize,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    workers: usize,
    queue: VecDeque<Job>,
}

type Job = Box<dyn FnOnce() + Send>;

impl PasswordVerifier {
    pub fn new(max_workers: NonZeroUsize) -> Self {
        Self {
            pool: Arc::new(Pool {
                max_workers: max_workers.get(),
                state: Mutex::default(),
            }),
        }
    }

    pub(crate) async fn run_blocking<T: Send + 'static>(
        &self,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> trc::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.pool.submit(Box::new(move || {
            if !tx.is_closed() {
                let _ = tx.send(task());
            }
        }));
        rx.await.map_err(thread_error)
    }
}

impl Pool {
    fn submit(self: &Arc<Self>, job: Job) {
        let mut state = self.lock();
        if state.workers < self.max_workers {
            state.workers += 1;
            drop(state);
            let pool = self.clone();
            tokio::task::spawn_blocking(move || pool.work(job));
        } else {
            state.queue.push_back(job);
        }
    }

    fn work(&self, mut job: Job) {
        loop {
            let _ = catch_unwind(AssertUnwindSafe(job));
            let mut state = self.lock();
            match state.queue.pop_front() {
                Some(next) => job = next,
                None => {
                    state.workers -= 1;
                    return;
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for PasswordVerifier {
    fn default() -> Self {
        Self::new(available_parallelism().unwrap_or(FALLBACK_WORKERS))
    }
}

#[cold]
fn thread_error(err: impl Display) -> trc::Error {
    trc::EventType::Server(trc::ServerEvent::ThreadError)
        .caused_by(trc::location!())
        .reason(err)
}

