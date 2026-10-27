/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    iter::once,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

const PRIMARY_RETRY_AFTER_MS: u64 = 60_000;

pub(crate) struct LdapServers {
    urls: Box<[String]>,
    failover: AtomicBool,
    active: AtomicUsize,
    last_failure: AtomicU64,
    retry_primary_after: u64,
    epoch: Instant,
}

impl LdapServers {
    pub fn new(urls: Box<[String]>) -> Self {
        Self {
            failover: AtomicBool::new(urls.len() > 1),
            urls,
            active: AtomicUsize::new(0),
            last_failure: AtomicU64::new(0),
            retry_primary_after: PRIMARY_RETRY_AFTER_MS,
            epoch: Instant::now(),
        }
    }

    pub fn server_count(&self) -> usize {
        self.urls.len()
    }

    pub fn primary(&self) -> &str {
        self.urls.first().map_or("", String::as_str)
    }

    pub fn has_failover(&self) -> bool {
        self.failover.load(Ordering::Relaxed)
    }

    pub fn disable_failover(&self) {
        self.failover.store(false, Ordering::Relaxed);
        self.active.store(0, Ordering::Relaxed);
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn start(&self) -> usize {
        if self.has_failover() {
            self.active()
        } else {
            0
        }
    }

    pub fn connect_order(&self, start: usize) -> impl Iterator<Item = (usize, &str)> {
        let count = if self.has_failover() {
            self.urls.len()
        } else {
            1
        };

        once(start)
            .chain((0..self.urls.len()).filter(move |&server| server != start))
            .take(count)
            .filter_map(|server| self.urls.get(server).map(|url| (server, url.as_str())))
    }

    pub fn connected(&self, start: usize, server: usize) {
        if server != start
            && self
                .active
                .compare_exchange(start, server, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            if server != 0 {
                self.last_failure.store(self.now(), Ordering::Relaxed);
            }
            self.log_switch(server);
        }
    }

    pub fn primary_recovered(&self) {
        if self.has_failover() && self.active.swap(0, Ordering::Relaxed) != 0 {
            self.log_switch(0);
        }
    }

    pub fn claim_primary_probe(&self) -> bool {
        if self.active() == 0 || !self.has_failover() {
            return false;
        }
        let last_failure = self.last_failure.load(Ordering::Relaxed);
        let now = self.now();
        now.saturating_sub(last_failure) >= self.retry_primary_after
            && self
                .last_failure
                .compare_exchange(last_failure, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    fn log_switch(&self, server: usize) {
        trc::event!(
            Store(trc::StoreEvent::LdapWarning),
            Reason = "Switched active LDAP server",
            Url = self.urls.get(server).cloned().unwrap_or_default()
        );
    }

    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

