/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What the link and the SMTP door share.

use crate::{
    events::Events,
    outbound::Outbox,
    recipients::Recipients,
    spool::Spool,
    state::{self, Identity, Paths},
};
use inbuxa_relay_proto::{
    allow::AllowList,
    time,
    types::{Mode, RelaySettings, RelayStatus, SpoolStatus, type_name},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
};
use tokio::sync::{Notify, broadcast, watch};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A data type's new state, for push.
#[derive(Debug, Clone)]
pub struct Changed {
    pub type_name: &'static str,
    pub state: String,
}

pub struct App {
    pub paths: Paths,
    pub identity: Mutex<Identity>,
    /// The settings the downstream last set, if any.
    pub settings: watch::Sender<Option<Arc<RelaySettings>>>,
    settings_state: AtomicU64,
    pub recipients: RwLock<Recipients>,
    pub spool: Mutex<Spool>,
    pub outbox: Mutex<Outbox>,
    /// Wakes the delivery engine when mail is handed over.
    pub outbound_wake: Notify,
    pub events: Mutex<Events>,
    pub push: broadcast::Sender<Changed>,
    /// Link connections, and those with push on for `Inbound`.
    pub link_clients: AtomicU32,
    pub live_clients: AtomicU32,
    next_conn: AtomicU64,
    pub started_at: u64,
    pub last_error: Mutex<Option<String>>,
    pub limiter: Mutex<Limiter>,
    pub self_upgrade: bool,
    /// The keys a release must be signed by (RL-29).
    pub release_keys: Vec<[u8; 32]>,
    /// The binary an upgrade replaces.
    pub exe: Option<std::path::PathBuf>,
    /// An upgrade is installing, or installed and waiting to restart.
    pub upgrading: AtomicBool,
    /// Wakes the run loop to exit for the supervisor's restart.
    pub restart: Notify,
    /// `run --link-allow-any`: the `linkAllowFrom` to ignore, until the
    /// downstream sets another (RL-33).
    pub link_allow_any: Mutex<Option<Vec<String>>>,
}

impl App {
    pub fn open(paths: Paths, identity: Identity) -> std::io::Result<App> {
        let settings = state::load_settings(&paths)?.map(Arc::new);
        let recipients = Recipients::load(&paths)?;
        let spool = Spool::open(&paths.spool_in())?;
        let outbox = Outbox::open(&paths.spool_out())?;
        let events = Events::open(paths.events())?;
        // Uploads don't survive a restart.
        if let Ok(dir) = std::fs::read_dir(paths.blobs()) {
            for entry in dir.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let (push, _) = broadcast::channel(256);
        Ok(App {
            paths,
            identity: Mutex::new(identity),
            settings: watch::Sender::new(settings),
            settings_state: AtomicU64::new(1),
            recipients: RwLock::new(recipients),
            spool: Mutex::new(spool),
            outbox: Mutex::new(outbox),
            outbound_wake: Notify::new(),
            events: Mutex::new(events),
            push,
            link_clients: AtomicU32::new(0),
            live_clients: AtomicU32::new(0),
            next_conn: AtomicU64::new(1),
            started_at: time::now(),
            last_error: Mutex::new(None),
            limiter: Mutex::new(Limiter::default()),
            self_upgrade: std::env::var_os("INBUXA_RELAY_CONTAINER").is_none(),
            release_keys: inbuxa_relay_proto::release::RELEASE_KEYS.to_vec(),
            exe: crate::upgrade::current_exe(),
            upgrading: AtomicBool::new(false),
            restart: Notify::new(),
            link_allow_any: Mutex::new(None),
        })
    }

    /// Whether `ip` may dial the link (RL-33): anyone until the first
    /// settings, so a relay can join, and while `--link-allow-any` ignores
    /// the list it was started with.
    pub fn link_allows(&self, ip: IpAddr) -> bool {
        let Some(settings) = self.settings() else {
            return true;
        };
        if settings.link_allow_from.is_empty()
            || self
                .link_allow_any
                .lock()
                .expect("link_allow_any")
                .as_ref()
                .is_some_and(|ignored| *ignored == settings.link_allow_from)
        {
            return true;
        }
        // Settings are checked before they are kept, so this parses
        AllowList::parse(&settings.link_allow_from).map_or(true, |list| list.allows(ip))
    }

    /// The downstream set `linkAllowFrom`: a list other than the one
    /// `--link-allow-any` ignores ends it.
    pub fn link_allow_from_changed(&self, list: &[String]) {
        let mut ignored = self.link_allow_any.lock().expect("link_allow_any");
        if ignored.as_deref().is_some_and(|ignored| ignored != list) {
            *ignored = None;
            eprintln!(
                "inbuxa-relay: the downstream set linkAllowFrom; --link-allow-any no longer applies"
            );
        }
    }

    pub fn conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    pub fn settings(&self) -> Option<Arc<RelaySettings>> {
        self.settings.borrow().clone()
    }

    pub fn relay_state(&self) -> String {
        self.settings_state.load(Ordering::Relaxed).to_string()
    }

    /// The `Relay` object changed (settings or status worth telling).
    pub fn relay_changed(&self) {
        let state = self.settings_state.fetch_add(1, Ordering::Relaxed) + 1;
        self.notify(type_name::RELAY, state.to_string());
    }

    pub fn notify(&self, type_name: &'static str, state: String) {
        let _ = self.push.send(Changed { type_name, state });
    }

    pub fn outbound_changed(&self) {
        let state = self.outbox.lock().expect("outbox").state();
        self.notify(type_name::OUTBOUND, state);
    }

    pub fn inbound_changed(&self) {
        let state = self.spool.lock().expect("spool").state();
        self.notify(type_name::INBOUND, state);
    }

    pub fn record(&self, kind: &str, data: serde_json::Map<String, serde_json::Value>) {
        let state = {
            let mut events = self.events.lock().expect("events");
            events.record(kind, data);
            events.state()
        };
        self.notify(type_name::RELAY_EVENT, state);
    }

    pub fn set_error(&self, error: impl Into<String>) {
        let error = error.into();
        eprintln!("inbuxa-relay: {error}");
        *self.last_error.lock().expect("last_error") = Some(error);
        self.relay_changed();
    }

    /// Port 25 stays closed until the downstream has sent valid settings
    /// and a recipient set (spec "Joining and reset", step 5).
    pub fn mode(&self) -> Mode {
        let configured = self.settings().is_some_and(|s| s.problems().is_empty())
            && self.recipients.read().expect("recipients").is_loaded();
        if !configured {
            Mode::Unconfigured
        } else if self.live_clients.load(Ordering::Relaxed) > 0 {
            Mode::Live
        } else {
            Mode::Held
        }
    }

    pub fn status(&self) -> RelayStatus {
        let (inbound, inbound_bytes) = {
            let spool = self.spool.lock().expect("spool");
            (spool.count(), spool.bytes())
        };
        let (outbound, outbound_bytes) = {
            let outbox = self.outbox.lock().expect("outbox");
            (outbox.count(), outbox.bytes())
        };
        RelayStatus {
            started_at: time::utc_date(self.started_at),
            relay_version: VERSION.to_string(),
            link_clients: self.link_clients.load(Ordering::Relaxed),
            mode: self.mode(),
            spool: SpoolStatus {
                inbound,
                outbound,
                bytes: inbound_bytes + outbound_bytes,
            },
            recipient_state: self.recipients.read().expect("recipients").state(),
            certificate_not_after: None,
            last_error: self.last_error.lock().expect("last_error").clone(),
            self_upgrade: self.self_upgrade,
            link_from: None,
        }
    }

    /// Whether the spool is too full for new mail, either way: past 90% of
    /// the cap.
    pub fn spool_full(&self, settings: &RelaySettings) -> bool {
        let bytes =
            self.spool.lock().expect("spool").bytes() + self.outbox.lock().expect("outbox").bytes();
        bytes.saturating_mul(10) >= settings.spool_max_bytes.saturating_mul(9)
            || disk_nearly_full(&self.paths.spool_in())
    }

    /// Writes `status.json`, for `inbuxa-relay status`.
    pub fn write_status(&self) {
        if let Err(e) = state::write_json(&self.paths.status(), &self.status()) {
            eprintln!("inbuxa-relay: could not write status: {e}");
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn disk_nearly_full(path: &std::path::Path) -> bool {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn statvfs(path: *const std::ffi::c_char, buf: *mut std::ffi::c_void) -> i32;
    }
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // On 64-bit Linux, glibc and musl both lay struct statvfs out as eight
    // bytes per field: bsize, frsize, blocks, bfree, bavail, ... in 112
    // bytes. The buffer is larger than that, so a different layout can
    // only give a wrong answer, never a write past the end.
    let mut buf = [0u64; 32];
    // SAFETY: a valid C string, and a buffer larger than struct statvfs.
    let rc = unsafe { statvfs(cpath.as_ptr(), buf.as_mut_ptr().cast()) };
    let (blocks, avail) = (buf[2], buf[4]);
    rc == 0 && blocks > 0 && avail.saturating_mul(10) < blocks
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn disk_nearly_full(_: &std::path::Path) -> bool {
    false
}

/// Per-IP limits at the door (spec "At the door, always", step 1).
#[derive(Default)]
pub struct Limiter {
    ips: HashMap<IpAddr, IpCount>,
}

#[derive(Default)]
struct IpCount {
    minute: u64,
    connections: u32,
    messages: u32,
    open: u32,
}

impl Limiter {
    fn entry(&mut self, ip: IpAddr, now: u64) -> &mut IpCount {
        let minute = now / 60;
        let count = self.ips.entry(ip).or_default();
        if count.minute != minute {
            count.minute = minute;
            count.connections = 0;
            count.messages = 0;
        }
        count
    }

    /// A new session from `ip`: allowed, or not.
    pub fn connect(&mut self, ip: IpAddr, s: &RelaySettings, now: u64) -> bool {
        let count = self.entry(ip, now);
        if count.connections >= s.rate_limits.connections_per_minute
            || count.open >= s.rate_limits.concurrent_sessions
        {
            return false;
        }
        count.connections += 1;
        count.open += 1;
        true
    }

    pub fn disconnect(&mut self, ip: IpAddr) {
        if let Some(count) = self.ips.get_mut(&ip) {
            count.open = count.open.saturating_sub(1);
        }
    }

    /// A new message from `ip`: allowed, or not.
    pub fn message(&mut self, ip: IpAddr, s: &RelaySettings, now: u64) -> bool {
        let count = self.entry(ip, now);
        if count.messages >= s.rate_limits.messages_per_minute {
            return false;
        }
        count.messages += 1;
        true
    }

    /// Forgets idle addresses.
    pub fn sweep(&mut self, now: u64) {
        let minute = now / 60;
        self.ips.retain(|_, c| c.open > 0 || c.minute == minute);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_relay_proto::types::RateLimits;

    #[test]
    fn limits_per_minute_and_open() {
        let s = RelaySettings {
            rate_limits: RateLimits {
                connections_per_minute: 3,
                messages_per_minute: 2,
                concurrent_sessions: 2,
            },
            ..Default::default()
        };
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut l = Limiter::default();
        assert!(l.connect(ip, &s, 0));
        assert!(l.connect(ip, &s, 0));
        assert!(!l.connect(ip, &s, 0), "two open at once");
        l.disconnect(ip);
        assert!(l.connect(ip, &s, 0));
        l.disconnect(ip);
        assert!(!l.connect(ip, &s, 0), "three a minute");
        assert!(l.connect(ip, &s, 60), "a new minute");
        assert!(l.message(ip, &s, 60));
        assert!(l.message(ip, &s, 60));
        assert!(!l.message(ip, &s, 60));
        l.sweep(200);
        assert!(l.ips.contains_key(&ip), "still open");
    }
}
