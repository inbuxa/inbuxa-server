/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:CountSettings`, the opt-in count (count spec, CNT-1 to CNT-11):
//! an administrator who chooses to be counted lets the server send a random
//! install ID and its version once a week, so the project can say how many
//! servers run. Off, nothing is sent and nothing is looked up.
//!
//! Stored as JSON under `Y` + `c` in the fork's subspace, not on a
//! generated registry object. Unset reads as off and undecided (CNT-1).
//!
//! This module holds the settings, the rules (endpoint, install ID, payload)
//! and the schedule as pure functions. The task that sends lives in
//! `services::inbuxa_count`.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::sync::Mutex;
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    rand::{RngExt, rng},
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// Where check-ins go unless the administrator names another collector.
pub const DEFAULT_ENDPOINT: &str = "https://inbuxa.org/count/v1";

/// CNT-8: the longest endpoint `/set` accepts.
pub const MAX_ENDPOINT_LEN: usize = 200;

/// What `preview` shows for the ID while the count is off.
pub const PLACEHOLDER_ID: &str = "00000000-0000-4000-8000-000000000000";

/// The version a check-in reports, as tags and `--version` name it.
pub const VERSION: &str = types::brand_version!();

/// Rung when the settings change on this node, so its task reads them now;
/// other nodes read them again within [`RECHECK_SECS`].
pub static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// CNT-7: the one `/forget` owed for each ID turned off on this node, sent
/// by this node's task. Never persisted, so it is never retried.
static FORGET: Mutex<Vec<Forget>> = Mutex::new(Vec::new());

#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CountSettings {
    /// The administrator chose to be counted.
    pub enabled: bool,
    /// The administrator answered the one-time question, either way.
    pub decided: bool,
    /// The collector; `None` is [`DEFAULT_ENDPOINT`].
    pub endpoint: Option<String>,
    /// CNT-3: present only while on.
    pub install_id: Option<String>,
    /// The UTC date (`YYYY-MM-DD`) of the last check-in that succeeded.
    pub last_check_in: Option<String>,
}

/// The properties `inbuxa:CountSettings` has, as they appear over JMAP.
pub const PROPERTIES: &[&str] = &[
    "enabled",
    "decided",
    "endpoint",
    "installId",
    "lastCheckIn",
    "preview",
];

impl CountSettings {
    /// The collector check-ins go to.
    pub fn endpoint(&self) -> &str {
        self.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT)
    }

    /// The exact body a check-in sends, or would send once on.
    pub fn preview(&self) -> String {
        checkin_body(self.install_id.as_deref().unwrap_or(PLACEHOLDER_ID))
    }

    /// CNT-3, CNT-7: moves from `before` to these settings. Turning on makes
    /// a new install ID; turning off removes it, with its last check-in, and
    /// returns the `/forget` owed for it.
    pub fn transition_from(&mut self, before: &CountSettings) -> Option<Forget> {
        match (before.enabled, self.enabled) {
            (false, true) => {
                self.install_id = Some(new_install_id());
                self.last_check_in = None;
                None
            }
            (true, false) => {
                self.install_id = None;
                self.last_check_in = None;
                before.install_id.as_ref().map(|id| Forget {
                    endpoint: before.endpoint().to_string(),
                    id: id.clone(),
                })
            }
            (true, true) if self.install_id.is_none() => {
                self.install_id = Some(new_install_id());
                None
            }
            _ => None,
        }
    }
}

/// CNT-8: an absolute `https://` URL with a host, no user name or password,
/// no query or fragment, printable ASCII only, at most 200 characters.
pub fn check_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(format!("must be at most {MAX_ENDPOINT_LEN} characters"));
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err("must be an https:// URL".into());
    };
    if !endpoint.bytes().all(|b| b.is_ascii_graphic()) || endpoint.contains('\\') {
        return Err("must be printable ASCII with no spaces".into());
    }
    if endpoint.contains('?') || endpoint.contains('#') {
        return Err("must not have a query or a fragment".into());
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        return Err("must not carry a user name or password".into());
    }
    let host = match authority.strip_prefix('[') {
        // An IPv6 literal, then an optional port
        Some(v6) => {
            let Some((addr, port)) = v6.split_once(']') else {
                return Err("has an unclosed IPv6 address".into());
            };
            if addr.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
                return Err("has an invalid IPv6 address".into());
            }
            check_port(port)?;
            addr
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            if let Some(port) = port {
                check_port(&format!(":{port}"))?;
            }
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            {
                return Err("has an invalid host name".into());
            }
            host
        }
    };
    if host.is_empty() {
        return Err("must name a host".into());
    }
    Ok(())
}

fn check_port(port: &str) -> Result<(), String> {
    match port.strip_prefix(':') {
        None if port.is_empty() => Ok(()),
        Some(digits) if digits.parse::<u16>().is_ok_and(|p| p > 0) => Ok(()),
        _ => Err("has an invalid port".into()),
    }
}

/// `{endpoint}/{path}`, without doubling a trailing slash.
pub fn url(endpoint: &str, path: &str) -> String {
    format!("{}/{path}", endpoint.trim_end_matches('/'))
}

/// CNT-3: a random UUID v4, lower-case and hyphenated.
pub fn new_install_id() -> String {
    format_uuid_v4(rng().random::<u128>().to_be_bytes())
}

/// Sets the version (4) and variant (10xx) bits of 16 random bytes and
/// writes them as `8-4-4-4-12` lower-case hex.
pub fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Whether `id` reads as an install ID: a lower-case, hyphenated UUID v4.
pub fn is_install_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            14 => *b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

#[derive(SerdeSerialize)]
struct CheckIn<'x> {
    id: &'x str,
    version: &'x str,
}

#[derive(SerdeSerialize)]
struct ForgetBody<'x> {
    id: &'x str,
}

/// CNT-5: `{"id":…,"version":…}`, and nothing else.
pub fn checkin_body(id: &str) -> String {
    serde_json::to_string(&CheckIn {
        id,
        version: VERSION,
    })
    .unwrap_or_default()
}

/// CNT-7: `{"id":…}`, and nothing else.
pub fn forget_body(id: &str) -> String {
    serde_json::to_string(&ForgetBody { id }).unwrap_or_default()
}

/// A `/forget` owed for an ID that was turned off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forget {
    pub endpoint: String,
    pub id: String,
}

/// CNT-7: queues the `/forget` for this node's task and wakes it.
pub fn queue_forget(forget: Forget) {
    if let Ok(mut queue) = FORGET.lock() {
        queue.push(forget);
    }
    CHANGED.notify_one();
}

/// The `/forget`s owed, emptying the queue: each is sent once.
pub fn take_forgets() -> Vec<Forget> {
    FORGET
        .lock()
        .map(|mut queue| std::mem::take(&mut *queue))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// CNT-4: the schedule, in seconds, as pure functions of uniform random
// numbers so the bounds can be tested.

pub const HOUR_SECS: u64 = 3_600;
pub const DAY_SECS: u64 = 86_400;
/// The first check-in falls within this long of being turned on or started.
pub const FIRST_WITHIN_SECS: u64 = DAY_SECS;
/// Then one every week ...
pub const EVERY_SECS: u64 = 7 * DAY_SECS;
/// ... give or take up to this.
pub const JITTER_SECS: u64 = 12 * HOUR_SECS;
/// A failed check-in is tried again this much later ...
pub const RETRY_AFTER_SECS: u64 = 6 * HOUR_SECS;
/// ... at most this many times, then waits for the next weekly slot.
pub const MAX_RETRIES: u8 = 3;
/// How often a node re-reads the settings without being told they changed:
/// a change made on another node of a cluster.
pub const RECHECK_SECS: u64 = HOUR_SECS;

/// The next attempt: when it is due, the weekly slot it belongs to, and how
/// many times that slot was retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub due: u64,
    pub slot: u64,
    pub retries: u8,
}

impl Plan {
    /// The first check-in: a random moment within 24 hours of `now`.
    pub fn first(now: u64, rand: u64) -> Plan {
        let due = now + rand % FIRST_WITHIN_SECS;
        Plan {
            due,
            slot: due,
            retries: 0,
        }
    }

    /// After an attempt at `now`: a week (± 12 hours) after its slot when
    /// it succeeded or used up its retries, else six hours later.
    pub fn after(self, succeeded: bool, now: u64, rand: u64) -> Plan {
        if !succeeded && self.retries < MAX_RETRIES {
            return Plan {
                due: now + RETRY_AFTER_SECS,
                slot: self.slot,
                retries: self.retries + 1,
            };
        }
        let slot = self.slot + EVERY_SECS - JITTER_SECS + rand % (2 * JITTER_SECS + 1);
        Plan {
            due: slot.max(now),
            slot,
            retries: 0,
        }
    }
}

/// A random number for [`Plan`].
pub fn random() -> u64 {
    rng().random()
}

/// The UTC date of a Unix time, `YYYY-MM-DD`.
pub fn utc_date(secs: u64) -> String {
    // Days since 1970-01-01 to a civil date (H. Hinnant's algorithm)
    let days = (secs / DAY_SECS) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

// ---------------------------------------------------------------------------
// Storage

fn key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Yc".to_vec(),
    })
}

struct Json(CountSettings);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// CNT-1: the settings in force; unset reads as off and undecided.
pub async fn get(data: &Store) -> trc::Result<CountSettings> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(settings)| settings)
        .unwrap_or_default())
}

/// Stores new settings.
pub async fn set(data: &Store, settings: &CountSettings) -> trc::Result<()> {
    let bytes = serde_json::to_vec(settings).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(key(), bytes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Notes a check-in that succeeded on `date`, if `id` is still the install
/// ID: one turned off or replaced meanwhile isn't brought back.
pub async fn record_check_in(data: &Store, id: &str, date: String) -> trc::Result<()> {
    let mut settings = get(data).await?;
    if settings.enabled && settings.install_id.as_deref() == Some(id) {
        settings.last_check_in = Some(date);
        set(data, &settings).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_is_off_and_undecided() {
        let settings: CountSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings, CountSettings::default());
        assert!(!settings.enabled);
        assert!(!settings.decided);
        assert_eq!(settings.install_id, None);
        assert_eq!(settings.endpoint(), DEFAULT_ENDPOINT);
        assert!(check_endpoint(DEFAULT_ENDPOINT).is_ok());
    }

    #[test]
    fn payload_is_exactly_id_and_version() {
        let id = "3f2c5a9e-1b7d-4c0a-9e3f-5d2b8a6c4e1f";
        let body = checkin_body(id);
        assert_eq!(body, format!(r#"{{"id":"{id}","version":"{VERSION}"}}"#));
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(forget_body(id), format!(r#"{{"id":"{id}"}}"#));
        assert!(!VERSION.is_empty());
        assert!(!VERSION.contains('"'));
    }

    #[test]
    fn preview_shows_the_placeholder_while_off() {
        let mut settings = CountSettings::default();
        assert_eq!(
            settings.preview(),
            format!(r#"{{"id":"{PLACEHOLDER_ID}","version":"{VERSION}"}}"#)
        );
        assert!(is_install_id(PLACEHOLDER_ID));
        settings.enabled = true;
        settings.transition_from(&CountSettings::default());
        let id = settings.install_id.clone().unwrap();
        assert!(settings.preview().contains(&id));
    }

    #[test]
    fn install_ids_are_uuid_v4() {
        for _ in 0..1_000 {
            let id = new_install_id();
            assert!(is_install_id(&id), "{id}");
            assert_eq!(id, id.to_lowercase());
        }
        assert_eq!(
            format_uuid_v4([0xff; 16]),
            "ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        assert_eq!(format_uuid_v4([0; 16]), PLACEHOLDER_ID);
        assert_ne!(new_install_id(), new_install_id());
        assert!(!is_install_id("3F2C5A9E-1B7D-4C0A-9E3F-5D2B8A6C4E1F"));
        assert!(!is_install_id("3f2c5a9e-1b7d-1c0a-9e3f-5d2b8a6c4e1f"));
        assert!(!is_install_id("3f2c5a9e1b7d4c0a9e3f5d2b8a6c4e1f"));
    }

    #[test]
    fn turning_on_and_off() {
        let off = CountSettings::default();
        let mut on = CountSettings {
            enabled: true,
            decided: true,
            ..Default::default()
        };
        assert_eq!(on.transition_from(&off), None);
        let first = on.install_id.clone().unwrap();
        assert!(is_install_id(&first));

        // Unchanged while on
        let mut again = on.clone();
        assert_eq!(again.transition_from(&on), None);
        assert_eq!(again.install_id.as_deref(), Some(first.as_str()));

        // Off removes it and owes one /forget, to the endpoint it was sent to
        let mut off_again = CountSettings {
            enabled: false,
            decided: true,
            endpoint: Some("https://count.example.org/v1".into()),
            install_id: on.install_id.clone(),
            last_check_in: Some("2026-11-27".into()),
        };
        let forget = off_again.transition_from(&on).unwrap();
        assert_eq!(forget.id, first);
        assert_eq!(forget.endpoint, DEFAULT_ENDPOINT);
        assert_eq!(off_again.install_id, None);
        assert_eq!(off_again.last_check_in, None);

        // On again: a new ID, nothing to do with the first
        let mut on_again = CountSettings {
            enabled: true,
            ..off_again.clone()
        };
        on_again.transition_from(&off_again);
        assert_ne!(on_again.install_id.as_deref(), Some(first.as_str()));

        // Off with no ID owes nothing
        assert_eq!(off.clone().transition_from(&off), None);
    }

    #[test]
    fn forgets_are_taken_once() {
        let forget = Forget {
            endpoint: DEFAULT_ENDPOINT.into(),
            id: new_install_id(),
        };
        queue_forget(forget.clone());
        let taken = take_forgets();
        assert!(taken.contains(&forget));
        assert!(!take_forgets().contains(&forget));
    }

    #[test]
    fn endpoints() {
        for good in [
            "https://inbuxa.org/count/v1",
            "https://count.example.org",
            "https://count.example.org/",
            "https://count.example.org:8443/a/b",
            "https://10.0.0.5/count",
            "https://[2001:db8::1]:8443/count",
            "https://localhost/count/v1",
        ] {
            assert!(check_endpoint(good).is_ok(), "{good}");
        }
        let long = format!("https://example.org/{}", "a".repeat(MAX_ENDPOINT_LEN));
        for bad in [
            "",
            "http://inbuxa.org/count/v1",
            "HTTPS://inbuxa.org/count/v1",
            "ftp://inbuxa.org",
            "inbuxa.org/count/v1",
            "/count/v1",
            "https://",
            "https:///count",
            "https://inbuxa.org/count?x=1",
            "https://inbuxa.org/count#v1",
            "https://user:pw@inbuxa.org/count",
            "https://inbuxa.org /count",
            "https://inbuxa.org/co\tunt",
            "https://inbuxa.org:0/count",
            "https://inbuxa.org:99999/count",
            "https://inbuxa.org:/count",
            "https://[2001:db8::1/count",
            "https://exa_mple.org/count",
            "https://inbuxa.org\\count",
            "https://inbüxa.org/count",
            long.as_str(),
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            url("https://inbuxa.org/count/v1", "checkin"),
            "https://inbuxa.org/count/v1/checkin"
        );
        assert_eq!(
            url("https://count.example.org/", "forget"),
            "https://count.example.org/forget"
        );
    }

    #[test]
    fn first_check_in_is_within_a_day() {
        let now = 1_800_000_000;
        for rand in [0, 1, FIRST_WITHIN_SECS - 1, FIRST_WITHIN_SECS, u64::MAX] {
            let plan = Plan::first(now, rand);
            assert!(plan.due >= now && plan.due < now + FIRST_WITHIN_SECS);
            assert_eq!(plan.slot, plan.due);
            assert_eq!(plan.retries, 0);
        }
        for _ in 0..1_000 {
            let plan = Plan::first(now, random());
            assert!(plan.due >= now && plan.due < now + FIRST_WITHIN_SECS);
        }
    }

    #[test]
    fn weekly_with_up_to_twelve_hours_either_way() {
        let slot = 1_800_000_000;
        let plan = Plan {
            due: slot,
            slot,
            retries: 0,
        };
        let (low, high) = (
            slot + EVERY_SECS - JITTER_SECS,
            slot + EVERY_SECS + JITTER_SECS,
        );
        for rand in [0, 1, 2 * JITTER_SECS, 2 * JITTER_SECS + 1, u64::MAX] {
            let next = plan.after(true, slot + 2, rand);
            assert!(next.due >= low && next.due <= high, "{rand}");
            assert_eq!(next.slot, next.due);
            assert_eq!(next.retries, 0);
        }
        assert_eq!(plan.after(true, slot, 0).due, low);
        assert_eq!(plan.after(true, slot, 2 * JITTER_SECS).due, high);
        for _ in 0..1_000 {
            let next = plan.after(true, slot, random());
            assert!(next.due >= low && next.due <= high);
        }
    }

    #[test]
    fn three_retries_six_hours_apart_then_the_next_week() {
        let slot = 1_800_000_000;
        let mut plan = Plan {
            due: slot,
            slot,
            retries: 0,
        };
        let mut now = slot;
        for retry in 1..=MAX_RETRIES {
            plan = plan.after(false, now, 0);
            assert_eq!(plan.due, now + RETRY_AFTER_SECS);
            assert_eq!(plan.slot, slot, "retries keep the week's slot");
            assert_eq!(plan.retries, retry);
            now = plan.due;
        }
        // The fourth failure waits for the next weekly slot
        let next = plan.after(false, now, JITTER_SECS);
        assert_eq!(next.retries, 0);
        assert_eq!(next.slot, slot + EVERY_SECS);
        assert_eq!(next.due, slot + EVERY_SECS);
        // A retry that succeeds goes back to the weekly slot too
        let mid = Plan {
            due: slot + RETRY_AFTER_SECS,
            slot,
            retries: 1,
        };
        assert_eq!(
            mid.after(true, slot + RETRY_AFTER_SECS, JITTER_SECS).due,
            slot + EVERY_SECS
        );
        // A slot already past (a suspended host) is due now, not in the past
        let late = plan.after(true, slot + 30 * DAY_SECS, 0);
        assert_eq!(late.due, slot + 30 * DAY_SECS);
    }

    #[test]
    fn dates_are_utc() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_date(1_795_823_999), "2026-11-27");
        assert_eq!(utc_date(1_795_824_000), "2026-11-28");
        assert_eq!(utc_date(4_107_542_400), "2100-03-01");
    }

    #[test]
    fn json_is_camel_case() {
        let settings = CountSettings {
            enabled: true,
            decided: true,
            endpoint: None,
            install_id: Some(new_install_id()),
            last_check_in: Some("2026-11-27".into()),
        };
        let json = serde_json::to_value(&settings).unwrap();
        for key in ["enabled", "decided", "installId", "lastCheckIn"] {
            assert!(json.get(key).is_some(), "{key}");
        }
    }
}
