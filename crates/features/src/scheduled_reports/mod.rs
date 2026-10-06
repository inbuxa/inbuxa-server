/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Scheduled reports and the weekly digest (scheduled-reports spec).
//!
//! An administrator picks sections, a schedule in a time zone and who gets
//! it; the server builds the report at that time from data it already keeps
//! and mails it. The weekly digest is a built-in report (RP-21).
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `S`, then one byte for the kind:
//!
//! - `r` + report id (u64): a report, as JSON.
//! - `s`: the settings, as JSON.
//!
//! Numbers are big-endian.

use chrono::{Datelike, Duration, LocalResult, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

const FEATURE: u8 = b'S';
const KIND_REPORT: u8 = b'r';
const KIND_SETTINGS: u8 = b's';

/// The weekly digest's id (RP-21); other reports count up from here.
pub const DIGEST_ID: u64 = 1;
/// RP-23.
pub const MAX_RECIPIENTS: usize = 50;
/// RP-16: runs kept per report.
pub const KEEP_RUNS: usize = 20;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SerdeSerialize, SerdeDeserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Section {
    MailFlow,
    Queue,
    Spoofing,
    TlsFailures,
    Deliverability,
    Security,
    Storage,
    Certificates,
}

impl Section {
    pub const ALL: [Section; 8] = [
        Section::MailFlow,
        Section::Queue,
        Section::Spoofing,
        Section::TlsFailures,
        Section::Deliverability,
        Section::Security,
        Section::Storage,
        Section::Certificates,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Section::MailFlow => "mailFlow",
            Section::Queue => "queue",
            Section::Spoofing => "spoofing",
            Section::TlsFailures => "tlsFailures",
            Section::Deliverability => "deliverability",
            Section::Security => "security",
            Section::Storage => "storage",
            Section::Certificates => "certificates",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Section::ALL.into_iter().find(|s| s.as_str() == value)
    }

    /// RP-12: what a tenant's report leaves out, being server-wide.
    pub fn server_wide(&self) -> bool {
        matches!(
            self,
            Section::MailFlow | Section::Queue | Section::Security | Section::Certificates
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Frequency {
    Daily,
    #[default]
    Weekly,
    Monthly,
}

/// RP-15.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Schedule {
    pub frequency: Frequency,
    /// 1 = Monday … 7 = Sunday; weekly only.
    pub weekday: u8,
    /// 1–28; monthly only.
    pub day_of_month: u8,
    pub hour: u8,
    pub minute: u8,
    /// An IANA zone, e.g. "Europe/Amsterdam".
    pub time_zone: String,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            frequency: Frequency::Weekly,
            weekday: 1,
            day_of_month: 1,
            hour: 7,
            minute: 0,
            time_zone: "UTC".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum RunStatus {
    #[default]
    Sent,
    Failed,
}

/// One time a report went, or tried to (RP-16).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Run {
    pub at: u64,
    pub by_hand: bool,
    pub status: RunStatus,
    pub reason: Option<String>,
    pub recipients: u32,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Report {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    /// The weekly digest: can be edited or turned off, not deleted (RP-21).
    pub built_in: bool,
    pub sections: Vec<Section>,
    pub schedule: Schedule,
    /// Addresses of accounts on this server (RP-23). The digest's are the
    /// system administrators' at send time, and this stays empty.
    pub recipients: Vec<String>,
    pub attach_csv: bool,
    /// RP-22: a tenant's report, limited as RP-12 says.
    pub tenant_id: Option<u32>,
    pub created_at: u64,
    /// The due time of the last run, so a run is never repeated (RP-16).
    pub last_due: u64,
    pub runs: Vec<Run>,
    /// RP-5: what was failing at the last run, to say what changed.
    pub failing: Vec<String>,
    /// RP-17: scheduled runs that failed in a row.
    pub failed_in_a_row: u32,
}

impl Report {
    /// The weekly digest as it starts (RP-21, Decision 1: on).
    pub fn digest(now: u64) -> Self {
        Report {
            id: DIGEST_ID,
            name: "Weekly digest".into(),
            enabled: true,
            built_in: true,
            sections: Section::ALL.to_vec(),
            schedule: Schedule::default(),
            recipients: Vec::new(),
            attach_csv: false,
            tenant_id: None,
            created_at: now,
            last_due: now,
            runs: Vec::new(),
            failing: Vec::new(),
            failed_in_a_row: 0,
        }
    }

    /// The sections this report covers, less the server-wide ones for a
    /// tenant (RP-12).
    pub fn effective_sections(&self) -> Vec<Section> {
        self.sections
            .iter()
            .copied()
            .filter(|s| self.tenant_id.is_none() || !s.server_wide())
            .collect()
    }

    pub fn push_run(&mut self, run: Run) {
        self.runs.insert(0, run);
        self.runs.truncate(KEEP_RUNS);
    }

    /// What an administrator may set, checked (RP-15, RP-23). Whether the
    /// recipients are local accounts is checked against the directory.
    pub fn validate(&self) -> Result<(), &'static str> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err("A name of 1 to 100 characters.");
        }
        if self.sections.is_empty() {
            return Err("At least one section.");
        }
        let mut seen = self.sections.clone();
        seen.sort();
        seen.dedup();
        if seen.len() != self.sections.len() {
            return Err("Each section once.");
        }
        self.schedule.validate()?;
        if !self.built_in && self.recipients.is_empty() {
            return Err("At least one recipient.");
        }
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err("At most 50 recipients.");
        }
        if self
            .recipients
            .iter()
            .any(|r| r.trim().is_empty() || !r.contains('@'))
        {
            return Err("Recipients are email addresses.");
        }
        Ok(())
    }
}

impl Schedule {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.time_zone.parse::<Tz>().is_err() {
            return Err("An IANA time zone, such as Europe/Amsterdam.");
        }
        if self.hour > 23 || self.minute > 59 {
            return Err("A time between 00:00 and 23:59.");
        }
        match self.frequency {
            Frequency::Weekly if !(1..=7).contains(&self.weekday) => {
                Err("A weekday from 1 (Monday) to 7 (Sunday).")
            }
            Frequency::Monthly if !(1..=28).contains(&self.day_of_month) => {
                Err("A day of the month from 1 to 28.")
            }
            _ => Ok(()),
        }
    }

    fn tz(&self) -> Tz {
        self.time_zone.parse().unwrap_or(chrono_tz::UTC)
    }

    fn matches(&self, date: NaiveDate) -> bool {
        match self.frequency {
            Frequency::Daily => true,
            Frequency::Weekly => date.weekday().number_from_monday() == self.weekday as u32,
            Frequency::Monthly => date.day() == self.day_of_month as u32,
        }
    }

    /// The schedule's instant on a local date. A time skipped by a clock
    /// change goes at the first moment after it; a repeated one, the first time.
    fn instant_on(&self, date: NaiveDate) -> Option<i64> {
        let tz = self.tz();
        let local = date.and_hms_opt(self.hour as u32, self.minute as u32, 0)?;
        match tz.from_local_datetime(&local) {
            LocalResult::Single(t) => Some(t.timestamp()),
            LocalResult::Ambiguous(first, _) => Some(first.timestamp()),
            LocalResult::None => (1..=4).find_map(|h| {
                tz.from_local_datetime(&(local + Duration::minutes(30 * h)))
                    .earliest()
                    .map(|t| t.timestamp())
            }),
        }
    }

    /// The first scheduled instant strictly after `after` (Unix seconds).
    pub fn next_due(&self, after: u64) -> Option<u64> {
        let tz = self.tz();
        let start = Utc
            .timestamp_opt(after as i64, 0)
            .single()?
            .with_timezone(&tz)
            .date_naive();
        (0..62)
            .filter_map(|d| start.checked_add_signed(Duration::days(d)))
            .filter(|date| self.matches(*date))
            .filter_map(|date| self.instant_on(date))
            .find(|ts| *ts > after as i64)
            .map(|ts| ts as u64)
    }

    /// The period a run due at `due` covers: the day, week or month before it.
    pub fn period(&self, due: u64) -> (u64, u64) {
        let from = match self.frequency {
            Frequency::Daily => due.saturating_sub(86_400),
            Frequency::Weekly => due.saturating_sub(7 * 86_400),
            Frequency::Monthly => {
                let tz = self.tz();
                Utc.timestamp_opt(due as i64, 0)
                    .single()
                    .map(|t| t.with_timezone(&tz).date_naive())
                    .and_then(|date| date.checked_sub_months(chrono::Months::new(1)))
                    .and_then(|date| self.instant_on(date))
                    .map(|ts| ts as u64)
                    .unwrap_or(due.saturating_sub(30 * 86_400))
            }
        };
        (from, due)
    }
}

/// "Sep 29 – Oct 5, 2026": a period ends at its due time, so the last day
/// covered is the one before.
pub fn period_label(from: u64, to: u64) -> String {
    let fmt = |ts: u64, year: bool| {
        Utc.timestamp_opt(ts as i64, 0)
            .single()
            .map(|t| {
                t.format(if year { "%b %-d, %Y" } else { "%b %-d" })
                    .to_string()
            })
            .unwrap_or_default()
    };
    format!("{} – {}", fmt(from, false), fmt(to.saturating_sub(1), true))
}

/// RP-20.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Empty means "inbuxa reports".
    pub from_name: Option<String>,
    /// Empty means postmaster at the server's default domain.
    pub from_address: Option<String>,
}

impl Settings {
    pub fn from_name(&self) -> &str {
        self.from_name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or("inbuxa reports")
    }
}

// --- Storage --------------------------------------------------------------

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize a scheduled report")
                .reason(err)
        })
    }
}

impl<T: for<'de> SerdeDeserialize<'de> + Send + Sync> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid scheduled report")
                .reason(err)
        })
    }
}

fn class(kind: u8, id: Option<u64>) -> ValueClass {
    let mut key = Vec::with_capacity(10);
    key.push(FEATURE);
    key.push(kind);
    if let Some(id) = id {
        key.extend_from_slice(&id.to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn report(data: &Store, id: u64) -> trc::Result<Option<Report>> {
    Ok(data
        .get_value::<Json<Report>>(ValueKey::from(class(KIND_REPORT, Some(id))))
        .await
        .caused_by(trc::location!())?
        .map(|Json(report)| report))
}

/// Every report, by id.
pub async fn reports(data: &Store) -> trc::Result<Vec<Report>> {
    let mut out = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(class(KIND_REPORT, Some(0))),
            ValueKey::from(class(KIND_REPORT, Some(u64::MAX))),
        ),
        |_, value| {
            if let Ok(Json(report)) = Json::<Report>::deserialize(value) {
                out.push(report);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    out.sort_by_key(|r| r.id);
    Ok(out)
}

pub async fn put_report(data: &Store, report: &Report) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        class(KIND_REPORT, Some(report.id)),
        Json(report).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

pub async fn delete_report(data: &Store, id: u64) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(KIND_REPORT, Some(id)));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// The id for a new report: one above the highest.
pub fn next_id(reports: &[Report]) -> u64 {
    reports
        .iter()
        .map(|r| r.id)
        .max()
        .unwrap_or(DIGEST_ID)
        .max(DIGEST_ID)
        + 1
}

/// Every server has the digest (RP-21); written the first time it's missed.
pub async fn ensure_digest(data: &Store, now: u64) -> trc::Result<()> {
    if report(data, DIGEST_ID).await?.is_none() {
        put_report(data, &Report::digest(now)).await?;
    }
    Ok(())
}

pub async fn settings(data: &Store) -> trc::Result<Settings> {
    Ok(data
        .get_value::<Json<Settings>>(ValueKey::from(class(KIND_SETTINGS, None)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(settings)| settings)
        .unwrap_or_default())
}

pub async fn put_settings(data: &Store, settings: &Settings) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(KIND_SETTINGS, None), Json(settings).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> u64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp() as u64
    }

    fn weekly(tz: &str) -> Schedule {
        Schedule {
            time_zone: tz.into(),
            ..Schedule::default()
        }
    }

    #[test]
    fn weekly_goes_monday_at_seven_local() {
        let s = weekly("Europe/Amsterdam");
        // Wednesday 2026-10-07 → Monday 2026-10-12 07:00 CEST (05:00Z)
        assert_eq!(
            s.next_due(ts("2026-10-07T12:00:00Z")),
            Some(ts("2026-10-12T05:00:00Z"))
        );
        // Exactly at the due time: the next one, a week on
        assert_eq!(
            s.next_due(ts("2026-10-12T05:00:00Z")),
            Some(ts("2026-10-19T05:00:00Z"))
        );
        // After the clocks go back (25 Oct): 07:00 CET is 06:00Z
        assert_eq!(
            s.next_due(ts("2026-10-20T00:00:00Z")),
            Some(ts("2026-10-26T06:00:00Z"))
        );
    }

    #[test]
    fn daily_and_monthly() {
        let daily = Schedule {
            frequency: Frequency::Daily,
            hour: 23,
            minute: 30,
            ..weekly("UTC")
        };
        assert_eq!(
            daily.next_due(ts("2026-10-06T23:30:00Z")),
            Some(ts("2026-10-07T23:30:00Z"))
        );
        let monthly = Schedule {
            frequency: Frequency::Monthly,
            day_of_month: 28,
            ..weekly("America/Phoenix")
        };
        // 28 Oct 07:00 MST (no DST in Phoenix) = 14:00Z
        assert_eq!(
            monthly.next_due(ts("2026-10-06T00:00:00Z")),
            Some(ts("2026-10-28T14:00:00Z"))
        );
        // Its period is the month before
        assert_eq!(
            monthly.period(ts("2026-10-28T14:00:00Z")),
            (ts("2026-09-28T14:00:00Z"), ts("2026-10-28T14:00:00Z"))
        );
    }

    #[test]
    fn a_time_the_clocks_skip_goes_just_after() {
        let s = Schedule {
            frequency: Frequency::Daily,
            hour: 2,
            minute: 30,
            ..weekly("Europe/Amsterdam")
        };
        // 29 Mar 2026: 02:00–03:00 doesn't exist; 03:00 CEST = 01:00Z
        assert_eq!(
            s.next_due(ts("2026-03-28T12:00:00Z")),
            Some(ts("2026-03-29T01:00:00Z"))
        );
    }

    #[test]
    fn validation() {
        let mut r = Report {
            name: "Ops".into(),
            sections: vec![Section::Storage],
            recipients: vec!["ops@example.org".into()],
            ..Report::default()
        };
        assert_eq!(r.validate(), Ok(()));
        r.schedule.time_zone = "Mars/Olympus".into();
        assert!(r.validate().is_err());
        r.schedule.time_zone = "UTC".into();
        r.recipients.clear();
        assert!(r.validate().is_err());
        r.recipients = vec!["ops@example.org".into(); 51];
        assert!(r.validate().is_err());
        r.recipients = vec!["ops@example.org".into()];
        r.sections = vec![Section::Storage, Section::Storage];
        assert!(r.validate().is_err());
        // The digest needs no recipients of its own
        assert_eq!(Report::digest(0).validate(), Ok(()));
    }

    #[test]
    fn tenants_lose_the_server_wide_sections() {
        let mut r = Report::digest(0);
        r.tenant_id = Some(3);
        assert_eq!(
            r.effective_sections(),
            vec![
                Section::Spoofing,
                Section::TlsFailures,
                Section::Deliverability,
                Section::Storage
            ]
        );
    }

    #[test]
    fn ids_and_runs() {
        assert_eq!(next_id(&[]), 2);
        assert_eq!(next_id(&[Report::digest(0)]), 2);
        let mut r = Report::digest(0);
        for at in 0..30 {
            r.push_run(Run {
                at,
                ..Run::default()
            });
        }
        assert_eq!(r.runs.len(), KEEP_RUNS);
        assert_eq!(r.runs[0].at, 29);
    }
}
