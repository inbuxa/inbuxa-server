/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:LogSettings`, how long rotated log files are kept (personal-data
//! catalog spec, default D1, settled 2026-09-28). Stored as JSON under `T` +
//! `l` in the fork's subspace, not on `x:TracerLog`: that object is also
//! stored inside `x:Bootstrap` with fields after it, so a new field there
//! would change `x:Bootstrap`'s stored format.
//!
//! Unset, files are kept as they always were: forever. A new install sets
//! 30 days. Each node deletes its own files, since log files are local.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// The fewest days a limit may keep, so a typo can't empty the log directory
/// of what an incident needs.
pub const MIN_KEEP_DAYS: u64 = 1;

/// The days a new install keeps (D1).
pub const NEW_INSTALL_KEEP_DAYS: u64 = 30;

/// Rung when the settings change here, so this node purges at once; other
/// nodes read the settings again within the hour.
pub static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogSettings {
    /// Rotated log files older than this many days are deleted; `None`
    /// keeps them all.
    pub keep_for_days: Option<u64>,
}

/// The properties `inbuxa:LogSettings` has, as they appear over JMAP.
pub const PROPERTIES: &[&str] = &["keepForDays"];

impl LogSettings {
    /// What's wrong with these values, naming the property.
    pub fn check(&self) -> Result<(), (&'static str, String)> {
        match self.keep_for_days {
            Some(days) if days < MIN_KEEP_DAYS => Err((
                "keepForDays",
                format!("must be at least {MIN_KEEP_DAYS}, or null to keep every file"),
            )),
            _ => Ok(()),
        }
    }
}

fn key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Tl".to_vec(),
    })
}

struct Json(LogSettings);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// The settings in force; unset reads as keep everything.
pub async fn get(data: &Store) -> trc::Result<LogSettings> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(settings)| settings)
        .unwrap_or_default())
}

/// Whether anything was ever stored: a new install writes its default only
/// when nothing is there.
pub async fn is_set(data: &Store) -> trc::Result<bool> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .is_some())
}

/// Stores new settings.
pub async fn set(data: &Store, settings: &LogSettings) -> trc::Result<()> {
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

/// A file in a log directory: its path, name, and when it last changed.
pub struct LogFile {
    pub path: PathBuf,
    pub name: String,
    pub modified: SystemTime,
    pub is_file: bool,
}

/// The files to delete: regular files named `<prefix>.<something>`, whose
/// last change is more than `keep` ago. The file being written changes all
/// the time, so it is never old enough; anything not named for this log is
/// never touched.
pub fn expired<'a>(
    files: &'a [LogFile],
    prefix: &str,
    keep: Duration,
    now: SystemTime,
) -> impl Iterator<Item = &'a Path> + 'a {
    let lead = format!("{prefix}.");
    files.iter().filter_map(move |file| {
        (file.is_file
            && file.name.starts_with(&lead)
            && now
                .duration_since(file.modified)
                .is_ok_and(|age| age > keep))
        .then_some(file.path.as_path())
    })
}

/// Deletes this log's expired files in `dir`, returning how many went.
pub fn purge(dir: &Path, prefix: &str, keep: Duration) -> std::io::Result<usize> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        files.push(LogFile {
            path: entry.path(),
            name: entry.file_name().to_string_lossy().into_owned(),
            modified: meta.modified()?,
            is_file: meta.is_file(),
        });
    }
    let mut removed = 0;
    for path in expired(&files, prefix, keep, SystemTime::now()) {
        std::fs::remove_file(path)?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    fn file(name: &str, age_days: u64, now: SystemTime) -> LogFile {
        LogFile {
            path: PathBuf::from(format!("/var/log/inbuxa/{name}")),
            name: name.to_string(),
            modified: now - DAY * age_days as u32,
            is_file: true,
        }
    }

    #[test]
    fn only_this_logs_old_files_go() {
        let now = SystemTime::now();
        let files = [
            file("inbuxa.log.2026-08-01", 58, now),
            file("inbuxa.log.2026-09-27", 1, now),
            file("inbuxa.log", 0, now),
            file("other.log.2026-01-01", 270, now),
            file("inbuxa.logs.old", 90, now),
            LogFile {
                is_file: false,
                ..file("inbuxa.log.dir", 90, now)
            },
        ];
        let gone: Vec<_> = expired(&files, "inbuxa.log", 30 * DAY, now)
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(gone, vec!["inbuxa.log.2026-08-01"]);
    }

    #[test]
    fn unset_keeps_everything_and_zero_is_refused() {
        assert_eq!(LogSettings::default().keep_for_days, None);
        assert!(LogSettings::default().check().is_ok());
        let zero = LogSettings {
            keep_for_days: Some(0),
        };
        assert_eq!(zero.check().unwrap_err().0, "keepForDays");
        let json: LogSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(json, LogSettings::default());
    }

    #[test]
    fn purge_deletes_on_disk() {
        let dir = std::env::temp_dir().join(format!("inbuxa-log-purge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("inbuxa.log.2020-01-01");
        let new = dir.join("inbuxa.log.today");
        let other = dir.join("keep-me.txt");
        for path in [&old, &new, &other] {
            std::fs::write(path, b"x").unwrap();
        }
        let long_ago = SystemTime::now() - 60 * DAY;
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&other)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        assert_eq!(purge(&dir, "inbuxa.log", 30 * DAY).unwrap(), 1);
        assert!(!old.exists());
        assert!(new.exists());
        assert!(other.exists(), "a file not named for the log is never touched");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
