/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The state directory (RL-22): the link key, the pins, the cached
//! settings, the recipient set, the spool and the unacknowledged events.
//! Everything else is rebuilt at start.

use inbuxa_relay_proto::{b64, pin::Pin, types::RelaySettings};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const DEFAULT_DIR: &str = "/var/lib/inbuxa-relay";

pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Paths { root: root.into() }
    }

    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    pub fn settings(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    pub fn recipients(&self) -> PathBuf {
        self.root.join("recipients.json")
    }

    pub fn status(&self) -> PathBuf {
        self.root.join("status.json")
    }

    pub fn events(&self) -> PathBuf {
        self.root.join("events.jsonl")
    }

    pub fn lock(&self) -> PathBuf {
        self.root.join("run.lock")
    }

    pub fn spool_in(&self) -> PathBuf {
        self.root.join("spool").join("in")
    }

    pub fn blobs(&self) -> PathBuf {
        self.root.join("blobs")
    }

    pub fn create_dirs(&self) -> io::Result<()> {
        for dir in [self.root.clone(), self.spool_in(), self.blobs()] {
            fs::create_dir_all(&dir)?;
            set_private(&dir, true)?;
        }
        Ok(())
    }
}

/// Owner-only permissions: the directory holds a private key.
#[cfg(unix)]
pub fn set_private(path: &Path, dir: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if dir { 0o700 } else { 0o600 }),
    )
}

#[cfg(not(unix))]
pub fn set_private(_: &Path, _: bool) -> io::Result<()> {
    Ok(())
}

/// Writes a file so that it is either the old or the new content, never a
/// mix: a temporary name, fsync, rename, then fsync of the directory.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        set_private(&tmp, false)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(dir)
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{path:?}: {e}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    write_atomic(
        path,
        &serde_json::to_vec_pretty(value).map_err(io::Error::other)?,
    )
}

/// Where the relay is in joining (spec "Joining and reset").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinStage {
    /// Waiting for the downstream's `Relay/join`.
    Waiting,
    /// The proof was given once; the first `Relay/set` completes the join.
    Answered,
    /// Joined: the secret is gone.
    Joined,
}

/// Who the relay is, and who it belongs to.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub relay_id: String,
    /// The downstream link CA's key pin (RL-6).
    #[serde(with = "b64")]
    pub ca_pin: Pin,
    /// The join token's secret, until the join completes.
    #[serde(default, with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub join_secret: Option<[u8; 32]>,
    /// When the join token expires: no `Relay/join` after it.
    pub join_expires_at: u64,
    pub stage: JoinStage,
    /// The relay's link key and its self-signed certificate (RL-7).
    pub link_key_pem: String,
    pub link_cert_pem: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("relay_id", &self.relay_id)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn load(paths: &Paths) -> io::Result<Option<Identity>> {
        read_json(&paths.identity())
    }

    pub fn save(&self, paths: &Paths) -> io::Result<()> {
        write_json(&paths.identity(), self)
    }
}

pub fn load_settings(paths: &Paths) -> io::Result<Option<RelaySettings>> {
    read_json(&paths.settings())
}

pub fn save_settings(paths: &Paths, settings: &RelaySettings) -> io::Result<()> {
    write_json(&paths.settings(), settings)
}

/// Held while the relay runs, so `reset` can't pull the state out from
/// under it.
pub struct RunLock {
    _file: File,
}

impl RunLock {
    pub fn acquire(paths: &Paths) -> io::Result<RunLock> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.lock())?;
        match file.try_lock() {
            Ok(()) => Ok(RunLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "inbuxa-relay is already running with this state directory",
            )),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "inbuxa-relay-test-{name}-{}-{}",
            std::process::id(),
            inbuxa_relay_proto::time::now()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_replaces() {
        let dir = temp_dir("atomic");
        let path = dir.join("f.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(!dir.join(".f.json.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = temp_dir("lock");
        let paths = Paths::new(&dir);
        let first = RunLock::acquire(&paths).unwrap();
        assert!(RunLock::acquire(&paths).is_err());
        drop(first);
        assert!(RunLock::acquire(&paths).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
}
