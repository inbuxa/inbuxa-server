/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `Relay/upgrade` (RL-29): a release binary, checked against its signature
//! by the inbuxa release key, replaces this one. The relay refuses a
//! downgrade, or a binary for another target; runs the new one once, to see
//! that it starts here and is the version it says; keeps the old one as
//! `inbuxa-relay.previous`; and exits with [`RESTART_EXIT`] for its
//! supervisor to start the new one.

use inbuxa_relay_proto::release::{self, Release, Version};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The exit status after an upgrade: EX_TEMPFAIL, which a supervisor set
/// to restart on failure restarts too.
pub const RESTART_EXIT: u8 = 75;

/// How long the new binary has to answer `--version`.
const TRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an upgrade was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The release won't do here: `invalidArguments`.
    Invalid(String),
    /// It would, but couldn't be put in place: `serverFail`.
    Failed(String),
}

/// Checks `binary` against `signature_file`, for this build at `current`.
pub fn check(
    binary: &[u8],
    signature_file: &str,
    keys: &[[u8; 32]],
    current: &str,
) -> Result<Release, Refused> {
    let release = release::verify(binary, signature_file, keys)
        .map_err(|err| Refused::Invalid(err.to_string()))?;
    let target = release::target();
    if release.target != target {
        return Err(Refused::Invalid(format!(
            "The release is for {}; this relay runs on {target}",
            release.target
        )));
    }
    let newer = match (Version::parse(&release.version), Version::parse(current)) {
        (Some(new), Some(current)) => new > current,
        _ => false,
    };
    if !newer {
        return Err(Refused::Invalid(format!(
            "The release is {}; this relay runs {current}, and won't go back or stay",
            release.version
        )));
    }
    Ok(release)
}

/// Puts `binary` in place of `exe`, once it has run here as `version`.
pub fn install(exe: &Path, binary: &[u8], version: &str) -> Result<(), Refused> {
    let failed = |what: &str, err: std::io::Error| Refused::Failed(format!("{what}: {err}"));
    let dir = exe
        .parent()
        .ok_or_else(|| Refused::Failed("The relay's binary has no directory".into()))?;
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("inbuxa-relay");
    let new = dir.join(format!(".{name}.new"));
    let previous = dir.join(format!("{name}.previous"));
    let result = (|| {
        {
            let mut file = open_executable(&new).map_err(|e| failed("Couldn't write it", e))?;
            file.write_all(binary)
                .and_then(|()| file.sync_all())
                .map_err(|e| failed("Couldn't write it", e))?;
        }
        try_version(&new, version)?;
        fs::copy(exe, &previous).map_err(|e| failed("Couldn't keep the old binary", e))?;
        fs::rename(&new, exe).map_err(|e| failed("Couldn't put it in place", e))?;
        if let Ok(dir) = fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&new);
    }
    result
}

#[cfg(unix)]
fn open_executable(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = fs::remove_file(path);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
}

#[cfg(not(unix))]
fn open_executable(path: &Path) -> std::io::Result<fs::File> {
    let _ = fs::remove_file(path);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Runs `path --version`: it must say it is `version`, in time.
fn try_version(path: &Path, version: &str) -> Result<(), Refused> {
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| Refused::Failed(format!("The new binary doesn't start here: {err}")))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < TRY_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Refused::Failed(
                    "The new binary didn't answer --version".into(),
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|err| Refused::Failed(format!("The new binary failed: {err}")))?;
    let said = String::from_utf8_lossy(&output.stdout);
    let expected = format!("inbuxa-relay {version}");
    if !output.status.success() || said.trim() != expected {
        return Err(Refused::Failed(format!(
            "The new binary says {:?}, not {expected:?}",
            said.trim()
        )));
    }
    Ok(())
}

/// This process's binary, to replace.
pub fn current_exe() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.canonicalize().ok())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::{
        digest,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use inbuxa_relay_proto::{b64, release::signed_text};

    pub fn test_key() -> (Ed25519KeyPair, [u8; 32]) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).unwrap();
        let public = pair.public_key().as_ref().try_into().unwrap();
        (pair, public)
    }

    pub fn sign(pair: &Ed25519KeyPair, binary: &[u8], version: &str, target: &str) -> String {
        let signed = signed_text(&Release {
            version: version.into(),
            target: target.into(),
            sha256: digest::digest(&digest::SHA256, binary)
                .as_ref()
                .try_into()
                .unwrap(),
        });
        format!(
            "{signed}signature {}\n",
            b64::encode(pair.sign(signed.as_bytes()).as_ref())
        )
    }

    /// A stand-in release: a script that says it is `version`.
    pub fn script(version: &str) -> Vec<u8> {
        format!("#!/bin/sh\necho 'inbuxa-relay {version}'\n").into_bytes()
    }

    #[test]
    fn checks_before_installing() {
        let (pair, key) = test_key();
        let binary = script("27.2.0");
        let target = release::target();
        let good = sign(&pair, &binary, "27.2.0", &target);
        assert!(check(&binary, &good, &[key], "27.1.0").is_ok());

        // RL-T16: a bad signature, or an older version, is refused
        let other = Ed25519KeyPair::from_seed_unchecked(&[4u8; 32]).unwrap();
        let forged = sign(&other, &binary, "27.2.0", &target);
        assert!(matches!(
            check(&binary, &forged, &[key], "27.1.0"),
            Err(Refused::Invalid(_))
        ));
        let older = sign(&pair, &binary, "27.0.3", &target);
        assert!(matches!(
            check(&binary, &older, &[key], "27.1.0"),
            Err(Refused::Invalid(_))
        ));
        assert!(matches!(
            check(&binary, &good, &[key], "27.2.0"),
            Err(Refused::Invalid(_))
        ));
        let elsewhere = sign(&pair, &binary, "27.2.0", "riscv64-linux-musl");
        assert!(matches!(
            check(&binary, &elsewhere, &[key], "27.1.0"),
            Err(Refused::Invalid(_))
        ));
        assert!(matches!(
            check(&binary, &good, &[], "27.1.0"),
            Err(Refused::Invalid(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installs_what_runs() {
        let dir = std::env::temp_dir().join(format!("inbuxa-relay-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("inbuxa-relay");
        fs::write(&exe, script("27.1.0")).unwrap();

        // One that says another version is refused, and nothing changes
        assert!(matches!(
            install(&exe, &script("27.3.0"), "27.2.0"),
            Err(Refused::Failed(_))
        ));
        assert_eq!(fs::read(&exe).unwrap(), script("27.1.0"));
        assert!(!dir.join(".inbuxa-relay.new").exists());
        assert!(!dir.join("inbuxa-relay.previous").exists());

        install(&exe, &script("27.2.0"), "27.2.0").unwrap();
        assert_eq!(fs::read(&exe).unwrap(), script("27.2.0"));
        assert_eq!(
            fs::read(dir.join("inbuxa-relay.previous")).unwrap(),
            script("27.1.0")
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
