/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use registry::schema::structs::DataStore;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::io::AsyncWriteExt;
use utils::snowflake::SnowflakeIdGenerator;

pub(crate) enum RegistryInit {
    Ok(DataStore),
    Err(String),
    Bootstrap,
}

impl RegistryStoreInner {
    pub(crate) fn new(local_path: PathBuf) -> Self {
        let env_hostname = types::branding::env_var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| {
                let host = gethostname::gethostname();
                let host = host.to_string_lossy();
                if host.parse::<IpAddr>().is_err() {
                    host.to_lowercase()
                } else {
                    "localhost".to_string()
                }
            });

        Self {
            local_path,
            store: Store::None,
            id_generator: SnowflakeIdGenerator::new(),
            node_id: Default::default(),
            env_recovery_mode: types::branding::env_var("RECOVERY_MODE")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            // inbuxa: K-S2: or from INBUXA_RECOVERY_ADMIN_FILE; boot has
            // already refused a bad one (check_secret_env_vars)
            env_recovery_admin: types::branding::secret_env_var("RECOVERY_ADMIN")
                .ok()
                .flatten()
                .and_then(|v| {
                    v.split_once(':')
                        .map(|(a, p)| (a.trim().to_string(), p.trim().to_string()))
                })
                .filter(|(a, p)| !a.is_empty() && !p.is_empty()),
            env_cluster_role: types::branding::env_var("ROLE")
                .ok()
                .filter(|r| !r.is_empty()),
            env_push_shard_id: types::branding::env_var("PUSH_SHARD")
                .ok()
                .and_then(|id| id.parse::<u32>().ok().and_then(|v| v.checked_sub(1)))
                .unwrap_or(0),
            env_public_url: types::branding::env_var("PUBLIC_URL")
                .ok()
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|u| !u.is_empty())
                .or_else(|| {
                    types::branding::env_var("HTTPS_PORT").ok().and_then(|p| {
                        p.parse::<u16>()
                            .ok()
                            .map(|port| format!("https://{}:{}", env_hostname, port))
                    })
                }),
            env_hostname,
            renamed_from: None,
            write_hook: Default::default(),
        }
    }

    pub(crate) async fn read_data_store(&self) -> RegistryInit {
        match tokio::fs::read_to_string(&self.local_path).await {
            Ok(contents) => match serde_json::from_str::<DataStore>(&contents) {
                Ok(data_store) => RegistryInit::Ok(data_store),
                Err(err) => RegistryInit::Err(format!(
                    "Failed to parse data store settings at {}: {}",
                    self.local_path.display(),
                    err
                )),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => RegistryInit::Bootstrap,
            Err(err) => RegistryInit::Err(format!(
                "Failed to read data store settings at {}: {}",
                self.local_path.display(),
                err
            )),
        }
    }
}

impl RegistryStore {
    pub async fn write_data_store(&self, data_store: &DataStore) -> trc::Result<()> {
        let json_text = serde_json::to_string(data_store).map_err(|err| {
            trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                .into_err()
                .caused_by(trc::location!())
                .reason(err)
        })?;
        write_private(&self.0.local_path, json_text.as_bytes())
            .await
            .map_err(|err| {
                trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                    .into_err()
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Path, self.0.local_path.display().to_string())
                    .reason(err)
            })
    }

    /// inbuxa: K-S5: whether the data store settings file can be written. It
    /// can't where something outside the server manages it, such as a
    /// read-only mount on Kubernetes (the chart's server.dataStore).
    pub async fn data_store_is_writable(&self) -> bool {
        match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.0.local_path)
            .await
        {
            Ok(_) => true,
            Err(err) => !is_read_only(&err),
        }
    }
}

/// inbuxa: the data store settings hold its credentials, so they are written
/// readable by the server's user only (0600), whatever the umask: to a new
/// file beside the old one that replaces it in one rename. Where that can't
/// be done (a directory the server can't add files to, or a file mounted on
/// its own) the file is written in place, as before, and tightened to 0600.
async fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    // a link is followed, so the file it names is replaced, not the link
    let path = match tokio::fs::canonicalize(path).await {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(err) => return Err(err),
    };
    if replace_private(&path, contents).await.is_ok() {
        Ok(())
    } else {
        write_private_in_place(&path, contents).await
    }
}

async fn replace_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let tmp = dir.join(format!(
        ".{}.{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));

    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp).await?;
    let result = async {
        set_private(&file).await?;
        file.write_all(contents).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return result;
    }

    // the rename itself survives a crash once the directory is synced
    if let Ok(dir) = tokio::fs::File::open(dir).await {
        let _ = dir.sync_all().await;
    }
    Ok(())
}

async fn write_private_in_place(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    // a file another user owns can't be changed; it keeps its mode
    let _ = set_private(&file).await;
    file.write_all(contents).await?;
    file.sync_all().await
}

async fn set_private(file: &tokio::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// inbuxa: K-S5: an error that says the file is managed elsewhere, as
/// against one worth reporting as a failure
pub(crate) fn is_read_only(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ReadOnlyFilesystem | std::io::ErrorKind::PermissionDenied
    )
}

#[cfg(test)]
mod tests {
    use super::is_read_only;

    // inbuxa: K-S5: a read-only config.json is one managed elsewhere, so a
    // save is refused as that rather than failed
    #[test]
    fn a_read_only_file_is_managed_elsewhere() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("inbuxa-ro-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let err = std::fs::OpenOptions::new().write(true).open(&path);
        // root can write anything; the check only means something otherwise
        if let Err(err) = err {
            assert!(is_read_only(&err));
        }
        let missing = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("absent.json"))
            .unwrap_err();
        assert!(!is_read_only(&missing));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // inbuxa: config.json holds the data store's credentials, so after a
    // write only the server's user can read it, whatever the umask, whether
    // the file is new, was left 0644 by an older version, or sits in a
    // directory the server can't create files in
    #[tokio::test]
    async fn data_store_settings_are_written_0600() {
        use crate::{RegistryStore, RegistryStoreInner};
        use registry::schema::structs::DataStore;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;

        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let dir = std::env::temp_dir().join(format!("inbuxa-config-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let store = RegistryStore(Arc::new(RegistryStoreInner::new(path.clone())));

        // a new file
        store.write_data_store(&DataStore::default()).await.unwrap();
        assert_eq!(mode(&path), 0o600, "a new config.json is {:o}", mode(&path));
        assert!(std::fs::read_to_string(&path).unwrap().contains("RocksDb"));

        // one an older version left readable by everyone
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        store.write_data_store(&DataStore::default()).await.unwrap();
        assert_eq!(
            mode(&path),
            0o600,
            "an existing config.json is {:o}",
            mode(&path)
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("RocksDb"));
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "the write left files beside config.json");

        // a link to the file stays a link, and the file it names is written
        let target = dir.join("target.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let linked = RegistryStore(Arc::new(RegistryStoreInner::new(link.clone())));
        linked
            .write_data_store(&DataStore::default())
            .await
            .unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(mode(&target), 0o600);
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("RocksDb")
        );

        // a writable file in a directory the server can't add files to is
        // written in place (root can write anywhere, so this means nothing
        // when the test runs as root)
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        let locked_path = locked.join("config.json");
        std::fs::write(&locked_path, "{}").unwrap();
        std::fs::set_permissions(&locked_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let in_place = RegistryStore(Arc::new(RegistryStoreInner::new(locked_path.clone())));
        let result = in_place.write_data_store(&DataStore::default()).await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.unwrap();
        assert_eq!(mode(&locked_path), 0o600);
        assert!(
            std::fs::read_to_string(&locked_path)
                .unwrap()
                .contains("RocksDb")
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
