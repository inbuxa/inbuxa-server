/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use registry::schema::structs::DataStore;
use std::{net::IpAddr, path::PathBuf};
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
        tokio::fs::write(&self.0.local_path, json_text)
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
}
