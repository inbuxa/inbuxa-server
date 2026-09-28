/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Deletes rotated log files past `inbuxa:LogSettings.keepForDays`
//! (personal-data catalog spec, D1). Log files are local, so every node
//! cleans its own: hourly, and at once when the settings change here.

use common::{BuildServer, Inner, Server};
use inbuxa_features::security::log_files;
use registry::schema::structs::Tracer;
use std::{path::PathBuf, sync::Arc, time::Duration};

const EVERY: Duration = Duration::from_secs(3600);

pub fn spawn_log_retention(inner: Arc<Inner>) {
    tokio::spawn(async move {
        loop {
            let server = inner.build_server();
            if let Err(err) = purge(&server).await {
                trc::error!(err.details("Failed to delete old log files"));
            }
            tokio::select! {
                _ = tokio::time::sleep(EVERY) => {}
                _ = log_files::CHANGED.notified() => {}
            }
        }
    });
}

async fn purge(server: &Server) -> trc::Result<()> {
    let Some(days) = log_files::get(&server.core.storage.data)
        .await?
        .keep_for_days
    else {
        return Ok(());
    };
    let keep = Duration::from_secs(days.max(log_files::MIN_KEEP_DAYS) * 86_400);
    for tracer in server.registry().list::<Tracer>().await? {
        let Tracer::Log(log) = tracer.object else {
            continue;
        };
        if !log.enable || log.path.is_empty() {
            continue;
        }
        let (dir, prefix) = (PathBuf::from(&log.path), log.prefix.clone());
        let result = tokio::task::spawn_blocking(move || log_files::purge(&dir, &prefix, keep))
            .await
            .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))?;
        if let Err(err) = result {
            trc::event!(
                Telemetry(trc::TelemetryEvent::LogError),
                Details = "Failed to delete old log files",
                Path = log.path.clone(),
                Reason = err.to_string(),
            );
        }
    }
    Ok(())
}
