/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Rereads certificates kept in files when the files change: stored
//! certificates whose certificate or key is a File, and the directories in
//! INBUXA_TLS_CERTIFICATE_DIRS. Something outside the server renews them
//! (cert-manager, in Kubernetes, rewrites a mounted Secret), and
//! certificates are otherwise read only at start and when a Certificate
//! changes in the store. Files are local, so every node
//! watches its own: once a minute, it reads the files of every file-backed
//! certificate and reloads the certificates when their contents differ from
//! the last look. A reload that finds new dates writes them to the store,
//! which tells the other nodes to reload too.

use common::{
    BuildServer, Inner, Server, config::server::tls::certificate_dir_files, ipc::RegistryChange,
};
use registry::schema::{
    prelude::ObjectType,
    structs::{Certificate, PublicText, SecretText},
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

const EVERY: Duration = Duration::from_secs(60);

pub fn spawn_certificate_files(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let mut last = None;
        loop {
            let server = inner.build_server();
            match fingerprint(&server).await {
                Ok(seen) => {
                    // The first look is the baseline: the certificates were
                    // read when the server started
                    if last.as_ref().is_some_and(|last| *last != seen) {
                        reload(&server).await;
                    }
                    last = Some(seen);
                }
                Err(err) => {
                    trc::error!(err.details("Failed to list file-backed TLS certificates"));
                }
            }
            tokio::time::sleep(EVERY).await;
        }
    });
}

/// The contents of every file a certificate is kept in, hashed together.
/// None when no certificate is kept in a file. A file that can't be read
/// counts as empty: when it comes back, it's a change.
async fn fingerprint(server: &Server) -> trc::Result<Option<[u8; 32]>> {
    let mut paths = Vec::new();
    for (cert, key) in certificate_dir_files() {
        paths.push(cert.display().to_string());
        paths.push(key.display().to_string());
    }
    for cert in server.registry().list::<Certificate>().await? {
        if let PublicText::File(file) = &cert.object.certificate {
            paths.push(file.file_path.clone());
        }
        if let SecretText::File(file) = &cert.object.private_key {
            paths.push(file.file_path.clone());
        }
    }
    if paths.is_empty() {
        return Ok(None);
    }
    paths.sort();
    paths.dedup();
    let mut hash = Sha256::new();
    for path in paths {
        let contents = tokio::fs::read(&path).await.unwrap_or_default();
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update((contents.len() as u64).to_be_bytes());
        hash.update(&contents);
    }
    Ok(Some(hash.finalize().into()))
}

async fn reload(server: &Server) {
    match Box::pin(server.reload_registry(RegistryChange::Reload(ObjectType::Certificate))).await {
        // A certificate the files no longer give is logged as a build error;
        // a renewed one shows by its new dates in the store
        Ok(result) => result.log(),
        Err(err) => {
            trc::error!(
                err.details("Certificate files changed, but reloading them failed")
                    .caused_by(trc::location!())
            );
        }
    }
}
