/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! inbuxa: K-C5: `--check`, whether the data layer this server is set up for
//! can be used: the data store, the blob store and the coordinator, in that
//! order. It reads the settings and writes one small object to the blob
//! store, which it deletes again; it starts nothing and claims no node id.
//!
//! Each part prints a line. A part that fails says why, in the words and with
//! the exit code of `store::registry::startup`; with more than one failing,
//! the exit code is the first one's. The Helm chart runs it as an init
//! container, so a pod that can't use the data layer says which part, and
//! why, in its status.

use coordinator::Coordinator;
use registry::schema::{enums::CompressionAlgo, structs};
use std::path::PathBuf;
use store::{
    BlobStore, RegistryStore,
    registry::{
        bootstrap::Bootstrap,
        startup::{Part, StartupError, StartupFailure},
    },
};

pub async fn run(config_path: PathBuf) -> ! {
    let registry = match RegistryStore::init(config_path.clone(), false).await {
        Ok(registry) => registry,
        Err(err) => fail(err),
    };
    if registry.is_bootstrap_mode() {
        fail(StartupError::new(
            StartupFailure::Config,
            format!(
                "there are no data store settings at {}",
                config_path.display()
            ),
        ));
    }
    println!("ok    data store");
    let mut bp = Bootstrap::new(registry).await;

    let mut failures = Vec::new();
    match blob_store(&mut bp).await {
        Ok(found) => println!("ok    blob store: {found}"),
        Err(err) => failures.push(err),
    }
    match coordinator(&mut bp).await {
        Ok(found) => println!("ok    coordinator: {found}"),
        Err(err) => failures.push(err),
    }

    let code = failures.first().map(|err| err.kind.exit_code());
    for err in failures {
        eprintln!("⚠️ Check failed: {err}");
    }
    std::process::exit(code.unwrap_or(0));
}

fn fail(err: StartupError) -> ! {
    eprintln!("⚠️ Check failed: {err}");
    std::process::exit(err.kind.exit_code());
}

/// The setting couldn't be read: a fault of the data store, which answered
/// a moment ago.
fn unreadable(part: Part, err: trc::Error) -> StartupError {
    StartupError::of_part(
        Part::DataStore,
        StartupFailure::of(&err),
        format!("reading the {} settings: {err}", part.name()),
    )
}

async fn blob_store(bp: &mut Bootstrap) -> Result<String, StartupError> {
    let part = Part::BlobStore;
    let config = bp
        .setting::<structs::BlobStore>()
        .await
        .map_err(|err| unreadable(part, err))?;
    if matches!(config, structs::BlobStore::Default) {
        return Ok("kept in the data store".into());
    }
    let mut warnings = Vec::new();
    let store = BlobStore::open(config, &bp.data_store, &mut warnings)
        .await
        .map_err(|err| StartupError::of_part(part, StartupFailure::Config, err))?;

    // Everything the server does to a blob: write it, read it back, delete it
    let key = format!(
        ".inbuxa-check/{}-{}",
        bp.registry.local_hostname(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let data = b"inbuxa --check";
    let failed = |what: &str, err: trc::Error| {
        StartupError::of_part(part, StartupFailure::of(&err), format!("{what}: {err}"))
    };
    store
        .put_blob(key.as_bytes(), data, CompressionAlgo::None)
        .await
        .map_err(|err| failed("writing a test object", err))?;
    let read = store
        .get_blob(key.as_bytes(), 0..usize::MAX)
        .await
        .map_err(|err| failed("reading the test object back", err));
    let deleted = store
        .delete_blob(key.as_bytes())
        .await
        .map_err(|err| failed("deleting the test object", err));
    match read? {
        Some(read) if read == data => {}
        _ => {
            return Err(StartupError::of_part(
                part,
                StartupFailure::Other,
                format!("the test object {key} read back differently, or not at all"),
            ));
        }
    }
    deleted?;
    Ok("wrote, read and deleted a test object".into())
}

async fn coordinator(bp: &mut Bootstrap) -> Result<String, StartupError> {
    let part = Part::Coordinator;
    let config = bp
        .setting::<structs::Coordinator>()
        .await
        .map_err(|err| unreadable(part, err))?;
    let none = matches!(config, structs::Coordinator::Disabled);
    match Coordinator::probe(config).await {
        Ok(Some(found)) => Ok(found),
        Ok(None) if none => Ok("none, so this server can't run beside others".into()),
        Ok(None) => Ok("not one this check can test".into()),
        Err((kind, message)) => Err(StartupError::of_part(part, kind, message)),
    }
}
