/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: a tracer whose own settings change is started over by the reload
// that follows the write: a Log tracer moved to another directory writes
// there from then on, and no event is lost or written twice on the way.

use crate::utils::{
    jmap::JmapResponse,
    server::{TestServer, TestServerBuilder},
};
use registry::{
    schema::{
        enums::{EventPolicy, LogRotateFrequency, TracingLevel},
        prelude::ObjectType,
        structs::{Expression, MtaStageAuth, Tracer, TracerLog},
    },
    types::map::Map,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use trc::{EventType, ServerEvent};

const PREFIX: &str = "tracer-reload";
const MAX_SEQ: usize = 100_000;

#[tokio::test(flavor = "multi_thread")]
pub async fn tracer_reload_tests() {
    let mut test = TestServerBuilder::new("tracer_reload_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;

    let admin = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
            "Admin",
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin.id(), &["user", "system"])
        .await;
    test.insert_account(admin);

    test_log_tracer_moves(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn test_log_tracer_moves(test: &TestServer) {
    println!("Running Log tracer path change...");
    let admin = test.account("admin@example.org");
    let old_dir = test.temp_dir.path.join("tracer-old");
    let new_dir = test.temp_dir.path.join("tracer-new");
    for dir in [&old_dir, &new_dir] {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
    }
    let old_file = old_dir.join(PREFIX);
    let new_file = new_dir.join(PREFIX);

    // A Log tracer for one event type, written to the old directory
    let response = admin
        .registry_create([Tracer::Log(TracerLog {
            path: old_dir.to_string_lossy().into_owned(),
            prefix: PREFIX.into(),
            rotate: LogRotateFrequency::Never,
            ansi: false,
            multiline: false,
            enable: true,
            level: TracingLevel::Trace,
            lossy: false,
            events: Map::new(vec![EventType::Server(ServerEvent::RecoveryMode)]),
            events_policy: EventPolicy::Include,
        })])
        .await;
    assert_applied(&response);
    let tracer_id = response.created_id(0);
    emit("marker-before");
    wait_for(&old_file, "marker-before").await;

    // Events keep coming while the path changes, until the reload has run
    let stop = Arc::new(AtomicBool::new(false));
    let stream = tokio::spawn({
        let stop = stop.clone();
        async move {
            let mut i = 0;
            while i < MAX_SEQ && (i < 2000 || !stop.load(Ordering::Relaxed)) {
                emit(&format!("seq-{i:06}-end"));
                if i % 50 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                i += 1;
            }
            i
        }
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    let response = admin
        .registry_update(
            ObjectType::Tracer,
            [(tracer_id, json!({"path": new_dir.to_string_lossy()}))],
        )
        .await;
    assert_applied(&response);
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.store(true, Ordering::Relaxed);
    let sent = stream.await.unwrap();
    assert!(sent < MAX_SEQ, "the stream outran the reload");

    // Once the reload has run, events go to the new file only
    emit("marker-after");
    wait_for(&new_file, "marker-after").await;
    wait_for(&new_file, &format!("seq-{:06}-end", sent - 1)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let old = read(&old_file);
    let new = read(&new_file);
    assert!(!old.contains("marker-after"), "old file still written to");
    assert!(!new.contains("marker-before"));

    // Every event written once, in one file or the other
    let old_seq = count_seq(&old);
    let new_seq = count_seq(&new);
    println!(
        "{} events in the old file, {} in the new one",
        old_seq.iter().filter(|c| **c > 0).count(),
        new_seq.iter().filter(|c| **c > 0).count()
    );
    for i in 0..sent {
        assert_eq!(
            old_seq[i] + new_seq[i],
            1,
            "seq-{i:06} written {} + {} times",
            old_seq[i],
            new_seq[i]
        );
    }
    assert!(
        new_seq.iter().any(|c| *c > 0),
        "no event of the stream reached the new file"
    );

    // Removing the tracer stops it
    let response = admin
        .registry_destroy(ObjectType::Tracer, [tracer_id])
        .await;
    assert_applied(&response);
    tokio::time::sleep(Duration::from_millis(200)).await;
    emit("marker-removed");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!read(&new_file).contains("marker-removed"));
    assert!(!read(&old_file).contains("marker-removed"));
}

// inbuxa: 1.0 dropped ServerEvent::Licensing; RecoveryMode is just as quiet
// while the tests run, so it stands in as the marker event
fn emit(marker: &str) {
    trc::event!(Server(ServerEvent::RecoveryMode), Details = marker.to_string());
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn count_seq(text: &str) -> Vec<u32> {
    let mut counts = vec![0u32; MAX_SEQ];
    for part in text.split("seq-").skip(1) {
        if let Some(n) = part.get(..6).and_then(|n| n.parse::<usize>().ok())
            && part[6..].starts_with("-end")
        {
            counts[n] += 1;
        }
    }
    counts
}

async fn wait_for(path: &PathBuf, marker: &str) {
    let started = Instant::now();
    while !read(path).contains(marker) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{marker} not in {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn assert_applied(response: &JmapResponse) {
    assert_eq!(
        response.pointer("/methodResponses/0/1/x:settingsReload"),
        Some(&json!({"applied": true})),
        "{response:?}"
    );
}
