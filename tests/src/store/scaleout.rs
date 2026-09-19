/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Scale-out storage acceptance tests, from
//! `docs/spec/features/scale-out-storage.md`: the sharded blob store over
//! FileSystem members (tests 2 to 8) and, built with `redis`, the sharded
//! in-memory and lookup stores (tests 20, 22 and 23). Each check names its
//! test number or requirement.

use crate::utils::server::TestServerBuilder;
use registry::{
    schema::{
        enums::CompressionAlgo,
        structs::{self, BlobStoreBase, FileSystemStore},
    },
    types::list::List,
};
use store::{
    BlobStore, Store,
    backend::{fs::FsStore, scaleout},
};
use types::blob_hash::BlobHash;

fn fs_member(dir: &std::path::Path) -> BlobStoreBase {
    std::fs::create_dir_all(dir).unwrap();
    BlobStoreBase::FileSystem(FileSystemStore {
        path: dir.to_str().unwrap().to_string(),
        ..Default::default()
    })
}

async fn open_blob(
    data: &Store,
    dirs: &[std::path::PathBuf],
) -> (Result<BlobStore, String>, Vec<String>) {
    let mut warnings = Vec::new();
    let result = scaleout::ShardedBlobStore::open(
        structs::ShardedBlobStore {
            stores: List::from_iter(dirs.iter().map(|dir| fs_member(dir))),
        },
        data,
        &mut warnings,
    )
    .await;
    (result, warnings)
}

async fn single(dir: &std::path::Path) -> BlobStore {
    FsStore::open(FileSystemStore {
        path: dir.to_str().unwrap().to_string(),
        ..Default::default()
    })
    .await
    .unwrap()
}

/// Which members hold a blob.
async fn holders(dirs: &[std::path::PathBuf], key: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    for (index, dir) in dirs.iter().enumerate() {
        if single(dir)
            .await
            .get_blob(key, 0..usize::MAX)
            .await
            .unwrap()
            .is_some()
        {
            found.push(index);
        }
    }
    found
}

/// `cargo test -p tests scaleout_blob_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scaleout_blob_tests() {
    let test = TestServerBuilder::new("scaleout_blob_tests")
        .await
        .build()
        .await;
    let data = test.server.core.storage.data.clone();
    let base = test.temp_dir.path.join("shards");
    let dirs = (1..=4)
        .map(|n| base.join(format!("member-{n}")))
        .collect::<Vec<_>>();

    // Test 2: each blob lands on exactly its home member (ST-16)
    let (three, warnings) = open_blob(&data, &dirs[..3]).await;
    let three = three.expect("test 8: a sharded blob store builds");
    assert!(warnings.is_empty(), "{warnings:?}");
    let blobs = (0..60u32)
        .map(|n| {
            let content = format!("blob number {n} with some content").into_bytes();
            (BlobHash::generate(&content), content)
        })
        .collect::<Vec<_>>();
    for (hash, content) in &blobs {
        three
            .put_blob(hash.as_slice(), content, CompressionAlgo::Lz4)
            .await
            .unwrap();
        assert_eq!(
            holders(&dirs[..3], hash.as_slice()).await,
            vec![scaleout::home(hash.as_slice(), 3)],
            "test 2"
        );
        assert_eq!(
            three
                .get_blob(hash.as_slice(), 5..11)
                .await
                .unwrap()
                .as_deref(),
            Some(&content[5..11]),
            "test 2: ranges"
        );
    }
    let spread = (0..3)
        .map(|m| {
            blobs
                .iter()
                .filter(|(h, _)| scaleout::home(h.as_slice(), 3) == m)
                .count()
        })
        .collect::<Vec<_>>();
    assert!(spread.iter().all(|n| *n > 0), "test 2: spread {spread:?}");

    // Test 7: two members naming the same directory (ST-22)
    let (same, _) = open_blob(&data, &[dirs[0].clone(), dirs[0].clone()]).await;
    assert!(
        same.err().is_some_and(|e| e.contains("same place")),
        "test 7"
    );
    let (alone, _) = open_blob(&data, &dirs[..1]).await;
    assert!(alone.is_err(), "ST-22: at least two members");

    // Test 3: a fourth member; every blob still reads, new ones land by the
    // new mapping (ST-17, ST-19, ST-20)
    let (four, warnings) = open_blob(&data, &dirs).await;
    let four = four.unwrap();
    assert!(
        warnings.iter().any(|w| w.contains("changed")),
        "ST-20: {warnings:?}"
    );
    for (hash, content) in &blobs {
        assert_eq!(
            four.get_blob(hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .as_deref(),
            Some(content.as_slice()),
            "test 3"
        );
    }
    let fresh = BlobHash::generate(b"written after the fourth member");
    four.put_blob(
        fresh.as_slice(),
        b"written after the fourth member",
        CompressionAlgo::None,
    )
    .await
    .unwrap();
    assert_eq!(
        holders(&dirs, fresh.as_slice()).await,
        vec![scaleout::home(fresh.as_slice(), 4)],
        "test 3"
    );

    // Test 6: a blob whose home moved is deleted from where it is (ST-18)
    let moved = blobs
        .iter()
        .find(|(h, _)| scaleout::home(h.as_slice(), 3) != scaleout::home(h.as_slice(), 4))
        .expect("some blob's home moved");
    assert!(
        four.delete_blob(moved.0.as_slice()).await.unwrap(),
        "test 6"
    );
    assert!(
        holders(&dirs, moved.0.as_slice()).await.is_empty(),
        "test 6"
    );
    assert!(
        !four.delete_blob(moved.0.as_slice()).await.unwrap(),
        "ST-18"
    );

    // Test 5: one member unreadable; the others still serve (ST-21)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let broken = 1usize;
        std::fs::set_permissions(&dirs[broken], std::fs::Permissions::from_mode(0o000)).unwrap();
        for (hash, content) in &blobs {
            if *hash == moved.0 {
                continue;
            }
            let located = holders_unchecked(&dirs, hash.as_slice(), broken).await;
            let result = four.get_blob(hash.as_slice(), 0..usize::MAX).await;
            match located {
                // On a readable member: served, whatever its home
                Some(_) => {
                    assert_eq!(
                        result.unwrap().as_deref(),
                        Some(content.as_slice()),
                        "test 5"
                    )
                }
                // On the unreadable one: a miss or an error, never the blob
                // (the FileSystem backend reports an unreadable file as missing)
                None => assert!(!matches!(result, Ok(Some(_))), "test 5"),
            }
        }
        let homed_on_broken = (0u32..)
            .map(|n| BlobHash::generate(format!("new blob {n}").as_bytes()))
            .find(|h| scaleout::home(h.as_slice(), 4) == broken)
            .unwrap();
        assert!(
            four.put_blob(homed_on_broken.as_slice(), b"x", CompressionAlgo::None)
                .await
                .is_err(),
            "test 5: a write homed on the broken member fails"
        );
        std::fs::set_permissions(&dirs[broken], std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Test 4: a recorded member removed: refused, named (ST-20)
    let (removed, _) = open_blob(&data, &dirs[..2]).await;
    let err = removed.err().expect("test 4: refused");
    assert!(
        err.contains("member-3") && err.contains("member-4"),
        "test 4: {err}"
    );

    // ST-1: nothing changes for a server without one
    assert!(
        matches!(test.server.core.storage.blob, BlobStore::Store(_)),
        "the default blob store is unchanged (ST-1)"
    );

    test.temp_dir.delete();
}

/// Where a blob is, skipping a member that can't be read.
async fn holders_unchecked(dirs: &[std::path::PathBuf], key: &[u8], skip: usize) -> Option<usize> {
    for (index, dir) in dirs.iter().enumerate() {
        if index == skip {
            continue;
        }
        if let Ok(Some(_)) = single(dir).await.get_blob(key, 0..usize::MAX).await {
            return Some(index);
        }
    }
    None
}

/// Tests 20, 22 and 23 over two databases of one Redis server, which the
/// store treats as two members. `cargo test -p tests --features redis
/// scaleout_memory_tests -- --ignored`.
#[cfg(feature = "redis")]
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scaleout_memory_tests() {
    use store::{InMemoryStore, dispatch::lookup::KeyValue};

    crate::utils::containers::ensure_redis().await;
    let test = TestServerBuilder::new("scaleout_memory_tests")
        .await
        .build()
        .await;
    let data = test.server.core.storage.data.clone();
    let member = |db: u32| {
        structs::InMemoryStoreBase::Redis(structs::RedisStore {
            url: format!("redis://127.0.0.1/{db}"),
            ..Default::default()
        })
    };
    let open = |dbs: Vec<u32>, name: &'static str| {
        let data = data.clone();
        async move {
            let mut warnings = Vec::new();
            let store = scaleout::ShardedInMemoryStore::open(
                structs::ShardedInMemoryStore {
                    stores: List::from_iter(dbs.into_iter().map(member)),
                },
                name,
                &data,
                &mut warnings,
            )
            .await;
            (store, warnings)
        }
    };
    let single = |db: u32| async move {
        store::backend::redis::RedisStore::open_single(structs::RedisStore {
            url: format!("redis://127.0.0.1/{db}"),
            ..Default::default()
        })
        .await
        .unwrap()
    };

    // Test 20: keys live on their home member (ST-23)
    let (sharded, warnings) = open(vec![11, 12], "").await;
    let sharded = sharded.unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(sharded.is_redis(), "ST-3");
    let members = [single(11).await, single(12).await];
    for n in 0..40u32 {
        let key = format!("scaleout-key-{n}").into_bytes();
        sharded
            .key_set(KeyValue::new(key.clone(), b"value".to_vec()).expires(60))
            .await
            .unwrap();
        let home = scaleout::home(&key, 2);
        for (index, member) in members.iter().enumerate() {
            assert_eq!(
                member.key_exists(key.clone()).await.unwrap(),
                index == home,
                "test 20: {n}"
            );
        }
        assert_eq!(
            sharded
                .key_get::<String>(key.clone())
                .await
                .unwrap()
                .as_deref(),
            Some("value")
        );
    }
    // Counters, locks and rate limits behave as with one Redis
    for n in 0..3 {
        assert_eq!(
            sharded
                .counter_incr(KeyValue::new(b"scaleout-counter".to_vec(), 2), true)
                .await
                .unwrap(),
            2 * (n + 1)
        );
    }
    assert!(sharded.try_lock(7, b"scaleout-lock", 30).await.unwrap());
    assert!(!sharded.try_lock(7, b"scaleout-lock", 30).await.unwrap());
    sharded.remove_lock(7, b"scaleout-lock").await.unwrap();
    assert!(
        sharded.try_lock(7, b"scaleout-lock", 30).await.unwrap(),
        "ST-23"
    );
    let rate = registry::schema::structs::Rate {
        count: 2,
        period: registry::types::duration::Duration::from_millis(60_000),
    };
    assert!(
        sharded
            .is_rate_allowed(9, b"who", &rate, false)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sharded
            .is_rate_allowed(9, b"who", &rate, false)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sharded
            .is_rate_allowed(9, b"who", &rate, false)
            .await
            .unwrap()
            .is_some()
    );
    // A prefix delete clears both members (ST-24)
    sharded.key_delete_prefix(b"scaleout-").await.unwrap();
    for member in &members {
        for n in 0..40u32 {
            assert!(
                !member
                    .key_exists(format!("scaleout-key-{n}").into_bytes())
                    .await
                    .unwrap(),
                "ST-24"
            );
        }
    }
    sharded.purge_in_memory_store().await.unwrap();

    // Test 22: a node with a different member list is told so (ST-26)
    let (other, warnings) = open(vec![11, 13], "").await;
    assert!(other.is_ok(), "ST-26: it still runs");
    assert!(
        warnings.iter().any(|w| w.contains("differs")),
        "test 22: {warnings:?}"
    );

    // Test 23: a sharded lookup store (ST-28)
    let (lookup, _) = open(vec![11, 12], "scaleout-ns").await;
    let lookup: InMemoryStore = lookup.unwrap();
    lookup
        .key_set(KeyValue::new(b"scaleout-lookup".to_vec(), b"1".to_vec()))
        .await
        .unwrap();
    assert!(
        lookup
            .key_exists(b"scaleout-lookup".to_vec())
            .await
            .unwrap()
    );
    lookup
        .key_delete(b"scaleout-lookup".to_vec())
        .await
        .unwrap();
    assert!(lookup.clone().into_store().is_none(), "ST-28");

    // ST-29: duplicates refused
    let (duplicate, _) = open(vec![11, 11], "").await;
    assert!(duplicate.is_err(), "ST-29");

    test.temp_dir.delete();
}
