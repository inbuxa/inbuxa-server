/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{
    imap::{AssertResult, ImapConnection, Type},
    server::TestServer,
};
use ahash::AHashSet;
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID, TRASH_ID},
};
use imap_proto::ResponseType;
use registry::{
    schema::{
        enums::{TaskAccountMaintenanceType, TaskStoreMaintenanceType},
        prelude::{ObjectType, Property},
        structs::{
            DataRetention, SpamClassifier, SpamTrainingSample, Task, TaskAccountMaintenance,
            TaskStatus, TaskStoreMaintenance,
        },
    },
    types::id::ObjectId,
};
use store::{
    IterateParams, LogKey, U32_LEN, U64_LEN, ValueKey,
    registry::RegistryQuery,
    write::{BlobLink, BlobOp, ValueClass, key::DeserializeBigEndian},
};
use types::{blob_hash::BlobHash, id::Id};

const EXPUNGE_TRASH_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn test(test: &mut TestServer) {
    println!("Running Account purge tests...");
    let inbox_id = Id::from(INBOX_ID).to_string();
    let trash_id = Id::from(TRASH_ID).to_string();
    let junk_id = Id::from(JUNK_ID).to_string();
    let admin = test.account("admin@example.org");

    // Set test settings
    admin
        .registry_update_setting(
            DataRetention {
                max_changes_history: Some(1),
                expunge_trash_after: Some(EXPUNGE_TRASH_AFTER.into()),
                ..Default::default()
            },
            &[Property::MaxChangesHistory, Property::ExpungeTrashAfter],
        )
        .await;
    admin
        .registry_update_setting(
            SpamClassifier {
                hold_samples_for: 1u64.into(),
                ..Default::default()
            },
            &[Property::HoldSamplesFor],
        )
        .await;
    admin.reload_settings().await;

    // Create test account
    let account = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &[],
            "jdoe@example.org",
        )
        .await;
    let client = account.jmap_client().await;

    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate("jdoe@example.org", "this is a very strong password")
        .await;
    imap.send("STATUS INBOX (UIDNEXT MESSAGES UNSEEN)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0");

    // Create test messages
    let mut message_ids = Vec::new();
    let mut pass = 0;
    let mut changes = AHashSet::new();

    loop {
        pass += 1;
        for folder_id in [&inbox_id, &trash_id, &junk_id] {
            message_ids.push(
                client
                    .email_import(
                        format!(
                            concat!(
                                "From: bill@example.org\r\n",
                                "To: jdoe@example.org\r\n",
                                "Subject: TPS Report #{} {}\r\n",
                                "\r\n",
                                "I'm going to need those TPS reports ASAP. ",
                                "So, if you could do that, that'd be great."
                            ),
                            pass, folder_id
                        )
                        .into_bytes(),
                        [folder_id],
                        None::<Vec<&str>>,
                        None,
                    )
                    .await
                    .unwrap()
                    .take_id(),
            );
        }

        if pass == 1 {
            let (changes_, is_truncated) = get_changes(&test.server).await;
            assert!(!is_truncated);
            changes = changes_;
            tokio::time::sleep(EXPUNGE_TRASH_AFTER + std::time::Duration::from_secs(1)).await;
        } else {
            break;
        }
    }

    // Check IMAP status
    imap.send("LIST \"\" \"*\" RETURN (STATUS (MESSAGES))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\"INBOX\" (MESSAGES 2)")
        .assert_contains("\"Deleted Items\" (MESSAGES 2)")
        .assert_contains("\"Junk Mail\" (MESSAGES 2)");

    // Make sure both messages and changes are present
    assert_eq!(
        test.server
            .get_cached_messages(account.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        6
    );

    // Purge junk/trash messages and old changes
    admin
        .registry_create_object(Task::AccountMaintenance(TaskAccountMaintenance {
            account_id: account.id(),
            maintenance_type: TaskAccountMaintenanceType::Purge,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    let cache = test
        .server
        .get_cached_messages(account.id().document_id())
        .await
        .unwrap();

    // Only 4 messages should remain
    assert_eq!(
        test.server
            .get_cached_messages(account.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        4
    );
    assert_eq!(cache.in_mailbox(INBOX_ID).count(), 2);
    assert_eq!(cache.in_mailbox(TRASH_ID).count(), 1);
    assert_eq!(cache.in_mailbox(JUNK_ID).count(), 1);

    // Check IMAP status
    imap.send("LIST \"\" \"*\" RETURN (STATUS (MESSAGES))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\"INBOX\" (MESSAGES 2)")
        .assert_contains("\"Deleted Items\" (MESSAGES 1)")
        .assert_contains("\"Junk Mail\" (MESSAGES 1)");

    // Compare changes
    let (new_changes, is_truncated) = get_changes(&test.server).await;
    assert!(!changes.is_empty());
    assert!(!new_changes.is_empty());
    assert!(is_truncated);
    for change in &changes {
        assert!(
            !new_changes.contains(change),
            "Change {change:?} was not purged, expected {} changes, got {}",
            changes.len(),
            new_changes.len()
        );
    }

    // Delete expired training samples
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;

    // inbuxa: a sample trained just before the account goes, held for a
    // month, so nothing but the destroy could remove it
    test.wait_for_tasks().await;
    admin
        .registry_update_setting(
            SpamClassifier {
                hold_samples_for: (30 * 86_400_000u64).into(), // milliseconds
                ..Default::default()
            },
            &[Property::HoldSamplesFor],
        )
        .await;
    admin.reload_settings().await;
    client
        .email_import(
            concat!(
                "From: bill@example.org\r\n",
                "To: jdoe@example.org\r\n",
                "Subject: TPS Report, held\r\n",
                "\r\n",
                "This one stays in the training samples for a month."
            )
            .as_bytes()
            .to_vec(),
            [&junk_id],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    let account_id = account.id().document_id();
    let samples = account_samples(&test.server, account_id).await;
    assert!(
        samples
            .iter()
            .any(|(_, hash, until)| *until > store::write::now() + 86400 && !hash.is_empty()),
        "no held sample to check: {samples:?}"
    );

    // Delete account
    // inbuxa: an index task that runs while the account is destroyed, after
    // its index was first cleared, leaves nothing of it in the index
    let account_id = account.id().document_id();
    services::task_manager::destroy_account::test_hooks::index_while_destroying(account_id);
    admin.destroy_account(account).await;
    test.wait_for_tasks().await;
    assert!(
        !services::task_manager::destroy_account::test_hooks::is_pending(account_id),
        "the account was destroyed without indexing it on the way"
    );
    // inbuxa: the destroyed account's samples and the links that kept their
    // messages are gone
    let left = account_samples(&test.server, account_id).await;
    assert!(left.is_empty(), "samples left after the destroy: {left:?}");
    for (id, hash, until) in samples {
        let link = test
            .server
            .store()
            .get_value::<ObjectId>(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Blob(BlobOp::Link {
                    hash,
                    to: BlobLink::Temporary { until },
                }),
            })
            .await
            .unwrap();
        assert!(link.is_none(), "sample {id}'s blob link was left");
    }
    test.assert_is_empty().await;

    // Reset settings
    admin
        .registry_update_setting(SpamClassifier::default(), &[Property::HoldSamplesFor])
        .await;
    test.cleanup().await;
}

async fn get_changes(server: &Server) -> (AHashSet<(u64, u8)>, bool) {
    let mut changes = AHashSet::new();
    let mut is_truncated = false;
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(
                LogKey {
                    account_id: 0,
                    collection: 0,
                    change_id: 0,
                },
                LogKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    change_id: u64::MAX,
                },
            )
            .ascending(),
            |key, value| {
                if !value.is_empty() {
                    changes.insert((
                        key.deserialize_be_u64(key.len() - U64_LEN).unwrap(),
                        key[U32_LEN],
                    ));
                } else {
                    is_truncated = true;
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    (changes, is_truncated)
}

// inbuxa: an account's spam training samples: id, blob and hold
async fn account_samples(server: &Server, account_id: u32) -> Vec<(Id, BlobHash, u64)> {
    let mut samples = Vec::new();
    for id in server
        .registry()
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::SpamTrainingSample).with_account(account_id),
        )
        .await
        .unwrap()
    {
        if let Some(sample) = server
            .registry()
            .object::<SpamTrainingSample>(id)
            .await
            .unwrap()
        {
            samples.push((
                id,
                sample.blob_id.hash,
                sample.expires_at.timestamp() as u64,
            ));
        } else {
            samples.push((id, BlobHash::default(), 0));
        }
    }
    samples
}
