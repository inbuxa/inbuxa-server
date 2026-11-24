/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    imap::Type,
    system::antispam::{HAM, SPAM, TEST},
    utils::{imap::AssertResult, server::TestServer, smtp::SmtpConnection},
};
use common::{
    Server,
    config::mailstore::spamfilter::SpamClassifier as SpamClassifierModel,
    ipc::RegistryChange,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use email::mailbox::JUNK_ID;
use imap_proto::ResponseType;
use registry::schema::{
    enums::TaskSpamFilterMaintenanceType,
    prelude::ObjectType,
    structs::{Task, TaskSpamFilterMaintenance, TaskStatus},
};
use serde_json::json;
use spam_filter::modules::classifier::SpamTrainer;
use std::sync::Arc;
use store::{
    Deserialize,
    write::{AlignedBytes, Archive},
};
use types::id::Id;

pub async fn test(test: &TestServer) {
    println!("Running Spam classifier tests...");
    let admin = test.account("admin@example.com");
    let account = test.account("sgd@example.com");
    let mut imap = account.imap_client().await;
    let account_id = account.id();

    // Make sure there are no training samples
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    assert_eq!(admin.spam_training_samples().await, vec![]);

    // inbuxa: #544: a plain APPEND to INBOX (a mailbox migration) trains
    // nothing; flagging the message $NotJunk does
    imap.append("INBOX", HAM[0]).await;
    assert_eq!(account.spam_training_samples().await, vec![]);
    imap.send_ok("SELECT INBOX").await;
    imap.send_ok("STORE 1 +FLAGS ($NotJunk)").await;

    // Train the classifier via APPEND
    imap.append("Junk Mail", SPAM[0]).await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 1);

    // Append two spam samples to "Drafts", then train the classifier via STORE and MOVE
    imap.append("Drafts", SPAM[1]).await;
    imap.append("Drafts", SPAM[2]).await;
    imap.send_ok("SELECT Drafts").await;
    imap.send_ok("STORE 1 +FLAGS ($Junk)").await;
    imap.send_ok("MOVE 2 \"Junk Mail\"").await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 3);

    // Add the remaining messages via APPEND; ham is flagged $NotJunk (#544)
    for message in HAM.iter().skip(1) {
        imap.send_ok(&format!(
            "APPEND INBOX ($NotJunk) {{{}+}}\r\n{}",
            message.len(),
            message
        ))
        .await;
    }
    for message in SPAM.iter().skip(3) {
        imap.append("Junk Mail", message).await;
    }
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 10);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);
    assert_eq!(samples.len(), 20);
    assert!(samples.iter().all(
        |(_, s)| s.blob_id.class.account_id() == account_id.document_id() && !s.delete_after_use
    ));

    // Train the classifier
    admin
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::Train,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    let model = spam_classifier_model(&test.server).await;
    assert_eq!(model.reservoir.ham.total_seen, 10);
    assert_eq!(model.reservoir.spam.total_seen, 10);
    assert_eq!(
        model.last_id,
        samples.iter().map(|(id, _)| id.id()).max().unwrap()
    );
    assert_eq!(account.spam_training_samples().await.len(), 20);
    assert!(test.server.inner.data.spam_classifier.load().is_active());

    // inbuxa: #545: a node that didn't train hears of the new model through
    // the SpamClassifier reload the training node broadcasts. Simulate a
    // node still on the model it loaded at boot (none), and run that reload.
    test.server
        .inner
        .data
        .spam_classifier
        .store(Arc::new(SpamClassifierModel::default()));
    assert!(!test.server.inner.data.spam_classifier.load().is_active());
    test.server
        .reload_registry(RegistryChange::Reload(ObjectType::SpamClassifier))
        .await
        .unwrap();
    assert!(
        test.server.inner.data.spam_classifier.load().is_active(),
        "the SpamClassifier reload didn't load the stored model"
    );

    // Send 3 test emails
    for message in TEST {
        let mut lmtp = SmtpConnection::connect().await;
        lmtp.ingest("bill@example.com", &["sgd@example.com"], message)
            .await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    imap.send_ok("SELECT INBOX").await;
    imap.send("FETCH 11 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: can someone explain")
        .assert_contains("X-Spam-Status: No")
        .assert_contains("PROB_HAM_HIGH");
    imap.send("FETCH 12 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: classifier test")
        .assert_contains("X-Spam-Status: No")
        .assert_contains_any(&["PROB_SPAM_UNCERTAIN", "PROB_HAM_LOW"]);
    imap.send_ok("SELECT \"Junk Mail\"").await;
    imap.send("FETCH 10 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($Junk")
        .assert_contains("Subject: save up to")
        .assert_contains("X-Spam-Status: Yes")
        .assert_contains("PROB_SPAM_HIGH");
    imap.send_ok("MOVE 10 INBOX").await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);

    // Make sure spam traps trigger spam classification
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest("bill@example.com", &["spamtrap@example.com"], SPAM[4])
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let samples = admin.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 11);

    let last_id = samples.iter().map(|(id, _)| id.id()).max().unwrap();
    for _ in 0..2 {
        admin
            .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
                maintenance_type: TaskSpamFilterMaintenanceType::Train,
                status: TaskStatus::now(),
            }))
            .await;
        test.wait_for_tasks().await;
        let model = spam_classifier_model(&test.server).await;
        assert_eq!(model.reservoir.ham.total_seen, 11);
        assert_eq!(model.reservoir.spam.total_seen, 11);
        assert_eq!(model.last_id, last_id);
    }

    // Global spam samples should not appear in the account
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);

    let support_id = test.account("support@example.com").id();
    let jane = test.account("jane.smith@example.com");
    let jane_id = jane.id();
    let mut imap_jane = jane.imap_client().await;
    let samples_for = |account_id, is_spam: bool| {
        let admin = &admin;
        async move {
            admin
                .spam_training_samples()
                .await
                .into_iter()
                .filter(|(_, sample)| {
                    sample.account_id == Some(account_id) && sample.is_spam == is_spam
                })
                .count()
        }
    };

    imap_jane
        .append("Shared Folders/support@example.com/Drafts", SPAM[1])
        .await;
    assert_eq!(samples_for(support_id, true).await, 0);

    imap_jane
        .send_ok("SELECT \"Shared Folders/support@example.com/Drafts\"")
        .await;
    imap_jane.send_ok("MOVE * \"Junk Mail\"").await;
    assert_eq!(samples_for(support_id, true).await, 1);

    imap_jane.send_ok("SELECT \"Junk Mail\"").await;
    imap_jane
        .send_ok("MOVE * \"Shared Folders/support@example.com/Drafts\"")
        .await;
    assert_eq!(samples_for(jane_id, false).await, 1);

    // inbuxa: #589: the samples of a move outlive the moved-out original
    test.wait_for_tasks().await;
    assert_eq!(samples_for(support_id, true).await, 1);
    assert_eq!(samples_for(jane_id, false).await, 1);

    // inbuxa: #589: so does the sample of a JMAP move (Email/copy destroying
    // the original) from the shared account into Jane's Junk Mail
    imap_jane
        .send_ok("SELECT \"Shared Folders/support@example.com/Drafts\"")
        .await;
    imap_jane.send("FETCH * (OBJECTID)").await;
    let email_id = imap_jane
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .iter()
        .find_map(|line| {
            line.split_once("EMAILID ").map(|(_, value)| {
                value
                    .trim_start_matches('(')
                    .split([' ', ')'])
                    .next()
                    .unwrap()
                    .to_string()
            })
        })
        .expect("Missing EMAILID");
    let support = test.account("support@example.com");
    let response = jane
        .jmap_copy(
            support,
            jane,
            "Email",
            [(
                "moved",
                json!({
                    "id": email_id,
                    "mailboxIds": { Id::from(JUNK_ID).to_string(): true }
                }),
            )],
            true,
        )
        .await;
    response.copied("moved");
    test.wait_for_tasks().await;
    assert_eq!(samples_for(support_id, true).await, 2);

    // inbuxa: #595: a Reset stops the node that ran it scoring with the
    // deleted model
    let trained = test.server.inner.data.spam_classifier.load_full();
    assert!(trained.is_active());
    admin
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::Reset,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    for key in [SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY] {
        assert!(
            test.server
                .blob_store()
                .get_blob(key, 0..usize::MAX)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        !test.server.inner.data.spam_classifier.load().is_active(),
        "the Reset left this node scoring with the deleted model"
    );

    // inbuxa: #595: so does every other node, through the SpamClassifier
    // reload the Reset broadcasts. Simulate a node still on the old model,
    // and run that reload.
    test.server.inner.data.spam_classifier.store(trained);
    test.server
        .reload_registry(RegistryChange::Reload(ObjectType::SpamClassifier))
        .await
        .unwrap();
    assert!(
        !test.server.inner.data.spam_classifier.load().is_active(),
        "the SpamClassifier reload kept a model that's no longer stored"
    );
}

pub async fn spam_classifier_model(server: &Server) -> SpamTrainer {
    server
        .blob_store()
        .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
        .await
        .and_then(|archive| match archive {
            Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                .and_then(|archive| archive.deserialize_untrusted::<SpamTrainer>())
                .map(Some),
            None => Ok(None),
        })
        .unwrap()
        .unwrap()
}
