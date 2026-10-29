/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{
    account::Account, http::HttpRequest, jmap::JmapUtils, server::TestServer, smtp::SmtpConnection,
};
use email::{cache::MessageCacheFetch, mailbox::INBOX_ID};
use jmap::blob::upload::DISABLE_UPLOAD_QUOTA;
use jmap_client::{
    core::set::{SetErrorType, SetObject},
    email::EmailBodyPart,
};
use registry::{
    schema::{
        enums::{Permission, StorageQuota, TaskAccountMaintenanceType},
        prelude::{ObjectType, Property},
        structs::{
            self, Credential, Jmap, PasswordCredential, PermissionsList, Task,
            TaskAccountMaintenance, TaskStatus, UserAccount,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use serde_json::{Value, json};
use types::id::Id;
use utils::map::vec_map::VecMap;

pub async fn test(test: &mut TestServer) {
    println!("Running Quota tests...");
    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Set test settings
    admin
        .registry_update_setting(
            Jmap {
                upload_quota: 50000,
                max_upload_count: 3,
                upload_ttl: registry::types::duration::Duration::from_millis(1000),
                ..Default::default()
            },
            &[
                Property::UploadQuota,
                Property::MaxUploadCount,
                Property::UploadTtl,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Create test accounts
    let account_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "user1".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password1".to_string(),
                ..Default::default()
            })]),
            quotas: VecMap::from_iter([(StorageQuota::MaxDiskQuota, 1024)]),
            permissions: structs::Permissions::Merge(PermissionsList {
                enabled_permissions: Map::new(vec![Permission::Impersonate]),
                disabled_permissions: Default::default(),
            }),
            ..Default::default()
        }))
        .await;
    let other_account_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "user2".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password2".to_string(),
                ..Default::default()
            })]),
            permissions: structs::Permissions::Merge(PermissionsList {
                enabled_permissions: Map::new(vec![Permission::Impersonate]),
                disabled_permissions: Default::default(),
            }),
            ..Default::default()
        }))
        .await;
    let account = Account::new(
        "user1@example.org",
        "this is a very strong password1",
        &[],
        "User1",
        account_id,
    );
    let other_account = Account::new(
        "user2@example.org",
        "this is a very strong password2",
        &[],
        "User2",
        other_account_id,
    );

    // Delete temporary blobs from previous tests
    test.blob_expire_all().await;

    // Test temporary blob quota (3 files)
    DISABLE_UPLOAD_QUOTA.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = account.jmap_client().await;
    let raw_http =
        HttpRequest::with_credentials(8899, "user1@example.org", "this is a very strong password1");
    let upload_url = format!("/jmap/upload/{account_id}");
    for i in 0..3 {
        assert_eq!(
            client
                .upload(None, vec![b'A' + i; 1024], None)
                .await
                .unwrap()
                .size(),
            1024
        );
    }
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            &upload_url,
            Some(vec![b'Z'; 1024]),
            Some("application/octet-stream"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        429,
        "blob-files-quota body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy on {:?}", resp.headers));
    assert!(
        policy.contains("\"blob-upload-files\";q=3"),
        "RateLimit-Policy = {policy}"
    );
    assert!(
        policy.contains("\"blob-upload-bytes\";q=50000")
            && policy.contains(r#"qu="content-bytes""#),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit on {:?}", resp.headers));
    assert!(
        state.contains("\"blob-upload-files\";r=0") && state.contains("t="),
        "RateLimit = {state}"
    );
    assert!(
        resp.retry_after().is_some(),
        "missing Retry-After on {:?}",
        resp.headers
    );
    assert!(resp.body.contains("quota"), "body = {}", resp.body);
    test.blob_expire_all().await;

    // Test temporary blob quota (50000 bytes)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    for i in 0..2 {
        assert_eq!(
            client
                .upload(None, vec![b'a' + i; 25000], None)
                .await
                .unwrap()
                .size(),
            25000
        );
    }
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            &upload_url,
            Some(vec![b'z'; 1024]),
            Some("application/octet-stream"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        429,
        "blob-bytes-quota body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy on {:?}", resp.headers));
    assert!(
        policy.contains("\"blob-upload-bytes\";q=50000")
            && policy.contains(r#"qu="content-bytes""#),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit on {:?}", resp.headers));
    assert!(
        state.contains("\"blob-upload-bytes\";r=0") && state.contains("t="),
        "RateLimit = {state}"
    );
    assert!(
        resp.retry_after().is_some(),
        "missing Retry-After on {:?}",
        resp.headers
    );
    test.blob_expire_all().await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Test JMAP Quotas extension
    let response = account
        .jmap_method_call(
            "Quota/get",
            json!({
                "accountId": account.id_string(),
                "ids": null
            }),
        )
        .await
        .to_string();
    assert!(response.contains("\"used\":0"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);
    assert!(response.contains("\"scope\":\"account\""), "{}", response);
    assert!(
        response.contains("\"name\":\"user1@example.org\""),
        "{}",
        response
    );

    // Test Email/import quota
    let inbox_id = Id::new(INBOX_ID as u64).to_string();
    let mut message_ids = Vec::new();
    for i in 0..2 {
        message_ids.push(
            client
                .email_import(
                    create_message_with_size(
                        "user2@example.org",
                        "user1@example.org",
                        &format!("Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }

    assert_over_quota(
        client
            .email_import(
                create_message_with_size("test@example.org", "user2@example.org", "Test 3", 100),
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Test JMAP Quotas extension
    let response = account
        .jmap_method_call(
            "Quota/get",
            json!({
                "accountId": account.id_string(),
                "ids": null
            }),
        )
        .await
        .to_string();
    assert!(response.contains("\"used\":1024"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);

    // Test registry quota
    assert_eq!(
        admin
            .registry_get_many(ObjectType::Account, [account_id])
            .await
            .list()[0]
            .integer_field(Property::UsedDiskQuota.as_str()),
        1024
    );

    // Delete messages and check available quota
    test.wait_for_tasks().await;
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }

    // Wait for pending index tasks
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/set quota
    let mut message_ids = Vec::new();
    for i in 0..2 {
        let mut request = client.build();
        let create_item = request.set_email().create();
        create_item
            .mailbox_ids([&inbox_id])
            .subject(format!("Test {i}"))
            .from(["user2@example.org"])
            .to(["user1@example.org"])
            .body_value("a".to_string(), String::from_utf8(vec![b'A'; 200]).unwrap())
            .text_body(EmailBodyPart::new().part_id("a"));
        let create_id = create_item.create_id().unwrap();
        message_ids.push(
            request
                .send_set_email()
                .await
                .unwrap()
                .created(&create_id)
                .unwrap()
                .take_id(),
        );
    }
    let mut request = client.build();
    let create_item = request.set_email().create();
    create_item
        .mailbox_ids([&inbox_id])
        .subject("Test 3")
        .from(["user2@example.org"])
        .to(["user1@example.org"])
        .body_value("a".to_string(), String::from_utf8(vec![b'A'; 400]).unwrap())
        .text_body(EmailBodyPart::new().part_id("a"));
    let create_id = create_item.create_id().unwrap();
    assert_over_quota(request.send_set_email().await.unwrap().created(&create_id));

    // Recalculate quota
    let prev_quota = test
        .server
        .get_used_quota_account(account.id().document_id())
        .await
        .unwrap();
    admin
        .registry_create_object(Task::AccountMaintenance(TaskAccountMaintenance {
            account_id,
            maintenance_type: TaskAccountMaintenanceType::RecalculateQuota,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap(),
        prev_quota
    );

    // Delete messages and check available quota
    test.wait_for_tasks().await;
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    // Wait for pending index tasks
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/copy quota
    let other_client = other_account.jmap_client().await;
    let mut other_message_ids = Vec::new();
    let mut message_ids = Vec::new();
    for i in 0..3 {
        other_message_ids.push(
            other_client
                .email_import(
                    create_message_with_size(
                        "jane@example.org",
                        "user2@example.org",
                        &format!("Other Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    for id in other_message_ids.iter().take(2) {
        message_ids.push(
            client
                .email_copy(
                    other_account.id_string(),
                    id,
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    assert_over_quota(
        client
            .email_copy(
                other_account.id_string(),
                &other_message_ids[2],
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Delete messages and check available quota
    test.wait_for_tasks().await;
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    // Wait for pending index tasks
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // inbuxa: calendar events, contacts and files count towards the quota of
    // the account they are written into, all the items of a request together
    groupware_quota(test, &account, &other_account).await;
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap(),
        0
    );

    // Test delivery quota
    let mut lmtp = SmtpConnection::connect().await;
    for i in 0..2 {
        lmtp.ingest(
            "jane@example.org",
            &["user1@example.org"],
            &String::from_utf8(create_message_with_size(
                "jane@example.org",
                "user1@example.org",
                &format!("Ingest test {i}"),
                500,
            ))
            .unwrap(),
        )
        .await;
    }
    let quota = test
        .server
        .get_used_quota_account(account.id().document_id())
        .await
        .unwrap();
    assert!(quota > 0 && quota <= 1024, "Quota is {}", quota);
    assert_eq!(
        test.server
            .get_cached_messages(account.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        1,
    );

    DISABLE_UPLOAD_QUOTA.store(true, std::sync::atomic::Ordering::Relaxed);

    // Remove test data
    test.wait_for_tasks().await;
    test.destroy_all_mailboxes(&account).await;
    test.destroy_all_mailboxes(&other_account).await;
    admin.registry_destroy_all(ObjectType::QueuedMessage).await;
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    test.assert_is_empty().await;

    admin
        .registry_destroy(ObjectType::Account, [account_id, other_account_id])
        .await
        .assert_destroyed(&[account_id, other_account_id]);

    // inbuxa: put the upload limits back; with a one-second upload lifetime
    // the next suite's uploads can expire before their import under load
    admin
        .registry_update_setting(
            Jmap::default(),
            &[
                Property::UploadQuota,
                Property::MaxUploadCount,
                Property::UploadTtl,
            ],
        )
        .await;
    admin.reload_settings().await;
    test.cleanup().await;
}

async fn groupware_quota(test: &TestServer, account: &Account, other_account: &Account) {
    let other_id = other_account.id_string().to_string();
    let used = || async {
        test.server
            .get_used_quota_account(account.id().document_id())
            .await
            .unwrap() as usize
    };
    // The size of an item that fits the quota alone but not twice over
    let half_size =
        |used: usize, overhead: usize| ((1024 - used) / 2 + 50).saturating_sub(overhead);

    // A sharee writing into the account is held to the account's quota
    let calendar_id = account
        .jmap_create(
            "Calendar",
            [json!({
                "name": "Quota",
                "shareWith": { &other_id: { "mayReadItems": true, "mayWriteAll": true } }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let event = |uid: &str, size: usize| {
        json!({
            "@type": "Event",
            "uid": uid,
            "title": "Quota",
            "description": "x".repeat(size),
            "start": "2026-01-15T13:00:00",
            "duration": "PT1H",
            "calendarIds": { &calendar_id: true },
        })
    };
    assert_eq!(
        other_account
            .jmap_create_account(
                account,
                "CalendarEvent",
                [event("quota-shared", 1200)],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .not_created(0)
            .typ(),
        "overQuota"
    );

    // Items created together count together
    let before = used().await;
    let small_id = account
        .jmap_create(
            "CalendarEvent",
            [event("quota-0", 0)],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let overhead = used().await - before;
    account
        .jmap_destroy(
            "CalendarEvent",
            [small_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);
    let size = half_size(used().await, overhead);
    let response = account
        .jmap_create(
            "CalendarEvent",
            [event("quota-1", size), event("quota-2", size)],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.created(0);
    assert_eq!(response.not_created(1).typ(), "overQuota");
    account.destroy_all_calendars().await;

    let book_id = account
        .jmap_create(
            "AddressBook",
            [json!({ "name": "Quota" })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let contact = |uid: &str, size: usize| {
        json!({
            "uid": uid,
            "name": { "full": "Quota" },
            "notes": { "n1": { "note": "x".repeat(size) } },
            "addressBookIds": { &book_id: true },
        })
    };
    let before = used().await;
    let small_id = account
        .jmap_create(
            "ContactCard",
            [contact("quota-0", 1)],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let overhead = used().await - before;
    account
        .jmap_destroy(
            "ContactCard",
            [small_id.as_str()],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .destroyed()
        .for_each(drop);
    let size = half_size(used().await, overhead);
    let response = account
        .jmap_create(
            "ContactCard",
            [contact("quota-1", size), contact("quota-2", size)],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.created(0);
    assert_eq!(response.not_created(1).typ(), "overQuota");
    account.destroy_all_addressbooks().await;

    // Files count towards the quota, created or copied in
    let file_with_blob = |owner: &Account, name: &str, size: usize, extra: Value| {
        let mut file = json!({ "name": name, "parentId": null, "blobId": "#file" });
        if let (Value::Object(file), Value::Object(extra)) = (&mut file, extra) {
            file.extend(extra);
        }
        json!([
            ["Blob/upload", {
                "accountId": owner.id_string(),
                "create": { "file": { "data": [{ "data:asText": "f".repeat(size) }] } }
            }, "0"],
            ["FileNode/set", {
                "accountId": owner.id_string(),
                "create": { "i0": file }
            }, "1"]
        ])
    };
    let response = account
        .jmap_method_calls(file_with_blob(account, "small.txt", 100, json!({})))
        .await
        .into_inner();
    assert!(
        response
            .pointer("/methodResponses/1/1/created/i0/id")
            .is_some(),
        "{response}"
    );
    let response = account
        .jmap_method_calls(file_with_blob(account, "big.txt", 2000, json!({})))
        .await
        .into_inner();
    assert_eq!(
        response.pointer("/methodResponses/1/1/notCreated/i0/type"),
        Some(&json!("overQuota")),
        "{response}"
    );

    // (the upload limit is three files a second)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let account_id = account.id_string().to_string();
    let folder_id = other_account
        .jmap_create(
            "FileNode",
            [json!({
                "name": "shared",
                "parentId": null,
                "shareWith": { &account_id: { "mayRead": true } }
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    let response = other_account
        .jmap_method_calls(file_with_blob(
            other_account,
            "big.txt",
            2000,
            json!({ "parentId": &folder_id }),
        ))
        .await
        .into_inner();
    let file_id = response
        .pointer("/methodResponses/1/1/created/i0/id")
        .and_then(|id| id.as_str())
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let response = account
        .jmap_copy(
            other_account,
            account,
            "FileNode",
            [(&file_id, json!({ "parentId": null, "name": "copied.txt" }))],
            false,
        )
        .await;
    assert_eq!(
        response.method_response()["notCreated"][&file_id].typ(),
        "overQuota"
    );

    for owner in [account, other_account] {
        owner
            .jmap_method_calls(json!([
                ["FileNode/get", {
                    "accountId": owner.id_string(),
                    "ids": null,
                    "properties": ["id"]
                }, "R1"],
                ["FileNode/set", {
                    "accountId": owner.id_string(),
                    "#destroy": { "resultOf": "R1", "name": "FileNode/get", "path": "/list/*/id" },
                    "onDestroyRemoveChildren": true
                }, "R2"]
            ]))
            .await;
    }
}

fn assert_over_quota<T: std::fmt::Debug>(result: Result<T, jmap_client::Error>) {
    match result {
        Ok(result) => panic!("Expected error, got {:?}", result),
        Err(jmap_client::Error::Set(err)) if err.error() == &SetErrorType::OverQuota => (),
        Err(err) => panic!("Expected OverQuota SetError, got {:?}", err),
    }
}

fn create_message_with_size(from: &str, to: &str, subject: &str, size: usize) -> Vec<u8> {
    let mut message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n",
        from, to, subject
    );
    for _ in 0..size - message.len() {
        message.push('A');
    }

    message.into_bytes()
}
