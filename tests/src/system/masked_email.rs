/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Masked email acceptance tests 1 to 11, from
//! `docs/spec/features/masked-email.md`, with the additions the spec makes
//! (ME-9, ME-10, ME-11, `/changes`). Each check names the test number or the
//! requirement it covers. Test 12 (compat) needs a copy of INBUXA's data.

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapUtils},
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use email::mailbox::{INBOX_ID, TRASH_ID};
use inbuxa_features::masked_email::data;
use jmap_proto::error::set::SetErrorType;
use registry::schema::{
    enums::StorageQuota,
    prelude::{ObjectType, Property},
    structs::{Expression, Imap, MaskedEmail, MtaStageAuth, MtaStageRcpt, UserRoles},
};
use serde_json::{Value, json};
use store::write::BatchBuilder;
use types::id::Id;
use utils::map::vec_map::VecMap;

const FASTMAIL: &str = "https://www.fastmail.com/dev/maskedemail";
const SECRET_ALICE: &str = "alice keeps her masks close";
const SECRET_BOB: &str = "bob would like to see them";
const SECRET_RATE: &str = "rate tester makes many masks";
const SECRET_T: &str = "tenant people on the mask test";

pub async fn test(test: &mut TestServer) {
    println!("Running masked email tests...");
    let admin = test.account("admin@example.org");
    admin.find_or_create_domain("example.org").await;
    admin.find_or_create_domain("mask-alias.example.org").await;
    admin.find_or_create_domain("not-linked.example.org").await;

    let alice = admin
        .create_user_account(
            "alice@example.org",
            SECRET_ALICE,
            "Alice",
            &["alice@mask-alias.example.org"],
            vec![],
        )
        .await;
    let bob = admin
        .create_user_account("bob@example.org", SECRET_BOB, "Bob", &[], vec![])
        .await;
    let mut lmtp = SmtpConnection::connect().await;
    // Refused recipients answer at once, so the refusals below are quick
    admin
        .registry_update_setting(
            MtaStageRcpt {
                wait_on_fail: Expression {
                    else_: "1ms".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            &[Property::WaitOnFail],
        )
        .await;
    admin.reload_settings().await;

    // Acceptance test 1: a Fastmail create with no arguments is pending, on
    // the account's primary domain, and reads enabled in x: (ME-7a)
    let pending = alice.fastmail_create(json!({})).await;
    let pending_email = pending["email"].as_str().unwrap().to_string();
    let pending_id = pending.object_id();
    assert!(pending_email.ends_with("@example.org"), "test 1: {pending}");
    assert!(
        !pending_email.split('@').next().unwrap().contains('.'),
        "ME-13: never upstream's shape"
    );
    assert_eq!(pending["state"], "pending", "test 1");
    assert!(alice.x_mask(pending_id).await.enabled, "test 1: x: enabled");
    // Through x: it starts enabled in both
    let x_id = alice.x_create(json!({})).await;
    assert_eq!(
        alice.fastmail_state(x_id).await,
        "enabled",
        "test 1: x: create"
    );

    // Acceptance test 2: mail to a pending mask is delivered, the mask turns
    // enabled and lastMessageAt is set (ME-7). It names the mask (ME-9).
    let inbox_before = alice.count_in(INBOX_ID).await;
    lmtp.ingest(
        "sender@remote.example.org",
        &[&pending_email],
        &message("to a pending mask"),
    )
    .await;
    alice.wait_for_count(INBOX_ID, inbox_before + 1).await;
    let mask = alice.fastmail_get(pending_id).await;
    assert_eq!(mask["state"], "enabled", "test 2");
    assert!(mask["lastMessageAt"].is_string(), "test 2: {mask}");
    assert_eq!(
        alice.latest_header("X-Masked-Email").await.trim(),
        pending_email,
        "ME-9"
    );

    // ME-10: sub-addressing on a mask
    let (local, domain) = pending_email.split_once('@').unwrap();
    lmtp.ingest(
        "sender@remote.example.org",
        &[&format!("{local}+news@{domain}")],
        &message("sub-addressed"),
    )
    .await;
    alice.wait_for_count(INBOX_ID, inbox_before + 2).await;

    // Acceptance test 3: a pending mask with no mail for 24 hours is removed
    // and tombstoned (ME-8). Its deadline is moved into the past here.
    let stale = alice.fastmail_create(json!({})).await;
    let stale_id = stale.object_id();
    let stale_email = stale["email"].as_str().unwrap().to_string();
    test.expire_pending(stale_id).await;
    assert!(
        alice.fastmail_get_raw(stale_id).await["list"]
            .as_array()
            .unwrap()
            .is_empty(),
        "test 3"
    );
    assert_eq!(
        test.tombstone(&stale_email).await,
        Some(false),
        "test 3: tombstoned"
    );

    // Acceptance test 4: disabled mail is accepted and lands in Trash (ME-5)
    alice
        .fastmail_update(pending_id, json!({"state": "disabled"}))
        .await;
    let trash_before = alice.count_in(TRASH_ID).await;
    lmtp.ingest(
        "sender@remote.example.org",
        &[&pending_email],
        &message("to a disabled mask"),
    )
    .await;
    alice.wait_for_count(TRASH_ID, trash_before + 1).await;
    assert!(
        alice.x_mask(pending_id).await.enabled,
        "disabled reads enabled in x:"
    );

    // Acceptance test 5: deleted, through either API, refuses mail at RCPT TO
    // (ME-6), and both APIs agree (ME-2)
    alice
        .fastmail_update(pending_id, json!({"state": "deleted"}))
        .await;
    assert!(!alice.x_mask(pending_id).await.enabled, "test 5");
    refused(&pending_email).await;
    alice.x_update(pending_id, json!({"enabled": true})).await;
    assert_eq!(alice.fastmail_state(pending_id).await, "enabled", "test 5");
    alice.x_update(pending_id, json!({"enabled": false})).await;
    assert_eq!(alice.fastmail_state(pending_id).await, "deleted", "test 5");
    refused(&pending_email).await;
    // ME-1: pending can't come back
    alice
        .fastmail_update_err(pending_id, json!({"state": "pending"}))
        .await;

    // Acceptance test 6: a destroyed mask is refused as unknown, and its
    // address stays reserved (ME-3, ME-13)
    alice.fastmail_destroy(pending_id).await;
    refused(&pending_email).await;
    assert_eq!(test.tombstone(&pending_email).await, Some(false), "test 6");

    // Acceptance test 7: prefixes
    let shop = alice
        .x_get_email(alice.x_create(json!({"emailPrefix": "shop"})).await)
        .await;
    assert!(shop.starts_with("shop_"), "test 7: {shop}");
    alice
        .x_create_err(json!({"emailPrefix": "Shop!"}))
        .await
        .assert_type(SetErrorType::InvalidProperties);

    // Acceptance test 8: domains (ME-12)
    let aliased = alice
        .x_get_email(
            alice
                .x_create(json!({"emailDomain": "mask-alias.example.org"}))
                .await,
        )
        .await;
    assert!(
        aliased.ends_with("@mask-alias.example.org"),
        "ME-12: {aliased}"
    );
    alice
        .x_create_err(json!({"emailDomain": "not-linked.example.org"}))
        .await
        .assert_type(SetErrorType::Forbidden)
        .assert_properties(&["emailDomain"]);

    // ME-11: an owner sends as its mask; nobody else can
    let identity = alice
        .jmap_method_call(
            "Identity/set",
            json!({"accountId": alice.id_string(), "create": {"i": {"email": shop, "name": "Shop"}}}),
        )
        .await;
    assert!(
        identity
            .0
            .pointer("/methodResponses/0/1/created/i")
            .is_some(),
        "ME-11: {identity:?}"
    );
    let identity = bob
        .jmap_method_call(
            "Identity/set",
            json!({"accountId": bob.id_string(), "create": {"i": {"email": shop, "name": "Shop"}}}),
        )
        .await;
    assert!(
        identity
            .0
            .pointer("/methodResponses/0/1/notCreated/i")
            .is_some(),
        "ME-11"
    );

    // Acceptance test 11: who reaches whose masks (ME-18, ME-19)
    assert_eq!(
        bob.x_list_for(&alice)
            .await
            .method_response()
            .text_field("type"),
        "forbidden",
        "test 11: another user"
    );
    assert!(
        admin.x_list_for(&alice).await.method_response()["list"]
            .as_array()
            .is_some_and(|list| !list.is_empty()),
        "test 11: server admin"
    );
    let t_id = admin
        .registry_create_object(registry::schema::structs::Tenant {
            name: "Mask tenant".to_string(),
            ..Default::default()
        })
        .await;
    let t_domain = admin
        .registry_create_object(registry::schema::structs::Domain {
            name: "mask-tenant.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(t_id),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_failures().await;
    let t_admin = admin
        .create_user_account(
            "tadmin@mask-tenant.example.org",
            SECRET_T,
            "T admin",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({ Property::Roles: UserRoles::Admin }),
        )
        .await;
    let t_user = admin
        .create_user_account(
            "tuser@mask-tenant.example.org",
            SECRET_T,
            "T user",
            &[],
            vec![],
        )
        .await;
    t_user.x_create(json!({})).await;
    assert!(
        t_admin.x_list_for(&t_user).await.method_response()["list"]
            .as_array()
            .is_some_and(|list| list.len() == 1),
        "test 11: tenant admin, own tenant"
    );
    assert_eq!(
        t_admin
            .x_list_for(&alice)
            .await
            .method_response()
            .text_field("type"),
        "forbidden",
        "test 11: tenant admin, other accounts"
    );

    // x:MaskedEmail/changes (a fork addition)
    let since = alice.x_state().await;
    let new_id = alice.x_create(json!({})).await;
    let changes = alice
        .jmap_method_call(
            "x:MaskedEmail/changes",
            json!({"accountId": alice.id_string(), "sinceState": since}),
        )
        .await;
    assert_eq!(
        changes.method_response()["created"],
        json!([new_id.to_string()]),
        "/changes: {changes:?}"
    );

    // Acceptance test 9: maxMaskedAddresses (ME-14)
    admin
        .registry_update_object(
            ObjectType::Account,
            bob.id(),
            json!({ Property::Quotas: VecMap::from_iter([(StorageQuota::MaxMaskedAddresses, 2u64)]) }),
        )
        .await;
    bob.x_create(json!({})).await;
    bob.x_create(json!({})).await;
    bob.x_create_err(json!({}))
        .await
        .assert_type(SetErrorType::OverQuota);
    admin
        .registry_update_object(
            ObjectType::Account,
            bob.id(),
            json!({ Property::Quotas: VecMap::from_iter([(StorageQuota::MaxMaskedAddresses, 0u64)]) }),
        )
        .await;
    bob.x_create_err(json!({}))
        .await
        .assert_type(SetErrorType::OverQuota);

    // Acceptance test 10: the 51st create in an hour is rate-limited (ME-15)
    let rate = admin
        .create_user_account("rate@example.org", SECRET_RATE, "Rate", &[], vec![])
        .await;
    // Above the server's default limit, so only the rate can stop it
    admin
        .registry_update_object(
            ObjectType::Account,
            rate.id(),
            json!({ Property::Quotas: VecMap::from_iter([(StorageQuota::MaxMaskedAddresses, 1000u64)]) }),
        )
        .await;
    for n in 0..50 {
        let response = rate.fastmail_set(json!({"create": {"n": {}}})).await;
        assert!(
            response
                .0
                .pointer("/methodResponses/0/1/created/n")
                .is_some(),
            "create {n}: {response:?}"
        );
    }
    let response = rate.fastmail_set(json!({"create": {"n": {}}})).await;
    assert_eq!(
        response
            .0
            .pointer("/methodResponses/0/1/notCreated/n/type")
            .and_then(|v| v.as_str()),
        Some("rateLimit"),
        "test 10: {response:?}"
    );

    // Clean up
    admin
        .registry_update_setting(MtaStageRcpt::default(), &[Property::WaitOnFail])
        .await;
    admin.reload_settings().await;
    for account in [alice, bob, rate, t_user, t_admin] {
        admin.destroy_account(account).await;
    }
    test.wait_for_tasks().await;
    admin.registry_destroy(ObjectType::Domain, [t_domain]).await;
    admin.registry_destroy(ObjectType::Tenant, [t_id]).await;
}

/// Runs the masked email tests alone:
/// `cargo test -p tests masked_email_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn masked_email_tests() {
    let mut test = TestServerBuilder::new("masked_email_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
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
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

fn message(subject: &str) -> String {
    format!(
        "From: sender@remote.example.org\r\nTo: someone@example.org\r\nSubject: {subject}\r\n\r\nHello.\r\n"
    )
}

impl TestServer {
    async fn expire_pending(&self, id: Id) {
        let data_store = &self.server.core.storage.data;
        let mut record = data::record(data_store, id).await.unwrap().unwrap();
        record.pending_until = Some(1);
        let mut batch = BatchBuilder::new();
        data::set_record(&mut batch, id, &record).unwrap();
        data_store.write(batch.build_all()).await.unwrap();
    }

    /// `Some(live)` when the address is in the fork's index.
    async fn tombstone(&self, address: &str) -> Option<bool> {
        data::address(&self.server.core.storage.data, address)
            .await
            .unwrap()
            .map(|entry| entry.live)
    }
}

/// ME-6: refused at RCPT TO with upstream's reply, on a fresh connection.
async fn refused(address: &str) {
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    let reply = lmtp.rcpt_to(address, 5).await;
    assert!(
        reply.iter().any(|line| line.starts_with("550 5.1.2")),
        "ME-6: {reply:?}"
    );
}

impl Account {
    async fn fastmail_set(&self, args: Value) -> JmapResponse {
        let mut args = args;
        args["accountId"] = json!(self.id_string());
        self.jmap_request(
            &["urn:ietf:params:jmap:core", FASTMAIL],
            json!([["MaskedEmail/set", args, "0"]]),
        )
        .await
    }

    async fn fastmail_create(&self, object: Value) -> Value {
        let response = self.fastmail_set(json!({"create": {"n": object}})).await;
        response
            .0
            .pointer("/methodResponses/0/1/created/n")
            .unwrap_or_else(|| panic!("not created: {response:?}"))
            .clone()
    }

    async fn fastmail_update(&self, id: Id, object: Value) {
        let response = self
            .fastmail_set(json!({"update": {id.to_string(): object}}))
            .await;
        assert!(
            response
                .0
                .pointer(&format!("/methodResponses/0/1/updated/{id}"))
                .is_some(),
            "not updated: {response:?}"
        );
    }

    async fn fastmail_update_err(&self, id: Id, object: Value) {
        let response = self
            .fastmail_set(json!({"update": {id.to_string(): object}}))
            .await;
        assert!(
            response
                .0
                .pointer(&format!("/methodResponses/0/1/notUpdated/{id}"))
                .is_some(),
            "updated: {response:?}"
        );
    }

    async fn fastmail_destroy(&self, id: Id) {
        let response = self
            .fastmail_set(json!({"destroy": [id.to_string()]}))
            .await;
        assert_eq!(
            response.method_response()["destroyed"],
            json!([id.to_string()]),
            "{response:?}"
        );
    }

    async fn fastmail_get_raw(&self, id: Id) -> Value {
        self.jmap_request(
            &["urn:ietf:params:jmap:core", FASTMAIL],
            json!([["MaskedEmail/get", {"accountId": self.id_string(), "ids": [id.to_string()]}, "0"]]),
        )
        .await
        .method_response()
        .clone()
    }

    async fn fastmail_get(&self, id: Id) -> Value {
        let response = self.fastmail_get_raw(id).await;
        response["list"][0].clone()
    }

    async fn fastmail_state(&self, id: Id) -> String {
        self.fastmail_get(id).await["state"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    async fn x_create(&self, object: Value) -> Id {
        self.registry_create_many(ObjectType::MaskedEmail, [object])
            .await
            .created_id(0)
    }

    async fn x_create_err(&self, object: Value) -> crate::utils::jmap::JmapSetError {
        self.registry_create_many(ObjectType::MaskedEmail, [object])
            .await
            .not_created(0)
            .to_set_error()
    }

    async fn x_update(&self, id: Id, object: Value) {
        self.registry_update_object(ObjectType::MaskedEmail, id, object)
            .await;
    }

    async fn x_mask(&self, id: Id) -> MaskedEmail {
        self.registry_get::<MaskedEmail>(id).await
    }

    async fn x_get_email(&self, id: Id) -> String {
        self.x_mask(id).await.email
    }

    async fn x_list_for(&self, owner: &Account) -> JmapResponse {
        self.jmap_method_call(
            "x:MaskedEmail/get",
            json!({"accountId": owner.id_string(), "ids": null}),
        )
        .await
    }

    async fn x_state(&self) -> String {
        self.x_list_for(self).await.method_response()["state"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    async fn count_in(&self, mailbox_id: u32) -> usize {
        self.jmap_method_call(
            "Email/query",
            json!({
                "accountId": self.id_string(),
                "filter": {"inMailbox": Id::from(mailbox_id).to_string()}
            }),
        )
        .await
        .method_response()["ids"]
            .as_array()
            .map(|ids| ids.len())
            .unwrap_or(0)
    }

    async fn wait_for_count(&self, mailbox_id: u32, count: usize) {
        for _ in 0..40 {
            if self.count_in(mailbox_id).await >= count {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!(
            "mailbox {mailbox_id} of {} never reached {count} messages",
            self.name()
        );
    }

    async fn latest_header(&self, header: &str) -> String {
        let response = self
            .jmap_method_calls(json!([
                ["Email/query", {
                    "accountId": self.id_string(),
                    "sort": [{"property": "receivedAt", "isAscending": false}],
                    "limit": 1
                }, "q"],
                ["Email/get", {
                    "accountId": self.id_string(),
                    "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                    "properties": [format!("header:{header}:asText")]
                }, "g"]
            ]))
            .await;
        response.0["methodResponses"][1][1]["list"][0][format!("header:{header}:asText")]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}
