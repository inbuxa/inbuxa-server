/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! MA-D0 (specs/multi-account.md): a group's members have its calendars,
//! address books and files, but can't share them on. Who is in a group is
//! an administrator's decision. Mailboxes are checked in `mail::acl`.

use crate::utils::{jmap::JmapUtils, server::TestServer};
use jmap_proto::request::method::MethodObject;
use registry::schema::prelude::ObjectType;
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running group sharing tests...");
    let admin = test.account("admin@example.com");
    let sales = test.account("sales@example.com");
    let bill = test.account("bill@example.com");
    let robert = test.account("robert@example.com");
    let robert_id = robert.id_string().to_string();

    // Bill joins the group; Robert stays outside it
    admin
        .registry_update_object(
            ObjectType::Account,
            bill.id(),
            json!({"memberGroupIds": {sales.id_string(): true}}),
        )
        .await;

    // Each kind's own name for "may read"
    for (object, read) in [
        (MethodObject::Calendar, "mayReadItems"),
        (MethodObject::AddressBook, "mayRead"),
        (MethodObject::FileNode, "mayRead"),
    ] {
        // Made with a share: refused
        let response = bill
            .jmap_create_account(
                sales,
                object,
                [json!({
                    "name": "Shared on",
                    "shareWith": {&robert_id: {read: true}}
                })],
                Vec::<(&str, &str)>::new(),
            )
            .await;
        assert_eq!(
            response.pointer("/methodResponses/0/1/notCreated/i0/type"),
            Some(&json!("forbidden")),
            "MA-D0: {object} created with a share: {:?}",
            response.pointer("/methodResponses/0")
        );

        // Made without one: fine, and it says it can't be shared
        let id = bill
            .jmap_create_account(
                sales,
                object,
                [json!({"name": "The group's"})],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .created(0)
            .id()
            .to_string();
        let rights = bill
            .jmap_get_account(sales, object, ["myRights"], [id.as_str()])
            .await
            .list()[0]["myRights"]
            .clone();
        assert_eq!(rights["mayShare"], false, "MA-D0: {object} myRights {rights}");
        assert_eq!(rights["mayDelete"], true, "MA-D0: {object} myRights {rights}");

        // Shared afterwards: refused
        let response = bill
            .jmap_update_account(
                sales,
                object,
                [(
                    &id,
                    json!({format!("shareWith/{robert_id}"): {read: true}}),
                )],
                Vec::<(&str, &str)>::new(),
            )
            .await;
        assert_eq!(
            response.pointer(&format!("/methodResponses/0/1/notUpdated/{id}/type")),
            Some(&json!("forbidden")),
            "MA-D0: {object} shared on: {:?}",
            response.pointer("/methodResponses/0")
        );

        // Robert still has nothing
        assert_eq!(
            robert
                .jmap_get_account(sales, object, Vec::<&str>::new(), [id.as_str()])
                .await
                .method_response()
                .typ(),
            "forbidden",
            "MA-D0: {object} reached from outside"
        );

        bill.jmap_destroy_account(sales, object, [id.as_str()], Vec::<(&str, &str)>::new())
            .await;
    }

    // Reaching the group's calendars and address books made its defaults
    let sales_id = sales.id_string();
    bill.jmap_method_calls(json!([
        ["Calendar/get", {"accountId": sales_id, "ids": (), "properties": ["id"]}, "c"],
        ["Calendar/set", {"accountId": sales_id, "onDestroyRemoveEvents": true,
            "#destroy": {"resultOf": "c", "name": "Calendar/get", "path": "/list/*/id"}}, "cd"],
        ["AddressBook/get", {"accountId": sales_id, "ids": (), "properties": ["id"]}, "a"],
        ["AddressBook/set", {"accountId": sales_id, "onDestroyRemoveContents": true,
            "#destroy": {"resultOf": "a", "name": "AddressBook/get", "path": "/list/*/id"}}, "ad"]
    ]))
    .await;

    admin
        .registry_update_object(
            ObjectType::Account,
            bill.id(),
            json!({"memberGroupIds": {sales.id_string(): false}}),
        )
        .await;
}
