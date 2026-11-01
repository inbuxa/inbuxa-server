/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use registry::schema::{prelude::Property, structs::Sharing};
use serde_json::{Value, json};

/// Runs before anything shares between these accounts, so that "already has
/// to do with" means the account itself and its groups.
pub async fn test(test: &TestServer) {
    println!("Running directory queries off tests...");
    let admin = test.account("admin");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string();
    let jane_id = jane.id_string();

    set_directory_queries(test, false).await;

    // A regular user holds every jmapPrincipal* permission and still can't list anyone
    assert_eq!(
        john.jmap_method_call("Principal/query", json!({ "accountId": john_id }))
            .await
            .method_response()
            .typ(),
        "forbidden"
    );

    // Principal/get answers for the account itself and nobody else, asked by id or for everyone
    let response = john
        .jmap_method_call(
            "Principal/get",
            json!({ "accountId": john_id, "ids": [john_id, jane_id], "properties": ["id"] }),
        )
        .await;
    let found = ids(&response.method_response()["list"]);
    assert_eq!(found, [john_id], "{response:?}");
    assert_eq!(
        response.method_response()["notFound"],
        json!([jane_id]),
        "{response:?}"
    );
    let response = john
        .jmap_method_call(
            "Principal/get",
            json!({ "accountId": john_id, "ids": null, "properties": ["id"] }),
        )
        .await;
    let found = ids(&response.method_response()["list"]);
    assert!(found.contains(&john_id), "{response:?}");
    assert!(!found.contains(&jane_id), "{response:?}");

    // Free/busy likewise
    let availability = |id: &str| {
        json!({
            "accountId": john_id,
            "id": id,
            "utcStart": "2026-01-01T00:00:00Z",
            "utcEnd": "2026-01-02T00:00:00Z",
        })
    };
    assert_eq!(
        john.jmap_method_call("Principal/getAvailability", availability(jane_id))
            .await
            .method_response()
            .typ(),
        "forbidden"
    );
    let response = john
        .jmap_method_call("Principal/getAvailability", availability(john_id))
        .await;
    assert!(
        response.method_response()["list"].is_array(),
        "{response:?}"
    );

    // Whoever can list accounts anyway isn't held back
    let response = admin
        .jmap_method_calls(json!([
            ["Principal/query", { "accountId": admin.id_string() }, "q"],
            ["Principal/get", {
                "accountId": admin.id_string(),
                "#ids": { "resultOf": "q", "name": "Principal/query", "path": "/ids" },
                "properties": ["id"]
            }, "g"]
        ]))
        .await;
    let found = ids(&response.response_at(1)["list"]);
    assert!(
        found.contains(&john_id) && found.contains(&jane_id),
        "{response:?}"
    );

    // Back on, a regular user can look people up again
    set_directory_queries(test, true).await;
    let response = john
        .jmap_method_calls(json!([
            ["Principal/query", { "accountId": john_id }, "q"],
            ["Principal/get", {
                "accountId": john_id,
                "#ids": { "resultOf": "q", "name": "Principal/query", "path": "/ids" },
                "properties": ["id"]
            }, "g"]
        ]))
        .await;
    assert!(
        ids(&response.response_at(1)["list"]).contains(&jane_id),
        "{response:?}"
    );

    // Asking for free/busy made John's default calendar
    john.destroy_all_calendars().await;
    test.assert_is_empty().await;
}

fn ids(list: &Value) -> Vec<&str> {
    list.as_array()
        .unwrap_or_else(|| panic!("Expected a list: {list:?}"))
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect()
}

pub async fn set_directory_queries(test: &TestServer, allow: bool) {
    let admin = test.account("admin");
    admin
        .registry_update_setting(
            Sharing {
                allow_directory_queries: allow,
                ..Default::default()
            },
            &[Property::AllowDirectoryQueries],
        )
        .await;
    admin.reload_settings().await;
}
