/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: deleting a file queues the task that archives it for undelete
// (UD-1). Each way of deleting one must wake the task manager, or that task
// sits until its next periodic look at the queue, minutes later.

use crate::utils::{server::TestServer, storage::task_left_after};
use hyper::StatusCode;
use serde_json::json;
use std::time::Duration;

const BASE: &str = "/dav/file/john%40example.com";

pub async fn test(test: &TestServer) {
    println!("Running file deletion task tests...");
    let account = test.account("john@example.com");
    let client = account.webdav_client();
    test.wait_for_tasks().await;

    // WebDAV DELETE
    let path = format!("{BASE}/tasks-1.txt");
    put(test, &path).await;
    client
        .request("DELETE", &path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_tasks_run(test, "WebDAV DELETE").await;

    // WebDAV COPY over an existing file deletes the file it replaces
    let (from, to) = (format!("{BASE}/tasks-2.txt"), format!("{BASE}/tasks-3.txt"));
    put(test, &from).await;
    put(test, &to).await;
    client
        .request_with_headers("COPY", &from, [("destination", to.as_str())], "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_tasks_run(test, "WebDAV COPY over a file").await;

    // WebDAV MOVE over an existing file deletes the source
    client
        .request_with_headers("MOVE", &from, [("destination", to.as_str())], "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_tasks_run(test, "WebDAV MOVE over a file").await;
    client
        .request("DELETE", &to, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    assert_tasks_run(test, "WebDAV DELETE").await;

    // JMAP FileNode/set destroy
    let response = account
        .jmap_method_calls(json!([
            ["Blob/upload", {
                "accountId": account.id_string(),
                "create": { "file": { "data": [{ "data:asText": "tasks" }] } }
            }, "0"],
            ["FileNode/set", {
                "accountId": account.id_string(),
                "create": { "i0": { "name": "tasks-4.txt", "parentId": null, "blobId": "#file" } }
            }, "1"]
        ]))
        .await
        .into_inner();
    let file_id = response
        .pointer("/methodResponses/1/1/created/i0/id")
        .and_then(|id| id.as_str())
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let response = account
        .jmap_method_calls(json!([
            ["FileNode/set", {
                "accountId": account.id_string(),
                "destroy": [&file_id]
            }, "0"]
        ]))
        .await
        .into_inner();
    assert_eq!(
        response.pointer("/methodResponses/0/1/destroyed/0"),
        Some(&json!(file_id)),
        "{response}"
    );
    assert_tasks_run(test, "JMAP FileNode/set destroy").await;
}

async fn put(test: &TestServer, path: &str) {
    test.account("john@example.com")
        .webdav_client()
        .request_with_headers("PUT", path, [("content-type", "text/plain")], "tasks")
        .await
        .with_status(StatusCode::CREATED);
}

async fn assert_tasks_run(test: &TestServer, what: &str) {
    if let Some(task) = task_left_after(&test.server, Duration::from_secs(10)).await {
        panic!("{what}: a task was still queued after 10 s: {task:?}");
    }
}
