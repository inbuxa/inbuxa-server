/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: open EventSource streams and WebSockets end when the sign-in they
//! were opened with stops being valid.

use crate::utils::server::TestServer;
use futures::{Stream, StreamExt};
use jmap_client::client_ws::WebSocketMessage;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{Permissions, PermissionsList},
    },
    types::map::Map,
};
use serde_json::json;
use std::time::Duration;

const FIRST_SECRET: &str = "the first secret of the streaming account";
const SECOND_SECRET: &str = "the second secret of the streaming account";

pub async fn test(test: &TestServer) {
    println!("Running EventSource and WebSocket sign-in checks...");
    let admin = test.account("admin@example.com");
    let mut account = admin
        .create_user_account(
            "streaming@example.com",
            FIRST_SECRET,
            "Streaming",
            &[],
            vec![],
        )
        .await;

    // A password change ends an open stream and WebSocket
    let client = account.jmap_client().await;
    let stream = client
        .event_source(None::<Vec<_>>, false, None, None)
        .await
        .unwrap();
    let mut ws = client.connect_ws().await.unwrap();
    let mut request = client.build();
    request.get_mailbox();
    request.send_ws().await.unwrap();
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await,
            Ok(Some(Ok(WebSocketMessage::Response(_))))
        ),
        "the WebSocket answers before the password changes"
    );
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({"credentials/0/secret": SECOND_SECRET}),
        )
        .await;
    assert_stream_ends(stream, "a password change").await;
    let mut request = client.build();
    request.get_mailbox();
    let _ = request.send_ws().await;
    let answer = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    assert!(
        !matches!(answer, Ok(Some(Ok(WebSocketMessage::Response(_))))),
        "the WebSocket answered after a password change: {answer:?}"
    );
    drop(ws);
    account.update_secret(SECOND_SECRET);

    // Losing a permission ends a stream, with no ping to wake it
    let client = account.jmap_client().await;
    let stream = client
        .event_source(None::<Vec<_>>, false, None, None)
        .await
        .unwrap();
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::default(),
                    disabled_permissions: Map::new(vec![Permission::JmapEmailQuery]),
                })
            }),
        )
        .await;
    assert_stream_ends(stream, "a permission was taken away").await;

    admin.destroy_account(account).await;
}

async fn assert_stream_ends<T, S>(mut stream: S, why: &str)
where
    S: Stream<Item = jmap_client::Result<T>> + Unpin,
{
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(_)) = stream.next().await {}
    })
    .await;
    assert!(ended.is_ok(), "the EventSource stream outlived {why}");
}
