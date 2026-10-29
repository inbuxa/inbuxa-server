/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{server::TestServer, webdav::GenerateTestDavResource};

use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();

    // inbuxa: every locked resource a request touches needs one of its
    // locks' tokens, not just the first one found
    println!("Running LOCK tests (several resources)...");
    let base_path = format!("{}/john%40example.com", DavResourceName::File.base_path());
    let src_path = format!("{base_path}/lock-src");
    let dst_path = format!("{base_path}/lock-dst");
    let mut tokens = Vec::new();
    for path in [&src_path, &dst_path] {
        client
            .request("MKCOL", path, "")
            .await
            .with_status(StatusCode::CREATED);
        tokens.push(
            client
                .lock_create(path, "some-client", true, "infinity", "Second-123")
                .await
                .with_status(StatusCode::CREATED)
                .lock_token()
                .to_string(),
        );
    }
    let src_only = format!("(<{}>)", tokens[0]);
    let both = format!("(<{}>) (<{}>)", tokens[0], tokens[1]);
    client
        .request_with_headers(
            "MOVE",
            &src_path,
            [
                ("destination", dst_path.as_str()),
                ("overwrite", "T"),
                ("if", src_only.as_str()),
            ],
            "",
        )
        .await
        .with_status(StatusCode::LOCKED)
        .with_value("D:error.D:lock-token-submitted.D:href", &dst_path);
    client
        .request_with_headers(
            "MOVE",
            &src_path,
            [
                ("destination", dst_path.as_str()),
                ("overwrite", "T"),
                ("if", both.as_str()),
            ],
            "",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    for (path, token) in [&src_path, &dst_path].into_iter().zip(&tokens) {
        client
            .unlock(path, token)
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    // A shared lock's holder writes with its own token alone
    let shared_path = format!("{base_path}/lock-shared");
    client
        .request("MKCOL", &shared_path, "")
        .await
        .with_status(StatusCode::CREATED);
    let mut tokens = Vec::new();
    for owner in ["client-a", "client-b"] {
        tokens.push(
            client
                .lock_create(&shared_path, owner, false, "infinity", "Second-123")
                .await
                .with_status(StatusCode::CREATED)
                .lock_token()
                .to_string(),
        );
    }
    let file_path = format!("{shared_path}/file.txt");
    client
        .request("PUT", &file_path, "content")
        .await
        .with_status(StatusCode::LOCKED);
    client
        .request_with_headers(
            "PUT",
            &file_path,
            [("if", format!("(<{}>)", tokens[1]).as_str())],
            "content",
        )
        .await
        .with_status(StatusCode::CREATED);
    for token in &tokens {
        client
            .unlock(&shared_path, token)
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    client
        .request("DELETE", &shared_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    client
        .request("DELETE", &dst_path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!(
            "Running LOCK/UNLOCK tests ({})...",
            resource_type.base_path()
        );
        let base_path = format!("{}/john%40example.com", resource_type.base_path());

        // Test 1: Creating a collection under an unmapped resource without providing a lock token should fail
        let path = format!("{base_path}/do-not-write");
        let response = client
            .lock_create(&path, "super-owner", true, "infinity", "Second-123")
            .await
            .with_status(StatusCode::CREATED);
        let lock_token = response
            .with_value(
                "D:prop.D:lockdiscovery.D:activelock.D:owner.href",
                "super-owner",
            )
            .with_value("D:prop.D:lockdiscovery.D:activelock.D:depth", "infinity")
            .with_value(
                "D:prop.D:lockdiscovery.D:activelock.D:timeout",
                "Second-123",
            )
            .lock_token()
            .to_string();

        // Test 2: Refreshing a lock token with an invalid a lock token should fail
        client
            .lock_refresh(&path, "urn:inbuxa:davlock:1234", "infinity", "Second-456")
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        // Test 3: Refreshing a lock token with valid a lock token should succeed
        client
            .lock_refresh(&path, &lock_token, "infinity", "Second-456")
            .await
            .with_status(StatusCode::OK)
            .with_value(
                "D:prop.D:lockdiscovery.D:activelock.D:owner.href",
                "super-owner",
            )
            .with_any_value(
                "D:prop.D:lockdiscovery.D:activelock.D:timeout",
                ["Second-456", "Second-455"],
            );

        // Test 3: Creating a collection under an unmapped resource with a lock token should fail
        client
            .request_with_headers("MKCOL", &path, [], "")
            .await
            .with_status(StatusCode::LOCKED)
            .with_value("D:error.D:lock-token-submitted.D:href", &path);

        // Test 4: Creating a collection under a mapped resource with a lock token should succeed
        client
            .request_with_headers(
                "MKCOL",
                &path,
                [("if", format!("(<{lock_token}>)").as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);

        // Test 5: Creating a lock under an infinity locked resource should fail
        let file_path = format!("{path}/file.txt");
        client
            .lock_create(&file_path, "super-owner", true, "0", "Second-123")
            .await
            .with_status(StatusCode::LOCKED)
            .with_value("D:error.D:lock-token-submitted.D:href", &path);

        // Test 6: Creating a file under a locked resource without a lock token should fail
        let contents = resource_type.generate();
        client
            .request("PUT", &file_path, &contents)
            .await
            .with_status(StatusCode::LOCKED)
            .with_value("D:error.D:lock-token-submitted.D:href", &path);

        // Test 7: Creating a file under a locked resource with a lock token should succeed
        client
            .request_with_headers(
                "PUT",
                &file_path,
                [("if", format!("(<{lock_token}>)").as_str())],
                &contents,
            )
            .await
            .with_status(StatusCode::CREATED);

        // Test 8: Locks should be included in propfind responses
        let response = client
            .propfind(&path, [DavProperty::WebDav(WebDavProperty::LockDiscovery)])
            .await;
        for href in [path.clone() + "/", file_path] {
            let props = response.properties(&href);
            props
                .get(DavProperty::WebDav(WebDavProperty::LockDiscovery))
                .with_some_values([
                    "D:activelock.D:owner.href:super-owner",
                    "D:activelock.D:depth:infinity",
                    format!("D:activelock.D:locktoken.D:href:{lock_token}").as_str(),
                    format!("D:activelock.D:lockroot.D:href:{path}").as_str(),
                    "D:activelock.D:locktype.D:write",
                    "D:activelock.D:lockscope.D:exclusive",
                ])
                .with_any_values([
                    "D:activelock.D:timeout:Second-456",
                    "D:activelock.D:timeout:Second-455",
                ]);
        }

        // Test 9: Delete with and without a lock token
        client
            .request("DELETE", &path, "")
            .await
            .with_status(StatusCode::LOCKED)
            .with_value("D:error.D:lock-token-submitted.D:href", &path);
        client
            .request_with_headers(
                "DELETE",
                &path,
                [("if", format!("(<{lock_token}>)").as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 10: Unlock with and without a lock token
        client
            .unlock(&path, "urn:inbuxa:davlock:1234")
            .await
            .with_status(StatusCode::CONFLICT)
            .with_value("D:error.D:lock-token-matches-request-uri", "");
        client
            .unlock(&path, &lock_token)
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 11: Locking with a large dead property should fail
        let path = format!("{base_path}/invalid-lock");
        client
            .lock_create(
                &path,
                (0..=test.server.core.groupware.dead_property_size.unwrap() + 1)
                    .map(|_| "a")
                    .collect::<String>()
                    .as_str(),
                true,
                "infinity",
                "Second-123",
            )
            .await
            .with_status(StatusCode::PAYLOAD_TOO_LARGE);

        // Test 12: Too many locks should fail
        for i in 0..test.server.core.groupware.max_locks_per_user {
            client
                .lock_create(
                    &format!("{base_path}/invalid-lock-{i}"),
                    "super-owner",
                    true,
                    "infinity",
                    "Second-123",
                )
                .await
                .with_status(StatusCode::CREATED);
        }
        client
            .lock_create(
                &format!("{base_path}/invalid-lock-greedy"),
                "super-owner",
                true,
                "infinity",
                "Second-123",
            )
            .await
            .with_status(StatusCode::TOO_MANY_REQUESTS);
    }

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}
