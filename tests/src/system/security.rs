/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    system::authentication::validate_password_with_ip,
    utils::{
        http::HttpRequest,
        imap::{ImapConnection, Type},
        registry::UnwrapRegistryId,
        server::TestServer,
    },
};
use common::ipc::RegistryChange;
use imap_proto::ResponseType;
use jmap_client::{
    client::{Client, Credentials},
    mailbox::{self},
};
use registry::{
    schema::{
        enums::BlockReason,
        prelude::{ObjectType, Property},
        structs::{Action, BlockedIp, Http, Jmap},
    },
    types::ipmask::IpAddrOrMask,
};
use serde_json::json;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use store::{registry::write::RegistryWrite, write::now};
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Security tests...");

    let admin = test.account("admin@example.org");

    // Set security settings
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: true,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin
        .registry_update_setting(
            Jmap {
                max_concurrent_uploads: Some(4),
                max_concurrent_requests: Some(8),
                max_upload_size: 5000000,
                ..Default::default()
            },
            &[
                Property::MaxConcurrentUploads,
                Property::MaxConcurrentRequests,
                Property::MaxUploadSize,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Create a test user
    let user = test
        .create_user_account(
            "admin@example.org",
            "user@example.org",
            "this is a very strong password",
            &[],
            "user@example.org",
        )
        .await;
    let user_id = user.id();

    // Incorrect passwords should be rejected with a 401 error
    assert!(matches!(
        Client::new()
            .credentials(Credentials::basic("user@example.org", "abcde"))
            .accept_invalid_certs(true) .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await,
        Err(jmap_client::Error::Problem(err)) if err.status() == Some(401)));

    // Wait until the beginning of the 5 seconds bucket
    const LIMIT: u64 = 5;
    let now = now();
    let range_start = now / LIMIT;
    let range_end = (range_start * LIMIT) + LIMIT;
    tokio::time::sleep(Duration::from_secs(range_end - now)).await;

    // Make sure that the IP address is not blocked before the test
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::BlockedIp,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await,
        Vec::<Id>::new()
    );

    for _ in 0..98 {
        validate_password_with_ip("unknown@example.org", "wrong password", "127.0.0.1", false)
            .await;
    }

    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    // There are already 100 failed login attempts for this IP address
    // so the next one should be rejected, even if done over IMAP
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_disconnect().await;

    // Make sure the IP address is blocked
    let blocked_id = test
        .server
        .registry()
        .primary_key(
            ObjectType::BlockedIp.into(),
            Property::Address,
            IpAddrOrMask::from_ip(Ipv4Addr::LOCALHOST.into()).to_index_key(),
        )
        .await
        .unwrap()
        .expect("Blocked IP should have been created after too many failed login attempts");
    let blocked_ip = test
        .server
        .registry()
        .object::<BlockedIp>(blocked_id.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);

    ImapConnection::connect(b"_y ")
        .await
        .assert_disconnect()
        .await;

    // Lift ban
    test.server
        .registry()
        .write(RegistryWrite::delete(blocked_id))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    test.server
        .reload_registry(RegistryChange::Delete(blocked_id))
        .await
        .unwrap();

    // Valid authentication requests should not be rate limited
    for _ in 0..110 {
        validate_password_with_ip(
            "user@example.org",
            "this is a very strong password",
            "127.0.0.1",
            true,
        )
        .await;
    }

    // Set fail2ban expiration
    admin
        .registry_update_object(
            ObjectType::Security,
            Id::singleton(),
            // inbuxa: five seconds, not one: the checks below make a hundred
            // more requests before the ban is tested, and under load a
            // one-second ban expired first
            json!({
                Property::AuthBanPeriod: registry::types::duration::Duration::from_millis(5000)
            }),
        )
        .await;
    admin.reload_settings().await;

    // Block IP 10.0.0.2
    for _ in 0..105 {
        validate_password_with_ip("unknown@example.org", "wrong password", "10.0.0.2", false).await;
    }
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        false,
    )
    .await;

    // Check that the IP is blocked
    let blocked_ids = admin
        .registry_query_ids(
            ObjectType::BlockedIp,
            [(Property::Address, "10.0.0.2")],
            Vec::<&str>::new(),
        )
        .await;
    assert_eq!(blocked_ids.len(), 1);
    let blocked_ip = admin.registry_get::<BlockedIp>(blocked_ids[0]).await;
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);
    assert!(blocked_ip.expires_at.is_some());

    // After the ban period the ban should be lifted
    tokio::time::sleep(Duration::from_secs(6)).await;
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        true,
    )
    .await;

    // inbuxa: an address that fails again after its ban ran out is banned
    // again, although the expired ban is still remembered and its record
    // not yet cleaned up
    for _ in 0..105 {
        validate_password_with_ip("unknown@example.org", "wrong password", "10.0.0.2", false).await;
    }
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        false,
    )
    .await;
    let blocked_ids = admin
        .registry_query_ids(
            ObjectType::BlockedIp,
            [(Property::Address, "10.0.0.2")],
            Vec::<&str>::new(),
        )
        .await;
    assert_eq!(blocked_ids.len(), 1);
    assert!(
        admin
            .registry_get::<BlockedIp>(blocked_ids[0])
            .await
            .expires_at
            .is_some_and(|at| at.timestamp() > store::write::now() as i64),
        "the second ban's record runs from the second ban"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        true,
    )
    .await;

    // inbuxa: personal-data catalog, D2: the daily clean-up removes the
    // expired ban's record, without waiting for settings to reload
    test.server.purge_expired_blocked_ips().await.unwrap();
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::BlockedIp,
                [(Property::Address, "10.0.0.2")],
                Vec::<&str>::new(),
            )
            .await,
        Vec::<Id>::new(),
        "the expired ban's record is gone"
    );

    // inbuxa: behind a proxy the client is the last hop the proxies didn't
    // add. A banned client can't pick another address by putting it first.
    for _ in 0..105 {
        validate_password_with_ip(
            "unknown@example.org",
            "wrong password",
            "203.0.113.7",
            false,
        )
        .await;
    }
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "198.51.100.1, 203.0.113.7",
        false,
    )
    .await;
    let blocked_id = test
        .server
        .registry()
        .primary_key(
            ObjectType::BlockedIp.into(),
            Property::Address,
            IpAddrOrMask::from_ip(Ipv4Addr::new(203, 0, 113, 7).into()).to_index_key(),
        )
        .await
        .unwrap()
        .expect("the ban is on the address the proxy saw");
    test.server
        .registry()
        .write(RegistryWrite::delete(blocked_id))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    test.server
        .reload_registry(RegistryChange::Delete(blocked_id))
        .await
        .unwrap();

    // inbuxa: a login's failures from many addresses ban only the address
    // that goes over the limit, and only until the count starts over. They
    // used to ban every address failing on that login afterwards, its
    // owner's included, for the whole ban period (forever, unset).
    admin
        .registry_update_object(
            ObjectType::Security,
            Id::singleton(),
            json!({ Property::AuthBanPeriod: null }),
        )
        .await;
    admin.reload_settings().await;
    let victim = test
        .create_user_account(
            "admin@example.org",
            "victim@example.org",
            "this is a very strong password",
            &[],
            "victim@example.org",
        )
        .await;
    // 100 failures on the login from two addresses, neither over its own limit
    for attacker_ip in ["198.18.0.1", "198.18.0.2"] {
        for _ in 0..50 {
            validate_password_with_ip("victim@example.org", "guess", attacker_ip, false).await;
        }
        validate_password_with_ip(
            "user@example.org",
            "this is a very strong password",
            attacker_ip,
            true,
        )
        .await;
    }
    // The 101st goes over: that address is banned, until the count starts over
    validate_password_with_ip("victim@example.org", "guess", "198.18.0.3", false).await;
    let tripped_id = test
        .server
        .registry()
        .primary_key(
            ObjectType::BlockedIp.into(),
            Property::Address,
            IpAddrOrMask::from_ip(Ipv4Addr::new(198, 18, 0, 3).into()).to_index_key(),
        )
        .await
        .unwrap()
        .expect("the address that went over the login's limit is banned");
    // The owner's typo, and anyone else's single failure, bans nobody
    for ip in ["192.0.2.10", "198.18.0.4"] {
        validate_password_with_ip("victim@example.org", "typo", ip, false).await;
        assert_eq!(
            admin
                .registry_query_ids(
                    ObjectType::BlockedIp,
                    [(Property::Address, ip)],
                    Vec::<&str>::new(),
                )
                .await,
            Vec::<Id>::new(),
            "{ip} was banned for one failure on a login over its limit"
        );
    }
    validate_password_with_ip(
        "victim@example.org",
        "this is a very strong password",
        "192.0.2.10",
        true,
    )
    .await;
    let tripped = test
        .server
        .registry()
        .object::<BlockedIp>(tripped_id.id())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tripped
            .expires_at
            .is_some_and(|at| at.timestamp() <= store::write::now() as i64 + 86_400),
        "a login's ban lasts at most until its count starts over: {tripped:?}"
    );
    test.server
        .registry()
        .write(RegistryWrite::delete(tripped_id))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    test.server
        .reload_registry(RegistryChange::Delete(tripped_id))
        .await
        .unwrap();
    admin.destroy_account(victim).await;
    admin
        .registry_update_object(
            ObjectType::Security,
            Id::singleton(),
            json!({
                Property::AuthBanPeriod: registry::types::duration::Duration::from_millis(5000)
            }),
        )
        .await;
    admin.reload_settings().await;

    // inbuxa: personal-data catalog, D1: how long rotated log files are kept.
    // Unset keeps every file; a value is days; zero is refused; null goes back
    let using = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"];
    let account = admin.id_string().to_string();
    let log_get = || {
        admin.jmap_request(
            using,
            json!([["inbuxa:LogSettings/get", {"accountId": account, "ids": null}, "0"]]),
        )
    };
    let log_set = |keep: serde_json::Value| {
        admin.jmap_request(
            using,
            json!([["inbuxa:LogSettings/set", {"accountId": account,
                "update": {"singleton": {"keepForDays": keep}}}, "0"]]),
        )
    };
    let got = log_get().await;
    assert_eq!(
        got.0.pointer("/methodResponses/0/1/list/0/keepForDays"),
        Some(&serde_json::Value::Null),
        "a server that never set it keeps every file: {}",
        got.0
    );
    let set = log_set(json!(14)).await;
    assert!(
        set.0
            .pointer("/methodResponses/0/1/updated/singleton")
            .is_some(),
        "{}",
        set.0
    );
    let got = log_get().await;
    assert_eq!(
        got.0.pointer("/methodResponses/0/1/list/0/keepForDays"),
        Some(&json!(14))
    );
    let refused = log_set(json!(0)).await;
    assert_eq!(
        refused
            .0
            .pointer("/methodResponses/0/1/notUpdated/singleton/type"),
        Some(&json!("invalidProperties")),
        "{}",
        refused.0
    );
    log_set(serde_json::Value::Null).await;
    let got = log_get().await;
    assert_eq!(
        got.0.pointer("/methodResponses/0/1/list/0/keepForDays"),
        Some(&serde_json::Value::Null)
    );
    // Each change is in the audit log, before and after
    let query = admin
        .jmap_request(
            using,
            json!([["inbuxa:AuditEvent/query", {"accountId": account,
                "filter": {"targetKind": "inbuxa:LogSettings"}}, "0"]]),
        )
        .await;
    assert!(
        query
            .0
            .pointer("/methodResponses/0/1/ids")
            .and_then(|ids| ids.as_array())
            .is_some_and(|ids| ids.len() >= 2),
        "log settings changes aren't recorded: {}",
        query.0
    );

    // Make sure the IP remains unblocked after reload
    admin.registry_create_object(Action::ReloadBlockedIps).await;
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        true,
    )
    .await;

    // Login with the correct credentials
    let client = Client::new()
        .credentials(Credentials::basic(
            "user@example.org",
            "this is a very strong password",
        ))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(client.session().username(), "user@example.org");
    assert_eq!(
        client
            .session()
            .account(&user_id.to_string())
            .unwrap()
            .name(),
        "user@example.org"
    );
    assert!(
        client
            .session()
            .account(&user_id.to_string())
            .unwrap()
            .is_personal()
    );

    // Uploads up to 5000000 bytes should be allowed
    assert_eq!(
        client
            .upload(None, vec![b'A'; 5000000], None)
            .await
            .unwrap()
            .size(),
        5000000
    );
    assert!(
        client
            .upload(None, vec![b'A'; 5000001], None)
            .await
            .is_err()
    );

    // Concurrent requests check
    let client = Arc::new(client);
    let raw_http =
        HttpRequest::with_credentials(8899, "user@example.org", "this is a very strong password");
    for _ in 0..8 {
        let client_ = client.clone();
        tokio::spawn(async move {
            let _ = client_
                .mailbox_query(
                    mailbox::query::Filter::name("__sleep").into(),
                    [mailbox::query::Comparator::name()].into(),
                )
                .await;
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let body = serde_json::to_vec(&json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Mailbox/query", {
                "accountId": user_id.to_string(),
                "filter": { "name": "__sleep" }
            }, "c1"]
        ]
    }))
    .unwrap();
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            "/jmap/",
            Some(body),
            Some("application/json"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        400,
        "concurrent-requests body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy header on {:?}", resp.headers));
    assert!(
        policy.contains("\"concurrent-requests\"") && policy.contains("q=8"),
        "RateLimit-Policy = {policy}"
    );
    assert!(
        policy.contains(r#"qu="concurrent-requests""#),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit header on {:?}", resp.headers));
    assert!(
        state.contains("\"concurrent-requests\"") && state.contains("r=0"),
        "RateLimit = {state}"
    );

    // Wait for sleep to be done
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Concurrent upload test
    for _ in 0..4 {
        let client_ = client.clone();
        tokio::spawn(async move {
            client_.upload(None, b"sleep".to_vec(), None).await.unwrap();
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            &format!("/jmap/upload/{user_id}"),
            Some(b"sleep".to_vec()),
            Some("application/octet-stream"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        400,
        "concurrent-uploads body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy header on {:?}", resp.headers));
    assert!(
        policy.contains("\"concurrent-uploads\"") && policy.contains("q=4"),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit header on {:?}", resp.headers));
    assert!(
        state.contains("\"concurrent-uploads\"") && state.contains("r=0"),
        "RateLimit = {state}"
    );

    // Wait for sleep to be done before continuing
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Disable X-Forwarded-For processing
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: false,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin.reload_settings().await;

    // Destroy account
    admin.destroy_account(user).await;

    test.cleanup().await;
}

/// inbuxa: HTTP-JMAP-PREAUTH-2. A page on any other site can make its
/// visitors' browsers fetch a scan-ban path, with `<img src=".../x.php">`
/// say. The browser marks such a request `Sec-Fetch-Site: cross-site` or
/// `same-site`: it gets the 404 and its address isn't banned. A request
/// without the header, as a scanner sends it, is still banned.
///
/// Runs alone: `cargo test -p tests scan_ban_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scan_ban_tests() {
    let test = crate::utils::server::TestServerBuilder::new("scan_ban_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    println!("Running scan ban tests...");

    let localhost: std::net::IpAddr = Ipv4Addr::LOCALHOST.into();
    let ban = || async {
        test.server
            .registry()
            .primary_key(
                ObjectType::BlockedIp.into(),
                Property::Address,
                IpAddrOrMask::from_ip(localhost).to_index_key(),
            )
            .await
            .unwrap()
    };
    assert!(ban().await.is_none(), "not banned before the test");

    // `/x.php` is answered with a redirect to `/x.php/`, which the browser
    // follows with the same Sec-Fetch-Site
    for site in ["cross-site", "same-site", "CROSS-SITE"] {
        for path in ["/x.php", "/wp-admin/setup-config.php"] {
            let status = get_scan_path(path, Some(site))
                .await
                .unwrap_or_else(|err| panic!("{site} {path}: {err}"));
            assert_eq!(status, 404, "{site} {path}");
            assert!(
                ban().await.is_none() && !test.server.is_ip_blocked(localhost),
                "a {site} request for {path} banned its address"
            );
        }
    }

    // The browser's own navigations and fetches from this origin, and
    // requests that say nothing, are banned as before
    for site in [Some("same-origin"), Some("none"), None] {
        let status = get_scan_path("/x.php", site)
            .await
            .unwrap_or_else(|err| panic!("{site:?}: {err}"));
        assert_eq!(status, 404, "{site:?}");
        let blocked_id = ban()
            .await
            .unwrap_or_else(|| panic!("a {site:?} scan request should ban its address"));
        let blocked_ip = test
            .server
            .registry()
            .object::<BlockedIp>(blocked_id.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blocked_ip.reason, BlockReason::PortScanning, "{site:?}");
        assert!(test.server.is_ip_blocked(localhost), "{site:?}");
        assert!(
            get_scan_path("/", None).await.is_err(),
            "{site:?}: the banned address is turned away"
        );

        // Lift ban
        test.server
            .registry()
            .write(RegistryWrite::delete(blocked_id))
            .await
            .unwrap()
            .unwrap_id(trc::location!());
        test.server
            .reload_registry(RegistryChange::Delete(blocked_id))
            .await
            .unwrap();
        assert!(!test.server.is_ip_blocked(localhost), "{site:?}: lifted");
    }

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// inbuxa: a request too large to parse, a URI over the server's limit or a
/// head over its buffer, gets its 414 or 431 and counts nothing toward the
/// scan ban. A page on any site can make its visitors' browsers send one,
/// with an `<img src>` URL of 100 KB. Requests that don't parse for any
/// other reason still count.
///
/// Runs alone: `cargo test -p tests parse_error_ban_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn parse_error_ban_tests() {
    let test = crate::utils::server::TestServerBuilder::new("parse_error_ban_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    println!("Running parse error ban tests...");
    let localhost: std::net::IpAddr = Ipv4Addr::LOCALHOST.into();

    // More than the default scan ban rate, 30 a day
    let uri_too_long = format!(
        "GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "a".repeat(70_000)
    );
    for n in 0..35 {
        let status = send_raw(uri_too_long.as_bytes())
            .await
            .unwrap_or_else(|| panic!("URI too long #{n}: turned away"));
        assert_eq!(status, Some(414), "URI too long #{n}");
        assert!(
            !test.server.is_ip_blocked(localhost),
            "URI too long #{n} banned its address"
        );
    }
    let head_too_large = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Padding: {}\r\n\r\n",
        "a".repeat(500_000)
    );
    for n in 0..5 {
        // The server may close before it read everything, so the 431 can
        // be lost; the address must not be banned either way
        send_raw(head_too_large.as_bytes())
            .await
            .unwrap_or_else(|| panic!("head too large #{n}: turned away"));
        assert!(
            !test.server.is_ip_blocked(localhost),
            "head too large #{n} banned its address"
        );
    }

    // A head that isn't HTTP still counts
    let mut banned = false;
    for _ in 0..35 {
        if send_raw(b"\x01\x02 not http\r\n\r\n").await.is_none()
            || test.server.is_ip_blocked(localhost)
        {
            banned = true;
            break;
        }
    }
    assert!(banned, "malformed requests no longer count toward the ban");

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// Sends `request` on a new TLS connection to the HTTP listener: None when
/// the connection was turned away, else the response status if one came
async fn send_raw(request: &[u8]) -> Option<Option<u16>> {
    use tokio::io::AsyncWriteExt;
    let mut stream = crate::utils::http::raw_https_connect().await.ok()?;
    let _ = stream.write_all(request).await;
    let _ = stream.flush().await;
    Some(crate::utils::http::read_http_status(&mut stream, Duration::from_secs(5)).await)
}

/// inbuxa: `POST /api/auth` and `POST /api/passkey/register` take a password.
/// A page on another site can POST there without a preflight only with a
/// type such as `text/plain`, so anything but `application/json` is refused
/// with a 415 and counts toward no ban. JSON sign-ins still count.
///
/// Runs alone: `cargo test -p tests api_content_type_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn api_content_type_tests() {
    let test = crate::utils::server::TestServerBuilder::new("api_content_type_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    println!("Running sign-in content type tests...");
    let admin = test.create_admin_account("admin@example.com").await;
    admin
        .registry_update_setting(
            registry::schema::structs::Security {
                auth_ban_rate: Some(registry::schema::structs::Rate {
                    count: 3,
                    period: registry::types::duration::Duration::from_millis(86_400_000),
                }),
                ..Default::default()
            },
            &[Property::AuthBanRate],
        )
        .await;
    admin.reload_settings().await;

    let localhost: std::net::IpAddr = Ipv4Addr::LOCALHOST.into();
    let ban = || async {
        test.server
            .registry()
            .primary_key(
                ObjectType::BlockedIp.into(),
                Property::Address,
                IpAddrOrMask::from_ip(localhost).to_index_key(),
            )
            .await
            .unwrap()
    };
    let login = json!({
        "type": "authCode",
        "accountName": "admin@example.com",
        "accountSecret": "not the password",
        "clientId": "content-type-test",
        "redirectUri": "com.example.app:/cb",
        "codeChallenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "codeChallengeMethod": "S256",
    })
    .to_string();
    let register = json!({
        "step": "start",
        "ticket": "no-such-ticket",
        "password": "not the password",
    })
    .to_string();

    for content_type in [
        Some("text/plain"),
        Some("text/plain;charset=UTF-8"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        Some("application/json-patch+json"),
        Some("application/jsonx"),
        None,
    ] {
        for (path, body) in [("/api/auth", &login), ("/api/passkey/register", &register)] {
            let status = post_typed(path, content_type, body).await;
            assert_eq!(status, 415, "{path} with {content_type:?}");
        }
        assert!(
            ban().await.is_none() && !test.server.is_ip_blocked(localhost),
            "a {content_type:?} sign-in counted toward the ban"
        );
    }

    // JSON is answered, and its failed sign-ins are counted as before
    for content_type in [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
    ] {
        let status = post_typed("/api/auth", Some(content_type), &login).await;
        assert_ne!(status, 415, "{content_type}");
    }
    assert!(
        post_typed("/api/passkey/register", Some("application/json"), &register).await != 415,
        "a JSON passkey registration is answered"
    );
    for _ in 0..3 {
        post_typed("/api/auth", Some("application/json"), &login).await;
    }
    let blocked_id = ban()
        .await
        .expect("failed JSON sign-ins should still ban the address");
    let blocked_ip = test
        .server
        .registry()
        .object::<BlockedIp>(blocked_id.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// POSTs `body` to `path` with `content_type` (none when None); the status,
/// or 0 when the server turned the connection away
async fn post_typed(path: &str, content_type: Option<&str>, body: &str) -> u16 {
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
        .post(format!("https://127.0.0.1:8899{path}"))
        .body(body.to_string());
    if let Some(content_type) = content_type {
        request = request.header("Content-Type", content_type);
    }
    request
        .send()
        .await
        .map_or(0, |response| response.status().as_u16())
}

/// inbuxa: one IPv6 host holds a whole /64 and can use any address in it,
/// so failures are counted and bans set per /64; IPv4 addresses stay one by
/// one. A network banned while the server runs is enforced at once, not at
/// the next reload.
///
/// Runs alone: `cargo test -p tests ipv6_ban_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn ipv6_ban_tests() {
    let test = crate::utils::server::TestServerBuilder::new("ipv6_ban_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    println!("Running IPv6 ban tests...");
    let admin = test.create_admin_account("admin@example.com").await;
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: true,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin
        .registry_update_setting(
            registry::schema::structs::Security {
                auth_ban_rate: Some(registry::schema::structs::Rate {
                    count: 3,
                    period: registry::types::duration::Duration::from_millis(86_400_000),
                }),
                ..Default::default()
            },
            &[Property::AuthBanRate],
        )
        .await;
    admin.reload_settings().await;
    let ip = |ip: &str| ip.parse::<std::net::IpAddr>().unwrap();
    let mut failures = Vec::new();

    // A network ban that reaches this node while it runs, as an admin's new
    // ban or a peer's broadcast does, on a node with no network bans yet
    let network = "2001:db8:5::/48".parse::<IpAddrOrMask>().unwrap();
    assert!(!test.server.is_ip_blocked(ip("2001:db8:5:1::1")));
    let id = test
        .server
        .registry()
        .write(RegistryWrite::insert(
            &registry::schema::prelude::Object::from(BlockedIp {
                address: network,
                created_at: registry::types::datetime::UTCDateTime::from_timestamp(now() as i64),
                expires_at: None,
                reason: BlockReason::Manual,
            }),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    test.server
        .reload_registry(RegistryChange::Insert(ObjectType::BlockedIp.id(id)))
        .await
        .unwrap();
    if !test.server.is_ip_blocked(ip("2001:db8:5:1::1")) {
        failures.push("a network banned at runtime isn't enforced until a reload");
    }
    assert!(!test.server.is_ip_blocked(ip("2001:db8:6::1")));

    // Failed sign-ins from four addresses of one /64 add up
    for (n, host) in ["::10", "::11", "::12", "::13"].into_iter().enumerate() {
        validate_password_with_ip(
            &format!("nobody{n}@example.com"),
            "wrong password",
            &format!("2001:db8:1:2{host}"),
            false,
        )
        .await;
    }
    let prefix = "2001:db8:1:2::/64".parse::<IpAddrOrMask>().unwrap();
    let blocked_id = test
        .server
        .registry()
        .primary_key(
            ObjectType::BlockedIp.into(),
            Property::Address,
            prefix.to_index_key(),
        )
        .await
        .unwrap();
    if !test.server.is_ip_blocked(ip("2001:db8:1:2:ffff::1")) || blocked_id.is_none() {
        failures.push("failures from one /64 don't ban the /64");
    }
    assert!(failures.is_empty(), "{failures:?}");
    let blocked_ip = test
        .server
        .registry()
        .object::<BlockedIp>(blocked_id.unwrap().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);
    assert!(!test.server.is_ip_blocked(ip("2001:db8:1:3::10")));
    // An address of the /64 that never failed is turned away
    validate_password_with_ip(
        "admin@example.com",
        admin.secret(),
        "2001:db8:1:2::99",
        false,
    )
    .await;

    // IPv4 addresses are counted one by one; an IPv4-mapped address is the
    // IPv4 address
    for (n, address) in ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"]
        .into_iter()
        .enumerate()
    {
        validate_password_with_ip(
            &format!("v4-{n}@example.com"),
            "wrong password",
            address,
            false,
        )
        .await;
    }
    assert!(!test.server.is_ip_blocked(ip("10.0.0.1")));
    assert!(!test.server.is_ip_blocked(ip("10.0.0.2")));
    validate_password_with_ip(
        "v4-mapped@example.com",
        "wrong password",
        "::ffff:10.0.0.1",
        false,
    )
    .await;
    assert!(test.server.is_ip_blocked(ip("10.0.0.1")));
    assert!(test.server.is_ip_blocked(ip("::ffff:10.0.0.1")));
    assert!(!test.server.is_ip_blocked(ip("10.0.0.2")));

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// inbuxa: failures counted by login are kept apart from those counted by
/// address. Login `abcd` is the four bytes of 97.98.99.100: failures on it
/// from elsewhere used to run up that address's count, so its owner's next
/// single failure banned it.
///
/// Runs alone: `cargo test -p tests auth_key_space_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn auth_key_space_tests() {
    let test = crate::utils::server::TestServerBuilder::new("auth_key_space_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    println!("Running sign-in counter key space tests...");
    let admin = test.create_admin_account("admin@example.com").await;
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: true,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin
        .registry_update_setting(
            registry::schema::structs::Security {
                auth_ban_rate: Some(registry::schema::structs::Rate {
                    count: 3,
                    period: registry::types::duration::Duration::from_millis(86_400_000),
                }),
                ..Default::default()
            },
            &[Property::AuthBanRate],
        )
        .await;
    admin.reload_settings().await;

    // Three failures on login `abcd`, one from each of three addresses: no
    // count goes over
    for address in ["10.1.1.1", "10.1.1.2", "10.1.1.3"] {
        validate_password_with_ip("abcd", "wrong password", address, false).await;
    }
    // One failure from 97.98.99.100 on another login
    validate_password_with_ip("owner@example.com", "wrong password", "97.98.99.100", false).await;
    assert!(
        !test.server.is_ip_blocked("97.98.99.100".parse().unwrap()),
        "failures on login abcd counted toward 97.98.99.100"
    );
    for address in ["10.1.1.1", "10.1.1.2", "10.1.1.3"] {
        assert!(!test.server.is_ip_blocked(address.parse().unwrap()));
    }

    // The login's own count still bans the address that takes it over
    validate_password_with_ip("abcd", "wrong password", "10.1.1.4", false).await;
    assert!(test.server.is_ip_blocked("10.1.1.4".parse().unwrap()));
    assert!(!test.server.is_ip_blocked("97.98.99.100".parse().unwrap()));

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// GETs `path` on a new connection, with `Sec-Fetch-Site: site` when given,
/// following redirects; the final status, or an error when the server
/// turned the connection away
async fn get_scan_path(path: &str, site: Option<&str>) -> Result<u16, String> {
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:8899{path}"));
    if let Some(site) = site {
        request = request.header("Sec-Fetch-Site", site);
    }
    let response = request.send().await.map_err(|err| err.to_string())?;
    match response.status().as_u16() {
        // inbuxa: a banned address is turned away when it connects, or with
        // a 403 on a connection it already had
        403 => Err("forbidden".to_string()),
        status => Ok(status),
    }
}
