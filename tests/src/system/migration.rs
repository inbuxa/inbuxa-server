/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Migration` (docs/spec/features/migrations.md), with a stand-in
//! for inbuxa-migrate (`tests/resources/migrations/fake-inbuxa-migrate`)
//! that answers like the real one and says what it was given.
//!
//! A migration is created and checked; a run needs the secret once, and
//! the child gets it and a run token through its environment and nothing
//! else of the server's. The token signs in as the administrator, from
//! loopback, and ends with the run. Preview, move, the passwords once (to
//! whichever administrator takes them), the final pass, stop, close;
//! destroy is refused, a tenant is refused, and the audit log never holds
//! the secret.
//!
//! `migration_real_engine_tests` runs the real inbuxa-migrate against a
//! Dovecot (`tests/resources/migrations/dovecot-source`), on demand.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];
const SECRET: &str = "s3cret-source-7731";

async fn call(account: &Account, method: &str, mut arguments: Value) -> (String, Value) {
    if arguments.get("accountId").is_none() {
        arguments["accountId"] = account.id_string().into();
    }
    let response = account
        .jmap_request(USING, json!([[method, arguments, "0"]]))
        .await;
    let call = response
        .0
        .pointer("/methodResponses/0")
        .cloned()
        .unwrap_or_else(|| panic!("{method}: {}", response.0));
    (
        call[0].as_str().unwrap_or_default().to_string(),
        call[1].clone(),
    )
}

async fn update(account: &Account, id: &str, patch: Value) -> Value {
    call(
        account,
        "inbuxa:Migration/set",
        json!({"update": {id: patch}}),
    )
    .await
    .1
}

async fn get(account: &Account, id: &str) -> Value {
    let (_, response) = call(account, "inbuxa:Migration/get", json!({"ids": [id]})).await;
    response["list"][0].clone()
}

/// The migration once its run is over.
async fn settled(account: &Account, id: &str) -> Value {
    for _ in 0..300 {
        let migration = get(account, id).await;
        if migration["status"] != "running" {
            return migration;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the run didn't end: {}", get(account, id).await);
}

fn seen(dir: &Path, id: &str, what: &str) -> Value {
    let text = std::fs::read_to_string(dir.join(id).join(format!("seen-{what}.json")))
        .unwrap_or_else(|err| panic!("seen-{what}.json: {err}"));
    serde_json::from_str(&text).unwrap()
}

/// Migration ids are the store's numbers; the work directory is named by
/// the number, the JMAP id is its encoding.
fn number(id: &str) -> String {
    types::id::Id::from_str(id).unwrap().id().to_string()
}

pub async fn test(test: &mut TestServer, dir: PathBuf) {
    println!("Running migration tests...");
    let admin = test.account("admin@example.com");
    let source = json!({"url": "imaps://old.example.org", "login": "{email}*master"});

    // Created, and checked
    let (_, response) = call(
        admin,
        "inbuxa:Migration/set",
        json!({"create": {
            "m": {"description": "From the old Dovecot", "sourceKind": "imap",
                  "source": source, "accounts": ["A@example.org", "b@example.org"],
                  "createAccounts": true},
            "maildir": {"sourceKind": "maildir", "accounts": ["a@example.org"]},
            "noLogin": {"sourceKind": "imap", "source": {"url": "imaps://old.example.org",
                        "login": "master"}, "accounts": ["a@example.org"]},
            "withSecret": {"sourceKind": "imap", "source": source,
                           "accounts": ["a@example.org"], "secret": SECRET},
            "serverSet": {"sourceKind": "imap", "source": source,
                          "accounts": ["a@example.org"], "status": "running"},
        }}),
    )
    .await;
    let id = response["created"]["m"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    for (client, property) in [
        ("maildir", "sourceKind"),
        ("noLogin", "source"),
        ("withSecret", "action"),
        ("serverSet", "status"),
    ] {
        assert_eq!(
            response["notCreated"][client]["properties"][0], property,
            "{client}: {response}"
        );
    }
    let m = get(admin, &id).await;
    assert_eq!(m["accounts"], json!(["a@example.org", "b@example.org"]));
    assert_eq!(m["status"], "idle");
    assert_eq!(m["createdBy"], "admin@example.com");
    assert_eq!(m["parallel"], 4);

    // A run needs the secret, once
    let response = update(admin, &id, json!({"action": "preview"})).await;
    assert_eq!(
        response["notUpdated"][&id]["properties"][0], "secret",
        "{response}"
    );
    let response = update(admin, &id, json!({"action": "finalPass", "secret": SECRET})).await;
    assert!(
        response["notUpdated"][&id]["description"]
            .as_str()
            .is_some_and(|d| d.contains("Move the accounts first")),
        "{response}"
    );

    // Preview: a dry run, on this node's loopback, as the administrator
    let response = update(admin, &id, json!({"action": "preview"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let m = settled(admin, &id).await;
    assert_eq!(m["run"], "preview", "{m}");
    assert_eq!(m["result"], "done", "{m}");
    assert_eq!(m["progress"]["total"], 2, "{m}");
    assert_eq!(m["progress"]["read"], 6, "{m}");
    assert_eq!(m["moved"], false);
    assert!(m["reportBlobId"].is_string(), "{m}");
    assert!(m["nodeId"].is_string(), "{m}");
    let work = number(&id);
    let plan = seen(&dir, &work, "plan");
    assert_eq!(
        plan["args"],
        json!(["plan", "--answers", "answers.json", "."])
    );
    let run = seen(&dir, &work, "run");
    assert!(
        run["args"]
            .as_array()
            .unwrap()
            .contains(&json!("--dry-run")),
        "{run}"
    );
    assert_eq!(run["secret"], SECRET);
    assert_eq!(run["signedIn"], "admin@example.com", "{run}");
    assert!(
        run["url"]
            .as_str()
            .unwrap()
            .starts_with("https://127.0.0.1:"),
        "{run}"
    );
    // Python sets LC_CTYPE itself when the locale is C
    let env: Vec<&Value> = run["env"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|var| *var != "LC_CTYPE")
        .collect();
    assert_eq!(
        env,
        ["MIGRATE_INBUXA_TOKEN", "MIGRATE_SOURCE_SECRET", "PATH"],
        "only its secrets reach the child"
    );
    let answers: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(&work).join("answers.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(answers["target"]["stayOnUrl"], true);
    assert_eq!(answers["target"]["allowInvalidCerts"], true);
    assert!(!answers.to_string().contains(SECRET), "{answers}");

    // The run's token ended with it
    let token = run["token"].as_str().unwrap();
    assert!(token.starts_with("MIG_"), "{token}");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let status = client
        .get(format!("{}/jmap/session", run["url"].as_str().unwrap()))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 401, "a run token outlived its run");

    // Move: the secret is held; one account doesn't finish
    let response = update(admin, &id, json!({"action": "move"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let m = settled(admin, &id).await;
    assert_eq!(m["run"], "move", "{m}");
    assert_eq!(m["result"], "unfinished", "{m}");
    assert_eq!(m["progress"]["written"], 5, "{m}");
    assert_eq!(m["progress"]["unfinished"], 1, "{m}");
    assert_eq!(m["failures"][0]["email"], "b@example.org", "{m}");
    assert_eq!(m["failures"][0]["step"], "export", "{m}");
    assert_eq!(m["moved"], true);
    assert_eq!(m["passwordsWaiting"], true, "{m}");
    assert!(m["diskUsed"].as_u64().unwrap() > 0, "{m}");
    let run = seen(&dir, &work, "run");
    assert!(
        !run["args"]
            .as_array()
            .unwrap()
            .contains(&json!("--dry-run"))
    );

    // The answers can't change source once moved
    let response = update(
        admin,
        &id,
        json!({"source": {"url": "imaps://elsewhere.example.org",
                                                       "login": "{email}"}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][&id]["properties"][0], "source",
        "{response}"
    );
    let response = update(admin, &id, json!({"description": "Dovecot, done"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");

    // The new passwords, once, to whichever administrator takes them
    let other = test.account("admin2@example.com");
    let response = update(other, &id, json!({"action": "passwords"})).await;
    let blob = response["updated"][&id]["passwordsBlobId"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let csv = client
        .get(format!(
            "{}/jmap/download/{}/{blob}/passwords.csv",
            run["url"].as_str().unwrap(),
            other.id_string()
        ))
        .basic_auth(other.name(), Some(other.secret()))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&csv).contains("a@example.org,generated-0"),
        "{}",
        String::from_utf8_lossy(&csv)
    );
    assert!(!dir.join(&work).join("passwords-1.csv").exists());
    let response = update(admin, &id, json!({"action": "passwords"})).await;
    assert!(response["notUpdated"].get(&id).is_some(), "{response}");
    assert_eq!(get(admin, &id).await["passwordsWaiting"], false);

    // The final pass
    update(admin, &id, json!({"action": "finalPass"})).await;
    let m = settled(admin, &id).await;
    assert_eq!(m["run"], "finalPass", "{m}");
    let run = seen(&dir, &work, "run");
    assert!(
        run["args"].as_array().unwrap().contains(&json!("--again")),
        "{run}"
    );

    // Stopped while it runs
    let (_, response) = call(
        admin,
        "inbuxa:Migration/set",
        json!({"create": {"slow": {"sourceKind": "jmap",
            "source": {"url": "https://old.example.org", "login": ""},
            "accounts": ["slow@example.org"]}}}),
    )
    .await;
    let slow = response["created"]["slow"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    update(admin, &slow, json!({"action": "move", "secret": SECRET})).await;
    assert_eq!(get(admin, &slow).await["status"], "running");
    let response = update(admin, &slow, json!({"action": "close"})).await;
    assert!(response["notUpdated"].get(&slow).is_some(), "{response}");
    let response = update(admin, &slow, json!({"action": "stop"})).await;
    assert!(response["updated"].get(&slow).is_some(), "{response}");
    let m = settled(admin, &slow).await;
    assert_eq!(m["result"], "stopped", "{m}");

    // Closed: the work directory goes, the migration stays listed
    let response = update(admin, &id, json!({"action": "close"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert!(!dir.join(&work).exists(), "the archives outlived the close");
    let m = get(admin, &id).await;
    assert_eq!(m["status"], "closed");
    let response = update(admin, &id, json!({"action": "move", "secret": SECRET})).await;
    assert!(
        response["notUpdated"][&id]["description"]
            .as_str()
            .is_some_and(|d| d.contains("closed")),
        "{response}"
    );
    let (_, response) = call(admin, "inbuxa:Migration/set", json!({"destroy": [&id]})).await;
    assert!(response["notDestroyed"].get(&id).is_some(), "{response}");
    update(admin, &slow, json!({"action": "close"})).await;

    // Nobody in a tenant reaches migrations
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Migration tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "migrations.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@migrations.example.org",
            "tenant-admin-secret-6610",
            "Tenant admin",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({Property::Roles: UserRoles::Admin}),
        )
        .await;
    for (method, arguments) in [
        ("inbuxa:Migration/get", json!({"ids": null})),
        (
            "inbuxa:Migration/set",
            json!({"create": {"x": {"sourceKind": "imap", "source": source,
                                    "accounts": ["a@example.org"]}}}),
        ),
    ] {
        let (name, response) = call(&t_admin, method, arguments).await;
        assert_eq!(name, "error", "{method} by a tenant: {response}");
    }

    // Every change audited, never the secret
    let (_, response) = call(
        admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Migration"}}),
    )
    .await;
    let ids = response["ids"].clone();
    assert!(
        ids.as_array().is_some_and(|ids| ids.len() >= 8),
        "creates and actions audited: {response}"
    );
    let (_, response) = call(admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    assert!(
        !response.to_string().contains(SECRET),
        "the secret was audited"
    );
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn migration_tests() {
    let mut test = TestServerBuilder::new("migration_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let dir = test.temp_dir.path.join("migrations");
    let engine =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/migrations/fake-inbuxa-migrate");
    // SAFETY: set before any run reads them, and only this test reads them
    unsafe {
        std::env::set_var("INBUXA_MIGRATIONS_DIR", &dir);
        std::env::set_var("INBUXA_MIGRATE_BIN", &engine);
    }
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    let other = test.create_admin_account("admin2@example.com").await;
    test.insert_account(other);
    self::test(&mut test, dir).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// The real inbuxa-migrate against a real IMAP source, on demand: a
/// Dovecot with a master login (`{email}*master`) holding a@example.org
/// (three messages in INBOX) and b@example.org (one in INBOX, one in
/// Projects), and the engine's binary.
///
/// ```text
/// cd tests/resources/migrations/dovecot-source
/// docker build -t inbuxa-e2e-dovecot . && docker run -d --rm \
///   --name inbuxa-e2e-dovecot -p 127.0.0.1:11143:143 inbuxa-e2e-dovecot
/// python3 seed.py 11143
/// INBUXA_MIGRATE_E2E_BIN=…/inbuxa-migrate \
/// INBUXA_MIGRATE_E2E_IMAP=imap://127.0.0.1:11143 \
/// INBUXA_MIGRATE_E2E_SECRET=m4ster-e2e \
///   cargo test -p tests system::migration::migration_real_engine_tests -- --ignored
/// ```
pub async fn real_engine(test: &mut TestServer, imap: &str, secret: &str) {
    println!("Running migrations with the real engine...");
    let admin = test.account("admin@example.com");
    let (_, response) = call(
        admin,
        "inbuxa:Migration/set",
        json!({"create": {"m": {
            "description": "From Dovecot", "sourceKind": "imap",
            "source": {"url": imap, "login": "{email}*master", "cleartext": true},
            "accounts": ["a@example.org", "b@example.org"], "createAccounts": true,
        }}}),
    )
    .await;
    let id = response["created"]["m"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();

    // Preview, then the move, then the final pass
    let response = update(admin, &id, json!({"action": "preview", "secret": secret})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let m = settled(admin, &id).await;
    assert_eq!(m["result"], "done", "{m}");
    assert_eq!(m["moved"], false, "{m}");

    let response = update(admin, &id, json!({"action": "move"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let m = settled(admin, &id).await;
    assert_eq!(m["result"], "done", "{m}");
    assert_eq!(m["progress"]["finished"], 2, "{m}");
    assert_eq!(m["moved"], true, "{m}");

    // The new accounts' passwords sign them in, and their mail is there
    let response = update(admin, &id, json!({"action": "passwords"})).await;
    let blob = response["updated"][&id]["passwordsBlobId"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://127.0.0.1:{}", admin.http_listener_port);
    let csv = client
        .get(format!(
            "{base}/jmap/download/{}/{blob}/passwords.csv",
            admin.id_string()
        ))
        .basic_auth(admin.name(), Some(admin.secret()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let password = |email: &str| {
        csv.lines()
            .find_map(|line| line.strip_prefix(&format!("{email},")))
            .unwrap_or_else(|| panic!("no password for {email}: {csv}"))
            .to_string()
    };
    let mail = async |email: &str| -> Vec<(String, String)> {
        let password = password(email);
        let session: Value = client
            .get(format!("{base}/jmap/session"))
            .basic_auth(email, Some(&password))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
            .as_str()
            .unwrap_or_else(|| panic!("{session}"));
        let response: Value = client
            .post(format!("{base}/jmap"))
            .basic_auth(email, Some(&password))
            .json(&json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [
                    ["Mailbox/get", {"accountId": account, "properties": ["name"]}, "b"],
                    ["Email/query", {"accountId": account}, "q"],
                    ["Email/get", {"accountId": account,
                        "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                        "properties": ["subject", "mailboxIds"]}, "g"],
                ],
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let mailboxes = &response["methodResponses"][0][1]["list"];
        let name_of = |id: &str| {
            mailboxes
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["id"] == id)
                .map(|m| m["name"].as_str().unwrap().to_string())
                .unwrap_or_default()
        };
        let mut found: Vec<(String, String)> = response["methodResponses"][2][1]["list"]
            .as_array()
            .unwrap_or_else(|| panic!("{response}"))
            .iter()
            .flat_map(|e| {
                let subject = e["subject"].as_str().unwrap_or_default().to_string();
                e["mailboxIds"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(|m| (name_of(m), subject.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        found.sort();
        found
    };
    let inbox = |subjects: &[&str]| -> Vec<(String, String)> {
        subjects
            .iter()
            .map(|s| ("Inbox".to_string(), s.to_string()))
            .collect()
    };
    assert_eq!(
        mail("a@example.org").await,
        inbox(&["A message 1", "A message 2", "A message 3"])
    );
    let mut b = vec![
        ("Inbox".to_string(), "B inbox".to_string()),
        ("Projects".to_string(), "B project".to_string()),
    ];
    b.sort();
    assert_eq!(mail("b@example.org").await, b);

    // Mail that arrives at the source before the switch comes over with
    // the final pass, and nothing comes over twice
    append(imap, "a@example.org*master", secret, "A message 4").await;
    let response = update(admin, &id, json!({"action": "finalPass"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let m = settled(admin, &id).await;
    assert_eq!(m["run"], "finalPass", "{m}");
    assert_eq!(m["result"], "done", "{m}");
    assert_eq!(
        mail("a@example.org").await,
        inbox(&["A message 1", "A message 2", "A message 3", "A message 4"])
    );

    let response = update(admin, &id, json!({"action": "close"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
}

/// One message into a source account's INBOX, over plain IMAP.
async fn append(url: &str, login: &str, password: &str, subject: &str) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let address = url.trim_start_matches("imap://");
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let message = format!(
        "From: old@example.net\r\nTo: x@example.org\r\nSubject: {subject}\r\n\
         Message-ID: <e2e-late@example.net>\r\nDate: Tue, 5 Mar 2024 09:00:00 +0000\r\n\r\nLate\r\n"
    );
    let commands = [
        format!("1 LOGIN \"{login}\" \"{password}\"\r\n"),
        format!("2 APPEND INBOX {{{}+}}\r\n{message}\r\n", message.len()),
        "3 LOGOUT\r\n".to_string(),
    ];
    lines.next_line().await.unwrap();
    for (n, command) in commands.iter().enumerate() {
        write.write_all(command.as_bytes()).await.unwrap();
        let tag = format!("{} ", n + 1);
        loop {
            let line = lines.next_line().await.unwrap().unwrap_or_default();
            if let Some(status) = line.strip_prefix(&tag) {
                assert!(status.starts_with("OK"), "{command}: {line}");
                break;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
pub async fn migration_real_engine_tests() {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} isn't set; see real_engine()"))
    };
    let (engine, imap, secret) = (
        var("INBUXA_MIGRATE_E2E_BIN"),
        var("INBUXA_MIGRATE_E2E_IMAP"),
        var("INBUXA_MIGRATE_E2E_SECRET"),
    );
    let mut test = TestServerBuilder::new("migration_real_engine_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let dir = test.temp_dir.path.join("migrations");
    // SAFETY: set before any run reads them, and only this test reads them
    unsafe {
        std::env::set_var("INBUXA_MIGRATIONS_DIR", &dir);
        std::env::set_var("INBUXA_MIGRATE_BIN", &engine);
    }
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    real_engine(&mut test, &imap, &secret).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
