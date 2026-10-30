/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Relay` (docs/spec/features/relay.md, "Registry objects"): a
//! create returns a join token once, every relay is pinned to the one link
//! CA, settings change one at a time, a private key reads back as `****`
//! and is kept when written back that way, a rejoin issues a new token,
//! nobody in a tenant reaches relays, and the audit log never holds the
//! key or a token.
//!
//! `relay_link_tests` runs a real `inbuxa-relay` (build it first with
//! `cargo build -p inbuxa-relay`): the server joins it, sets it up, and its
//! port 25 takes mail only for this server's real recipients. Live, a
//! message is delivered before the sender hears 250, and this server's
//! refusal is the sender's reply; held while the link is off, it is
//! delivered once the link is back, exactly once. The relay's events are
//! taken and acknowledged.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use inbuxa_relay_proto::{time, token::JoinToken};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use std::str::FromStr;

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

const KEY_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nTUFSS0VSLXJlbGF5LXByaXZhdGUta2V5\n-----END PRIVATE KEY-----\n";
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

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

fn relay(name: &str) -> Value {
    json!({
        "name": name,
        "address": "relay1.example.net",
        "settings": {"hostname": "mx1.example.com"}
    })
}

async fn get(account: &Account, id: &str) -> Value {
    let (name, response) = call(account, "inbuxa:Relay/get", json!({"ids": [id]})).await;
    assert_eq!(name, "inbuxa:Relay/get", "{response}");
    response["list"][0].clone()
}

pub async fn test(test: &mut TestServer) {
    println!("Running inbuxa Relay tests...");
    let admin = test.account("admin@example.com");
    let now = time::now();

    // Created with a join token, shown once, for the shared link CA
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"create": {"a": relay("Edge one"), "b": relay("Edge two")}}),
    )
    .await;
    let id = response["created"]["a"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("relay created: {response}"))
        .to_string();
    let token = response["created"]["a"]["joinToken"]
        .as_str()
        .unwrap()
        .to_string();
    let first = JoinToken::decode(&token, now).expect("a join token");
    let second =
        JoinToken::decode(response["created"]["b"]["joinToken"].as_str().unwrap(), now).unwrap();
    assert_eq!(first.relay_id, id);
    assert_eq!(first.ca_spki, second.ca_spki, "one link CA for every relay");
    assert_ne!(first.secret, second.secret);
    let other = response["created"]["b"]["id"].as_str().unwrap().to_string();

    let relay_a = get(admin, &id).await;
    assert_eq!(relay_a["joinState"], "waiting", "{relay_a}");
    assert_eq!(relay_a["linkPort"], 443);
    assert_eq!(relay_a["enabled"], true);
    assert_eq!(relay_a["settings"]["heldMaxAge"], 30);
    assert_eq!(relay_a["settings"]["hostname"], "mx1.example.com");
    assert!(relay_a["settings"].get("sealingKey").is_none(), "{relay_a}");
    assert!(
        relay_a["settings"].get("recipientKey").is_none(),
        "{relay_a}"
    );
    assert_eq!(relay_a["smtpPrivateKey"], Value::Null);
    assert_eq!(relay_a["createdBy"], "admin@example.com");
    assert!(relay_a.get("joinToken").is_none(), "{relay_a}");
    let (_, response) = call(
        admin,
        "inbuxa:Relay/get",
        json!({"ids": [&id], "properties": ["joinToken"]}),
    )
    .await;
    assert_eq!(response["list"][0]["joinToken"], Value::Null, "{response}");

    // Checked when written
    let mut no_hostname = relay("x");
    no_hostname["settings"] = json!({});
    let mut unknown_setting = relay("x");
    unknown_setting["settings"]["noSuchSetting"] = 1.into();
    let mut server_set = relay("x");
    server_set["joinState"] = "joined".into();
    let mut rejoin = relay("x");
    rejoin["rejoin"] = true.into();
    let mut masked = relay("x");
    masked["smtpCertificate"] = CERT_PEM.into();
    masked["smtpPrivateKey"] = "****".into();
    let mut keys = relay("x");
    keys["settings"]["sealingKey"] = "AAAA".into();
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"create": {
            "a": no_hostname, "b": unknown_setting, "c": server_set,
            "d": rejoin, "e": masked, "f": keys
        }}),
    )
    .await;
    for (client_id, property) in [
        ("a", "settings"),
        ("b", "settings"),
        ("c", "joinState"),
        ("d", "rejoin"),
        ("e", "smtpPrivateKey"),
        ("f", "settings"),
    ] {
        assert_eq!(
            response["notCreated"][client_id]["properties"][0], property,
            "{client_id}: {response}"
        );
    }
    assert!(
        response["notCreated"]["b"]["description"]
            .as_str()
            .is_some_and(|d| d.contains("noSuchSetting")),
        "{response}"
    );

    // One setting at a time; the rest stay as they were
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {
            "settings/heldMaxAge": 10,
            "settings/maxRecipients": 20,
            "name": "Edge north",
            "smtpCertificate": CERT_PEM,
            "smtpPrivateKey": KEY_PEM
        }}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let relay_a = get(admin, &id).await;
    assert_eq!(relay_a["name"], "Edge north");
    assert_eq!(relay_a["settings"]["heldMaxAge"], 10);
    assert_eq!(relay_a["settings"]["maxRecipients"], 20);
    assert_eq!(relay_a["settings"]["hostname"], "mx1.example.com");
    assert_eq!(relay_a["smtpPrivateKey"], "****", "{relay_a}");
    assert_eq!(relay_a["smtpCertificate"], CERT_PEM);

    // A setting put back to its default, and the key written back masked
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"settings/heldMaxAge": null, "smtpPrivateKey": "****"}}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert_eq!(get(admin, &id).await["settings"]["heldMaxAge"], 30);
    let stored = inbuxa_features::relay::get(
        test.server.store(),
        u32::try_from(types::id::Id::from_str(&id).unwrap().id()).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        stored.smtp_private_key.as_deref(),
        Some(KEY_PEM),
        "key kept"
    );

    // A change made from a stale read is refused, so a join being recorded
    // and an administrator's edit can't overwrite each other
    let (mut stored, version) =
        inbuxa_features::relay::get_versioned(test.server.store(), stored.id)
            .await
            .unwrap()
            .unwrap();
    stored.description = "changed".into();
    assert!(
        !inbuxa_features::relay::replace(test.server.store(), &stored, version ^ 1)
            .await
            .unwrap()
    );
    assert!(
        inbuxa_features::relay::replace(test.server.store(), &stored, version)
            .await
            .unwrap()
    );
    assert_eq!(get(admin, &id).await["description"], "changed");

    // Out of range, a bad setting name, and a server property: refused
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {
            &id: {"settings/heldMaxAge": 91},
            &other: {"settings/nope": 1}
        }}),
    )
    .await;
    assert_eq!(response["notUpdated"][&id]["properties"][0], "settings");
    assert_eq!(response["notUpdated"][&other]["properties"][0], "settings");
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"linkKeyPin": "AAAA"}}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][&id]["properties"][0], "linkKeyPin",
        "{response}"
    );

    // A rejoin issues a new token for the same relay
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"rejoin": true}}}),
    )
    .await;
    let again = JoinToken::decode(
        response["updated"][&id]["joinToken"]
            .as_str()
            .unwrap_or_else(|| panic!("rejoin token: {response}")),
        now,
    )
    .unwrap();
    assert_eq!(again.relay_id, id);
    assert_eq!(again.ca_spki, first.ca_spki);
    assert_ne!(again.secret, first.secret);
    assert_eq!(get(admin, &id).await["joinState"], "waiting");

    // Nobody in a tenant reaches relays
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Relay tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "relays.example.org".to_string(),
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
            "tadmin@relays.example.org",
            "tenant-admin-secret-8841",
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
        ("inbuxa:Relay/get", json!({"ids": null})),
        (
            "inbuxa:Relay/set",
            json!({"create": {"x": relay("Tenant's own")}}),
        ),
    ] {
        let (name, response) = call(&t_admin, method, arguments).await;
        assert_eq!(name, "error", "{method} by a tenant: {response}");
    }

    // Destroyed
    let (_, response) = call(admin, "inbuxa:Relay/set", json!({"destroy": [&other]})).await;
    assert_eq!(response["destroyed"][0], other.as_str(), "{response}");
    let (_, response) = call(admin, "inbuxa:Relay/get", json!({"ids": [&other]})).await;
    assert_eq!(response["notFound"][0], other.as_str(), "{response}");

    // Every change audited, with neither the key nor a token in it
    let (_, response) = call(
        admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Relay"}}),
    )
    .await;
    let ids = response["ids"].clone();
    assert!(
        ids.as_array().is_some_and(|ids| ids.len() >= 6),
        "creates, updates, rejoin and destroy audited: {response}"
    );
    let (_, response) = call(admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let text = response.to_string();
    assert!(!text.contains("TUFSS0VS"), "the private key was audited");
    assert!(!text.contains(&token), "a join token was audited");
    assert!(!text.contains(&again.encode()), "a join token was audited");

    call(admin, "inbuxa:Relay/set", json!({"destroy": [&id]})).await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn relay_tests() {
    let mut test = TestServerBuilder::new("relay_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// The `inbuxa-relay` binary: `INBUXA_RELAY_BIN`, or the workspace's debug
/// build.
fn relay_binary() -> std::path::PathBuf {
    std::env::var_os("INBUXA_RELAY_BIN")
        .map(Into::into)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/inbuxa-relay")
        })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The relay process, stopped when the test ends.
struct RelayProcess(std::process::Child);

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Polls `check` against the relay object until it's true, or panics.
async fn wait_for(
    account: &Account,
    id: &str,
    what: &str,
    seconds: u64,
    check: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        let relay = get(account, id).await;
        if check(&relay) {
            return relay;
        }
        if std::time::Instant::now() > deadline {
            panic!("{what}: {relay}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// The relay's replies to one SMTP transaction's recipients, after EHLO and
/// MAIL FROM. Port 25 opens a few seconds after the relay is set up.
async fn rcpt_replies(port: u16, recipients: &[&str]) -> Vec<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let stream = loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => break stream,
            Err(e) if std::time::Instant::now() > deadline => panic!("port {port}: {e}"),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    async fn reply(read: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            read.read_line(&mut line).await.unwrap();
            all.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return all;
            }
        }
    }
    assert!(reply(&mut read).await.starts_with("220"));
    let mut replies = Vec::new();
    for line in [
        "EHLO client.example.org".to_string(),
        "MAIL FROM:<sender@example.org>".into(),
    ]
    .into_iter()
    .chain(recipients.iter().map(|r| format!("RCPT TO:<{r}>")))
    {
        write
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        replies.push(reply(&mut read).await);
    }
    let _ = write.write_all(b"QUIT\r\n").await;
    replies.split_off(2)
}

/// Sends one message through the relay; the reply to its final dot.
async fn send_mail(port: u16, rcpt: &str, message: &str) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    async fn reply(read: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            read.read_line(&mut line).await.unwrap();
            all.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return all;
            }
        }
    }
    assert!(reply(&mut read).await.starts_with("220"));
    for line in [
        "EHLO sender.example".to_string(),
        "MAIL FROM:<someone@sender.example>".to_string(),
        format!("RCPT TO:<{rcpt}>"),
        "DATA".to_string(),
    ] {
        write
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        let answer = reply(&mut read).await;
        assert!(
            answer.starts_with('2') || answer.starts_with('3'),
            "{line}: {answer}"
        );
    }
    let body = message.replace('\n', "\r\n");
    write
        .write_all(format!("{body}\r\n.\r\n").as_bytes())
        .await
        .unwrap();
    let answer = reply(&mut read).await;
    let _ = write.write_all(b"QUIT\r\n").await;
    answer
}

/// The subjects of every message in `account`'s mailboxes.
async fn subjects(account: &Account) -> Vec<String> {
    let response = account
        .jmap_request(
            &["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            json!([
                ["Email/query", {"accountId": account.id_string()}, "q"],
                ["Email/get", {
                    "accountId": account.id_string(),
                    "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                    "properties": ["subject"]
                }, "g"]
            ]),
        )
        .await;
    response
        .0
        .pointer("/methodResponses/1/1/list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|email| email["subject"].as_str().map(str::to_string))
        .collect()
}

/// Waits until `account` has `count` messages titled `subject`.
async fn wait_for_mail(account: &Account, subject: &str, count: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let found = subjects(account).await;
        let n = found.iter().filter(|s| *s == subject).count();
        if n == count {
            return;
        }
        assert!(
            n < count && std::time::Instant::now() < deadline,
            "{count} of {subject:?}: {found:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Sends a message from `sender` to `to` by JMAP submission.
async fn submit(sender: &Account, identity: &str, mailbox: &str, to: &[&str], subject: &str) {
    let (_, response) = call(
        sender,
        "Email/set",
        json!({"create": {"e": {
            "mailboxIds": {mailbox: true},
            "from": [{"email": sender.name()}],
            "to": to.iter().map(|a| json!({"email": a})).collect::<Vec<_>>(),
            "subject": subject,
            "bodyValues": {"b": {"value": "Hello from the far side."}},
            "textBody": [{"partId": "b", "type": "text/plain"}]
        }}}),
    )
    .await;
    let email = response["created"]["e"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("draft: {response}"))
        .to_string();
    let (_, response) = call(
        sender,
        "EmailSubmission/set",
        json!({"create": {"s": {"emailId": email, "identityId": identity}}}),
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
}

/// The destination the relay sends to (`INBUXA_RELAY_TEST_MX`): takes
/// `bob`, refuses `nobody`, defers `later`. The messages it took.
async fn scripted_mx() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let taken = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let taken = taken.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut read = BufReader::new(read);
                let _ = write.write_all(b"220 remote.test ready\r\n").await;
                let mut accepted = 0;
                loop {
                    let mut line = String::new();
                    if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let upper = line.to_ascii_uppercase();
                    let answer = if upper.starts_with("EHLO") {
                        "250-remote.test\r\n250 8BITMIME\r\n"
                    } else if upper.starts_with("MAIL") {
                        accepted = 0;
                        "250 2.1.0 Ok\r\n"
                    } else if upper.starts_with("RCPT") && upper.contains("<BOB@") {
                        accepted += 1;
                        "250 2.1.5 Ok\r\n"
                    } else if upper.starts_with("RCPT") && upper.contains("<LATER@") {
                        "451 4.7.1 Try again later\r\n"
                    } else if upper.starts_with("RCPT") {
                        "550 5.1.1 No such user here\r\n"
                    } else if upper.starts_with("DATA") && accepted > 0 {
                        let _ = write.write_all(b"354 Go ahead\r\n").await;
                        let mut message = String::new();
                        loop {
                            let mut line = String::new();
                            if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if line == ".\r\n" {
                                break;
                            }
                            message.push_str(&line);
                        }
                        taken.lock().unwrap().push(message);
                        "250 2.0.0 Queued as 1\r\n"
                    } else if upper.starts_with("DATA") {
                        "554 5.5.1 No valid recipients\r\n"
                    } else if upper.starts_with("QUIT") {
                        let _ = write.write_all(b"221 Bye\r\n").await;
                        return;
                    } else {
                        "250 Ok\r\n"
                    };
                    let _ = write.write_all(answer.as_bytes()).await;
                }
            });
        }
    });
    (port, seen)
}

fn message(subject: &str, extra_headers: &str) -> String {
    format!(
        "{extra_headers}From: Someone <someone@sender.example>\nTo: jane@example.com\n\
         Subject: {subject}\nMessage-ID: <{}@sender.example>\n\nHello from outside.",
        subject.replace(' ', "-")
    )
}

pub async fn link(test: &mut TestServer) {
    println!("Running inbuxa Relay link tests...");
    let admin = test.account("admin@example.com");
    let binary = relay_binary();
    assert!(
        binary.exists(),
        "{} is missing: run cargo build -p inbuxa-relay --features test-mx",
        binary.display()
    );
    let jane = admin
        .create_user_account(
            "jane@example.com",
            "jane-secret-4417",
            "Jane",
            &["jane.doe@example.com"],
            vec![],
        )
        .await;
    let link_port = free_port();
    let smtp_port = free_port();
    let (mx_port, mx_seen) = scripted_mx().await;

    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"create": {"r": {
            "name": "Edge",
            "address": "127.0.0.1",
            "linkPort": link_port,
            "settings": {
                "hostname": "mx1.example.com",
                "smtpListen": [format!("127.0.0.1:{smtp_port}")],
                "domains": ["example.com"]
            }
        }}}),
    )
    .await;
    let id = response["created"]["r"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("relay created: {response}"))
        .to_string();
    let token = response["created"]["r"]["joinToken"]
        .as_str()
        .unwrap()
        .to_string();

    // The relay host: join with the token, then run
    let state = test.temp_dir.path.join("relay-state");
    let joined = std::process::Command::new(&binary)
        .args(["join", &token, "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(joined.status.success(), "{joined:?}");
    let _relay = RelayProcess(
        std::process::Command::new(&binary)
            .args([
                "run",
                "--link-listen",
                &format!("127.0.0.1:{link_port}"),
                "--state",
            ])
            .arg(&state)
            .env("INBUXA_RELAY_TEST_MX", mx_port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );

    // The server joins it, pins its key, and sets it up: port 25 opens
    let relay = wait_for(admin, &id, "the relay joined and took mail", 60, |relay| {
        relay["joinState"] == "joined"
            && relay["links"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|link| link["state"] == "linked" && link["relay"]["mode"] == "live")
    })
    .await;
    assert!(relay["linkKeyPin"].as_str().is_some(), "{relay}");
    let link = &relay["links"][0];
    // The administrator, jane and her alias, at least
    let recipients = link["recipients"].as_u64().unwrap_or_default();
    assert!(recipients >= 3, "{relay}");
    assert_eq!(link["lastError"], Value::Null, "{relay}");

    // Real recipients only (RL-1)
    let replies = rcpt_replies(
        smtp_port,
        &[
            "jane@example.com",
            "Jane.Doe@example.com",
            "jane+news@example.com",
            "nobody@example.com",
            "jane@elsewhere.org",
        ],
    )
    .await;
    assert!(replies[0].starts_with("250"), "{replies:?}");
    assert!(replies[1].starts_with("250"), "alias: {replies:?}");
    assert!(replies[2].starts_with("250"), "sub-address: {replies:?}");
    assert!(replies[3].starts_with("550 5.1.1"), "unknown: {replies:?}");
    assert!(
        replies[4].starts_with("550 5.7.1"),
        "not served: {replies:?}"
    );

    // Live (RL-12): delivered here before the sender hears 250
    let reply = send_mail(smtp_port, "jane@example.com", &message("Live one", "")).await;
    assert!(reply.starts_with("250"), "{reply}");
    wait_for_mail(&jane, "Live one", 1).await;

    // Live: this server's refusal is the sender's reply, and the relay
    // keeps nothing
    let loop_headers =
        "Received: from a.example by b.example; Thu, 29 Oct 2026 10:00:00 +0000\n".repeat(60);
    let reply = send_mail(
        smtp_port,
        "jane@example.com",
        &message("Looped one", &loop_headers),
    )
    .await;
    assert!(reply.starts_with("450 4.4.6"), "{reply}");
    wait_for(admin, &id, "the relay kept nothing", 30, |relay| {
        relay["links"][0]["relay"]["spool"]["inbound"] == 0
    })
    .await;

    // A new account reaches the relay as a change
    admin
        .create_user_account("joe@example.com", "joe-secret-5529", "Joe", &[], vec![])
        .await;
    wait_for(
        admin,
        &id,
        "the new recipient reached the relay",
        45,
        |relay| relay["links"][0]["recipients"].as_u64() == Some(recipients + 1),
    )
    .await;
    let replies = rcpt_replies(smtp_port, &["joe@example.com"]).await;
    assert!(replies[0].starts_with("250"), "{replies:?}");

    // A setting reaches it too
    call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"settings/maxRecipients": 1}}}),
    )
    .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let replies = rcpt_replies(smtp_port, &["jane@example.com", "joe@example.com"]).await;
        if replies[1].starts_with("452") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "maxRecipients reached the relay: {replies:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Turned off, the link ends and says why
    call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"enabled": false}}}),
    )
    .await;
    wait_for(admin, &id, "the link ended", 30, |relay| {
        relay["links"][0]["state"] == "down"
            && relay["links"][0]["lastError"]
                .as_str()
                .is_some_and(|e| e.contains("turned off"))
    })
    .await;

    // Held while the link is off: the relay says 250 itself, and the
    // message is delivered once the link is back, once
    let reply = send_mail(smtp_port, "jane@example.com", &message("Held one", "")).await;
    assert!(reply.starts_with("250"), "{reply}");
    let pending_events = std::fs::read_to_string(state.join("events.jsonl")).unwrap_or_default();
    assert!(
        pending_events.contains("inbound.accepted"),
        "the relay recorded the held message: {pending_events}"
    );
    call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"enabled": true}}}),
    )
    .await;
    wait_for_mail(&jane, "Held one", 1).await;
    wait_for(admin, &id, "the held message was taken", 30, |relay| {
        relay["links"][0]["state"] == "linked"
            && relay["links"][0]["relay"]["spool"]["inbound"] == 0
    })
    .await;
    assert_eq!(
        subjects(&jane)
            .await
            .iter()
            .filter(|s| *s == "Held one" || *s == "Live one")
            .count(),
        2
    );

    // Outbound through the relay (RL-24): handed over, sent by the relay,
    // and each recipient's reply recorded here, with one DSN (RL-T11)
    call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"sendThrough": true, "settings/maxRecipients": 10}}}),
    )
    .await;
    let (_, response) = call(
        &jane,
        "Identity/set",
        json!({"create": {"i": {"name": "Jane", "email": "jane@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let (_, response) = call(
        &jane,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Outbound drafts"}}}),
    )
    .await;
    let drafts = response["created"]["m"]["id"].as_str().unwrap().to_string();
    // The relay has the new maxRecipients before anything is handed to it
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let replies = rcpt_replies(smtp_port, &["jane@example.com", "joe@example.com"]).await;
        if replies[1].starts_with("250") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "maxRecipients reached the relay: {replies:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    submit(
        &jane,
        &identity,
        &drafts,
        &["bob@remote.test", "nobody@remote.test"],
        "Through the relay",
    )
    .await;
    wait_for_mail(&jane, "Failed to deliver message", 1).await;
    let seen = mx_seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|m| m.contains("Subject: Through the relay")),
        "the relay sent it on: {seen:?}"
    );
    // Gone from this server's queue, and from the relay's
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (_, queued) = call(admin, "x:QueuedMessage/get", json!({"ids": null})).await;
        let in_queue = queued.to_string().contains("nobody@remote.test");
        let at_relay = std::fs::read_dir(state.join("spool").join("out"))
            .map(|dir| dir.count())
            .unwrap_or_default();
        if !in_queue && at_relay == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "queued here: {in_queue}, files at the relay: {at_relay}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    // A deferral stays queued here, with the remote server's reply
    submit(
        &jane,
        &identity,
        &drafts,
        &["later@remote.test"],
        "Deferred by the remote",
    )
    .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (_, queued) = call(admin, "x:QueuedMessage/get", json!({"ids": null})).await;
        let text = queued.to_string();
        if text.contains("later@remote.test") && text.contains("Try again later") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferral is shown: {queued}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        subjects(&jane)
            .await
            .iter()
            .filter(|s| s.starts_with("Failed") || s.starts_with("Warning"))
            .count(),
        1,
        "one DSN, for the refusal"
    );

    // The relay's events were taken as this server's relay.* trace events,
    // and acknowledged, so the relay forgot them
    let events = state.join("events.jsonl");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let left = std::fs::read_to_string(&events)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        if left == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{left} relay events left unacknowledged"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    call(admin, "inbuxa:Relay/set", json!({"destroy": [&id]})).await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn relay_link_tests() {
    let mut test = TestServerBuilder::new("relay_link_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::link(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
