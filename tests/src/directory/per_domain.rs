/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Per-domain directory acceptance tests, from
//! `docs/spec/features/per-domain-directories.md`, over SQL directories on
//! SQLite files, so no container is needed. Each check names its test
//! number or requirement.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use common::{BuildServer, auth::AuthRequest};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{
        self, Authentication, CertificateManagement, DkimManagement, DnsManagement, Domain,
        Expression, MtaStageRcpt, PasswordCredential, SqlAuthStore, SqlDirectory, SqliteStore,
        Tenant, UserAccount,
    },
};
use serde_json::json;
use std::net::IpAddr;
use types::id::Id;

/// An SQLite directory database with its rows.
async fn directory_db(path: &str, accounts: &[(&str, &str, &str, &str, &str)], extra: &[&str]) {
    let store = store::backend::sqlite::SqliteStore::open(SqliteStore {
        path: path.to_string(),
        ..Default::default()
    })
    .unwrap();
    let mut queries = vec![
        "CREATE TABLE accounts (login TEXT PRIMARY KEY, name TEXT, secret TEXT, description TEXT, type TEXT NOT NULL, active BOOLEAN DEFAULT TRUE)".to_string(),
        "CREATE TABLE group_members (name TEXT NOT NULL, member_of TEXT NOT NULL, PRIMARY KEY (name, member_of))".to_string(),
        "CREATE TABLE emails (name TEXT NOT NULL, address TEXT NOT NULL, PRIMARY KEY (name, address))".to_string(),
    ];
    for (login, name, secret, description, typ) in accounts {
        queries.push(format!(
            "INSERT INTO accounts (login, name, secret, description, type) VALUES ('{login}', '{name}', '{secret}', '{description}', '{typ}')"
        ));
    }
    queries.extend(extra.iter().map(|q| q.to_string()));
    for query in queries {
        store
            .sql_query::<usize>(&query, vec![])
            .await
            .unwrap_or_else(|err| panic!("{query}: {err:?}"));
    }
}

fn sql_directory(path: &str, description: &str) -> structs::Directory {
    structs::Directory::Sql(SqlDirectory {
        description: description.to_string(),
        query_login: "SELECT name, secret, description, type FROM accounts WHERE login = $1 AND active = true".into(),
        query_recipient: "SELECT name, secret, description, type FROM accounts WHERE name = $1 AND active = true".into(),
        query_email_aliases: Some("SELECT address FROM emails WHERE name = $1".into()),
        query_member_of: Some("SELECT member_of FROM group_members WHERE name = $1".into()),
        column_class: Some("type".into()),
        column_description: Some("description".into()),
        column_email: "name".into(),
        column_secret: "secret".into(),
        store: SqlAuthStore::Sqlite(SqliteStore {
            path: path.to_string(),
            ..Default::default()
        }),
        member_tenant_id: None,
    })
}

/// A directory that fails to open at once: the test build has no MySQL
/// backend, so it's unavailable (a bad SQLite path would make every reload
/// wait out the pool's connection timeout).
fn broken_directory(description: &str) -> structs::Directory {
    let structs::Directory::Sql(mut sql) = sql_directory("", description) else {
        unreachable!()
    };
    sql.store = SqlAuthStore::MySql(structs::MySqlStore {
        host: "127.0.0.1".into(),
        port: 3306,
        database: "none".into(),
        ..Default::default()
    });
    structs::Directory::Sql(sql)
}

fn domain(name: &str, directory_id: Option<Id>) -> Domain {
    Domain {
        is_enabled: true,
        name: name.to_string(),
        certificate_management: CertificateManagement::Manual,
        dns_management: DnsManagement::Manual,
        dkim_management: DkimManagement::Manual,
        directory_id,
        ..Default::default()
    }
}

async fn sign_in(test: &TestServer, user: &str, secret: &str) -> trc::Result<u32> {
    // The core as it is now, after any reload
    test.server
        .inner
        .build_server()
        .authenticate(&AuthRequest::from_plain(
            user,
            secret,
            0,
            IpAddr::from([127, 0, 0, 1]),
        ))
        .await
        .map(|token| token.account_id())
}

async fn account_of(test: &TestServer, address: &str) -> Option<u32> {
    test.server
        .inner
        .build_server()
        .account_id_from_email(address, false)
        .await
        .unwrap()
}

async fn user(test: &TestServer, id: u32) -> UserAccount {
    test.account("admin")
        .registry_get::<structs::Account>(Id::from(id))
        .await
        .into_user()
        .unwrap()
}

async fn set_directory(test: &TestServer, domain_id: Id, directory: Option<Id>) {
    test.account("admin")
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({ Property::DirectoryId: directory.map(|id| id.to_string()) }),
        )
        .await;
}

async fn rcpt(address: &str) -> char {
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example", 2).await;
    lmtp.send(&format!("RCPT TO:<{address}>")).await;
    let reply = lmtp.read(1, u8::MAX).await;
    lmtp.quit().await;
    reply
        .last()
        .and_then(|line| line.chars().next())
        .unwrap_or('?')
}

/// `cargo test -p tests per_domain_directory_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn per_domain_directory_tests() {
    let test = TestServerBuilder::new("per_domain_directory_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(MtaStageRcpt {
            wait_on_fail: Expression {
                else_: "1ms".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin.mta_disable_spam_filter().await;
    admin.reload_settings().await;

    let base = test.temp_dir.path.to_str().unwrap().to_string();
    let path_a = format!("{base}/directory-a.sqlite");
    let path_b = format!("{base}/directory-b.sqlite");
    directory_db(
        &path_a,
        &[
            (
                "alice@a.test",
                "alice@a.test",
                "alice secret",
                "Alice",
                "individual",
            ),
            (
                "dave@a.test",
                "dave@a.test",
                "dave secret",
                "Dave",
                "individual",
            ),
            (
                "mallory@a.test",
                "mallory@b.test",
                "mallory secret",
                "Mallory",
                "individual",
            ),
            (
                "carol@c.test",
                "carol@c.test",
                "carol directory secret",
                "Carol",
                "individual",
            ),
            ("team@a.test", "team@a.test", "", "Team", "group"),
        ],
        &[
            "INSERT INTO emails (name, address) VALUES ('alice@a.test', 'alice.a@a.test')",
            "INSERT INTO emails (name, address) VALUES ('alice@a.test', 'alice@b.test')",
            "INSERT INTO group_members (name, member_of) VALUES ('alice@a.test', 'team@a.test')",
            "INSERT INTO group_members (name, member_of) VALUES ('alice@a.test', 'crew@b.test')",
        ],
    )
    .await;
    directory_db(
        &path_b,
        &[(
            "bob@b.test",
            "bob@b.test",
            "bob secret",
            "Bob",
            "individual",
        )],
        &[],
    )
    .await;

    let dir_a = admin
        .registry_create_object(sql_directory(&path_a, "A"))
        .await;
    let dir_b = admin
        .registry_create_object(sql_directory(&path_b, "B"))
        .await;
    let broken = admin
        .registry_create_object(broken_directory("Broken"))
        .await;
    let a = admin
        .registry_create_object(domain("a.test", Some(dir_a)))
        .await;
    let b = admin
        .registry_create_object(domain("b.test", Some(dir_b)))
        .await;
    let c = admin.registry_create_object(domain("c.test", None)).await;
    // d.test gets its broken directory after dora's internal password exists,
    // since passwords can't be set on a directory domain (DIR-13)
    let d = admin.registry_create_object(domain("d.test", None)).await;
    admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "ghost".to_string(),
            domain_id: a,
            ..Default::default()
        }))
        .await;
    for (name, domain_id) in [("carol", c), ("dora", d)] {
        admin
            .registry_create_object(structs::Account::User(UserAccount {
                name: name.to_string(),
                domain_id,
                credentials: registry::types::list::List::from_iter([
                    structs::Credential::Password(PasswordCredential {
                        secret: format!("{name} internal secret"),
                        ..Default::default()
                    }),
                ]),
                ..Default::default()
            }))
            .await;
    }

    set_directory(&test, d, Some(broken)).await;

    // Test 1: each domain against its own directory (DIR-1)
    let alice = sign_in(&test, "alice@a.test", "alice secret")
        .await
        .expect("test 1: alice through A");
    sign_in(&test, "bob@b.test", "bob secret")
        .await
        .expect("test 1: bob through B");
    sign_in(&test, "carol@c.test", "carol internal secret")
        .await
        .expect("test 1: carol, internal");
    assert!(
        sign_in(&test, "bob@b.test", "alice secret").await.is_err(),
        "test 1"
    );

    // DIR-14, DIR-6: aliases and groups on another directory's domain dropped
    let account = user(&test, alice).await;
    assert_eq!(account.description.as_deref(), Some("Alice"), "DIR-14");
    let aliases = account
        .aliases
        .values()
        .map(|alias| alias.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(aliases, vec!["alice.a".to_string()], "test 4: DIR-6");
    assert_eq!(account.member_group_ids.len(), 1, "test 4: DIR-6");
    assert!(account_of(&test, "team@a.test").await.is_some(), "DIR-14");
    assert!(
        account_of(&test, "crew@b.test").await.is_none(),
        "test 4: DIR-6"
    );

    // With A as the server default, C signs in against A (DIR-1)
    admin
        .registry_update_setting(
            Authentication {
                directory_id: Some(dir_a),
                ..Default::default()
            },
            &[Property::DirectoryId],
        )
        .await;
    assert!(
        sign_in(&test, "carol@c.test", "carol internal secret")
            .await
            .is_err(),
        "test 1: no longer internal"
    );
    sign_in(&test, "carol@c.test", "carol directory secret")
        .await
        .expect("test 1: carol through the default");
    sign_in(&test, "bob@b.test", "bob secret")
        .await
        .expect("test 1: B unchanged");
    admin
        .registry_update_setting(
            Authentication {
                directory_id: None,
                ..Default::default()
            },
            &[Property::DirectoryId],
        )
        .await;

    // Test 4: A answering for a B address: refused, nothing created (DIR-6)
    assert!(
        sign_in(&test, "mallory@a.test", "mallory secret")
            .await
            .is_err(),
        "test 4"
    );
    assert!(
        account_of(&test, "mallory@b.test").await.is_none(),
        "test 4"
    );

    // Test 3: a domain whose directory failed to open (DIR-5, DIR-4)
    assert!(
        sign_in(&test, "dora@d.test", "dora internal secret")
            .await
            .is_err(),
        "test 3: never the internal store"
    );

    // Test 7: mail creates the account; an internal-only account on a
    // directory domain isn't a recipient (DIR-9, DIR-14)
    assert!(account_of(&test, "dave@a.test").await.is_none());
    assert_eq!(rcpt("dave@a.test").await, '2', "test 7");
    assert!(account_of(&test, "dave@a.test").await.is_some(), "test 7");
    assert_eq!(rcpt("ghost@a.test").await, '5', "test 7");

    // Test 11: no password change on a directory account (DIR-13)
    let refused = admin
        .registry_update(
            ObjectType::Account,
            [(
                Id::from(alice).to_string(),
                json!({"credentials/0/secret": "a brand new strong password"}),
            )],
        )
        .await;
    assert_eq!(
        refused.not_updated(&Id::from(alice).to_string())["type"],
        json!("forbidden"),
        "test 11"
    );

    // Test 6: an app password works while the directory is down (DIR-3)
    let alice_account = Account::new("alice@a.test", "alice secret", &[], "", Id::from(alice));
    let app = alice_account
        .registry_create([structs::AppPassword {
            description: "mail client".to_string(),
            ..Default::default()
        }])
        .await;
    let app_secret = app.created(0)["secret"].as_str().unwrap().to_string();
    admin
        .registry_update_object(
            ObjectType::Directory,
            dir_a,
            json!({"store": {"@type": "MySql", "host": "127.0.0.1", "port": 3306, "database": "none"}}),
        )
        .await;
    assert!(
        sign_in(&test, "alice@a.test", "alice secret")
            .await
            .is_err(),
        "test 2: no fallback to the synchronized password (DIR-4)"
    );
    sign_in(&test, "alice@a.test", &app_secret)
        .await
        .expect("test 6: app password (DIR-3)");
    // Test 9: recipients on a domain whose directory is down: 4xx (DIR-11)
    assert_eq!(rcpt("newcomer@a.test").await, '4', "test 9");
    // DIR-21: the broken directory didn't stop other changes applying
    sign_in(&test, "bob@b.test", "bob secret")
        .await
        .expect("DIR-21: B still works");

    // Test 11 continued: moved to the internal directory, the synchronized
    // password keeps working and can be changed (DIR-20)
    set_directory(&test, a, None).await;
    sign_in(&test, "alice@a.test", "alice secret")
        .await
        .expect("test 11: DIR-20");
    admin
        .registry_update(
            ObjectType::Account,
            [(
                Id::from(alice).to_string(),
                json!({"credentials/0/secret": "a brand new strong password"}),
            )],
        )
        .await
        .updated_id(Id::from(alice));

    // Test 19: a domain's directory changes on the next sign-in (DIR-17)
    set_directory(&test, b, Some(dir_a)).await;
    assert!(
        sign_in(&test, "bob@b.test", "bob secret").await.is_err(),
        "test 19"
    );
    set_directory(&test, b, Some(dir_b)).await;
    sign_in(&test, "bob@b.test", "bob secret")
        .await
        .expect("test 19");

    // Test 15: a directory in use can't be deleted (DIR-21); a tenant's
    // domain can't name a server-level directory (DIR-22)
    let response = admin.registry_destroy(ObjectType::Directory, [dir_b]).await;
    assert_eq!(
        response.not_destroyed(&dir_b.to_string())["type"],
        json!("objectIsLinked"),
        "test 15"
    );
    let tenant = admin
        .registry_create_object(Tenant {
            name: "dirtenant".into(),
            ..Default::default()
        })
        .await;
    let mut tenant_domain = domain("t.test", Some(dir_b));
    tenant_domain.member_tenant_id = Some(tenant);
    admin
        .registry_create_object_expect_err(tenant_domain)
        .await
        .assert_type(jmap_proto::error::set::SetErrorType::InvalidForeignKey);

    let _ = (c, d);
    test.temp_dir.delete();
}
