/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: open IMAP, POP3 and ManageSieve sessions end when the sign-in
//! they were opened with stops being valid.

use crate::utils::{
    imap::{ImapConnection, Type},
    pop3::{self, Pop3Connection},
    server::TestServer,
    sieve::SieveConnection,
};
use imap_proto::ResponseType;
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

const FIRST_SECRET: &str = "the first secret of the revoked account";
const SECOND_SECRET: &str = "the second secret of the revoked account";

struct Sessions {
    imap: ImapConnection,
    idle: ImapConnection,
    pop3: Pop3Connection,
    sieve: SieveConnection,
}

impl Sessions {
    async fn open(name: &str, secret: &str) -> Self {
        let mut imap = ImapConnection::connect(b"_r ").await;
        imap.assert_read(Type::Untagged, ResponseType::Ok).await;
        imap.authenticate(name, secret).await;
        imap.send("NOOP").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        let mut idle = ImapConnection::connect(b"_i ").await;
        idle.assert_read(Type::Untagged, ResponseType::Ok).await;
        idle.authenticate(name, secret).await;
        idle.send("IDLE").await;
        idle.assert_read(Type::Continuation, ResponseType::Ok).await;

        let mut pop3 = Pop3Connection::connect().await;
        pop3.authenticate(name, secret).await;
        pop3.send("NOOP").await;
        pop3.assert_read(pop3::ResponseType::Ok).await;

        let mut sieve = SieveConnection::connect().await;
        sieve.assert_read(ResponseType::Ok).await;
        sieve.authenticate(name, secret).await;
        sieve.send("NOOP").await;
        sieve.assert_read(ResponseType::Ok).await;

        Sessions {
            imap,
            idle,
            pop3,
            sieve,
        }
    }

    async fn assert_ended(mut self, why: &str) {
        // IMAP: the next command gets BYE and the connection closes
        self.imap.send("NOOP").await;
        let lines = self.imap.read(Type::Untagged).await;
        assert!(
            lines.last().unwrap().starts_with("* BYE"),
            "IMAP after {why}: {lines:?}"
        );
        self.imap.assert_disconnect().await;

        // IMAP IDLE: ended without a command
        let lines = self.idle.read(Type::Untagged).await;
        assert!(
            lines.last().unwrap().starts_with("* BYE"),
            "IMAP IDLE after {why}: {lines:?}"
        );
        self.idle.assert_disconnect().await;

        // POP3: -ERR, then the connection closes
        self.pop3.send("STAT").await;
        self.pop3.assert_read(pop3::ResponseType::Err).await;
        self.pop3.assert_disconnect().await;

        // ManageSieve: BYE, then the connection closes
        self.sieve.send("LISTSCRIPTS").await;
        let lines = self.sieve.read().await;
        assert!(
            lines.last().unwrap().starts_with("BYE"),
            "ManageSieve after {why}: {lines:?}"
        );
        self.sieve.assert_disconnect().await;
    }
}

pub async fn test(test: &TestServer) {
    println!("Running session sign-in checks...");
    let admin = test.account("admin@example.com");
    let mut account = admin
        .create_user_account("revoked@example.com", FIRST_SECRET, "Revoked", &[], vec![])
        .await;

    // A password change ends the sessions opened with the old password
    let sessions = Sessions::open(account.name(), account.secret()).await;
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({"credentials/0/secret": SECOND_SECRET}),
        )
        .await;
    sessions.assert_ended("a password change").await;
    account.update_secret(SECOND_SECRET);

    // Losing a permission ends them too; IDLE notices within a few seconds
    let sessions = Sessions::open(account.name(), account.secret()).await;
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::default(),
                    disabled_permissions: Map::new(vec![Permission::ImapIdle]),
                })
            }),
        )
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    sessions.assert_ended("a permission was taken away").await;

    // Gaining one ends nothing
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::default(),
                    disabled_permissions: Map::default(),
                })
            }),
        )
        .await;
    let mut imap = ImapConnection::connect(b"_r ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate(account.name(), account.secret()).await;
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::new(vec![Permission::UnlimitedRequests]),
                    disabled_permissions: Map::default(),
                })
            }),
        )
        .await;
    imap.send("NOOP").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Removing the Authenticate permission (disabling the account) ends it
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::default(),
                    disabled_permissions: Map::new(vec![Permission::Authenticate]),
                })
            }),
        )
        .await;
    imap.send("NOOP").await;
    let lines = imap.read(Type::Untagged).await;
    assert!(
        lines.last().unwrap().starts_with("* BYE"),
        "IMAP after the account was disabled: {lines:?}"
    );
    imap.assert_disconnect().await;

    admin.destroy_account(account).await;
}
