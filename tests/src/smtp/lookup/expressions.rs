/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{dns::DnsCache, server::TestServerBuilder};
use common::expr::{if_block::IfBlock, tokenizer::TokenMap, *};
use mail_auth::{DnssecStatus, Mx};
use registry::schema::{
    enums::ExpressionVariable,
    prelude::{ObjectType, Property},
    structs::{LookupStore, SqliteStore, StoreLookup},
};
use smtp::queue::RecipientDomain;
use std::time::{Duration, Instant};

// inbuxa: 1.0 keeps keys and counters in in-memory stores only (an SQL
// lookup store answers NotSupported), so those calls use the default one
const TESTS: &[(&str, &str)] = &[
    ("dns_query(rcpt_domain, 'mx')[0]", "mx.foobar.org"),
    (
        "key_get('*', 'hello') + '-' + key_exists('*', 'hello') + '-' + key_set('*', 'hello', 'world') + '-' + key_get('*', 'hello') + '-' + key_exists('*', 'hello')",
        "-0-1-world-1",
    ),
    (
        "counter_get('*', 'county') + '-' + counter_incr('*', 'county', 1) + '-' + counter_incr('*', 'county', 1) + '-' + counter_get('*', 'county')",
        "0-1-2-2",
    ),
    (
        "sql_query('sql', 'SELECT description FROM domains WHERE name = ?', 'foobar.org')",
        "Main domain",
    ),
    (
        "is_local_domain('foobar.org') + '-' + is_local_domain('unknown.org')  + '-' + is_local_address('john@foobar.org') + '-' + is_local_address('unknown@foobar.org')",
        "1-0-1-0",
    ),
    (
        "is_local_domain('FooBar.org') + '-' + is_local_address('John@FooBar.org') + '-' + is_local_address('JOHN@FOOBAR.ORG')",
        "1-1-1",
    ),
    (
        "bit_and(254, 16) + '-' + bit_and(254, 1) + '-' + bit_and(80, 64) + '-' + bit_and(255, 128)",
        "16-0-64-128",
    ),
];

#[tokio::test]
async fn expressions() {
    let mut test = TestServerBuilder::new("smtp_lookup_test")
        .await
        .with_http_listener(19017)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Create test data
    let admin = test.account("admin");
    for (name, secret, description, aliases) in [
        ("john@foobar.org", "12345 + extra safety", "John Doe", &[]),
        ("jane@domain.net", "abcde + extra safety", "Jane Smith", &[]),
    ] {
        admin
            .create_user_account(name, secret, description, aliases, vec![])
            .await;
    }
    admin
        .registry_create_object(StoreLookup {
            namespace: "sql".into(),
            store: LookupStore::Sqlite(SqliteStore {
                path: format!("{}/smtp_sql.db", test.tmp_dir()),
                pool_max_connections: Some(10),
                pool_workers: None,
            }),
        })
        .await;
    admin.reload_lookup_stores().await;
    test.reload_core();

    test.server.mx_add(
        "test.org",
        vec![Mx {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );

    let sql = test
        .server
        .get_lookup_store("sql")
        .unwrap()
        .into_store()
        .unwrap();
    sql.create_tables().await.unwrap();
    for query in [
        "CREATE TABLE domains (name TEXT PRIMARY KEY, description TEXT);",
        "INSERT INTO domains (name, description) VALUES ('foobar.org', 'Main domain');",
        "INSERT INTO domains (name, description) VALUES ('foobar.net', 'Secondary domain');",
        "CREATE TABLE allowed_ips (addr TEXT PRIMARY KEY);",
        "INSERT INTO allowed_ips (addr) VALUES ('10.0.0.50');",
    ] {
        sql.sql_query::<usize>(query, Vec::new()).await.unwrap();
    }

    // Test expression functions
    let token_map = TokenMap::default().with_variables(&[
        ExpressionVariable::Rcpt,
        ExpressionVariable::RcptDomain,
        ExpressionVariable::Sender,
        ExpressionVariable::SenderDomain,
        ExpressionVariable::Mx,
        ExpressionVariable::HeloDomain,
        ExpressionVariable::AuthenticatedAs,
        ExpressionVariable::Listener,
        ExpressionVariable::RemoteIp,
        ExpressionVariable::LocalIp,
        ExpressionVariable::Priority,
    ]);
    for (expr, expected) in TESTS {
        // inbuxa: 1.0 evaluates compiled if-blocks only, so the expression
        // becomes the default of an otherwise empty block
        let e = IfBlock::new(
            ObjectType::Account.singleton(),
            Property::AccountName,
            Box::default(),
            Expression::parse(&token_map, expr).unwrap(),
        );
        assert_eq!(
            test.server
                .eval_if::<String, _>(&e, &RecipientDomain::new("test.org"), &mut Bump::new(), 0)
                .await
                .unwrap_or_else(|| panic!("no result for '{expr}'")),
            *expected,
            "failed for '{}'",
            expr
        );
    }
}
