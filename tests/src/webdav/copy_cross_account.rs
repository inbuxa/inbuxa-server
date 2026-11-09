/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A calendar or address book copied or moved into another account keeps
//! every entry, also when its id in the old account is the id of the one it
//! lands on in the new account.

use crate::utils::{server::TestServer, webdav::DummyWebDavClient};
use groupware::{DavResourceName, cache::GroupwareCache};
use hyper::StatusCode;
use types::collection::SyncCollection;

struct Kind {
    base: DavResourceName,
    collection: SyncCollection,
    resource_type: &'static str,
    item: &'static str,
    body: &'static str,
}

pub async fn test(test: &TestServer) {
    println!("Running cross-account collection COPY/MOVE tests...");
    let kinds = [
        Kind {
            base: DavResourceName::Cal,
            collection: SyncCollection::Calendar,
            resource_type: "A:calendar",
            item: "event.ics",
            body: EVENT_ICS,
        },
        Kind {
            base: DavResourceName::Card,
            collection: SyncCollection::AddressBook,
            resource_type: "B:addressbook",
            item: "card.vcf",
            body: CARD_VCF,
        },
    ];
    let owner = test.account("bill@example.com").webdav_client();
    let sharee = test.account("john@example.com").webdav_client();
    let sharee_principal = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );

    for kind in &kinds {
        for method in ["COPY", "MOVE"] {
            let base = kind.base.base_path();
            let mut created = Vec::new();
            let mut create = async |client: &DummyWebDavClient, user: &str, n: usize| {
                let name = format!("cross-{method}-{n}");
                let href = format!("{base}/{user}%40example.com/{name}/");
                client
                    .mkcol("MKCOL", &href, ["D:collection", kind.resource_type], [])
                    .await
                    .with_status(StatusCode::CREATED);
                let id = test
                    .server
                    .fetch_dav_resources(client.account_id, client.account_id, kind.collection)
                    .await
                    .unwrap()
                    .by_path(&name)
                    .unwrap()
                    .document_id();
                created.push((client.account_id, href.clone()));
                (href, id)
            };

            // Bill's collection and one of John's with the same id
            let mut n = 0;
            let (mut source, mut source_id) = create(&owner, "bill", n).await;
            let (mut target, mut target_id) = create(&sharee, "john", n).await;
            while source_id != target_id {
                n += 1;
                if target_id < source_id {
                    (target, target_id) = create(&sharee, "john", n).await;
                } else {
                    (source, source_id) = create(&owner, "bill", n).await;
                }
            }

            let source_item = format!("{source}{}", kind.item);
            owner
                .request("PUT", &source_item, kind.body.replace('\n', "\r\n"))
                .await
                .with_status(StatusCode::CREATED);
            owner
                .acl(&source, sharee_principal.as_str(), ["read", "write"])
                .await
                .with_status(StatusCode::OK);

            sharee
                .request_with_headers(
                    method,
                    &source,
                    [("destination", target.as_str()), ("overwrite", "T")],
                    "",
                )
                .await
                .with_status(StatusCode::NO_CONTENT);
            let body = sharee
                .request("GET", &format!("{target}{}", kind.item), "")
                .await
                .with_status(StatusCode::OK)
                .expect_body()
                .to_string();
            assert!(
                body.contains("Cross account"),
                "{method} into another account lost an entry: {body}"
            );
            if method == "MOVE" {
                owner
                    .request("GET", &source_item, "")
                    .await
                    .with_status(StatusCode::NOT_FOUND);
            }

            for (account_id, href) in created.iter().rev() {
                let client = if *account_id == owner.account_id {
                    &owner
                } else {
                    &sharee
                };
                // A moved source is gone already
                let _ = client.request("DELETE", href, "").await;
            }
        }
    }

    sharee.delete_default_containers().await;
    owner.delete_default_containers().await;
    test.assert_is_empty().await;
}

const EVENT_ICS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Cross//EN
BEGIN:VEVENT
UID:cross-account@example.com
DTSTAMP:20200101T000000Z
DTSTART:20200203T100000Z
DTEND:20200203T110000Z
SUMMARY:Cross account
END:VEVENT
END:VCALENDAR
";

const CARD_VCF: &str = "BEGIN:VCARD
VERSION:4.0
UID:cross-account@example.com
FN:Cross account
END:VCARD
";
