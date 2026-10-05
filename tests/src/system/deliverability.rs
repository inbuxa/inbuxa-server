/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The deliverability check (deliverability spec): what a node finds about
//! its own addresses and the domains it sends for, which lists it leaves out,
//! what a tenant administrator sees of it, and who may ask for a check.

use crate::utils::{
    account::Account,
    dns::DnsCache,
    server::{TestServer, TestServerBuilder},
};
use inbuxa_features::deliverability::{AddressSource, DkimState, ListingState};
use mail_auth::{
    DnssecStatus, MX, common::parse::TxtRecordParser, dmarc::Dmarc, mta_sts::MtaSts,
    mta_sts::TlsRpt, spf::Spf,
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use smtp::outbound::mta_sts::lookup::STS_TEST_POLICY;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use types::id::Id;

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

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

async fn domain(admin: &Account, name: &str, tenant: Option<Id>) -> Id {
    admin
        .registry_create_object(Domain {
            name: name.to_string(),
            is_enabled: true,
            member_tenant_id: tenant,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await
}

pub async fn test(test: &mut TestServer) {
    println!("Running deliverability tests...");
    let admin = test.account("admin@example.com");
    let server = test.server.clone();
    let soon = Instant::now() + Duration::from_secs(600);

    // --- The settings: the lists, and leaving one out (DL-6) -------------
    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilitySettings/get",
        json!({"ids": null}),
    )
    .await;
    let settings = &response["list"][0];
    assert_eq!(settings["disabledLists"], json!([]), "{response}");
    let lists = settings["lists"].as_array().unwrap();
    assert_eq!(lists.len(), 9, "{response}");
    let barracuda = lists.iter().find(|l| l["name"] == "Barracuda").unwrap();
    assert!(
        barracuda["note"].as_str().unwrap().contains("registered"),
        "{barracuda}"
    );

    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilitySettings/set",
        json!({"update": {"singleton": {"disabledLists": ["My own list"]}}}),
    )
    .await;
    assert!(
        response["notUpdated"]["singleton"].is_object(),
        "an unknown list was taken: {response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilitySettings/set",
        json!({"update": {"singleton": {"disabledLists": ["Barracuda"]}}}),
    )
    .await;
    assert!(
        response["updated"]["singleton"].is_null() && response["updated"].is_object(),
        "{response}"
    );

    // --- What the world says about this node ------------------------------
    let hostname = server.core.network.server_name.to_lowercase();
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    server.ipv4_add(hostname.as_str(), vec!["192.0.2.10".parse().unwrap()], soon);
    server.ptr_add(ip, vec![format!("{hostname}.")], soon);
    // Listed on ZEN, refused by SpamCop, an undefined answer from Mailspike
    server.ipv4_add(
        "10.2.0.192.zen.spamhaus.org",
        vec!["127.0.0.2".parse().unwrap()],
        soon,
    );
    server.ipv4_add(
        "10.2.0.192.bl.spamcop.net",
        vec!["127.255.255.254".parse().unwrap()],
        soon,
    );
    server.ipv4_add(
        "10.2.0.192.bl.mailspike.net",
        vec!["127.0.0.200".parse().unwrap()],
        soon,
    );

    // A tenant's domain that's in order, and the server's own that isn't
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Deliverability tenant".to_string(),
            ..Default::default()
        })
        .await;
    domain(&admin, "good.example.org", Some(tenant)).await;
    domain(&admin, "bad.example.org", None).await;
    server.txt_add(
        "good.example.org",
        Spf::parse(b"v=spf1 ip4:192.0.2.10 -all").unwrap(),
        soon,
    );
    server.txt_add(
        "bad.example.org",
        Spf::parse(b"v=spf1 ip4:198.51.100.1 -all").unwrap(),
        soon,
    );
    server.txt_add(
        "_dmarc.good.example.org",
        Dmarc::parse(b"v=DMARC1; p=reject; adkim=s").unwrap(),
        soon,
    );
    server.txt_add(
        "_smtp._tls.good.example.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:tls@good.example.org").unwrap(),
        soon,
    );
    server.txt_add(
        "_mta-sts.good.example.org",
        MtaSts::parse(b"v=STSv1; id=20261005").unwrap(),
        soon,
    );
    {
        let mut policy = STS_TEST_POLICY.lock();
        policy.clear();
        policy.extend_from_slice(
            b"version: STSv1\nmode: enforce\nmx: mx1.good.example.org\nmax_age: 86400\n",
        );
    }
    server.mx_add(
        "good.example.org",
        vec![
            MX {
                exchanges: vec!["mx1.good.example.org.".into()].into_boxed_slice(),
                preference: 10,
            },
            MX {
                exchanges: vec!["mx2.good.example.org.".into()].into_boxed_slice(),
                preference: 20,
            },
        ],
        DnssecStatus::Insecure,
        soon,
    );
    server.ipv4_add(
        "bad.example.org.dbl.spamhaus.org",
        vec!["127.0.1.2".parse().unwrap()],
        soon,
    );

    let report = services::inbuxa_deliverability::run(&server)
        .await
        .expect("the check runs");

    // DL-2: no addresses set, so what the EHLO name resolves to
    assert_eq!(report.addresses.len(), 1, "{report:#?}");
    let address = &report.addresses[0];
    assert_eq!(address.ip, "192.0.2.10");
    assert_eq!(address.source, AddressSource::Ehlo);
    // DL-5
    assert_eq!(address.ptr, [hostname.clone()]);
    assert!(
        address.forward_confirmed && address.ehlo_matches,
        "{address:#?}"
    );
    // DL-4, DL-6
    let state = |list: &str| {
        address
            .listings
            .iter()
            .find(|l| l.list == list)
            .unwrap_or_else(|| panic!("{list} not asked: {address:#?}"))
            .state
    };
    assert_eq!(state("Spamhaus ZEN"), ListingState::Listed);
    assert_eq!(state("SpamCop"), ListingState::Refused);
    assert_eq!(state("Mailspike"), ListingState::Refused);
    assert_eq!(state("Barracuda"), ListingState::Off);
    assert_eq!(state("PSBL"), ListingState::Clean);
    assert!(
        address.listings.iter().all(|l| l.list != "Spamhaus DBL"),
        "a domain list was asked about an address"
    );

    let good = report
        .domains
        .iter()
        .find(|d| d.domain == "good.example.org")
        .unwrap();
    let bad = report
        .domains
        .iter()
        .find(|d| d.domain == "bad.example.org")
        .unwrap();
    // DL-7
    assert_eq!(good.spf[0].result, "pass", "{good:#?}");
    assert_eq!(bad.spf[0].result, "fail", "{bad:#?}");
    // DL-8: no keys of its own, so nothing to compare
    assert!(good.dkim.iter().all(|k| k.state != DkimState::Different));
    // DL-9
    let dmarc = good.dmarc.as_ref().expect("the DMARC record");
    assert_eq!(
        (dmarc.policy.as_str(), dmarc.adkim.as_str()),
        ("reject", "strict")
    );
    assert!(bad.dmarc.is_none());
    // DL-10: the policy is fetched, and one MX isn't in it
    assert_eq!(good.mta_sts.record_id.as_deref(), Some("20261005"));
    assert!(good.mta_sts.fetched, "{:#?}", good.mta_sts);
    assert_eq!(good.mta_sts.mode.as_deref(), Some("enforce"));
    assert_eq!(good.mta_sts.mx_not_covered, ["mx2.good.example.org"]);
    assert!(bad.mta_sts.record_id.is_none());
    // DL-11
    assert!(good.tls_rpt && !bad.tls_rpt);
    // DL-12
    let dbl = bad
        .listings
        .iter()
        .find(|l| l.list == "Spamhaus DBL")
        .unwrap();
    assert_eq!(dbl.state, ListingState::Listed);
    // DL-13: the EHLO name is checked
    assert!(
        report.certificates.iter().any(|c| c.name == hostname),
        "{:#?}",
        report.certificates
    );

    // --- Over JMAP ---------------------------------------------------------
    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilityReport/get",
        json!({"ids": null}),
    )
    .await;
    let listed = response["list"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "{response}");
    assert_eq!(listed[0]["addresses"][0]["ip"], "192.0.2.10", "{response}");
    // The two above and the test server's own
    assert_eq!(
        listed[0]["domains"].as_array().unwrap().len(),
        report.domains.len(),
        "{response}"
    );
    assert!(listed[0]["checkedAt"].as_str().unwrap().ends_with('Z'));

    // Check now: queued, with when the node last checked (DL-15)
    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilityReport/set",
        json!({"create": {"now": {}}}),
    )
    .await;
    assert_eq!(
        response["created"]["now"]["checkedAt"], listed[0]["checkedAt"],
        "{response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:DeliverabilityReport/set",
        json!({"destroy": [listed[0]["id"]]}),
    )
    .await;
    assert!(response["notDestroyed"].is_object(), "{response}");

    // --- A tenant administrator (DL-20) -------------------------------------
    let t_admin = admin
        .create_user_account(
            "tadmin@good.example.org",
            "tenant-admin-secret-5520",
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
    let (_, response) = call(
        &t_admin,
        "inbuxa:DeliverabilityReport/get",
        json!({"ids": null}),
    )
    .await;
    let seen = &response["list"][0];
    assert_eq!(seen["addresses"], json!([]), "{response}");
    assert_eq!(seen["certificates"], json!([]), "{response}");
    let domains = seen["domains"].as_array().unwrap();
    assert_eq!(domains.len(), 1, "{response}");
    assert_eq!(domains[0]["domain"], "good.example.org");

    let (name, response) = call(
        &t_admin,
        "inbuxa:DeliverabilityReport/set",
        json!({"create": {"now": {}}}),
    )
    .await;
    assert_eq!(
        name, "error",
        "a tenant administrator ran the check: {response}"
    );
    let (name, response) = call(
        &t_admin,
        "inbuxa:DeliverabilitySettings/set",
        json!({"update": {"singleton": {"disabledLists": []}}}),
    )
    .await;
    assert_eq!(
        name, "error",
        "a tenant administrator changed the lists: {response}"
    );

    // Cleared for the tests that follow
    call(
        &admin,
        "inbuxa:DeliverabilitySettings/set",
        json!({"update": {"singleton": {"disabledLists": []}}}),
    )
    .await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn deliverability_tests() {
    let mut test = TestServerBuilder::new("deliverability_tests")
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
