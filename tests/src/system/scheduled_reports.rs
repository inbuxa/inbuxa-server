/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Scheduled reports and the weekly digest (scheduled-reports spec): the
//! digest every server has, making and changing reports, who they may go
//! to, Send now, and what a tenant administrator sees.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use store::{
    SUBSPACE_INBUXA, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};

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

async fn reports(account: &Account) -> Vec<Value> {
    let (_, response) = call(account, "inbuxa:ScheduledReport/get", json!({"ids": null})).await;
    response["list"].as_array().cloned().unwrap_or_default()
}

pub async fn test(test: &mut TestServer) {
    println!("Running scheduled reports tests...");
    let admin = test.account("admin@example.com");
    let me = "admin@example.com";

    // --- Moved from where 2026.10.6.2 kept them (`S`, shared with the spam
    // rules marker and replica markers), touching nothing else ---------------
    let any = |key: Vec<u8>| {
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key,
        })
    };
    let legacy_digest = [b"Sr".as_slice(), &1u64.to_be_bytes()].concat();
    let mut batch = BatchBuilder::new();
    batch.set(
        any(legacy_digest.clone()),
        serde_json::to_vec(&json!({
            "id": 1, "name": "Weekly digest (moved)",
            "enabled": true,
            "builtIn": true,
            "sections": ["mailFlow", "queue", "spoofing", "tlsFailures", "deliverability",
                "security", "storage", "certificates"],
            "createdAt": 1790000000,
            "lastDue": 1790000000
        }))
        .unwrap(),
    );
    batch.set(
        any(b"Ss".to_vec()),
        serde_json::to_vec(&json!({"fromName": "Moved sender"})).unwrap(),
    );
    batch.set(any(b"Sr".to_vec()), b"3.0.2+2".to_vec());
    test.server.store().write(batch.build_all()).await.unwrap();
    let list = reports(admin).await;
    assert!(
        list.iter().any(|r| r["name"] == "Weekly digest (moved)"),
        "the digest wasn't moved: {list:?}"
    );
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReportSettings/get",
        json!({"ids": null}),
    )
    .await;
    assert_eq!(
        response["list"][0]["fromName"], "Moved sender",
        "{response}"
    );
    let raw = |key: Vec<u8>| {
        let store = test.server.store().clone();
        async move {
            store
                .get_value::<String>(ValueKey::from(any(key)))
                .await
                .unwrap()
        }
    };
    assert!(
        raw(legacy_digest).await.is_none(),
        "the old digest key is still there"
    );
    assert!(
        raw(b"Ss".to_vec()).await.is_none(),
        "the old settings key is still there"
    );
    assert_eq!(
        raw(b"Sr".to_vec()).await.as_deref(),
        Some("3.0.2+2"),
        "the spam rules marker was touched"
    );
    // Back to the default sender for what follows
    call(
        admin,
        "inbuxa:ScheduledReportSettings/set",
        json!({"update": {"singleton": {"fromName": ""}}}),
    )
    .await;

    // --- The weekly digest every server has (RP-21) ------------------------
    let list = reports(admin).await;
    let digest = list
        .iter()
        .find(|r| r["builtIn"] == true)
        .unwrap_or_else(|| panic!("no digest: {list:?}"));
    let digest_id = digest["id"].as_str().unwrap().to_string();
    assert_eq!(digest["enabled"], true, "{digest}");
    assert_eq!(digest["sections"].as_array().unwrap().len(), 8, "{digest}");
    assert_eq!(digest["schedule"]["frequency"], "weekly", "{digest}");
    assert_eq!(digest["schedule"]["weekday"], 1, "{digest}");
    assert_eq!(digest["schedule"]["hour"], 7, "{digest}");
    assert!(digest["nextRunAt"].is_string(), "{digest}");

    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"destroy": [digest_id]}),
    )
    .await;
    assert!(
        response["notDestroyed"][&digest_id].is_object(),
        "the digest was deleted: {response}"
    );
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"update": {&digest_id: {"recipients": [me]}}}),
    )
    .await;
    assert!(
        response["notUpdated"][&digest_id].is_object(),
        "the digest took recipients: {response}"
    );
    // It can be changed and turned off
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"update": {&digest_id: {"enabled": false, "schedule": {
            "frequency": "weekly", "weekday": 5, "hour": 16, "minute": 30,
            "timeZone": "America/Phoenix"
        }}}}),
    )
    .await;
    assert!(
        response["updated"][&digest_id].is_null() && response["notUpdated"].is_null(),
        "{response}"
    );
    let digest = reports(admin)
        .await
        .into_iter()
        .find(|r| r["id"] == digest_id.as_str())
        .unwrap();
    assert_eq!(digest["enabled"], false, "{digest}");
    assert!(
        digest["nextRunAt"].is_null(),
        "an off report has no next run: {digest}"
    );
    assert_eq!(digest["schedule"]["timeZone"], "America/Phoenix");

    // --- Making a report: what's checked (RP-15, RP-23) ---------------------
    let good = json!({
        "name": "Daily storage",
        "sections": ["storage", "certificates"],
        "schedule": {"frequency": "daily", "hour": 6, "minute": 0, "timeZone": "Europe/Amsterdam"},
        "recipients": [me],
        "attachCsv": true
    });
    let mut outside = good.clone();
    outside["recipients"] = json!(["someone@elsewhere.example"]);
    let mut bad_zone = good.clone();
    bad_zone["schedule"]["timeZone"] = json!("Mars/Olympus");
    let mut no_sections = good.clone();
    no_sections["sections"] = json!([]);
    let mut unknown_section = good.clone();
    unknown_section["sections"] = json!(["weather"]);
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"create": {
            "outside": outside, "zone": bad_zone, "empty": no_sections,
            "unknown": unknown_section, "good": good
        }}),
    )
    .await;
    for refused in ["outside", "zone", "empty", "unknown"] {
        assert!(
            response["notCreated"][refused].is_object(),
            "{refused} was accepted: {response}"
        );
    }
    assert!(
        response["notCreated"]["outside"]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("isn't an account on this server"),
        "{response}"
    );
    let id = response["created"]["good"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not created: {response}"))
        .to_string();
    assert!(
        response["created"]["good"]["nextRunAt"].is_string(),
        "{response}"
    );

    // The server's own fields can't be set
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"update": {&id: {"runs": []}}}),
    )
    .await;
    assert!(response["notUpdated"][&id].is_object(), "{response}");

    // --- Send now (RP-18), never unsigned (RP-14) ----------------------------
    async fn send_now(admin: &Account, id: &str, runs_before: usize) -> Value {
        let (_, response) = call(
            admin,
            "inbuxa:ScheduledReport/set",
            json!({"update": {id: {"sendNow": true}}}),
        )
        .await;
        assert!(response["notUpdated"].is_null(), "{response}");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let report = reports(admin)
                .await
                .into_iter()
                .find(|r| r["id"] == id)
                .unwrap();
            let runs = report["runs"].as_array().cloned().unwrap_or_default();
            if runs.len() > runs_before {
                return runs[0].clone();
            }
            assert!(Instant::now() < deadline, "Send now never ran: {report}");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    // The default sender's domain has no DKIM key: refused, with the reason
    let run = send_now(admin, &id, 0).await;
    assert_eq!(run["byHand"], true, "{run}");
    assert_eq!(run["status"], "failed", "{run}");
    assert!(
        run["reason"].as_str().unwrap_or_default().contains("DKIM"),
        "{run}"
    );
    // A domain with keys signs it, and the queue takes it
    let (_, response) = call(
        admin,
        "x:Domain/query",
        json!({"filter": {"name": "example.com"}}),
    )
    .await;
    let domain_id = response["ids"][0]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .parse::<types::id::Id>()
        .unwrap();
    admin.create_dkim_signatures(domain_id).await;
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReportSettings/set",
        json!({"update": {"singleton": {"fromAddress": "reports@example.com"}}}),
    )
    .await;
    assert!(response["notUpdated"].is_null(), "{response}");
    let run = send_now(admin, &id, 1).await;
    assert_eq!(run["status"], "sent", "{run}");
    assert_eq!(run["recipients"], 1, "{run}");
    assert!(run["size"].as_u64().unwrap() > 500, "{run}");

    // --- Who it comes from (RP-20) -------------------------------------------
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReportSettings/get",
        json!({"ids": null}),
    )
    .await;
    let settings = &response["list"][0];
    assert_eq!(settings["fromName"], "inbuxa reports", "{response}");
    assert_eq!(settings["fromAddress"], "reports@example.com", "{response}");
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReportSettings/set",
        json!({"update": {"singleton": {"fromAddress": "not an address"}}}),
    )
    .await;
    assert!(
        response["notUpdated"]["singleton"].is_object(),
        "{response}"
    );

    // --- A tenant administrator (RP-22) --------------------------------------
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Reports tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "reports.example.org".to_string(),
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
            "tadmin@reports.example.org",
            "tenant-admin-secret-6120",
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
    assert!(
        reports(&t_admin).await.is_empty(),
        "a tenant administrator saw the server's reports"
    );
    let (_, response) = call(
        &t_admin,
        "inbuxa:ScheduledReport/set",
        json!({"create": {"mine": {
            "name": "Our domains",
            "sections": ["spoofing", "deliverability", "mailFlow"],
            "schedule": {"frequency": "monthly", "dayOfMonth": 1, "hour": 8, "minute": 0, "timeZone": "UTC"},
            "recipients": ["tadmin@reports.example.org"]
        }}}),
    )
    .await;
    let mine = response["created"]["mine"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("tenant report not created: {response}"))
        .to_string();
    let seen = reports(&t_admin).await;
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0]["memberTenantId"], tenant.to_string(), "{seen:?}");
    // The system administrator sees it too, and the tenant can't touch theirs
    assert!(
        reports(admin)
            .await
            .iter()
            .any(|r| r["id"] == mine.as_str())
    );
    let (_, response) = call(
        &t_admin,
        "inbuxa:ScheduledReport/set",
        json!({"update": {&id: {"enabled": false}}}),
    )
    .await;
    assert!(response["notUpdated"][&id].is_object(), "{response}");
    let (name, response) = call(
        &t_admin,
        "inbuxa:ScheduledReportSettings/set",
        json!({"update": {"singleton": {"fromName": "Tenant"}}}),
    )
    .await;
    assert_eq!(name, "error", "a tenant changed the sender: {response}");

    // --- Download (RP-19) ----------------------------------------------------
    let (_, response) = call(
        admin,
        "inbuxa:ReportExport/set",
        json!({"create": {
            "last": {"reportId": &id},
            "old": {"reportId": &id, "from": "2020-01-01T00:00:00Z", "to": "2020-01-02T00:00:00Z"}
        }}),
    )
    .await;
    let export = &response["created"]["last"];
    assert!(export["blobId"].is_string(), "{response}");
    assert!(
        export["size"].as_u64().unwrap_or_default() > 0,
        "{response}"
    );
    assert_eq!(
        export["sha256"].as_str().map(|s| s.len()),
        Some(64),
        "{response}"
    );
    assert_eq!(export["files"][0], "summary.txt", "{response}");
    assert!(
        response["notCreated"]["old"].is_object(),
        "a 2020 period was exported: {response}"
    );
    // A tenant administrator can't download a report that isn't theirs
    let (_, response) = call(
        &t_admin,
        "inbuxa:ReportExport/set",
        json!({"create": {"theirs": {"reportId": &id}}}),
    )
    .await;
    assert!(response["notCreated"]["theirs"].is_object(), "{response}");

    // --- Deleting ------------------------------------------------------------
    let (_, response) = call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"destroy": [&id, &mine]}),
    )
    .await;
    assert_eq!(
        response["destroyed"].as_array().map(|d| d.len()),
        Some(2),
        "{response}"
    );
    // Put the digest back as it was for the tests that follow
    call(
        admin,
        "inbuxa:ScheduledReport/set",
        json!({"update": {&digest_id: {"enabled": true, "schedule": {
            "frequency": "weekly", "weekday": 1, "hour": 7, "minute": 0, "timeZone": "UTC"
        }}}}),
    )
    .await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scheduled_reports_tests() {
    let mut test = TestServerBuilder::new("scheduled_reports_tests")
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
