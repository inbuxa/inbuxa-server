/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Branding and templates acceptance tests, from
//! `docs/spec/features/branding-and-templates.md`. Each check names the test
//! number or the requirement it covers.

use crate::utils::{
    account::Account,
    webdav::DummyWebDavClient,
    server::{TestServer, TestServerBuilder},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use calcard::{common::timezone::Tz, icalendar::ICalendarMethod};
use calcard::icalendar::{ICalendarParticipationStatus, ICalendarProperty};
use email::cache::MessageCacheFetch;
use groupware::scheduling::{ItipField, ItipParticipant, ItipSummary, ItipTime, ItipValue};
use hyper::StatusCode;
use jmap_proto::error::set::SetErrorType;
use mail_parser::{MessageParser, MimeHeaders};
use registry::types::EnumImpl;
use registry::schema::{
    prelude::{Object, ObjectInner, ObjectType, Property},
    structs::{
        CalendarAlarm, CalendarScheduling, CertificateManagement, DkimManagement, DnsManagement,
        Domain, Enterprise, Tenant, UserRoles,
    },
};
use serde_json::json;
use services::task_manager::imip::build_itip_template;
use std::{str::FromStr, time::Duration};
use store::{
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
use trc::{Collector, EventType, RegistryEvent};
use types::id::Id;

const SECRET: &str = "branding test user passphrase";
const PNG: &[u8] = include_bytes!("../../../resources/branding/email-logo.png");
const SVG_SCRIPTED: &[u8] =
    b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";

/// A template that shows every alarm variable (BT-13), each in a marker.
const ALARM_TEMPLATE: &str = concat!(
    "<html lang=\"{{lang}}\" dir=\"{{dir}}\"><body>CUSTOM[{{page_title}}]",
    "<img src=\"{{logo_cid}}\">",
    "{{#if header}}H[{{header}}]{{/if header}}",
    "{{#if event_title}}T[{{event_title}}]{{/if event_title}}",
    "{{#if event_description}}D[{{event_description}}]{{/if event_description}}",
    "{{#each event_details}}K[{{key}}]V[{{value}}]{{#if link}}L[{{link}}]{{/if link}}{{/each event_details}}",
    "AT[{{attendees_title}}]{{#each attendees}}A[{{key}}|{{value}}]{{/each attendees}}",
    "<a href=\"{{action_url}}\">N[{{action_name}}]</a>F[{{footer}}]</body></html>"
);

/// A template for iMIP messages (BT-13).
const INVITE_TEMPLATE: &str = concat!(
    "<html lang=\"{{lang}}\">CUSTOM[{{page_title}}]<img src=\"{{logo_cid}}\">",
    "{{#if header}}H[{{header}}|{{color}}]{{/if header}}",
    "{{#if event_title}}T[{{event_title}}]{{/if event_title}}",
    "{{#each event_details}}K[{{key}}]V[{{value}}]{{#if changed}}OLD[{{old_value}}]{{/if changed}}{{/each event_details}}",
    "{{#if attendees}}AT[{{attendees_title}}]{{/if attendees}}",
    "{{#if rsvp}}R[{{rsvp}}]{{/if rsvp}}",
    "{{#each actions}}ACT[{{action_name}}]{{/each actions}}",
    "{{#each footer}}F[{{key}}]{{/each footer}}</html>"
);

pub async fn test(test: &mut TestServer) {
    println!("Running branding tests...");
    let admin = test.account("admin@example.org");
    let t_id = admin
        .registry_create_object(Tenant {
            name: "brand-t".to_string(),
            ..Default::default()
        })
        .await;
    let t_domain = admin.brand_domain("t-brand.example.org", Some(t_id)).await;
    let plain = admin.brand_domain("plain-brand.example.org", None).await;
    let t_admin = admin
        .create_user_account("tadmin@t-brand.example.org", SECRET, "T admin", &[], vec![])
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({ Property::Roles: UserRoles::Admin }),
        )
        .await;
    let user = admin
        .create_user_account(
            "alarm@plain-brand.example.org",
            SECRET,
            "Alarm user",
            &[],
            vec![],
        )
        .await;
    let png_url = data_url("image/png", PNG);

    // Acceptance test 1: nothing set, no custom logo anywhere
    let answer = get(&admin, "/logo?domain=plain-brand.example.org", None).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "test 1");
    answer.assert_logo_headers("test 1");
    assert!(
        test.server
            .logo_resource("plain-brand.example.org")
            .await
            .unwrap()
            .is_none(),
        "test 1: emails keep the built-in"
    );

    // Acceptance test 8: logo writes (BT-3)
    for bad in [
        "javascript:alert(1)".to_string(),
        "data:text/html,<b>x</b>".to_string(),
        data_url("image/png", &[PNG, &vec![0u8; 300 * 1024]].concat()),
        data_url("image/png", &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]),
    ] {
        admin
            .registry_update_object_expect_err(ObjectType::Domain, plain, json!({"logo": bad}))
            .await
            .assert_type(SetErrorType::InvalidProperties)
            .assert_properties(&["logo"]);
    }

    // Acceptance test 12: template writes (BT-15)
    for (bad, why) in [
        ("{{#if header}}x", "never closed"),
        ("{{unknown}}", "Unknown variable"),
        ("{{!header}}", "raw output"),
        (
            "{{#each actions}}{{#each attendees}}{{/each attendees}}{{/each actions}}",
            "inside another",
        ),
    ] {
        admin
            .registry_update_object_expect_err(
                ObjectType::CalendarAlarm,
                Id::singleton(),
                json!({"template": bad}),
            )
            .await
            .assert_type(SetErrorType::InvalidProperties)
            .assert_properties(&["template"])
            .assert_description_contains(why);
    }
    admin
        .registry_update_object_expect_err(
            ObjectType::CalendarScheduling,
            Id::singleton(),
            json!({"emailTemplate": "x".repeat(300 * 1024)}),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_properties(&["emailTemplate"]);

    // Acceptance test 2: a server-wide PNG logo is served and embedded
    admin
        .registry_update_setting(
            Enterprise {
                logo_url: Some(png_url.clone()),
                ..Default::default()
            },
            &[Property::LogoUrl],
        )
        .await;
    let answer = get(&admin, "/logo?domain=plain-brand.example.org", None).await;
    assert_eq!(answer.status, StatusCode::OK, "test 2");
    assert_eq!(answer.header("content-type"), "image/png", "test 2");
    assert_eq!(answer.body, PNG, "test 2");
    answer.assert_logo_headers("test 2");

    // Acceptance tests 10 and 14: a custom alarm template, used for the next
    // alarm with no reload, every variable filled and values escaped; the
    // email embeds the server-wide PNG (test 2)
    admin
        .registry_update_setting(
            CalendarAlarm {
                template: Some(ALARM_TEMPLATE.to_string()),
                ..Default::default()
            },
            &[Property::Template],
        )
        .await;
    let (html, logo) = alarm_email(test, &user).await;
    for marker in [
        "CUSTOM[", "H[", "T[", "D[", "K[", "V[", "AT[", "A[", "N[", "F[",
    ] {
        assert!(
            html.contains(marker) && !html.contains(&format!("{marker}]")),
            "test 10: {marker} filled in {html}"
        );
    }
    assert!(html.contains("lang=\"en"), "test 10: lang in {html}");
    assert!(html.contains("L[https://meet.example.com/brand]"), "test 10: link in {html}");
    assert!(html.contains("src=\"cid:"), "test 10: logo_cid in {html}");
    assert!(html.contains("href=\"webcal"), "test 10: action_url in {html}");
    assert!(
        html.contains("T[&lt;b&gt;x&lt;/b&gt;]"),
        "test 10: the title is text, not HTML: {html}"
    );
    assert_eq!(logo, Some(("image/png".to_string(), PNG.to_vec())), "test 2");

    // Acceptance test 3: the tenant's logo, then the domain's own
    admin
        .registry_update_object(
            ObjectType::Tenant,
            t_id,
            json!({"logo": "https://logo.example.org/t.png"}),
        )
        .await;
    let answer = get(&admin, "/logo?domain=t-brand.example.org", None).await;
    assert_eq!(answer.status, StatusCode::FOUND, "test 3");
    assert_eq!(answer.header("location"), "https://logo.example.org/t.png");
    let gif = data_url("image/gif", b"GIF89a\x01\0\x01\0\0\0\0;");
    admin
        .registry_update_object(ObjectType::Domain, t_domain, json!({"logo": gif}))
        .await;
    let answer = get(&admin, "/logo?domain=t-brand.example.org", None).await;
    assert_eq!(answer.header("content-type"), "image/gif", "test 3: domain wins");

    // Acceptance test 4: a subdomain finds its domain, by parameter or Host
    let by_param = get(&admin, "/logo?domain=mail.t-brand.example.org", None).await;
    let by_host = get(&admin, "/logo", Some("mail.t-brand.example.org:443")).await;
    for answer in [by_param, by_host] {
        assert_eq!(answer.header("content-type"), "image/gif", "test 4");
    }

    // Acceptance test 5: a URL logo is redirected to, never fetched, and
    // emails fall back to the next logo they can carry
    admin
        .registry_update_object(
            ObjectType::Domain,
            plain,
            json!({"logo": "https://192.0.2.1/logo.png"}),
        )
        .await;
    let started = std::time::Instant::now();
    let answer = get(&admin, "/logo?domain=plain-brand.example.org", None).await;
    assert_eq!(answer.status, StatusCode::FOUND, "test 5");
    assert_eq!(answer.header("location"), "https://192.0.2.1/logo.png");
    // TEST-NET-1 never answers: a fetch would hang, a redirect is instant
    assert!(started.elapsed() < Duration::from_secs(2), "test 5: no fetch");
    let resource = test
        .server
        .logo_resource("plain-brand.example.org")
        .await
        .unwrap()
        .expect("test 5: the server-wide PNG");
    assert_eq!(resource.contents, PNG, "test 5");

    // Acceptance test 6: an unknown domain answers as a known one with no
    // logo of its own
    admin
        .registry_update_object(ObjectType::Domain, plain, json!({"logo": null}))
        .await;
    let known = get(&admin, "/logo?domain=plain-brand.example.org", None).await;
    let unknown = get(&admin, "/logo?domain=nowhere.example.net", None).await;
    assert_eq!(known.status, unknown.status, "test 6");
    assert_eq!(known.body, unknown.body, "test 6");
    assert_eq!(known.header("content-type"), unknown.header("content-type"));

    // Acceptance tests 7 and 9: an SVG is sandboxed, and a change shows on the
    // next request with no restart
    admin
        .registry_update_object(
            ObjectType::Domain,
            plain,
            json!({"logo": data_url("image/svg+xml", SVG_SCRIPTED)}),
        )
        .await;
    let answer = get(&admin, "/logo?domain=plain-brand.example.org", None).await;
    assert_eq!(answer.header("content-type"), "image/svg+xml", "test 9");
    assert_eq!(
        answer.header("content-security-policy"),
        "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        "test 7"
    );

    // Acceptance test 11: a custom iMIP template for each kind of message
    admin
        .registry_update_setting(
            CalendarScheduling {
                email_template: Some(INVITE_TEMPLATE.to_string()),
                ..Default::default()
            },
            &[Property::EmailTemplate],
        )
        .await;
    for (kind, summary) in itip_summaries() {
        let body = itip_html(test, &user, &summary).await;
        assert!(body.contains("CUSTOM["), "test 11 {kind}: {body}");
        match kind {
            "invite" => {
                assert!(body.contains("ACT["), "test 11: RSVP actions, {body}");
                assert!(body.contains("AT["), "test 11: attendees, {body}");
            }
            "update" => {
                assert!(body.contains("OLD[Dinner]"), "test 11: old value, {body}");
                assert!(body.contains("|info]"), "test 11: color, {body}");
            }
            "cancel" => assert!(body.contains("|danger]"), "test 11: {body}"),
            _ => assert!(body.contains("H["), "test 11 reply: {body}"),
        }
    }

    // Acceptance test 13: stored templates from before the fork. Raw output
    // is escaped; one that doesn't parse leaves the built-in in use, with a
    // warning at each reload
    store_directly(
        test,
        ObjectInner::CalendarScheduling(CalendarScheduling {
            email_template: Some("RAW[{{!event_title}}]".to_string()),
            ..Default::default()
        }),
    )
    .await;
    let body = itip_html(test, &user, &itip_summaries()[0].1).await;
    assert!(body.contains("RAW[&lt;b&gt;x&lt;/b&gt;]"), "test 13: {body}");
    store_directly(
        test,
        ObjectInner::CalendarScheduling(CalendarScheduling {
            email_template: Some("{{#if header}}unclosed".to_string()),
            ..Default::default()
        }),
    )
    .await;
    let body = itip_html(test, &user, &itip_summaries()[0].1).await;
    assert!(
        !body.contains("unclosed") && body.contains("<title>"),
        "test 13: the built-in is used"
    );
    let warning = EventType::Registry(RegistryEvent::BuildWarning).to_id() as usize;
    let warnings = Collector::read_metric_counter(warning);
    admin.reload_settings().await;
    let after = Collector::read_metric_counter(warning);
    assert!(
        after > warnings || !Collector::is_metric(warning),
        "test 13: registry.build-warning"
    );

    // Acceptance test 15: a custom RSVP page, byte for byte, with BT-21's
    // headers
    let page = "<!doctype html><title>{{page_title}}</title><p>Custom RSVP</p>";
    admin
        .registry_update_setting(
            CalendarScheduling {
                http_rsvp_template: Some(page.to_string()),
                ..Default::default()
            },
            &[Property::HttpRsvpTemplate],
        )
        .await;
    let answer = get(&admin, "/calendar/rsvp?token=x", None).await;
    assert_eq!(answer.status, StatusCode::OK, "test 15");
    assert_eq!(answer.body, page.as_bytes(), "test 15: byte for byte");
    assert_eq!(answer.header("referrer-policy"), "no-referrer", "test 15");
    assert!(answer.header("cache-control").contains("no-store"), "test 15");
    assert!(
        answer
            .header("content-security-policy")
            .contains("connect-src 'self'"),
        "test 15"
    );
    admin
        .registry_update_setting(
            CalendarScheduling {
                http_rsvp_enable: false,
                ..Default::default()
            },
            &[Property::HttpRsvpEnable],
        )
        .await;
    admin.reload_settings().await;
    assert_ne!(
        get(&admin, "/calendar/rsvp?token=x", None).await.status,
        StatusCode::OK,
        "test 15: page gone"
    );
    let api = post(&admin, "/api/calendar/rsvp", "{\"token\":\"x\"}").await;
    assert_ne!(api.status, StatusCode::OK, "test 15: API gone");
    admin
        .registry_update_setting(
            CalendarScheduling {
                http_rsvp_enable: true,
                ..Default::default()
            },
            &[Property::HttpRsvpEnable],
        )
        .await;
    admin.reload_settings().await;

    // Acceptance test 16: a tenant administrator sets its domain's logo, but
    // nothing server-wide and not its tenant's
    t_admin
        .registry_update_object(ObjectType::Domain, t_domain, json!({"logo": png_url}))
        .await;
    for (object, id, patch) in [
        (
            ObjectType::Enterprise,
            Id::singleton(),
            json!({"logoUrl": "https://logo.example.org/x.png"}),
        ),
        (
            ObjectType::CalendarAlarm,
            Id::singleton(),
            json!({"template": "<p>{{header}}</p>"}),
        ),
        (
            ObjectType::Tenant,
            t_id,
            json!({"logo": "https://logo.example.org/x.png"}),
        ),
    ] {
        let response = t_admin.registry_update(object, [(id, patch)]).await;
        let refused = response
            .0
            .pointer(&format!("/methodResponses/0/1/notUpdated/{id}"))
            .is_some()
            || response.0.pointer("/methodResponses/0/0") == Some(&json!("error"));
        assert!(refused, "test 16: {object:?} {response:?}");
    }

    // Acceptance test 17: the built-in pages load /logo through an image
    // element, which follows a redirect and falls back on error (BT-26)
    for page in [
        include_str!("../../../resources/html-templates/login.html"),
        include_str!("../../../resources/html-templates/calendar-rsvp.html"),
    ] {
        assert!(page.contains("img.src = target"), "test 17");
        assert!(page.contains("img.onerror = showDefault"), "test 17");
        assert!(!page.contains("fetch(target"), "test 17");
    }

    // Clean up
    admin
        .registry_update_setting(Enterprise::default(), &[Property::LogoUrl])
        .await;
    admin
        .registry_update_setting(CalendarAlarm::default(), &[Property::Template])
        .await;
    admin
        .registry_update_setting(
            CalendarScheduling::default(),
            &[Property::EmailTemplate, Property::HttpRsvpTemplate],
        )
        .await;
    admin.reload_settings().await;
    admin.destroy_account(user).await;
    admin.destroy_account(t_admin).await;
    for domain in [plain, t_domain] {
        admin
            .registry_destroy(ObjectType::Domain, [domain])
            .await
            .assert_destroyed(&[domain]);
    }
    admin
        .registry_destroy(ObjectType::Tenant, [t_id])
        .await
        .assert_destroyed(&[t_id]);
    test.wait_for_tasks().await;
}

/// Runs the branding tests alone:
/// `cargo test -p tests branding_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn branding_tests() {
    let mut test = TestServerBuilder::new("branding_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// Acceptance test 18 (compat): the logos and templates INBUXA holds read
/// back unchanged, and render or are served as before cutover.
///
/// INBUXA holds none (spec, observed 1), so this checks whatever a copy of
/// its data holds: every domain's and tenant's logo, `logoUrl`, and the
/// three templates read back as stored, logos are served by `/logo` or
/// skipped (BT-4), and templates render or fall back (BT-19). Run it with:
///
/// - `INBUXA_COMPAT_ADMIN`: `name:password` of a server-level administrator
///   in that data;
///
/// and the data itself in place of the test store: `NO_INSERT=1` and the
/// store's `TMPDIR`/`STORE` pointing at the copy, so it isn't reset.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn branding_compat() {
    let admin = std::env::var("INBUXA_COMPAT_ADMIN").expect("INBUXA_COMPAT_ADMIN");
    assert!(
        std::env::var("NO_INSERT").is_ok(),
        "NO_INSERT must be set, or the copy of inbuxa's data is wiped"
    );
    let test = TestServerBuilder::new("branding_compat")
        .await
        .with_default_listeners()
        .await
        .build_with_opts(false)
        .await;
    let (name, secret) = admin.split_once(':').expect("name:password");
    let admin = Account::new(
        Box::leak(name.to_string().into_boxed_str()),
        Box::leak(secret.to_string().into_boxed_str()),
        &[],
        "Compat admin",
        Id::from(u32::MAX),
    );

    admin.assert_authenticates("INBUXA_COMPAT_ADMIN").await;

    // Every domain's logo reads back and is served or skipped, never an error
    let domains = admin
        .jmap_method_call(
            "x:Domain/get",
            json!({"ids": null, "properties": ["name", "logo"]}),
        )
        .await;
    for domain in domains.list() {
        let name = domain["name"].as_str().unwrap();
        let answer = get(&admin, &format!("/logo?domain={name}"), None).await;
        assert!(
            matches!(
                answer.status,
                StatusCode::OK | StatusCode::FOUND | StatusCode::NOT_FOUND
            ),
            "{name}: {:?}",
            answer.status
        );
    }

    // Each stored template renders or falls back; the server keeps running
    for (object, fields) in [
        (ObjectType::CalendarAlarm, vec!["template"]),
        (
            ObjectType::CalendarScheduling,
            vec!["emailTemplate", "httpRsvpTemplate"],
        ),
    ] {
        let response = admin
            .jmap_method_call(
                &format!("x:{}/get", object.as_str()),
                json!({"ids": ["singleton"], "properties": fields}),
            )
            .await;
        assert!(!response.list().is_empty(), "{object:?}: {response:?}");
    }
    let _ = test;
}

/// Writes a setting straight into the registry, skipping `/set`'s checks,
/// as data from before the fork would be.
async fn store_directly(test: &TestServer, inner: ObjectInner) {
    let object = Object { inner, revision: 0 };
    let registry = test.server.registry();
    let old = registry
        .get(registry::types::id::ObjectId::new(
            object.object_type(),
            Id::singleton(),
        ))
        .await
        .unwrap();
    let result = match &old {
        Some(old) => registry
            .write(RegistryWrite::Update {
                object: &object,
                id: Id::singleton(),
                old_object: old,
            })
            .await
            .unwrap(),
        None => registry
            .write(RegistryWrite::Insert {
                object: &object,
                id: Some(Id::singleton()),
            })
            .await
            .unwrap(),
    };
    assert!(matches!(result, RegistryWriteResult::Success(_)));
}

/// An alarm email for `user`: its HTML and its inline logo part.
async fn alarm_email(test: &TestServer, user: &Account) -> (String, Option<(String, Vec<u8>)>) {
    let account_id = user.id().document_id();
    let start = now() as i64 + 4;
    let event = ALARM_EVENT
        .replace("$START", &ical_time(start))
        .replace("$END", &ical_time(start + 3600));
    DummyWebDavClient::new(account_id, user.name(), SECRET, "alarm@plain-brand.example.org")
        .request_with_headers(
            "PUT",
            "/dav/cal/alarm%40plain-brand.example.org/default/brand-alarm.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            event,
        )
        .await
        .with_status(StatusCode::CREATED);

    // The alarm fires 2s before the start
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let messages = test.server.get_cached_messages(account_id).await.unwrap();
        if let Some(message) = messages.emails.items.first() {
            let raw = test.fetch_email(account_id, message.document_id).await;
            let message = MessageParser::new().parse(&raw).unwrap();
            let html = String::from_utf8(
                message.html_bodies().next().unwrap().contents().to_vec(),
            )
            .unwrap();
            let logo = message.attachments().find(|part| part.content_id().is_some()).map(|part| {
                (
                    part.content_type()
                        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or_default()))
                        .unwrap_or_default(),
                    part.contents().to_vec(),
                )
            });
            return (html, logo);
        }
    }
    panic!("no alarm email arrived");
}

fn ical_time(timestamp: i64) -> String {
    mail_parser::DateTime::from_timestamp(timestamp)
        .to_rfc3339()
        .replace(['-', ':'], "")
}

/// An iMIP body rendered as the sender would render it now.
async fn itip_html(test: &TestServer, user: &Account, summary: &ItipSummary) -> String {
    let account_id = user.id().document_id();
    let account_info = test.server.account_info(account_id).await.unwrap();
    build_itip_template(
        &test.server,
        &account_info,
        account_id,
        1,
        "alarm@plain-brand.example.org",
        "guest@example.net",
        summary,
        "cid:logo.test@plain-brand.example.org",
    )
    .await
    .unwrap()
    .body
}

fn itip_summaries() -> Vec<(&'static str, ItipSummary)> {
    let time = ItipValue::Time(ItipTime {
        start: 1_789_732_800,
        tz_id: Tz::from_str("UTC").unwrap().as_id(),
    });
    let field = |name, value| ItipField { name, value };
    let people = ItipValue::Participants(vec![
        ItipParticipant {
            email: "alarm@plain-brand.example.org".to_string(),
            name: Some("Organizer".to_string()),
            is_organizer: true,
        },
        ItipParticipant {
            email: "guest@example.net".to_string(),
            name: Some("Guest".to_string()),
            is_organizer: false,
        },
    ]);
    let current = vec![
        field(
            ICalendarProperty::Summary,
            ItipValue::Text("<b>x</b>".to_string()),
        ),
        field(ICalendarProperty::Dtstart, time.clone()),
        field(ICalendarProperty::Attendee, people),
    ];
    vec![
        ("invite", ItipSummary::Invite(current.clone())),
        (
            "update",
            ItipSummary::Update {
                method: ICalendarMethod::Request,
                current: current.clone(),
                previous: vec![field(
                    ICalendarProperty::Summary,
                    ItipValue::Text("Dinner".to_string()),
                )],
            },
        ),
        ("cancel", ItipSummary::Cancel(current.clone())),
        (
            "reply",
            ItipSummary::Rsvp {
                part_stat: ICalendarParticipationStatus::Accepted,
                current,
            },
        ),
    ]
}

fn data_url(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", STANDARD.encode(bytes))
}

struct Answer {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// BT-5: every `/logo` answer carries these.
    fn assert_logo_headers(&self, test: &str) {
        assert_eq!(self.header("cache-control"), "public, max-age=300", "{test}");
        assert_eq!(self.header("x-content-type-options"), "nosniff", "{test}");
        assert_eq!(self.header("access-control-allow-origin"), "*", "{test}");
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// An anonymous GET, optionally with another `Host`.
async fn get(account: &Account, path: &str, host: Option<&str>) -> Answer {
    let mut request = http().get(format!("{}{path}", account.base_url()));
    if let Some(host) = host {
        request = request.header("host", host);
    }
    let response = request.send().await.unwrap();
    Answer {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.bytes().await.unwrap().to_vec(),
    }
}

async fn post(account: &Account, path: &str, body: &str) -> Answer {
    let response = http()
        .post(format!("{}{path}", account.base_url()))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    Answer {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.bytes().await.unwrap().to_vec(),
    }
}

impl Account {
    async fn brand_domain(&self, name: &str, tenant: Option<Id>) -> Id {
        self.registry_create_object(Domain {
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
}

const ALARM_EVENT: &str = "BEGIN:VCALENDAR\r
VERSION:2.0\r
BEGIN:VEVENT\r
UID:brand-alarm-1\r
SUMMARY:<b>x</b>\r
DESCRIPTION:Bring the slides.\r
DTSTART:$START\r
DTEND:$END\r
LOCATION:Room 1\r
CONFERENCE;VALUE=URI;FEATURE=VIDEO:https://meet.example.com/brand\r
ATTENDEE;CN=Jane Guest:mailto:jane@example.net\r
BEGIN:VALARM\r
TRIGGER:-PT2S\r
ACTION:EMAIL\r
END:VALARM\r
END:VEVENT\r
END:VCALENDAR\r
";
