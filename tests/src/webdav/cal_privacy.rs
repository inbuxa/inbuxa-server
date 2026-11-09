/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A sharee of a calendar reads over CalDAV what JMAP shows it: the time only
//! of a private or confidential event, and only the owners and itself among
//! the attendees of an event that hides them.

use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use groupware::DavResourceName;
use hyper::StatusCode;
use jmap_proto::{object::calendar::CalendarProperty, request::method::MethodObject};
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running CalDAV sharee privacy tests...");
    let bill = test.account("bill@example.com");
    let owner_client = bill.webdav_client();
    let sharee_client = test.account("john@example.com").webdav_client();
    let cal_base = DavResourceName::Cal.base_path();
    let sharee_principal = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let owner_calendar = format!("{cal_base}/bill%40example.com/privacy-shared/");
    let sharee_calendar = format!("{cal_base}/john%40example.com/default/");
    let private_href = format!("{owner_calendar}private.ics");
    let confidential_href = format!("{owner_calendar}confidential.ics");
    let hidden_href = format!("{owner_calendar}hidden.ics");

    owner_client
        .mkcol(
            "MKCALENDAR",
            &owner_calendar,
            [],
            [("D:displayname", "Privacy shared")],
        )
        .await
        .with_status(StatusCode::CREATED);
    for (href, ics) in [
        (&private_href, PRIVATE_ICS),
        (&confidential_href, CONFIDENTIAL_ICS),
        (&hidden_href, HIDDEN_ICS),
    ] {
        owner_client
            .request("PUT", href, ics.replace('\n', "\r\n"))
            .await
            .with_status(StatusCode::CREATED);
    }

    // The attendees of the third event are hidden (a JMAP-only setting)
    let response = bill
        .jmap_get(
            MethodObject::CalendarEvent,
            ["id", "uid"],
            Vec::<&str>::new(),
        )
        .await;
    let hidden_id = response
        .list()
        .iter()
        .find(|event| event.text_field("uid") == "privacy-hidden@example.com")
        .expect("hidden attendees event")
        .id()
        .to_string();
    bill.jmap_update(
        MethodObject::CalendarEvent,
        [(&hidden_id, json!({"hideAttendees": true}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&hidden_id);

    // The owner sees everything
    for (href, expect) in [
        (&private_href, "Dentist appointment"),
        (&confidential_href, "Performance review"),
        (&hidden_href, "guest@remote.org"),
    ] {
        let body = owner_client
            .request("GET", href, "")
            .await
            .with_status(StatusCode::OK)
            .expect_body()
            .to_string();
        assert!(body.contains(expect), "owner lost {expect}: {body}");
    }

    // Share the calendar for reading
    owner_client
        .acl(&owner_calendar, sharee_principal.as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);

    // Every way calendar data reaches the sharee: GET, multiget, a
    // calendar-query, a PROPFIND and a sync-collection
    let mut bodies = Vec::new();
    for href in [&private_href, &confidential_href, &hidden_href] {
        bodies.push((
            format!("GET {href}"),
            sharee_client
                .request("GET", href, "")
                .await
                .with_status(StatusCode::OK)
                .expect_body()
                .to_string(),
        ));
    }
    bodies.push((
        "calendar-multiget".to_string(),
        sharee_client
            .request(
                "REPORT",
                &owner_calendar,
                MULTIGET.replace(
                    "$HREFS",
                    &[&private_href, &confidential_href, &hidden_href]
                        .iter()
                        .map(|href| format!("<D:href>{href}</D:href>"))
                        .collect::<String>(),
                ),
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .expect_body()
            .to_string(),
    ));
    bodies.push((
        "calendar-query".to_string(),
        sharee_client
            .request("REPORT", &owner_calendar, QUERY_ANY_VEVENT)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_href_count(3)
            .expect_body()
            .to_string(),
    ));
    bodies.push((
        "PROPFIND".to_string(),
        sharee_client
            .request_with_headers(
                "PROPFIND",
                &owner_calendar,
                [("depth", "1")],
                PROPFIND_CALENDAR_DATA,
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .expect_body()
            .to_string(),
    ));
    bodies.push((
        "sync-collection".to_string(),
        sharee_client
            .request("REPORT", &owner_calendar, SYNC_CALENDAR_DATA)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .expect_body()
            .to_string(),
    ));
    for (source, body) in &bodies {
        for hidden in [
            "Dentist appointment",
            "Room 4",
            "Main street clinic",
            "Reminder text",
            "VALARM",
            "Performance review",
            "guest@remote.org",
        ] {
            assert!(
                !body.contains(hidden),
                "{source} showed the sharee {hidden:?}: {body}"
            );
        }
    }
    for (source, body) in &bodies[..3] {
        assert!(
            body.contains("DTSTART:20200203T100000Z"),
            "{source} lost the event's time: {body}"
        );
    }
    let body = &bodies[2].1;
    assert!(
        body.contains("Board meeting") && body.contains("jdoe@example.com"),
        "the sharee lost the visible parts of the hidden attendees event: {body}"
    );

    // Matching on what the sharee can't see finds nothing
    let body = sharee_client
        .request("REPORT", &owner_calendar, QUERY_SUMMARY_DENTIST)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .expect_body()
        .to_string();
    assert!(
        !body.contains("private.ics"),
        "a sharee matched a private event's title: {body}"
    );

    // A private event can't be copied out; a copy of the hidden attendees
    // event keeps them hidden, and so does a copy of the whole calendar
    sharee_client
        .request_with_headers(
            "COPY",
            &private_href,
            [(
                "destination",
                format!("{sharee_calendar}private-copy.ics").as_str(),
            )],
            "",
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    let hidden_copy = format!("{sharee_calendar}hidden-copy.ics");
    sharee_client
        .request_with_headers(
            "COPY",
            &hidden_href,
            [("destination", hidden_copy.as_str())],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);
    let body = sharee_client
        .request("GET", &hidden_copy, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(
        !body.contains("guest@remote.org") && body.contains("Board meeting"),
        "a copy showed the sharee a hidden attendee: {body}"
    );
    sharee_client
        .request("DELETE", &hidden_copy, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    // A copy of a calendar skips events whose calendar's id is the new
    // calendar's (a separate bug), so it is copied over one of the sharee's
    // with another id
    let shared_calendar_id = calendar_id(bill, "Privacy shared").await;
    let john = test.account("john@example.com");
    let mut sharee_copies = Vec::new();
    let copy_target = loop {
        let name = format!("privacy-copy-{}", sharee_copies.len());
        let href = format!("{cal_base}/john%40example.com/{name}/");
        sharee_client
            .mkcol("MKCALENDAR", &href, [], [("D:displayname", name.as_str())])
            .await
            .with_status(StatusCode::CREATED);
        sharee_copies.push(href.clone());
        if calendar_id(john, &name).await != shared_calendar_id {
            break href;
        }
    };
    sharee_client
        .request_with_headers(
            "COPY",
            &owner_calendar,
            [("destination", copy_target.as_str()), ("overwrite", "T")],
            "",
        )
        .await
        .with_status(StatusCode::FORBIDDEN);
    for href in &sharee_copies {
        sharee_client
            .request("DELETE", href, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    // A sharee that may change the events sees every attendee, but still the
    // time only of a private event, and can't write that back over it
    owner_client
        .acl(
            &owner_calendar,
            sharee_principal.as_str(),
            ["read", "write-content"],
        )
        .await
        .with_status(StatusCode::OK);
    let body = sharee_client
        .request("GET", &hidden_href, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(
        body.contains("guest@remote.org"),
        "a sharee that may change the event lost its attendees: {body}"
    );
    let redacted = sharee_client
        .request("GET", &private_href, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(
        !redacted.contains("Dentist appointment"),
        "a writer saw a private event's title: {redacted}"
    );
    sharee_client
        .request("PUT", &private_href, &redacted)
        .await
        .with_status(StatusCode::FORBIDDEN);
    let body = owner_client
        .request("GET", &private_href, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .to_string();
    assert!(
        body.contains("Dentist appointment") && body.contains("Room 4"),
        "a sharee's write wiped a private event: {body}"
    );

    owner_client
        .request("DELETE", &owner_calendar, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    sharee_client.delete_default_containers().await;
    owner_client.delete_default_containers().await;
    test.assert_is_empty().await;
}

async fn calendar_id(account: &Account, name: &str) -> String {
    account
        .jmap_get(
            MethodObject::Calendar,
            [CalendarProperty::Id, CalendarProperty::Name],
            Vec::<&str>::new(),
        )
        .await
        .list()
        .iter()
        .find(|calendar| calendar.text_field("name") == name)
        .unwrap_or_else(|| panic!("calendar {name}"))
        .id()
        .to_string()
}

const PRIVATE_ICS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Privacy//EN
BEGIN:VEVENT
UID:privacy-private@example.com
DTSTAMP:20200101T000000Z
DTSTART:20200203T100000Z
DTEND:20200203T110000Z
SUMMARY:Dentist appointment
DESCRIPTION:Room 4, bring the files
LOCATION:Main street clinic
CLASS:PRIVATE
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Reminder text
TRIGGER:-PT15M
END:VALARM
END:VEVENT
END:VCALENDAR
";

const CONFIDENTIAL_ICS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Privacy//EN
BEGIN:VEVENT
UID:privacy-confidential@example.com
DTSTAMP:20200101T000000Z
DTSTART:20200203T100000Z
DTEND:20200203T110000Z
SUMMARY:Performance review
CLASS:CONFIDENTIAL
END:VEVENT
END:VCALENDAR
";

const HIDDEN_ICS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Privacy//EN
BEGIN:VEVENT
UID:privacy-hidden@example.com
DTSTAMP:20200101T000000Z
DTSTART:20200203T100000Z
DTEND:20200203T110000Z
SUMMARY:Board meeting
ORGANIZER:mailto:organizer@remote.org
ATTENDEE;PARTSTAT=ACCEPTED:mailto:organizer@remote.org
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:jdoe@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:guest@remote.org
END:VEVENT
END:VCALENDAR
";

const MULTIGET: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
  $HREFS
</C:calendar-multiget>"#;

const QUERY_ANY_VEVENT: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT"/>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#;

const QUERY_SUMMARY_DENTIST: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/></D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:prop-filter name="SUMMARY">
          <C:text-match collation="i;ascii-casemap">Dentist</C:text-match>
        </C:prop-filter>
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#;

const PROPFIND_CALENDAR_DATA: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
</D:propfind>"#;

const SYNC_CALENDAR_DATA: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:sync-collection xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:sync-token/>
  <D:sync-level>1</D:sync-level>
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
</D:sync-collection>"#;
