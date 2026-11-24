/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{server::TestServer, storage::wait_for_tasks};
use common::Server;
use email::cache::MessageCacheFetch;
use hyper::StatusCode;
use mail_parser::{DateTime, MessageParser};
use registry::{
    schema::{enums::TaskType, structs::Task},
    types::EnumImpl,
};
use store::{
    Deserialize, IterateParams, U64_LEN, ValueKey,
    write::{TaskQueueClass, ValueClass, key::DeserializeBigEndian, now},
};

pub async fn test(test: &TestServer) {
    println!("Running calendar e-mail alarms tests...");
    let account = test.account("john@example.com");
    let client = account.webdav_client();
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john%40example.com/default/its-alarming-how-charming-i-feel.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            TEST_ALARM_1.replace(
                "$START",
                &DateTime::from_timestamp(now() as i64 + 5)
                    .to_rfc3339()
                    .replace(['-', ':'], ""),
            ),
        )
        .await
        .with_status(StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    // Check that the alarm was sent
    let messages = test
        .server
        .get_cached_messages(client.account_id)
        .await
        .unwrap();
    assert_eq!(messages.emails.items.len(), 2);

    for (idx, message) in messages.emails.items.iter().enumerate() {
        let contents = test
            .fetch_email(client.account_id, message.document_id)
            .await;

        let message = MessageParser::new().parse(&contents).unwrap();
        let contents = message
            .html_bodies()
            .next()
            .unwrap()
            .text_contents()
            .unwrap();

        if idx == 0 {
            // First alarm does not have a summary or description
            assert!(
                contents.contains("See the pretty girl in that mirror there"),
                "failed for {contents}"
            );
            assert!(
                contents.contains("What mirror where?!"),
                "failed for {contents}"
            );
        } else {
            assert!(
                contents.contains("I feel pretty and witty and gay"),
                "failed for {contents}"
            );
            assert!(
                contents.contains("It&#39;s alarming how charming I feel."),
                "failed for {contents}"
            );
        }
        assert!(
            contents.contains(concat!(
                "/dav/cal/john%40example.com/default/",
                "its-alarming-how-charming-i-feel.ics"
            )),
            "failed for {contents}"
        );

        // The logo is an inline part, so the template must reference it by cid: URI
        let html = message.html_bodies().next().unwrap().contents().to_vec();
        let html = String::from_utf8(html).unwrap();
        assert!(
            html.contains("src=\"cid:logo."),
            "alarm logo must be referenced as a cid: URI: {html}"
        );

        // A conference URI is rendered as a hyperlink
        assert!(
            html.contains("href=\"https://meet.example.com/west-side\""),
            "alarm must link the conference URI: {html}"
        );

        if let Some(out_dir) = super::template_out_dir() {
            let path = out_dir.join(format!("alarm_template_{idx}.html"));
            std::fs::write(&path, &html).expect("Failed to write alarm template to file");
            println!("Alarm template {idx} -> {}", path.display());
        }
    }

    client.delete_default_containers().await;
    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;

    destroyed_account_alarms(test).await;
}

/// inbuxa: #562: destroying an account takes its queued alarms with it.
async fn destroyed_account_alarms(test: &TestServer) {
    println!("Running destroyed account alarm tests...");
    let admin = test.account("admin");
    let account = admin
        .create_user_account(
            "alarmed@example.com",
            "alarmed secret + some more text",
            "Alarmed",
            &["alarmed@example.com"],
            vec![],
        )
        .await;
    let account_id = account.id().document_id();
    account
        .webdav_client()
        .request_with_headers(
            "PUT",
            "/dav/cal/alarmed%40example.com/default/tomorrow.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            TEST_ALARM_1.replace(
                "$START",
                &DateTime::from_timestamp(now() as i64 + 86_400)
                    .to_rfc3339()
                    .replace(['-', ':'], ""),
            ),
        )
        .await
        .with_status(StatusCode::CREATED);
    let (tasks, due) = alarm_rows(&test.server, account_id).await;
    assert!(
        !tasks.is_empty() && !due.is_empty(),
        "the event must queue its alarm: {tasks:?} {due:?}"
    );

    admin.destroy_account(account).await;
    wait_for_tasks(&test.server, true, false).await;
    let (tasks, due) = alarm_rows(&test.server, account_id).await;
    assert_eq!(
        (tasks, due),
        (vec![], vec![]),
        "a destroyed account must leave no alarm in the task queue"
    );
}

/// The ids of the account's queued calendar alarms: from the task rows, and
/// from the due rows that schedule them.
async fn alarm_rows(server: &Server, account_id: u32) -> (Vec<u64>, Vec<u64>) {
    let store = &server.core.storage.data;
    let mut tasks = Vec::new();
    store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: 0 })),
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: u64::MAX })),
            )
            .ascending(),
            |key, value| {
                let task_account_id = match Task::deserialize(value)? {
                    Task::CalendarAlarmEmail(task) => task.account_id,
                    Task::CalendarAlarmNotification(task) => task.account_id,
                    _ => return Ok(true),
                };
                if task_account_id.document_id() == account_id {
                    tasks.push(key.deserialize_be_u64(U64_LEN)?);
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    let mut due = Vec::new();
    store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 1 })),
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: u64::MAX,
                    due: u64::MAX,
                })),
            )
            .ascending(),
            |key, value| {
                let id = key.deserialize_be_u64(U64_LEN)?;
                let is_alarm = value
                    .deserialize_be_u16(0)
                    .ok()
                    .and_then(TaskType::from_id)
                    .is_some_and(|typ| {
                        matches!(
                            typ,
                            TaskType::CalendarAlarmEmail | TaskType::CalendarAlarmNotification
                        )
                    });
                if is_alarm && (id >> 32) as u32 == account_id {
                    due.push(id);
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    (tasks, due)
}

const TEST_ALARM_1: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:See the pretty girl in that mirror there
DESCRIPTION:What mirror where?!
DTSTART:$START
DTEND;TZID=America/New_York:21250221T180000
LOCATION:West Side
CONFERENCE;VALUE=URI;FEATURE=VIDEO:https://meet.example.com/west-side
BEGIN:VALARM
TRIGGER:-P2S
ACTION:EMAIL
ATTENDEE:mailto:john_doe@unknown.com
SUMMARY:I feel pretty and witty and gay
DESCRIPTION:I feel charming, Oh, so charming, It's alarming how charming I feel.
END:VALARM
BEGIN:VALARM
TRIGGER:-P4S
ACTION:EMAIL
END:VALARM
END:VEVENT
END:VCALENDAR
"#;
