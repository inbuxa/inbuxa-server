/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{LONG_1Y_SLUMBER, config::telemetry::WebhookTracer};
use aws_lc_rs::hmac;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use store::write::now;
use tokio::sync::mpsc;
use trc::{
    Event, EventDetails, ServerEvent, TelemetryEvent,
    ipc::subscriber::{EventBatch, SubscriberBuilder},
    serializers::json::JsonEventSerializer,
};

pub(crate) fn spawn_webhook_tracer(builder: SubscriberBuilder, settings: WebhookTracer) {
    let (tx, mut rx) = builder.register();
    // inbuxa: failed deliveries come back through a weak sender, so the
    // channel closes when the collector drops this webhook (removed, or
    // replaced after a settings change) and the task ends; upstream held a
    // sender here and the task outlived its subscription
    let tx = tx.downgrade();
    tokio::spawn(async move {
        let settings = Arc::new(settings);
        let mut wakeup_time = LONG_1Y_SLUMBER;
        let discard_after = settings.discard_after.as_secs();
        let mut pending_events = Vec::new();
        let mut next_delivery = Instant::now();
        let in_flight = Arc::new(AtomicBool::new(false));

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(wakeup_time, rx.recv()).await;
            let now = now();

            match event_or_timeout {
                Ok(Some(events)) => {
                    let mut discard_count = 0;
                    for event in events {
                        if now.saturating_sub(event.inner.timestamp) < discard_after {
                            pending_events.push(event)
                        } else {
                            discard_count += 1;
                        }
                    }

                    if discard_count > 0 {
                        trc::event!(
                            Telemetry(TelemetryEvent::WebhookError),
                            Details = "Discarded stale events",
                            Total = discard_count
                        );
                    }
                }
                Ok(None) => {
                    // inbuxa: deliver what is pending rather than drop it
                    if !pending_events.is_empty() {
                        spawn_webhook_handler(
                            settings.clone(),
                            in_flight.clone(),
                            std::mem::take(&mut pending_events),
                            tx.clone(),
                        );
                    }
                    break;
                }
                Err(_) => (),
            }

            // Process events
            let mut next_retry = None;
            let now = Instant::now();
            if next_delivery <= now {
                if !pending_events.is_empty() {
                    next_delivery = now + settings.throttle;
                    if !in_flight.load(Ordering::Relaxed) {
                        spawn_webhook_handler(
                            settings.clone(),
                            in_flight.clone(),
                            std::mem::take(&mut pending_events),
                            tx.clone(),
                        );
                    }
                }
            } else if !pending_events.is_empty() {
                // Retry later
                let this_retry = next_delivery - now;
                match next_retry {
                    Some(next_retry) if this_retry >= next_retry => {}
                    _ => {
                        next_retry = Some(this_retry);
                    }
                }
            }
            wakeup_time = next_retry.unwrap_or(LONG_1Y_SLUMBER);
        }
    });
}

#[derive(Serialize)]
struct EventWrapper {
    events: JsonEventSerializer<Vec<Arc<Event<EventDetails>>>>,
}

fn spawn_webhook_handler(
    settings: Arc<WebhookTracer>,
    in_flight: Arc<AtomicBool>,
    events: EventBatch,
    webhook_tx: mpsc::WeakSender<EventBatch>,
) {
    tokio::spawn(async move {
        in_flight.store(true, Ordering::Relaxed);
        let wrapper = EventWrapper {
            events: JsonEventSerializer::new(events).with_id().with_spans(),
        };

        if let Err(err) = post_webhook_events(&settings, &wrapper).await {
            trc::event!(Telemetry(TelemetryEvent::WebhookError), Details = err);

            let sent = match webhook_tx.upgrade() {
                Some(webhook_tx) => webhook_tx.send(wrapper.events.into_inner()).await.is_ok(),
                None => false,
            };
            if !sent {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Failed to send failed webhook events back to main thread",
                    CausedBy = trc::location!()
                );
            }
        }

        in_flight.store(false, Ordering::Relaxed);
    });
}

async fn post_webhook_events(
    settings: &WebhookTracer,
    events: &EventWrapper,
) -> Result<(), String> {
    // Serialize body
    let body = serde_json::to_string(events)
        .map_err(|err| format!("Failed to serialize events: {}", err))?;

    // Add HMAC-SHA256 signature
    let mut headers = settings.headers.clone();
    sign(&mut headers, &settings.key, &body);

    // Send request
    let response = settings
        .client
        .post(&settings.url)
        .timeout(settings.timeout)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Webhook request to {} failed: {err}", settings.url))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Webhook request to {} failed with code {}: {}",
            settings.url,
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}

/// Adds the HMAC-SHA256 `X-Signature` a receiver checks, when the webhook has a key.
fn sign(headers: &mut hyper::HeaderMap, key: &str, body: &str) {
    if !key.is_empty() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
        let tag = hmac::sign(&key, body.as_bytes());

        headers.insert(
            "X-Signature",
            STANDARD.encode(tag.as_ref()).parse().unwrap(),
        );
    }
}

/// inbuxa: "Send test" for a saved webhook (settings-reorg, Webhooks). One
/// sample event, sent the way a real batch is: the same URL, headers, sign-in,
/// signature, timeout and certificate checks. The event's type,
/// `webhook.test`, is none the server raises, and an `X-Inbuxa-Test` header
/// marks it, so a receiver can tell it apart. Answers the HTTP status, or why
/// nothing came back.
pub async fn send_test(hook: &registry::schema::structs::WebHook) -> Result<u16, String> {
    let mut headers = hook
        .http_auth
        .build_headers(hook.http_headers.clone(), "application/json".into())
        .await
        .map_err(|err| format!("Unable to build HTTP headers: {err}"))?;
    let key = hook
        .signature_key
        .secret()
        .await
        .map_err(|err| format!("Unable to retrieve signature key: {err}"))?
        .unwrap_or_default()
        .into_owned();

    let created = now();
    let body = serde_json::json!({
        "events": [{
            "id": format!("test-{created}"),
            "createdAt": mail_parser::DateTime::from_timestamp(created as i64).to_rfc3339(),
            "type": "webhook.test",
            "data": { "details": "A test from inbuxa Admin. Nothing happened on the server." },
        }]
    })
    .to_string();
    sign(&mut headers, &key, &body);
    headers.insert("X-Inbuxa-Test", "true".parse().unwrap());

    let response = utils::http::http_client_builder(hook.allow_invalid_certs)
        .build()
        .map_err(|err| format!("Unable to build an HTTP client: {err}"))?
        .post(&hook.url)
        .timeout(hook.timeout.into_inner())
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Webhook request to {} failed: {err}", hook.url))?;
    Ok(response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs::{SecretKeyOptional, SecretKeyValue, WebHook};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One request in, the given status out; hands back what was received.
    async fn receiver(status: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + length || n == 0 {
                        break;
                    }
                }
            }
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });
        (url, task)
    }

    #[tokio::test]
    async fn send_test_signs_and_marks_the_sample() {
        let (url, task) = receiver("204 No Content").await;
        let hook = WebHook {
            url,
            enable: false,
            signature_key: SecretKeyOptional::Value(SecretKeyValue { secret: "k".into() }),
            ..Default::default()
        };
        assert_eq!(send_test(&hook).await, Ok(204));

        let request = task.await.unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        let head = head.to_ascii_lowercase();
        assert!(head.contains("x-inbuxa-test: true"), "{head}");
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["events"][0]["type"], "webhook.test");
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, b"k"), body.as_bytes());
        assert!(
            head.contains(&format!(
                "x-signature: {}",
                STANDARD.encode(tag.as_ref()).to_ascii_lowercase()
            )),
            "{head}"
        );
    }

    #[tokio::test]
    async fn send_test_reports_what_came_back() {
        let (url, _task) = receiver("403 Forbidden").await;
        let hook = WebHook {
            url,
            ..Default::default()
        };
        assert_eq!(send_test(&hook).await, Ok(403));

        let hook = WebHook {
            url: "http://127.0.0.1:9/hook".into(),
            ..Default::default()
        };
        assert!(send_test(&hook).await.unwrap_err().contains("failed"));
    }
}
