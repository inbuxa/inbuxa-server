/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{LONG_1Y_SLUMBER, config::telemetry::WebhookTracer};
use aws_lc_rs::hmac;
use bytes::Bytes;
use compact_str::{CompactString, format_compact};
use encodify::base64::STANDARD;
use reqwest::header::HeaderValue;
use std::{sync::Arc, time::Instant};
use store::write::now;
use tokio::task::JoinHandle;
use trc::{
    TelemetryEvent,
    ipc::subscriber::{EventBatch, SubscriberBuilder},
    serializers::json::JsonEventSerializer,
};

struct Payload {
    body: Bytes,
    signature: Option<HeaderValue>,
    events: EventBatch,
    oldest_event: u64,
}

enum Delivery {
    Events(EventBatch),
    Retry(Payload),
}

const MAX_PENDING_EVENTS: usize = 1 << 16;

type DeliveryResult = Result<(), (Option<Box<Payload>>, CompactString)>;

pub(crate) fn spawn_webhook_tracer(builder: SubscriberBuilder, settings: WebhookTracer) {
    let (_, mut rx, _) = builder.register();
    tokio::spawn(async move {
        let settings = Arc::new(settings);
        let discard_after = settings.discard_after.as_secs();
        let mut pending_events = Vec::new();
        let mut failed_payload = None;
        let mut next_delivery = Instant::now();
        let mut in_flight: Option<JoinHandle<DeliveryResult>> = None;
        let mut in_flight_events = 0;
        let mut is_failing = false;
        let mut last_error = CompactString::const_new("");
        let mut overflowed_events = 0;

        loop {
            let has_work = !pending_events.is_empty() || failed_payload.is_some();
            let wakeup_time = if has_work && in_flight.is_none() {
                next_delivery.saturating_duration_since(Instant::now())
            } else {
                LONG_1Y_SLUMBER
            };

            tokio::select! {
                events = rx.recv() => match events {
                    Some(events) => {
                        let now = now();
                        let mut stale = 0;
                        for event in events {
                            if now.saturating_sub(event.inner.timestamp) >= discard_after {
                                stale += 1;
                            } else if pending_events.len() < MAX_PENDING_EVENTS {
                                pending_events.push(event);
                            } else {
                                overflowed_events += 1;
                            }
                        }
                        report_discarded(stale);
                    }
                    None => {
                        // inbuxa: deliver what is pending rather than drop it
                        if !pending_events.is_empty() {
                            drop(spawn_webhook_handler(
                                settings.clone(),
                                Delivery::Events(std::mem::take(&mut pending_events)),
                            ));
                        }
                        break;
                    }
                },
                result = wait_for_delivery(&mut in_flight, in_flight_events) => {
                    match result {
                        Ok(()) => {
                            if is_failing {
                                is_failing = false;
                                last_error = CompactString::const_new("");
                                trc::event!(
                                    Telemetry(TelemetryEvent::WebhookError),
                                    Details = "Resumed webhook deliveries",
                                );
                            }
                        }
                        Err((payload, error)) => {
                            failed_payload = payload.map(|payload| *payload);
                            if !is_failing || last_error != error {
                                is_failing = true;
                                last_error = error.clone();
                                trc::event!(
                                    Telemetry(TelemetryEvent::WebhookError),
                                    Details = error,
                                );
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(wakeup_time) => {}
            }

            if in_flight.is_some() || Instant::now() < next_delivery {
                continue;
            }

            let delivery = if let Some(mut payload) = failed_payload.take() {
                let now = now();
                if now.saturating_sub(payload.oldest_event) < discard_after {
                    Some(Delivery::Retry(payload))
                } else {
                    let expected = payload.events.len();
                    payload
                        .events
                        .retain(|event| now.saturating_sub(event.inner.timestamp) < discard_after);
                    report_discarded(expected - payload.events.len());
                    (!payload.events.is_empty()).then(|| Delivery::Events(payload.events))
                }
            } else if !pending_events.is_empty() {
                let now = now();
                let expected = pending_events.len();
                pending_events
                    .retain(|event| now.saturating_sub(event.inner.timestamp) < discard_after);
                report_discarded(expected - pending_events.len());
                (!pending_events.is_empty())
                    .then(|| Delivery::Events(std::mem::take(&mut pending_events)))
            } else {
                None
            };

            if overflowed_events > 0 {
                trc::event!(
                    Telemetry(TelemetryEvent::WebhookError),
                    Details = "Webhook queue full, discarded events",
                    Total = std::mem::take(&mut overflowed_events),
                );
            }

            if let Some(delivery) = delivery {
                in_flight_events = delivery.num_events();
                next_delivery = Instant::now() + settings.throttle;
                in_flight = Some(spawn_webhook_handler(settings.clone(), delivery));
            }
        }
    });
}

fn report_discarded(discarded: usize) {
    if discarded > 0 {
        trc::event!(
            Telemetry(TelemetryEvent::WebhookError),
            Details = "Discarded stale events",
            Total = discarded
        );
    }
}

async fn wait_for_delivery(
    in_flight: &mut Option<JoinHandle<DeliveryResult>>,
    num_events: usize,
) -> DeliveryResult {
    match in_flight {
        Some(handle) => {
            let result = handle.await;
            *in_flight = None;
            result.unwrap_or_else(|err| {
                Err((
                    None,
                    format_compact!(
                        "Webhook delivery task failed, discarded {num_events} events: {err}"
                    ),
                ))
            })
        }
        None => std::future::pending().await,
    }
}

impl Delivery {
    fn num_events(&self) -> usize {
        match self {
            Delivery::Events(events) => events.len(),
            Delivery::Retry(payload) => payload.events.len(),
        }
    }
}

fn spawn_webhook_handler(
    settings: Arc<WebhookTracer>,
    delivery: Delivery,
) -> JoinHandle<DeliveryResult> {
    tokio::spawn(async move {
        match delivery {
            Delivery::Events(events) => match Payload::build(&settings, events) {
                Ok(payload) => post_webhook_events(&settings, payload).await,
                Err((err, discarded)) => {
                    report_discarded(discarded);
                    Err((None, err))
                }
            },
            Delivery::Retry(payload) => post_webhook_events(&settings, payload).await,
        }
    })
}

impl Payload {
    fn build(settings: &WebhookTracer, events: EventBatch) -> Result<Self, (CompactString, usize)> {
        let oldest_event = events
            .iter()
            .map(|event| event.inner.timestamp)
            .min()
            .unwrap_or_default();
        let num_events = events.len();
        let wrapper = EventWrapper {
            events: JsonEventSerializer::new(events).with_id().with_spans(),
        };
        let body = serde_json::to_vec(&wrapper).map_err(|err| {
            (
                format_compact!("Failed to serialize events: {err}"),
                num_events,
            )
        })?;

        let signature = sign(&settings.key, &body);

        Ok(Payload {
            body: Bytes::from(body),
            signature,
            events: wrapper.events.into_inner(),
            oldest_event,
        })
    }
}

#[derive(serde::Serialize)]
struct EventWrapper {
    events: JsonEventSerializer<EventBatch>,
}

async fn post_webhook_events(settings: &WebhookTracer, payload: Payload) -> DeliveryResult {
    let mut headers = settings.headers.clone();
    if let Some(signature) = &payload.signature {
        headers.insert("X-Signature", signature.clone());
    }

    let error = match settings
        .client
        .post(&settings.url)
        .timeout(settings.timeout)
        .headers(headers)
        .body(payload.body.clone())
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => return Ok(()),
        Ok(response) => format_compact!(
            "Webhook request to {} failed with code {}: {}",
            settings.url,
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ),
        Err(err) => format_compact!("Webhook request to {} failed: {err}", settings.url),
    };

    Err((Some(Box::new(payload)), error))
}

/// The HMAC-SHA256 `X-Signature` a receiver checks, when the webhook has a key.
fn sign(key: &str, body: &[u8]) -> Option<HeaderValue> {
    if !key.is_empty() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
        let tag = hmac::sign(&key, body);
        HeaderValue::try_from(STANDARD.encode(tag.as_ref())).ok()
    } else {
        None
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
    if let Some(signature) = sign(&key, body.as_bytes()) {
        headers.insert("X-Signature", signature);
    }
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
