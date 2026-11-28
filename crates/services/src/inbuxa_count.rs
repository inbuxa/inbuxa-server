/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The opt-in count's task (count spec, CNT-2 to CNT-7, CNT-11). Every node
//! runs it; only the node holding the task scheduler's lease sends, and the
//! install ID lives in the stored settings, so a cluster is counted once.
//!
//! Off, it does nothing on the network: no client is built, nothing is
//! looked up or connected to. It waits for the settings to change, reading
//! them from the store again each hour for a change made on another node.
//! Recovery mode never starts it (`spawn_services`).

use common::{BuildServer, Inner, Server, manager::singleton_lease::SingletonRole};
use inbuxa_features::count::{self, Forget, Plan};
use reqwest::{Client, ClientBuilder, header::CONTENT_TYPE, redirect};
use std::{sync::Arc, time::Duration};
use store::write::now;

/// CNT-5, CNT-7: no request waits longer than this.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// After a start, wait this long before the first check-in's window opens.
const SETTLE: u64 = 120;

pub fn spawn_count(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let started = now();
        // The install ID being counted, and its next attempt
        let mut current: Option<(String, Plan)> = None;
        loop {
            let server = inner.build_server();

            // CNT-7: the one /forget for each ID turned off on this node
            for forget in count::take_forgets() {
                send_forget(&forget).await;
            }

            match count::get(server.store()).await {
                Ok(settings) => match (settings.enabled, settings.install_id) {
                    (true, Some(id)) => {
                        if current.as_ref().is_none_or(|(known, _)| *known != id) {
                            // CNT-4: within a day of being turned on, or of
                            // this start once it has settled
                            let from = now().max(started + SETTLE);
                            current = Some((id, Plan::first(from, count::random())));
                        }
                    }
                    _ => current = None,
                },
                Err(err) => {
                    trc::error!(err.details("Failed to read the count settings"));
                }
            }

            let wait = match &current {
                Some((_, plan)) => plan.due.saturating_sub(now()).min(count::RECHECK_SECS),
                None => count::RECHECK_SECS,
            };
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                _ = count::CHANGED.notified() => continue,
            }

            let Some((id, plan)) = current.as_mut() else {
                continue;
            };
            if plan.due > now() {
                continue;
            }
            let server = inner.build_server();
            // CNT-6: only the node holding the lease; the others keep time
            if !server.runs_singleton(SingletonRole::TaskScheduler) {
                *plan = plan.after(true, now(), count::random());
                continue;
            }
            // Turned off or replaced since: read again before sending
            let endpoint = match count::get(server.store()).await {
                Ok(settings) if settings.enabled && settings.install_id.as_deref() == Some(id) => {
                    settings.endpoint().to_string()
                }
                _ => continue,
            };
            let sent = send_checkin(&endpoint, id).await;
            if sent {
                record(&server, id).await;
            }
            *plan = plan.after(sent, now(), count::random());
        }
    });
}

async fn record(server: &Server, id: &str) {
    if let Err(err) = count::record_check_in(server.store(), id, count::utc_date(now())).await {
        trc::error!(err.details("Failed to record the count's check-in"));
    }
}

/// CNT-5: no default headers that carry anything, no redirects (the body
/// goes only where the administrator said), and the proxy the environment
/// names, if any.
pub fn client_builder() -> ClientBuilder {
    utils::http::http_client_builder(false)
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(redirect::Policy::none())
}

/// One POST of `body` to `url`; 2xx is success, and the response body is
/// never read. Failures are logged at debug level only: a host with no way
/// out isn't told so every week.
pub async fn post(client: &Client, url: &str, body: String) -> bool {
    match client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            debug_only(url, &format!("status {}", response.status()));
            false
        }
        Err(err) => {
            debug_only(url, &err.to_string());
            false
        }
    }
}

/// `Http(Error)` is logged at debug level.
fn debug_only(url: &str, reason: &str) {
    trc::event!(
        Http(trc::HttpEvent::Error),
        Details = "Count request failed",
        Url = url.to_string(),
        Reason = reason.to_string(),
    );
}

/// CNT-5: `POST {endpoint}/checkin` with `{"id","version"}`.
async fn send_checkin(endpoint: &str, id: &str) -> bool {
    match client_builder().build() {
        Ok(client) => {
            post(
                &client,
                &count::url(endpoint, "checkin"),
                count::checkin_body(id),
            )
            .await
        }
        Err(err) => {
            debug_only(endpoint, &err.to_string());
            false
        }
    }
}

/// CNT-7: `POST {endpoint}/forget` with `{"id"}`, once, whatever happens.
async fn send_forget(forget: &Forget) {
    if let Ok(client) = client_builder().build() {
        post(
            &client,
            &count::url(&forget.endpoint, "forget"),
            count::forget_body(&forget.id),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// One request read off a local listener, answered with `status`.
    async fn serve_once(status: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            stream
                .write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\n\r\nok").as_bytes())
                .await
                .unwrap();
            String::from_utf8(raw).unwrap()
        });
        (format!("http://{addr}/count/v1"), handle)
    }

    fn client() -> Client {
        // The test's own listener, whatever proxy the environment names
        client_builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn a_checkin_is_one_post_of_id_and_version() {
        let (endpoint, request) = serve_once("204 No Content").await;
        let id = count::new_install_id();
        assert!(
            post(
                &client(),
                &count::url(&endpoint, "checkin"),
                count::checkin_body(&id)
            )
            .await
        );
        let request = request.await.unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        let mut lines = head.lines();
        assert_eq!(lines.next(), Some("POST /count/v1/checkin HTTP/1.1"));
        let mut names: Vec<String> = lines
            .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
            .collect();
        names.sort();
        // Nothing else that could carry data: no user agent, no cookie.
        // Accept-Encoding comes with the compression the workspace builds
        // reqwest with, and says nothing about the server.
        names.retain(|name| name != "accept-encoding");
        assert_eq!(names, ["accept", "content-length", "content-type", "host"]);
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json")
        );
        assert_eq!(
            body,
            format!(r#"{{"id":"{id}","version":"{}"}}"#, count::VERSION)
        );
    }

    #[tokio::test]
    async fn a_forget_carries_only_the_id() {
        let (endpoint, request) = serve_once("200 OK").await;
        assert!(
            post(
                &client(),
                &count::url(&endpoint, "forget"),
                count::forget_body("3f2c5a9e-1b7d-4c0a-9e3f-5d2b8a6c4e1f")
            )
            .await
        );
        let request = request.await.unwrap();
        assert!(request.starts_with("POST /count/v1/forget HTTP/1.1\r\n"));
        assert!(request.ends_with(r#"{"id":"3f2c5a9e-1b7d-4c0a-9e3f-5d2b8a6c4e1f"}"#));
    }

    #[tokio::test]
    async fn not_2xx_and_no_answer_are_failures() {
        let (endpoint, request) = serve_once("500 Internal Server Error").await;
        assert!(!post(&client(), &count::url(&endpoint, "checkin"), "{}".into()).await);
        request.await.unwrap();
        // A redirect isn't followed: the body goes only where it was told
        let (endpoint, request) = serve_once("302 Found\r\nlocation: http://127.0.0.1:9/").await;
        assert!(!post(&client(), &count::url(&endpoint, "checkin"), "{}".into()).await);
        request.await.unwrap();
        // Nothing listening
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        assert!(!post(&client(), &format!("http://{addr}/checkin"), "{}".into()).await);
    }
}
