/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use hyper::Method;
use reqwest::header::HeaderMap;
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

pub struct HttpRequest {
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct HttpResponseFull {
    pub status: reqwest::StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl HttpResponseFull {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn rate_limit_policy(&self) -> Option<&str> {
        self.header("RateLimit-Policy")
    }

    pub fn rate_limit(&self) -> Option<&str> {
        self.header("RateLimit")
    }

    pub fn retry_after(&self) -> Option<u64> {
        self.header("Retry-After").and_then(|v| v.parse().ok())
    }
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self {
            port: 8899,
            username: None,
            password: None,
        }
    }
}

impl HttpRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_credentials(port: u16, username: &str, password: &str) -> Self {
        Self {
            port,
            username: Some(username.to_string()),
            password: Some(password.to_string()),
        }
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        self.request_raw(
            Method::POST,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<T>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn patch<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        self.request_raw(
            Method::PATCH,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<T>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn delete<T: DeserializeOwned>(&self, query: &str) -> Result<T, String> {
        self.request_raw(Method::DELETE, query, None)
            .await
            .map(|result| {
                serde_json::from_str::<T>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
            })
    }

    pub async fn get<T: DeserializeOwned>(&self, query: &str) -> Result<T, String> {
        self.request_raw(Method::GET, query, None)
            .await
            .map(|result| {
                serde_json::from_str::<T>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
            })
    }
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        query: &str,
    ) -> Result<T, String> {
        self.request_raw(method, query, None).await.map(|result| {
            serde_json::from_str::<T>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn send_full(
        &self,
        method: Method,
        query: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> HttpResponseFull {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(method, format!("https://127.0.0.1:{}{query}", self.port));

        if let Some(body) = body {
            request = request.body(body);
        }

        if let Some(ct) = content_type {
            request = request.header(hyper::header::CONTENT_TYPE, ct);
        }

        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await.expect("HTTP request failed");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();
        HttpResponseFull {
            status,
            headers,
            body,
        }
    }

    async fn request_raw(
        &self,
        method: Method,
        query: &str,
        body: Option<String>,
    ) -> Result<String, String> {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(method, format!("https://127.0.0.1:{}{query}", self.port));

        // inbuxa: every body here is JSON, and the sign-in routes take no
        // other type
        if let Some(body) = body {
            request = request
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body);
        }

        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request = request.basic_auth(username, Some(password));
        }

        request
            .send()
            .await
            .map_err(|err| err.to_string())?
            .bytes()
            .await
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(|err| err.to_string())
    }
}

/// inbuxa: a TLS connection to the test HTTP listener, for requests no HTTP
/// client sends: a head over the server's limits, a body that stops.
pub async fn raw_https_connect() -> std::io::Result<TlsStream<TcpStream>> {
    utils::tls::build_tls_connector(true)
        .unwrap()
        .connect(
            rustls_pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            TcpStream::connect("127.0.0.1:8899").await?,
        )
        .await
}

/// inbuxa: the status code of the HTTP response that arrives on `stream`
/// within `wait`, or None when none does
pub async fn read_http_status(
    stream: &mut (impl AsyncRead + Unpin),
    wait: Duration,
) -> Option<u16> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    tokio::time::timeout(wait, async {
        while !head.ends_with(b"\r\n") && head.len() < 1024 {
            match stream.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => break,
            }
        }
    })
    .await
    .ok()?;
    std::str::from_utf8(&head)
        .ok()?
        .strip_prefix("HTTP/1.1 ")?
        .get(..3)?
        .parse()
        .ok()
}
