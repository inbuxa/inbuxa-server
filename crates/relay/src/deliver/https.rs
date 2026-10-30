/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The one HTTPS request the relay makes: an MTA-STS policy (RFC 8461
//! §3.3). WebPKI checked, no redirects, small.

use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn get(host: &str, path: &str, max: usize) -> Result<Vec<u8>, String> {
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, 443)))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let tls = TlsConnector::from(super::tls::verified())
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let request = Request::get(path)
        .header("Host", host)
        .header(
            "User-Agent",
            concat!("inbuxa-relay/", env!("CARGO_PKG_VERSION")),
        )
        .body(Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| e.to_string())?;
    // RFC 8461 §3.3: a redirect is not followed.
    if response.status() != StatusCode::OK {
        return Err(format!("the server answered {}", response.status()));
    }
    Limited::new(response.into_body(), max)
        .collect()
        .await
        .map(|body| body.to_bytes().to_vec())
        .map_err(|_| "the policy is too large".to_string())
}
