/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: a JMAP request over maxSizeRequest is refused once that much has
// arrived, over HTTP and over a WebSocket, not after the server has held
// whatever the client sent. These accounts hold UnlimitedUploads, which
// used to lift the HTTP limit altogether.

use crate::utils::{
    http::{raw_https_connect, read_http_status},
    server::TestServer,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn test(test: &TestServer) {
    println!("Running JMAP request size limit tests...");

    let account = test.account("jdoe@example.com");
    let max_size = account
        .jmap_client()
        .await
        .session()
        .core_capabilities()
        .unwrap()
        .max_size_request();
    let authorization = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", account.name(), account.secret()))
    );

    // POST /jmap: the body says it is three times the limit, and stops
    // arriving one byte past it. The answer comes then.
    let mut stream = raw_https_connect().await.unwrap();
    stream
        .write_all(
            format!(
                concat!(
                    "POST /jmap/ HTTP/1.1\r\nHost: localhost\r\n",
                    "Authorization: {}\r\nContent-Type: application/json\r\n",
                    "Content-Length: {}\r\n\r\n"
                ),
                authorization,
                max_size * 3
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    // One byte past the limit, all of which the server reads
    let chunk = vec![b' '; 64 * 1024];
    let mut left = max_size + 1;
    while left > 0 {
        let len = left.min(chunk.len());
        stream.write_all(&chunk[..len]).await.unwrap();
        left -= len;
    }
    stream.flush().await.unwrap();
    assert_eq!(
        read_http_status(&mut stream, Duration::from_secs(10)).await,
        Some(400),
        "POST /jmap past maxSizeRequest ({max_size}) wasn't refused once the limit was read"
    );

    // WebSocket: a frame that announces one byte more than the limit is
    // refused with close code 1009 before its payload is read
    let mut stream = raw_https_connect().await.unwrap();
    stream
        .write_all(
            format!(
                concat!(
                    "GET /jmap/ws HTTP/1.1\r\nHost: localhost\r\n",
                    "Authorization: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
                    "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "Sec-WebSocket-Protocol: jmap\r\n\r\n"
                ),
                authorization
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        read_http_status(&mut stream, Duration::from_secs(5)).await,
        Some(101)
    );
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let mut frame = vec![0x81, 0x80 | 127];
    frame.extend_from_slice(&(max_size as u64 + 1).to_be_bytes());
    frame.extend_from_slice(&[1, 2, 3, 4]);
    stream.write_all(&frame).await.unwrap();
    stream.flush().await.unwrap();
    let mut close = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut close))
        .await
        .expect("a WebSocket message past maxSizeRequest wasn't refused on its header")
        .unwrap();
    assert_eq!(close[0], 0x88, "expected a close frame: {close:?}");
    assert_eq!(
        u16::from_be_bytes([close[2], close[3]]),
        1009,
        "expected close code 1009 (message too big): {close:?}"
    );
}
