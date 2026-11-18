/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! How long an HTTP client may keep a connection without sending or
//! reading.
//!
//! hyper times only the request head. A body that stops arriving is cut by
//! `http_proto::request::fetch_body` after `BODY_IDLE_TIMEOUT`, and an
//! answer the client stops reading by [`WriteDeadline`] after
//! [`WRITE_STALL_TIMEOUT`]. Both count from the last progress, so a slow
//! upload or download that keeps moving is never cut, and a connection that
//! is only waiting (an event stream, a WebSocket, keep-alive) is not either.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};

/// The longest a write to the client may make no progress before the
/// connection is dropped.
pub const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// A connection whose writes fail once one has been waiting on the client
/// for longer than the timeout. Reads pass through untimed.
pub struct WriteDeadline<S> {
    inner: S,
    timeout: Duration,
    stalled: Option<Pin<Box<Sleep>>>,
}

impl<S> WriteDeadline<S> {
    pub fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            stalled: None,
        }
    }

    fn check<T>(
        &mut self,
        cx: &mut Context<'_>,
        result: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if result.is_ready() {
            self.stalled = None;
            return result;
        }
        let timeout = self.timeout;
        let stalled = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match stalled.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client stopped reading",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.check(cx, result)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.check(cx, result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.check(cx, result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.check(cx, result)
    }
}

#[cfg(test)]
mod tests {
    use crate::request::serve_http1;
    use http_body_util::Full;
    use hyper::{Response, body::Bytes, service::service_fn};
    use std::{convert::Infallible, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A request that declares a body and stops sending it gets an answer
    // and the connection ends, instead of holding the connection for good
    #[tokio::test(start_paused = true)]
    async fn stalled_request_body_is_cut_off() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve_http1(
            server,
            service_fn(|mut req| async move {
                let body = http_proto::request::fetch_body(&mut req, 1024 * 1024, 0).await;
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(if body.is_some() { 200 } else { 408 })
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
            }),
        ));
        client
            .write_all(
                b"POST /api/x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\nabc",
            )
            .await
            .unwrap();
        let mut reply = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(120), client.read(&mut reply)).await;
        let Ok(Ok(read)) = read else {
            panic!("no answer 120 s after the body stopped: {read:?}");
        };
        assert!(
            reply[..read].starts_with(b"HTTP/1.1 408"),
            "{}",
            String::from_utf8_lossy(&reply[..read])
        );
    }

    // A client that never reads its answer is disconnected once the answer
    // stops moving
    #[tokio::test(start_paused = true)]
    async fn client_that_never_reads_is_cut_off() {
        let (mut client, server) = tokio::io::duplex(4096);
        let connection = tokio::spawn(serve_http1(
            server,
            service_fn(|_req| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![
                    b'x';
                    1024 * 1024
                ]))))
            }),
        ));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(120), connection).await;
        assert!(
            matches!(result, Ok(Ok(Err(_)))),
            "connection still open 120 s after the client stopped reading: {result:?}"
        );
        drop(client);
    }
}
