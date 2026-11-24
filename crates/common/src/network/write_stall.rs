/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: writes to a mail client (SMTP, IMAP, POP3, ManageSieve) that
//! give up once the client stops reading.
//!
//! A client that stops reading (a zero TCP window) used to hold its session,
//! its slot under the listener's connection limit and its buffers for as
//! long as it liked, before signing in too. As with HTTP's
//! `WRITE_STALL_TIMEOUT`, the clock counts from the last progress: a large
//! answer to a slow client that keeps reading is never cut. The limit is the
//! session's own read timeout, so a client that stops reading holds its
//! session no longer than one that stops sending.

use std::{io, time::Duration};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Writes all of `bytes` and flushes them, failing with `TimedOut` once the
/// client has taken nothing for `stall`.
pub async fn write_all_or_stall<W: AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
    bytes: &[u8],
    stall: Duration,
) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        match tokio::time::timeout(stall, stream.write(rest)).await {
            Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(Ok(written)) => rest = &rest[written..],
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(stalled()),
        }
    }
    tokio::time::timeout(stall, stream.flush())
        .await
        .map_err(|_| stalled())?
}

fn stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the client stopped reading")
}

#[cfg(test)]
mod tests {
    use super::write_all_or_stall;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    // A client that never reads makes the write fail once it stops moving
    #[tokio::test]
    async fn client_that_never_reads_times_out() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let result = write_all_or_stall(
            &mut server,
            &vec![b'x'; 64 * 1024],
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(
            result.map_err(|err| err.kind()),
            Err(std::io::ErrorKind::TimedOut)
        );
    }

    // A client that reads slowly but keeps reading gets all of it, however
    // much longer than the timeout the whole write takes
    #[tokio::test]
    async fn slow_reader_is_not_cut_off() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let reader = tokio::spawn(async move {
            let mut received = 0;
            let mut buf = [0u8; 512];
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => received += read,
                }
            }
            received
        });
        write_all_or_stall(
            &mut server,
            &vec![b'x'; 32 * 1024],
            Duration::from_millis(200),
        )
        .await
        .unwrap();
        drop(server);
        assert_eq!(reader.await.unwrap(), 32 * 1024);
    }
}
