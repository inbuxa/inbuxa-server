/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: a client that sends commands and never reads the answers is
//! dropped once an answer has stood still for the session's read timeout,
//! before signing in too, on IMAP, POP3 and ManageSieve.

use crate::utils::server::TestServer;
use registry::schema::{prelude::Property, structs::Imap};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpSocket,
};

// Commands sent without reading: their answers are several times what the
// socket buffers between the server and the client hold
const COMMANDS: usize = 50_000;

pub async fn test(test: &TestServer) {
    println!("Running write stall tests...");

    // A short sign-in timeout, which is also how long an answer to a client
    // that hasn't signed in may stand still
    let admin = test.account("admin@example.com");
    admin
        .registry_update_setting(
            Imap {
                timeout_anonymous: Duration::from_secs(2).into(),
                ..Default::default()
            },
            &[Property::TimeoutAnonymous],
        )
        .await;
    admin.reload_settings().await;

    for (protocol, port, command, is_answer) in [
        (
            "IMAP",
            9991,
            "a CAPABILITY\r\n",
            (|line: &str| line.starts_with("a OK")) as fn(&str) -> bool,
        ),
        ("POP3", 4111, "CAPA\r\n", |line: &str| line == "."),
        ("ManageSieve", 4191, "CAPABILITY\r\n", |line: &str| {
            line.starts_with("OK")
        }),
    ] {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let (rx, mut tx) = socket
            .connect(format!("127.0.0.1:{port}").parse().unwrap())
            .await
            .unwrap()
            .into_split();

        // Send every command and read nothing
        let writer = tokio::spawn(async move {
            let commands = command.repeat(COMMANDS);
            let _ = tx.write_all(commands.as_bytes()).await;
            tx
        });
        tokio::time::sleep(Duration::from_secs(8)).await;

        // A server that waited for the client has every answer to give once
        // it reads; one that gave up has dropped the session part way
        let started = Instant::now();
        let mut lines = BufReader::new(rx).lines();
        let mut answers = 0;
        while started.elapsed() < Duration::from_secs(120) {
            match tokio::time::timeout(Duration::from_secs(30), lines.next_line()).await {
                Ok(Ok(Some(line))) => {
                    if is_answer(&line) {
                        answers += 1;
                    }
                }
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => panic!("{protocol}: the server neither answered nor closed"),
            }
        }
        writer.abort();
        assert!(
            answers < COMMANDS,
            "{protocol}: the session waited for a client that read nothing and gave all \
             {answers} answers"
        );
    }

    admin
        .registry_update_setting(Imap::default(), &[Property::TimeoutAnonymous])
        .await;
    admin.reload_settings().await;
}
