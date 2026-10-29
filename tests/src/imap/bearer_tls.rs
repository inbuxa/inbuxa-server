/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: bearer tokens are never offered or accepted on a clear-text
//! connection, even with plain-text sign-in allowed. Password sign-in
//! there keeps following that setting.

use base64::{Engine, engine::general_purpose};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpStream, tcp::OwnedReadHalf},
};

// Expects plain-text sign-in to be allowed, as the imap suite leaves it.
pub async fn test() {
    println!("Running clear-text bearer token tests...");

    let token = general_purpose::STANDARD
        .encode("n,a=jdoe@example.com,\u{1}auth=Bearer not-a-real-token\u{1}\u{1}");
    let mut problems = Vec::new();

    // IMAP, clear text with STARTTLS available
    let (mut rx, mut tx) = connect("127.0.0.1:9991").await;
    let greeting = rx.next_line().await.unwrap().unwrap();
    check_offer(
        &mut problems,
        "IMAP greeting",
        &greeting,
        "AUTH=PLAIN",
        &["AUTH=OAUTHBEARER", "AUTH=XOAUTH2"],
    );
    tx.write_all(b"a CAPABILITY\r\n").await.unwrap();
    let capability = read_until(&mut rx, "a ").await.join("\n");
    check_offer(
        &mut problems,
        "IMAP CAPABILITY",
        &capability,
        "AUTH=PLAIN",
        &["AUTH=OAUTHBEARER", "AUTH=XOAUTH2"],
    );
    tx.write_all(format!("b AUTHENTICATE OAUTHBEARER {token}\r\n").as_bytes())
        .await
        .unwrap();
    let reply = read_until(&mut rx, "b ").await.join("\n");
    if !reply.contains("b NO [PRIVACYREQUIRED]") {
        problems.push(format!(
            "IMAP AUTHENTICATE OAUTHBEARER not refused: {reply}"
        ));
    }
    tx.write_all(b"c AUTHENTICATE XOAUTH2\r\n").await.unwrap();
    let reply = rx.next_line().await.unwrap().unwrap();
    if !reply.starts_with("c NO [PRIVACYREQUIRED]") {
        problems.push(format!("IMAP AUTHENTICATE XOAUTH2 not refused: {reply}"));
    }
    drop(tx);

    // POP3, clear text
    let (mut rx, mut tx) = connect("127.0.0.1:4111").await;
    assert!(rx.next_line().await.unwrap().unwrap().starts_with("+OK"));
    tx.write_all(b"CAPA\r\n").await.unwrap();
    let capa = read_until(&mut rx, ".").await.join("\n");
    check_offer(
        &mut problems,
        "POP3 CAPA",
        &capa,
        "SASL PLAIN",
        &["OAUTHBEARER", "XOAUTH2"],
    );
    for (mechanism, param) in [("OAUTHBEARER", token.as_str()), ("XOAUTH2", "")] {
        tx.write_all(
            format!("AUTH {mechanism} {param}\r\n")
                .trim_end()
                .as_bytes(),
        )
        .await
        .unwrap();
        tx.write_all(b"\r\n").await.unwrap();
        let reply = rx.next_line().await.unwrap().unwrap();
        if !(reply.starts_with("-ERR") && reply.contains("TLS")) {
            problems.push(format!("POP3 AUTH {mechanism} not refused: {reply}"));
        }
    }
    drop(tx);

    // ManageSieve, clear text with STARTTLS available
    let (mut rx, mut tx) = connect("127.0.0.1:4191").await;
    let greeting = read_until(&mut rx, "OK").await.join("\n");
    check_offer(
        &mut problems,
        "ManageSieve greeting",
        &greeting,
        "PLAIN",
        &["OAUTHBEARER", "XOAUTH2"],
    );
    for (mechanism, param) in [
        ("OAUTHBEARER", format!(" \"{token}\"")),
        ("XOAUTH2", "".into()),
    ] {
        tx.write_all(format!("AUTHENTICATE \"{mechanism}\"{param}\r\n").as_bytes())
            .await
            .unwrap();
        let reply = rx.next_line().await.unwrap().unwrap();
        if !reply.starts_with("NO (ENCRYPT-NEEDED)") {
            problems.push(format!(
                "ManageSieve AUTHENTICATE {mechanism} not refused: {reply}"
            ));
        }
    }
    drop(tx);

    assert!(
        problems.is_empty(),
        "bearer tokens on clear text:\n{}",
        problems.join("\n")
    );
}

fn check_offer(problems: &mut Vec<String>, what: &str, text: &str, keep: &str, drop: &[&str]) {
    if !text.contains(keep) {
        problems.push(format!("{what} lost {keep}: {text}"));
    }
    for mechanism in drop {
        if text.contains(mechanism) {
            problems.push(format!("{what} offered {mechanism}: {text}"));
        }
    }
}

async fn connect(
    addr: &str,
) -> (
    Lines<BufReader<OwnedReadHalf>>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let (rx, tx) = TcpStream::connect(addr).await.unwrap().into_split();
    (BufReader::new(rx).lines(), tx)
}

async fn read_until(rx: &mut Lines<BufReader<OwnedReadHalf>>, prefix: &str) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = rx.next_line().await.unwrap().unwrap();
        let done = line.starts_with(prefix);
        lines.push(line);
        if done {
            return lines;
        }
    }
}
