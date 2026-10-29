/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: commands a client pipelines in one write run in order. A
//! command that changes state waits for the commands before it and the
//! commands after it wait for it, so they see its result.

use crate::utils::server::TestServer;
use base64::{Engine, engine::general_purpose};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpStream, tcp::OwnedReadHalf},
};

const MESSAGES: usize = 8;

pub async fn test(test: &TestServer) {
    println!("Running pipelined command ordering tests...");

    let account = test.account("jdoe@example.com");
    let (rx, mut tx) = TcpStream::connect("127.0.0.1:9991")
        .await
        .unwrap()
        .into_split();
    let mut rx = BufReader::new(rx).lines();
    rx.next_line().await.unwrap().unwrap();
    let credentials =
        general_purpose::STANDARD.encode(format!("\0{}\0{}", account.name(), account.secret()));
    tx.write_all(
        format!(
            "a AUTHENTICATE PLAIN {{{}+}}\r\n{credentials}\r\n",
            credentials.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let login = read_tags(&mut rx, &["a"]).await;
    assert!(
        login
            .tagged
            .first()
            .is_some_and(|line| line.starts_with("a OK")),
        "sign-in failed: {:?}",
        login.lines
    );

    let mut problems = Vec::new();

    // CREATE, then APPENDs into the new mailbox, then STATUS, in one write
    let mut script = String::from("p00 CREATE \"Pipelined\"\r\n");
    let mut tags = vec!["p00".to_string()];
    for i in 1..=MESSAGES {
        let message =
            format!("From: pipe@example.com\r\nSubject: pipelined {i}\r\n\r\nbody {i}\r\n");
        script.push_str(&format!(
            "p{i:02} APPEND \"Pipelined\" {{{}+}}\r\n{message}\r\n",
            message.len()
        ));
        tags.push(format!("p{i:02}"));
    }
    let status_tag = format!("p{:02}", MESSAGES + 1);
    script.push_str(&format!("{status_tag} STATUS \"Pipelined\" (MESSAGES)\r\n"));
    tags.push(status_tag);
    tx.write_all(script.as_bytes()).await.unwrap();
    let tags = tags.iter().map(String::as_str).collect::<Vec<_>>();
    let result = read_tags(&mut rx, &tags).await;
    result.check_in_order(&mut problems, "CREATE/APPEND/STATUS", &tags);
    let expected = format!("MESSAGES {MESSAGES})");
    if !result
        .lines
        .iter()
        .any(|line| line.starts_with("* STATUS") && line.contains(&expected))
    {
        problems.push(format!(
            "STATUS after the pipelined APPENDs did not report {expected}: {:?}",
            result.untagged("* STATUS")
        ));
    }

    // STORE, then FETCH of the same messages, then DELETE, in one write.
    // SELECT goes first on its own: the commands after it are checked
    // against the session state as they are read.
    tx.write_all(b"q1 SELECT \"Pipelined\"\r\n").await.unwrap();
    let result = read_tags(&mut rx, &["q1"]).await;
    result.check_in_order(&mut problems, "SELECT", &["q1"]);
    let tags = ["q2", "q3", "q4", "q5"];
    tx.write_all(
        concat!(
            "q2 STORE 1:* +FLAGS.SILENT (\\Flagged)\r\n",
            "q3 FETCH 1:* (FLAGS)\r\n",
            "q4 UNSELECT\r\n",
            "q5 DELETE \"Pipelined\"\r\n",
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let result = read_tags(&mut rx, &tags).await;
    result.check_in_order(&mut problems, "STORE/FETCH/UNSELECT/DELETE", &tags);
    let fetched = result.untagged("FETCH (");
    if fetched.len() != MESSAGES || fetched.iter().any(|line| !line.contains("\\Flagged")) {
        problems.push(format!(
            "FETCH after the pipelined STORE did not see \\Flagged on all {MESSAGES} messages: {fetched:?}"
        ));
    }

    tx.write_all(b"z LOGOUT\r\n").await.unwrap();

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

struct Responses {
    lines: Vec<String>,
    tagged: Vec<String>,
}

impl Responses {
    fn check_in_order(&self, problems: &mut Vec<String>, what: &str, tags: &[&str]) {
        let order = self
            .tagged
            .iter()
            .map(|line| line.split_once(' ').map_or(line.as_str(), |(tag, _)| tag))
            .collect::<Vec<_>>();
        if order != tags {
            problems.push(format!(
                "{what}: completions out of order: {:?}",
                self.tagged
            ));
        }
        for line in &self.tagged {
            if !line.split(' ').nth(1).is_some_and(|status| status == "OK") {
                problems.push(format!("{what}: command failed: {line:?}"));
            }
        }
    }

    fn untagged(&self, needle: &str) -> Vec<&String> {
        self.lines
            .iter()
            .filter(|line| line.starts_with("* ") && line.contains(needle))
            .collect()
    }
}

// Reads until every tag has completed, keeping the order they completed in
async fn read_tags(rx: &mut Lines<BufReader<OwnedReadHalf>>, tags: &[&str]) -> Responses {
    let mut responses = Responses {
        lines: Vec::new(),
        tagged: Vec::new(),
    };
    while responses.tagged.len() < tags.len() {
        let line = match tokio::time::timeout(Duration::from_secs(15), rx.next_line()).await {
            Ok(Ok(Some(line))) => line,
            other => panic!(
                "no response for all of {tags:?} ({other:?}); got {:?}",
                responses.lines
            ),
        };
        if tags.iter().any(|tag| {
            line.strip_prefix(tag)
                .is_some_and(|rest| rest.starts_with(' '))
        }) {
            responses.tagged.push(line.clone());
        }
        responses.lines.push(line);
    }
    responses
}
