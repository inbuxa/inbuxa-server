/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Calibrating a real model against labelled mail: how often it answers in
//! the configured format, how often its category is right, and how long it
//! takes. It sends exactly what the classifier sends (the fork's framing,
//! markers and limits, `inbuxa_features::ai::request`) and reads the answer
//! exactly as the classifier does (`ai::answer::parse`).
//!
//! Not part of any suite. Run with:
//!
//! - `CALIB_URL`: the model server's chat completions URL;
//! - `CALIB_SAMPLE`: a file of `label<TAB>path` lines, `label` `spam` or `ham`;
//! - `CALIB_OUT`: where to write one JSON line per message;
//! - `CALIB_LIMIT` (optional): stop after this many messages;
//! - `CALIB_PROMPT` (optional): a prompt other than the default;
//! - `CALIB_MAX_BYTES` (optional): text sent per message, default 2048, as the server's.

use inbuxa_features::ai::{answer, request};
use mail_parser::MessageParser;
use serde_json::json;
use std::{
    io::Write,
    time::{Duration, Instant},
};

/// The fork's default prompt (spec, "Default prompt").
pub const DEFAULT_PROMPT: &str = "Classify the email below as one of: Unsolicited, Commercial, \
Harmful, Legitimate. Unsolicited: bulk mail the recipient didn't ask for. Commercial: selling \
something. Harmful: phishing, fraud or malware. Legitimate: anything else. Then give your \
confidence: High, Medium or Low. Answer on one line as Category,Confidence,Reason with a reason \
of at most 20 words.";

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn ai_calibration() {
    let url = std::env::var("CALIB_URL").expect("CALIB_URL");
    let sample = std::fs::read_to_string(std::env::var("CALIB_SAMPLE").expect("CALIB_SAMPLE"))
        .expect("sample file");
    let limit = std::env::var("CALIB_LIMIT")
        .ok()
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let prompt = std::env::var("CALIB_PROMPT").unwrap_or_else(|_| DEFAULT_PROMPT.to_string());
    let max_bytes = std::env::var("CALIB_MAX_BYTES")
        .ok()
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(2_048);
    let mut out = std::fs::File::create(std::env::var("CALIB_OUT").expect("CALIB_OUT"))
        .expect("output file");

    let categories = ["Unsolicited", "Commercial", "Harmful", "Legitimate"].map(String::from);
    let confidence = ["High", "Medium", "Low"].map(String::from);
    let rules = answer::Rules {
        separator: ",",
        pos_category: 0,
        pos_confidence: Some(1),
        pos_explanation: Some(2),
        categories: &categories,
        confidence: &confidence,
    };
    let system = request::system_text(&prompt);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap();

    for line in sample.lines().filter(|l| !l.is_empty()).take(limit) {
        let (label, path) = line.split_once('\t').expect("label<TAB>path");
        let raw = std::fs::read(path).expect("message");
        let Some(message) = MessageParser::new().parse(&raw) else {
            continue;
        };
        let subject = message.subject().unwrap_or_default().to_string();
        let text = (0..message.text_body.len())
            .filter_map(|i| message.body_text(i))
            .collect::<Vec<_>>()
            .join("\n\n");
        let user = request::classification_text(&subject, &text, max_bytes, &request::nonce());
        let body = request::body(
            request::Kind::Chat,
            "calibration",
            Some(&system),
            &user,
            0.5,
            request::CLASSIFY_MAX_TOKENS,
            false,
        );

        let started = Instant::now();
        let reply = match client
            .post(&url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
        {
            Ok(response) => response.bytes().await.ok(),
            Err(_) => None,
        };
        let elapsed = started.elapsed().as_millis() as u64;
        let answer = reply
            .as_deref()
            .and_then(|bytes| request::answer(request::Kind::Chat, bytes));
        let tag = answer
            .as_deref()
            .and_then(|a| answer::parse(a, &rules))
            .map(|c| c.tag);
        writeln!(
            out,
            "{}",
            json!({
                "label": label,
                "path": path,
                "answer": answer,
                "tag": tag,
                "ms": elapsed,
            })
        )
        .unwrap();
    }
}
