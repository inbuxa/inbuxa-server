/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Remembered and prepared answers (ai-explain spec, EX-24 to EX-27).
//!
//! A question is keyed by everything that decides its answer: the kind of
//! subject, the facts and reference notes the server built, and the prompts'
//! version, plus the model for answers a model gave just now. The same
//! question is then answered from memory instead of asking the model again.
//! Prepared answers, shipped with each release for settings at their
//! defaults, use the same key without the model.
//!
//! Nothing here is written anywhere: the memory is this node's, and a restart
//! forgets it (EX-10).

use super::{Facts, Kind, prompts::PROMPT_VERSION};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// The most answers a node remembers (EX-24).
pub const CAPACITY: usize = 1_000;

/// How long an answer is remembered (EX-24).
pub const TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The key a question is remembered by. `model` is the model's name and
/// entry id for a live answer, and empty for a prepared one (EX-26). The hash
/// is xxh3, so the same question gives the same key on every machine and in
/// every build, which is what lets a release ship prepared answers.
pub fn key(kind: Kind, facts: &Facts, model: &str) -> u64 {
    // Separators that can't occur in labels, values or notes
    let mut text = format!("v{PROMPT_VERSION}\u{1d}{}\u{1d}{model}\u{1d}", kind.as_str());
    for (label, value) in &facts.lines {
        text.push_str(label);
        text.push('\u{1f}');
        text.push_str(value);
        text.push('\u{1e}');
    }
    text.push('\u{1d}');
    for note in &facts.grounding {
        text.push_str(note);
        text.push('\u{1e}');
    }
    xxhash_rust::xxh3::xxh3_64(text.as_bytes())
}

/// A key as prepared answers write it: sixteen lowercase hex digits.
pub fn key_hex(key: u64) -> String {
    format!("{key:016x}")
}

/// An answer this node gave, as remembered.
#[derive(Debug, Clone, PartialEq)]
pub struct Remembered {
    pub text: String,
    pub model: String,
    pub node: String,
    /// When the model gave it, seconds since the epoch.
    pub answered_at: u64,
    pub grounded: Vec<&'static str>,
}

struct Entry {
    answer: Remembered,
    stored: Instant,
    used: u64,
}

/// A node's remembered answers: at most `CAPACITY`, the least recently used
/// going first, each for at most `TTL`.
pub struct Memory {
    inner: Mutex<(HashMap<u64, Entry>, u64)>,
    capacity: usize,
    ttl: Duration,
}

impl Memory {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Memory {
            inner: Mutex::new((HashMap::new(), 0)),
            capacity,
            ttl,
        }
    }

    /// This node's memory.
    pub fn global() -> &'static Memory {
        static MEMORY: OnceLock<Memory> = OnceLock::new();
        MEMORY.get_or_init(|| Memory::new(CAPACITY, TTL))
    }

    pub fn get(&self, key: u64) -> Option<Remembered> {
        self.get_at(key, Instant::now())
    }

    fn get_at(&self, key: u64, now: Instant) -> Option<Remembered> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, clock) = &mut *guard;
        let expired = map
            .get(&key)
            .is_some_and(|entry| now.saturating_duration_since(entry.stored) >= self.ttl);
        if expired {
            map.remove(&key);
            return None;
        }
        *clock += 1;
        let used = *clock;
        map.get_mut(&key).map(|entry| {
            entry.used = used;
            entry.answer.clone()
        })
    }

    pub fn put(&self, key: u64, answer: Remembered) {
        self.put_at(key, answer, Instant::now());
    }

    fn put_at(&self, key: u64, answer: Remembered, now: Instant) {
        if self.capacity == 0 {
            return;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, clock) = &mut *guard;
        *clock += 1;
        let used = *clock;
        if !map.contains_key(&key) && map.len() >= self.capacity {
            // Expired first, then the least recently used
            let ttl = self.ttl;
            map.retain(|_, entry| now.saturating_duration_since(entry.stored) < ttl);
            if map.len() >= self.capacity
                && let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.used)
                    .map(|(key, _)| *key)
            {
                map.remove(&oldest);
            }
        }
        map.insert(
            key,
            Entry {
                answer,
                stored: now,
                used,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.0.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Prepared answers shipped with a release (EX-26), read from
/// `resources/explain/settings.json.gz`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Prepared {
    /// The release they were prepared for.
    #[serde(default)]
    pub release: String,
    /// The model that wrote them.
    #[serde(default)]
    pub model: String,
    #[serde(default, rename = "promptVersion")]
    pub prompt_version: u32,
    /// Answers by `key_hex(key(kind, facts, ""))`.
    #[serde(default)]
    pub answers: HashMap<String, String>,
}

impl Prepared {
    /// Reads the shipped file's JSON. Answers written for other prompts are
    /// dropped, since their keys can't match anyway.
    pub fn parse(json: &[u8]) -> Prepared {
        let prepared: Prepared = serde_json::from_slice(json).unwrap_or_default();
        if prepared.prompt_version == PROMPT_VERSION {
            prepared
        } else {
            Prepared::default()
        }
    }

    pub fn answer(&self, kind: Kind, facts: &Facts) -> Option<&str> {
        self.answers
            .get(&key_hex(key(kind, facts, "")))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(value: &str) -> Facts {
        let mut facts = Facts::default();
        facts.push("Setting", "x:Domain › DNS Management");
        facts.push("Current value", value);
        facts.ground("schemaDescription", "dnsManagement: how DNS is managed");
        facts
    }

    fn answer(text: &str) -> Remembered {
        Remembered {
            text: text.into(),
            model: "m".into(),
            node: "n".into(),
            answered_at: 1,
            grounded: vec!["schemaDescription"],
        }
    }

    #[test]
    fn keys_follow_everything_that_decides_the_answer() {
        let a = key(Kind::Setting, &facts("Manual"), "m@1");
        assert_eq!(a, key(Kind::Setting, &facts("Manual"), "m@1"));
        assert_ne!(a, key(Kind::Setting, &facts("Automatic"), "m@1"));
        assert_ne!(a, key(Kind::Event, &facts("Manual"), "m@1"));
        assert_ne!(a, key(Kind::Setting, &facts("Manual"), "other@1"));
        assert_ne!(a, key(Kind::Setting, &facts("Manual"), ""));
        // Stable across builds and machines: prepared answers depend on it
        assert_eq!(key_hex(0xab), "00000000000000ab");
    }

    #[test]
    fn remembers_and_forgets() {
        let memory = Memory::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        memory.put_at(1, answer("one"), t0);
        memory.put_at(2, answer("two"), t0);
        assert_eq!(memory.get_at(1, t0).unwrap().text, "one");
        // Full: the least recently used (2) goes
        memory.put_at(3, answer("three"), t0);
        assert!(memory.get_at(2, t0).is_none());
        assert!(memory.get_at(1, t0).is_some() && memory.get_at(3, t0).is_some());
        // Expired
        assert!(memory.get_at(1, t0 + Duration::from_secs(10)).is_none());
    }

    #[test]
    fn prepared_answers_match_only_their_prompts() {
        let f = facts("Manual");
        let json = format!(
            r#"{{"release":"2026.9.27","model":"q","promptVersion":{PROMPT_VERSION},"answers":{{"{}":"Prepared."}}}}"#,
            key_hex(key(Kind::Setting, &f, ""))
        );
        let prepared = Prepared::parse(json.as_bytes());
        assert_eq!(prepared.answer(Kind::Setting, &f), Some("Prepared."));
        assert_eq!(prepared.answer(Kind::Setting, &facts("Automatic")), None);
        let old = json.replace(
            &format!("\"promptVersion\":{PROMPT_VERSION}"),
            "\"promptVersion\":1",
        );
        assert_eq!(Prepared::parse(old.as_bytes()).answer(Kind::Setting, &f), None);
        assert!(Prepared::parse(b"not json").answers.is_empty());
    }
}
