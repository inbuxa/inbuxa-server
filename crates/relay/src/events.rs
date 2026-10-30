/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Relay events, for the downstream's history and tracer. Kept until the
//! downstream acknowledges them (RL-22), in an append-only file that is
//! rewritten when events are acknowledged.
//!
//! Events carry no message content. They name addresses only where the
//! downstream already has them: the envelope of a message it receives.

use crate::state::write_atomic;
use inbuxa_relay_proto::{time, types::RelayEvent};
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{self, BufRead, Write},
    path::PathBuf,
};

/// The most events kept; past it, the oldest go.
const MAX_EVENTS: usize = 10_000;

pub struct Events {
    path: PathBuf,
    list: VecDeque<(u64, RelayEvent)>,
    next: u64,
    modseq: u64,
    floor: u64,
    destroyed: VecDeque<(u64, String)>,
}

impl Events {
    pub fn open(path: PathBuf) -> io::Result<Events> {
        let mut list = VecDeque::new();
        let mut next = 1;
        match fs::File::open(&path) {
            Ok(file) => {
                for line in io::BufReader::new(file).lines() {
                    let line = line?;
                    if let Ok(event) = serde_json::from_str::<RelayEvent>(&line) {
                        let seq = event
                            .id
                            .strip_prefix('e')
                            .and_then(|n| n.parse().ok())
                            .unwrap_or(next);
                        next = next.max(seq + 1);
                        list.push_back((seq, event));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // A state from before the restart can't be answered: the client
        // starts over with a full /get.
        Ok(Events {
            path,
            list,
            next,
            modseq: next,
            floor: next,
            destroyed: VecDeque::new(),
        })
    }

    pub fn state(&self) -> String {
        self.modseq.to_string()
    }

    /// Records an event. A failure to write it is reported, not fatal: an
    /// event must never hold mail.
    pub fn record(&mut self, kind: &str, data: Map<String, Value>) -> String {
        let seq = self.next;
        self.next += 1;
        self.modseq += 1;
        let event = RelayEvent {
            id: format!("e{seq}"),
            at: time::utc_date(time::now()),
            kind: kind.to_string(),
            data,
        };
        let line = serde_json::to_string(&event).expect("event serializes");
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = written {
            eprintln!("inbuxa-relay: could not record an event: {e}");
        }
        let id = event.id.clone();
        self.list.push_back((self.modseq, event));
        if self.list.len() > MAX_EVENTS {
            self.drop_oldest();
        }
        id
    }

    fn drop_oldest(&mut self) {
        while self.list.len() > MAX_EVENTS {
            if let Some((_, event)) = self.list.pop_front() {
                self.modseq += 1;
                self.destroyed.push_back((self.modseq, event.id));
            }
        }
        self.trim_tombstones();
        let _ = self.rewrite();
    }

    fn trim_tombstones(&mut self) {
        while self.destroyed.len() > MAX_EVENTS {
            if let Some((seq, _)) = self.destroyed.pop_front() {
                self.floor = seq;
            }
        }
    }

    pub fn get(&self, ids: Option<&[String]>) -> (Vec<RelayEvent>, Vec<String>) {
        match ids {
            None => (self.list.iter().map(|(_, e)| e.clone()).collect(), vec![]),
            Some(ids) => {
                let mut found = Vec::new();
                let mut missing = Vec::new();
                for id in ids {
                    match self.list.iter().find(|(_, e)| &e.id == id) {
                        Some((_, e)) => found.push(e.clone()),
                        None => missing.push(id.clone()),
                    }
                }
                (found, missing)
            }
        }
    }

    /// `(created, destroyed)` since `since`, or `None` if it can't say.
    pub fn changes(&self, since: &str) -> Option<(Vec<String>, Vec<String>)> {
        let since: u64 = since.parse().ok()?;
        if since < self.floor || since > self.modseq {
            return None;
        }
        let created = self
            .list
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, e)| e.id.clone())
            .collect();
        let destroyed = self
            .destroyed
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, id)| id.clone())
            .collect();
        Some((created, destroyed))
    }

    /// The downstream has the events: forget them. Returns those removed.
    pub fn acknowledge(&mut self, ids: &[String]) -> Vec<String> {
        let mut removed = Vec::new();
        self.list.retain(|(_, e)| {
            if ids.contains(&e.id) {
                removed.push(e.id.clone());
                false
            } else {
                true
            }
        });
        for id in &removed {
            self.modseq += 1;
            self.destroyed.push_back((self.modseq, id.clone()));
        }
        self.trim_tombstones();
        if !removed.is_empty()
            && let Err(e) = self.rewrite()
        {
            eprintln!("inbuxa-relay: could not rewrite the event file: {e}");
        }
        removed
    }

    fn rewrite(&self) -> io::Result<()> {
        let mut data = Vec::new();
        for (_, e) in &self.list {
            data.extend_from_slice(&serde_json::to_vec(e).map_err(io::Error::other)?);
            data.push(b'\n');
        }
        write_atomic(&self.path, &data)
    }
}

/// Builds an event's data from pairs.
pub fn data<const N: usize>(pairs: [(&str, Value); N]) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn record_ack_reload() {
        let dir = std::env::temp_dir().join(format!("inbuxa-relay-events-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");

        let mut ev = Events::open(path.clone()).unwrap();
        let s0 = ev.state();
        let a = ev.record("inbound.accepted", data([("id", json!("i1"))]));
        let b = ev.record("smtp.rejected", data([("reply", json!("550 5.1.1"))]));
        assert_eq!(ev.changes(&s0).unwrap().0, vec![a.clone(), b.clone()]);
        let s1 = ev.state();
        assert_eq!(ev.acknowledge(std::slice::from_ref(&a)), vec![a.clone()]);
        assert_eq!(ev.changes(&s1).unwrap().1, vec![a.clone()]);

        let ev = Events::open(path).unwrap();
        let (list, missing) = ev.get(Some(&[a.clone(), b.clone()]));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, b);
        assert_eq!(missing, vec![a]);
        fs::remove_dir_all(dir).unwrap();
    }
}
