/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! State strings and `/changes` for the spools: a counter, and the ids
//! destroyed lately. Runtime only; a restart starts every client over.

use std::collections::VecDeque;

/// How many destroyed ids `/changes` can still report.
const TOMBSTONES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    pub old_state: String,
    pub new_state: String,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    pub has_more: bool,
}

pub struct Changelog {
    modseq: u64,
    tombstones: VecDeque<(u64, String)>,
    /// `/changes` can't go back past this.
    floor: u64,
}

impl Default for Changelog {
    fn default() -> Self {
        Changelog {
            modseq: 1,
            tombstones: VecDeque::new(),
            floor: 1,
        }
    }
}

impl Changelog {
    pub fn state(&self) -> String {
        self.modseq.to_string()
    }

    /// The next modseq, for an object created or changed.
    pub fn bump(&mut self) -> u64 {
        self.modseq += 1;
        self.modseq
    }

    pub fn destroyed(&mut self, id: &str) {
        let modseq = self.bump();
        self.tombstones.push_back((modseq, id.to_string()));
        while self.tombstones.len() > TOMBSTONES {
            if let Some((seq, _)) = self.tombstones.pop_front() {
                self.floor = seq;
            }
        }
    }

    /// What changed since `since`, given each live object's id and its
    /// created and last-changed modseqs. `None` when the client must start
    /// over: an unknown state, or more than `max` changes.
    pub fn changes<'a>(
        &self,
        since: &str,
        max: usize,
        objects: impl Iterator<Item = (&'a String, u64, u64)>,
    ) -> Option<Changes> {
        let since: u64 = since.parse().ok()?;
        if since < self.floor || since > self.modseq {
            return None;
        }
        let mut created = Vec::new();
        let mut updated = Vec::new();
        for (id, created_at, modseq) in objects {
            if created_at > since {
                created.push(id.clone());
            } else if modseq > since {
                updated.push(id.clone());
            }
        }
        let destroyed: Vec<String> = self
            .tombstones
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, id)| id.clone())
            .collect();
        if created.len() + updated.len() + destroyed.len() > max {
            return None;
        }
        Some(Changes {
            old_state: since.to_string(),
            new_state: self.state(),
            created,
            updated,
            destroyed,
            has_more: false,
        })
    }
}
