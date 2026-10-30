/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The accepted-recipient set the downstream pushes (RL-1, RL-11), kept in
//! memory and in the state directory.

use crate::state::{Paths, read_json, write_json};
use inbuxa_relay_proto::{
    b64,
    recipient::{self, Lookup, RecipientDomain, RecipientHash},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    io,
};

#[derive(Default)]
pub struct Recipients {
    /// Bumped on every change; 0 until the downstream sends a set.
    state: u64,
    domains: BTreeMap<String, RecipientDomain>,
    hashes: HashSet<RecipientHash>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    state: u64,
    domains: Vec<RecipientDomain>,
    hashes: Vec<String>,
}

impl Recipients {
    pub fn load(paths: &Paths) -> io::Result<Recipients> {
        let Some(stored) = read_json::<Stored>(&paths.recipients())? else {
            return Ok(Recipients::default());
        };
        let mut hashes = HashSet::with_capacity(stored.hashes.len());
        for text in &stored.hashes {
            let hash = b64::decode(text)
                .and_then(|b| RecipientHash::try_from(b).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recipient hash"))?;
            hashes.insert(hash);
        }
        Ok(Recipients {
            state: stored.state,
            domains: stored
                .domains
                .into_iter()
                .map(|d| (d.domain.clone(), d))
                .collect(),
            hashes,
        })
    }

    pub fn save(&self, paths: &Paths) -> io::Result<()> {
        let mut hashes: Vec<String> = self.hashes.iter().map(|h| b64::encode(h)).collect();
        hashes.sort_unstable();
        write_json(
            &paths.recipients(),
            &Stored {
                state: self.state,
                domains: self.domains.values().cloned().collect(),
                hashes,
            },
        )
    }

    /// Whether the downstream has sent a recipient set yet.
    pub fn is_loaded(&self) -> bool {
        self.state > 0
    }

    pub fn state(&self) -> String {
        self.state.to_string()
    }

    pub fn domains(&self) -> impl Iterator<Item = &RecipientDomain> {
        self.domains.values()
    }

    pub fn domain(&self, domain: &str) -> Option<&RecipientDomain> {
        self.domains.get(domain)
    }

    fn bump(&mut self) {
        self.state += 1;
    }

    pub fn put_domain(&mut self, mut domain: RecipientDomain) {
        domain.domain = domain.domain.trim_end_matches('.').to_lowercase();
        self.domains.insert(domain.domain.clone(), domain);
        self.bump();
    }

    pub fn remove_domain(&mut self, domain: &str) -> bool {
        let removed = self.domains.remove(domain).is_some();
        if removed {
            self.bump();
        }
        removed
    }

    /// Applies one `Recipient/set`: adds and removes hashes.
    pub fn apply(&mut self, create: &[RecipientHash], destroy: &[RecipientHash]) {
        for hash in destroy {
            self.hashes.remove(hash);
        }
        self.hashes.extend(create.iter().copied());
        self.bump();
    }

    /// `Recipient/replace`: a file of 32-byte hashes, swapped in whole.
    pub fn replace(&mut self, file: &[u8]) -> Result<usize, &'static str> {
        if !file.len().is_multiple_of(32) {
            return Err("the file is not a whole number of 32-byte hashes");
        }
        self.hashes = file.as_chunks::<32>().0.iter().copied().collect();
        self.bump();
        Ok(self.hashes.len())
    }

    /// RL-1: what to answer at RCPT for `address`. `served` says whether
    /// the settings list the domain; a served domain without rules of its
    /// own has no catch-all and no sub-addressing.
    pub fn lookup(&self, address: &str, key: &[u8; 32], served: impl Fn(&str) -> bool) -> Lookup {
        let Some((_, domain)) = recipient::split(address) else {
            return Lookup::BadAddress;
        };
        if !served(&domain) {
            return Lookup::NotServed;
        }
        let rules = self
            .domains
            .get(&domain)
            .cloned()
            .unwrap_or_else(|| RecipientDomain {
                domain: domain.clone(),
                catch_all: false,
                subaddress_separator: None,
            });
        recipient::lookup(
            address,
            key,
            |_| Some(&rules),
            |hash| self.hashes.contains(hash),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_relay_proto::recipient::hash;

    #[test]
    fn replace_apply_persist() {
        let dir = std::env::temp_dir().join(format!("inbuxa-relay-rcpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::new(&dir);
        let key = [9u8; 32];

        let mut r = Recipients::default();
        assert!(!r.is_loaded());
        r.put_domain(RecipientDomain {
            domain: "Example.COM".into(),
            catch_all: false,
            subaddress_separator: Some("+".into()),
        });
        let mut file = Vec::new();
        file.extend_from_slice(&hash(&key, "a@example.com"));
        file.extend_from_slice(&hash(&key, "b@example.com"));
        assert_eq!(r.replace(&file), Ok(2));
        assert_eq!(
            r.replace(&file[..31]),
            Err("the file is not a whole number of 32-byte hashes")
        );
        r.apply(
            &[hash(&key, "c@example.com")],
            &[hash(&key, "b@example.com")],
        );
        r.save(&paths).unwrap();

        let r = Recipients::load(&paths).unwrap();
        let all = |_: &str| true;
        assert_eq!(r.lookup("a+x@example.com", &key, all), Lookup::Accept);
        assert_eq!(r.lookup("b@example.com", &key, all), Lookup::UnknownUser);
        assert_eq!(r.lookup("c@example.com", &key, all), Lookup::Accept);
        // A domain with rules but no longer in the settings isn't served.
        assert_eq!(
            r.lookup("a@example.com", &key, |_| false),
            Lookup::NotServed
        );
        // A served domain without rules: exact addresses only.
        let mut r = r;
        r.apply(&[hash(&key, "d+x@example.net")], &[]);
        assert_eq!(r.lookup("d+x@example.net", &key, all), Lookup::Accept);
        assert_eq!(r.lookup("d@example.net", &key, all), Lookup::UnknownUser);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
