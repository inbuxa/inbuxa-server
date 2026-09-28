/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The personal-data catalog, evaluated (personal-data catalog spec, §6).
//!
//! `resources/privacy/catalog.toml` says what the server *can* hold; this
//! module turns it into what *this* server holds, given the live facts the
//! caller gathers from its settings ([`LiveFacts`]). Facts in, facts out:
//! nothing here judges, and nothing here reads the store, so every
//! configuration can be tested with made-up facts.

pub mod snapshot;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// The catalog, as shipped with this build.
pub const CATALOG: &str = include_str!("../../../../resources/privacy/catalog.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Retention {
    Word(String),
    Setting { setting: String },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ObjectEntry {
    #[serde(default)]
    pub whose: Vec<String>,
    #[serde(default, rename = "where")]
    pub location: Vec<String>,
    pub scope: Option<String>,
    pub retention: Option<Retention>,
    #[serde(default)]
    pub properties: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SourceEntry {
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub whose: Vec<String>,
    #[serde(default, rename = "where")]
    pub location: Vec<String>,
    pub scope: Option<String>,
    pub retention: Option<Retention>,
    #[serde(default)]
    pub enabled_by: Vec<String>,
    #[serde(default)]
    pub captures: Vec<String>,
    #[serde(default)]
    pub leaves_host: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub object: BTreeMap<String, ObjectEntry>,
    #[serde(default)]
    pub source: BTreeMap<String, SourceEntry>,
}

/// The shipped catalog, parsed once. It is checked in CI
/// (`tools/fork/privacy-check.py`), so a parse failure is a build bug.
pub fn catalog() -> &'static Catalog {
    static CATALOG_PARSED: OnceLock<Catalog> = OnceLock::new();
    CATALOG_PARSED.get_or_init(|| toml::from_str(CATALOG).expect("resources/privacy/catalog.toml parses"))
}

/// A duration setting's live value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Days {
    /// Set, in whole days (rounded up).
    Days(u64),
    /// Unset: nothing bounds it.
    Unbounded,
}

/// Everything the evaluation needs from the running server.
#[derive(Debug, Clone, Default)]
pub struct LiveFacts {
    /// Duration settings by name (`x:DataRetention.holdTracesFor`,
    /// `inbuxa:AuditSettings.keepForDays` ...). A setting not here is
    /// reported by name, without a value.
    pub durations: BTreeMap<String, Days>,
    /// Whether each source or object is collected at all, by catalog id. An
    /// id not here is taken as collected.
    pub collected: BTreeMap<String, bool>,
    /// The endpoints each source or object sends to, by catalog id: hosts or
    /// URLs as configured. Loopback endpoints are left out: what goes there
    /// stays on the host ([`is_loopback`]).
    pub endpoints: BTreeMap<String, Vec<String>>,
    /// Stores pointed at a remote backend, by location (`data-store`,
    /// `blob-store`, `search-store`, `in-memory-store`), with the host.
    pub remote_stores: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionOut {
    /// `unbounded`, `days`, `object-life`, `receiver`, or `setting` (named but
    /// not evaluated).
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    /// `object` or `source`.
    pub kind: String,
    pub categories: Vec<String>,
    pub whose: Vec<String>,
    #[serde(rename = "where")]
    pub location: Vec<String>,
    pub scope: String,
    pub collected: bool,
    pub retention: RetentionOut,
    pub leaves_host: bool,
    pub controlled_by: Vec<String>,
    pub endpoints: Vec<String>,
}

/// A host that receives personal data: a candidate processor, since whether
/// it is one in law is the operator's determination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Processor {
    pub host: String,
    pub receives: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub items: Vec<Item>,
    pub processors: Vec<Processor>,
}

/// Counts for a snapshot's summary and the Overview.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub collected: u64,
    pub unbounded: u64,
    pub leaving_host: u64,
    pub processors: u64,
}

impl Inventory {
    pub fn summary(&self) -> Summary {
        let collected = self.items.iter().filter(|i| i.collected);
        Summary {
            collected: collected.clone().count() as u64,
            unbounded: collected
                .clone()
                .filter(|i| i.retention.kind == "unbounded")
                .count() as u64,
            leaving_host: collected.filter(|i| i.leaves_host).count() as u64,
            processors: self.processors.len() as u64,
        }
    }
}

/// The host part of an endpoint as configured: a URL's host, or the string
/// itself when it is a bare host or zone.
pub fn host_of(endpoint: &str) -> String {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, rest)| rest);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = if host.starts_with('[') {
        host.split_once(']').map_or(host, |(h, _)| h.trim_start_matches('['))
    } else {
        host.rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
            .map_or(host, |(h, _)| h)
    };
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether an endpoint is this host: what is sent there stays here.
pub fn is_loopback(endpoint: &str) -> bool {
    let host = host_of(endpoint);
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn retention_out(retention: Option<&Retention>, facts: &LiveFacts) -> RetentionOut {
    match retention {
        Some(Retention::Setting { setting }) => match facts.durations.get(setting) {
            Some(Days::Days(days)) => RetentionOut {
                kind: "days".into(),
                days: Some(*days),
                setting: Some(setting.clone()),
            },
            Some(Days::Unbounded) => RetentionOut {
                kind: "unbounded".into(),
                days: None,
                setting: Some(setting.clone()),
            },
            None => RetentionOut {
                kind: "setting".into(),
                days: None,
                setting: Some(setting.clone()),
            },
        },
        Some(Retention::Word(word)) => RetentionOut {
            kind: word.clone(),
            days: None,
            setting: None,
        },
        None => RetentionOut {
            kind: "object-life".into(),
            days: None,
            setting: None,
        },
    }
}

/// What the catalog says `id` holds, evaluated against `facts`. Objects with
/// nothing personal are left out. `tenant_only` keeps the entries a tenant
/// can be told about: tenant-scoped, and none of the server's processors.
pub fn evaluate(catalog: &Catalog, facts: &LiveFacts, tenant_only: bool) -> Inventory {
    let mut items = Vec::new();
    let mut add = |id: &str,
                   kind: &str,
                   categories: Vec<String>,
                   whose: &[String],
                   location: &[String],
                   scope: Option<&String>,
                   retention: Option<&Retention>,
                   controlled_by: Vec<String>,
                   leaves: bool| {
        let scope = scope.cloned().unwrap_or_else(|| "server".into());
        if tenant_only && scope != "tenant" {
            return;
        }
        let mut endpoints: Vec<String> = facts.endpoints.get(id).cloned().unwrap_or_default();
        // Anything sent to an endpoint off this host leaves it
        let mut leaves_host = leaves || !endpoints.is_empty();
        for place in location {
            if let Some(host) = facts.remote_stores.get(place) {
                leaves_host = true;
                endpoints.push(host.clone());
            }
        }
        endpoints.sort();
        endpoints.dedup();
        items.push(Item {
            id: id.to_string(),
            kind: kind.to_string(),
            categories,
            whose: whose.to_vec(),
            location: location.to_vec(),
            scope,
            collected: facts.collected.get(id).copied().unwrap_or(true),
            retention: retention_out(retention, facts),
            leaves_host,
            controlled_by,
            endpoints,
        });
    };

    for (id, entry) in &catalog.source {
        let controlled_by = entry
            .enabled_by
            .iter()
            .chain(&entry.captures)
            .cloned()
            .collect();
        add(
            id,
            "source",
            entry.categories.clone(),
            &entry.whose,
            &entry.location,
            entry.scope.as_ref(),
            entry.retention.as_ref(),
            controlled_by,
            entry.leaves_host,
        );
    }
    for (id, entry) in &catalog.object {
        if entry.properties.is_empty() || entry.whose.is_empty() {
            // Nothing personal, or a credential field of a configuration
            // object with no place of its own in the inventory
            continue;
        }
        let categories: BTreeSet<String> = entry.properties.values().flatten().cloned().collect();
        let leaves = entry.location.iter().any(|place| place == "external");
        add(
            id,
            "object",
            categories.into_iter().collect(),
            &entry.whose,
            &entry.location,
            entry.scope.as_ref(),
            entry.retention.as_ref(),
            Vec::new(),
            leaves,
        );
    }

    // Candidate processors: each host that receives something, once
    let mut processors: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    if !tenant_only {
        for item in items.iter().filter(|i| i.collected && i.leaves_host) {
            for endpoint in &item.endpoints {
                let entry = processors.entry(host_of(endpoint)).or_default();
                entry.0.extend(item.categories.iter().cloned());
                entry.1.insert(item.id.clone());
            }
        }
    }
    Inventory {
        items,
        processors: processors
            .into_iter()
            .filter(|(host, _)| !host.is_empty())
            .map(|(host, (receives, sources))| Processor {
                host,
                receives: receives.into_iter().collect(),
                sources: sources.into_iter().collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> LiveFacts {
        LiveFacts::default()
    }

    fn item<'a>(inventory: &'a Inventory, id: &str) -> &'a Item {
        inventory
            .items
            .iter()
            .find(|i| i.id == id)
            .unwrap_or_else(|| panic!("{id} not in the inventory"))
    }

    #[test]
    fn the_shipped_catalog_parses() {
        let catalog = catalog();
        assert!(catalog.source.contains_key("log-file"));
        assert!(catalog.object.contains_key("x:UserAccount"));
    }

    #[test]
    fn defaults_a_new_install_would_report() {
        let mut facts = facts();
        facts
            .durations
            .insert("x:DataRetention.holdTracesFor".into(), Days::Days(14));
        facts
            .durations
            .insert("inbuxa:LogSettings.keepForDays".into(), Days::Days(30));
        facts.endpoints.insert("spam-pyzor".into(), vec!["public.pyzor.org:24441".into()]);
        facts.collected.insert("spam-pyzor".into(), false);
        facts.endpoints.insert(
            "spam-dnsbl".into(),
            vec!["zen.spamhaus.org".into(), "bl.spamcop.net".into()],
        );
        let inventory = evaluate(catalog(), &facts, false);

        let trace = item(&inventory, "x:Trace");
        assert_eq!(trace.retention.kind, "days");
        assert_eq!(trace.retention.days, Some(14));
        assert!(!trace.leaves_host);
        assert_eq!(item(&inventory, "log-file").retention.days, Some(30));
        // Pyzor off: listed, not collected, not a processor
        assert!(!item(&inventory, "spam-pyzor").collected);
        let hosts: Vec<_> = inventory.processors.iter().map(|p| p.host.as_str()).collect();
        assert_eq!(hosts, vec!["bl.spamcop.net", "zen.spamhaus.org"]);
        // Nothing personal isn't listed
        assert!(inventory.items.iter().all(|i| i.id != "x:Http"));
    }

    #[test]
    fn an_external_store_makes_what_lives_there_leave_the_host() {
        let mut facts = facts();
        facts
            .remote_stores
            .insert("blob-store".into(), "https://s3.example.net/mail".into());
        let inventory = evaluate(catalog(), &facts, false);
        let archived = item(&inventory, "x:ArchivedEmail");
        assert!(archived.leaves_host);
        assert_eq!(archived.endpoints, vec!["https://s3.example.net/mail"]);
        assert!(inventory.processors.iter().any(|p| p.host == "s3.example.net"
            && p.sources.contains(&"x:ArchivedEmail".to_string())));
        // What lives only in the data store stays
        assert!(!item(&inventory, "x:UserAccount").leaves_host);
    }

    #[test]
    fn a_hosted_ai_endpoint_is_a_processor_of_content() {
        let mut facts = facts();
        facts.collected.insert("spam-llm".into(), true);
        facts
            .endpoints
            .insert("spam-llm".into(), vec!["https://api.example-ai.com/v1".into()]);
        let inventory = evaluate(catalog(), &facts, false);
        let ai = inventory
            .processors
            .iter()
            .find(|p| p.host == "api.example-ai.com")
            .expect("the AI endpoint is listed");
        assert_eq!(ai.receives, vec!["content"]);
    }

    #[test]
    fn telemetry_off_is_reported_as_not_collected() {
        let mut facts = facts();
        for id in ["x:Trace", "trace-index", "log-file"] {
            facts.collected.insert(id.into(), false);
        }
        let inventory = evaluate(catalog(), &facts, false);
        for id in ["x:Trace", "trace-index", "log-file"] {
            assert!(!item(&inventory, id).collected, "{id}");
        }
        assert_eq!(item(&inventory, "log-file").retention.kind, "setting");
    }

    #[test]
    fn a_tenant_sees_its_slice_and_no_processors() {
        let mut facts = facts();
        facts.endpoints.insert("spam-dnsbl".into(), vec!["zen.spamhaus.org".into()]);
        let inventory = evaluate(catalog(), &facts, true);
        assert!(inventory.items.iter().all(|i| i.scope == "tenant"));
        assert!(inventory.items.iter().any(|i| i.id == "x:UserAccount"));
        assert!(inventory.items.iter().all(|i| i.id != "log-file"));
        assert!(inventory.processors.is_empty());
    }

    #[test]
    fn hosts_are_read_from_urls_and_bare_names() {
        assert_eq!(host_of("https://user:pw@Hooks.Example.com:8443/path?x"), "hooks.example.com");
        assert_eq!(host_of("public.pyzor.org:24441"), "public.pyzor.org");
        assert_eq!(host_of("zen.spamhaus.org."), "zen.spamhaus.org");
        assert_eq!(host_of("http://[::1]:11434/v1"), "::1");
        assert_eq!(host_of("postgres://db.internal:5432/mail"), "db.internal");
    }

    #[test]
    fn loopback_stays_on_the_host() {
        assert!(is_loopback("http://127.0.0.1:11434/v1"));
        assert!(is_loopback("http://localhost:8080"));
        assert!(is_loopback("http://[::1]:11434"));
        assert!(!is_loopback("http://10.77.0.2:11434"), "another node leaves the host");
        assert!(!is_loopback("https://api.example-ai.com"));
    }

    #[test]
    fn a_configured_endpoint_means_it_leaves() {
        let mut facts = facts();
        facts.endpoints.insert("x:Trace".into(), vec!["postgres://traces.example.net".into()]);
        let inventory = evaluate(catalog(), &facts, false);
        assert!(item(&inventory, "x:Trace").leaves_host);
    }

    #[test]
    fn a_summary_counts_what_is_collected() {
        let mut facts = facts();
        facts.collected.insert("log-file".into(), true);
        let inventory = evaluate(catalog(), &facts, false);
        let summary = inventory.summary();
        assert!(summary.collected > 10);
        assert!(summary.unbounded >= 1, "sources the catalog marks unbounded");
    }
}
