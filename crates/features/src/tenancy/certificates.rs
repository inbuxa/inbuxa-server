/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The names a tenant's domain may have certificates for.
//!
//! This server answers the HTTP-01 and TLS-ALPN-01 challenges for every name
//! that points at it, and serves the newest certificate it holds for a name.
//! So a certificate a tenant's domain orders may name only what is the
//! tenant's own: the domain itself, and names under a domain or alias the
//! tenant has proven (MT-24). Not the server's own host name, and not
//! another tenant's domain. The save is refused otherwise, and an order
//! leaves such names out. Server-level domains aren't limited.

use ahash::AHashSet;
use registry::schema::{prelude::ObjectType, structs::Domain};
use store::{RegistryStore, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;

/// The proven names of a tenant's domains, lowercased: each domain's name
/// and aliases, leaving out those still waiting for their DNS proof.
pub async fn proven_names(
    registry: &RegistryStore,
    tenant_id: u32,
) -> trc::Result<AHashSet<String>> {
    let mut names = AHashSet::new();
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain).with_tenant(Some(tenant_id)))
        .await
        .caused_by(trc::location!())?
    {
        if let Some(domain) = registry.object::<Domain>(id).await? {
            names.extend(proven_domain_names(&domain));
        }
    }
    Ok(names)
}

/// One domain's proven name and aliases, lowercased.
pub fn proven_domain_names(domain: &Domain) -> impl Iterator<Item = String> + '_ {
    std::iter::once(&domain.name)
        .chain(domain.aliases.iter())
        .filter(|name| !domain.unverified_names.contains(*name))
        .map(|name| name.to_lowercase())
}

/// Whether a certificate name is one of `names` or a name under one of them.
/// A wildcard counts as the name it stands under.
pub fn covers(names: &AHashSet<String>, name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_lowercase();
    let mut rest = lower.strip_prefix("*.").unwrap_or(&lower);
    loop {
        if rest.is_empty() {
            return false;
        }
        if names.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, parent)) => rest = parent,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::types::map::Map;

    fn names() -> AHashSet<String> {
        ["t.example".to_string(), "alias.example".to_string()]
            .into_iter()
            .collect()
    }

    #[test]
    fn own_names_and_under_them() {
        for name in [
            "t.example",
            "T.Example.",
            "mail.t.example",
            "a.b.t.example",
            "*.t.example",
            "*.mail.t.example",
            "webmail.alias.example",
        ] {
            assert!(covers(&names(), name), "{name}");
        }
    }

    #[test]
    fn nothing_else() {
        for name in [
            "mx.server.example",
            "u.example",
            "mail.u.example",
            "evilt.example",
            "example",
            "t.example.evil",
            "*.example",
            "*",
            "",
            ".",
        ] {
            assert!(!covers(&names(), name), "{name}");
        }
    }

    #[test]
    fn unproven_names_dont_count() {
        let domain = Domain {
            name: "t.example".to_string(),
            aliases: Map::new(vec![
                "proven.example".to_string(),
                "Claimed.Example".to_string(),
            ]),
            unverified_names: Map::new(vec!["Claimed.Example".to_string()]),
            ..Default::default()
        };
        let mut found = proven_domain_names(&domain).collect::<Vec<_>>();
        found.sort();
        assert_eq!(found, ["proven.example", "t.example"]);
    }
}
