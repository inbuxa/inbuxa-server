/*
 * SPDX-FileCopyrightText: 2026 John Coffey
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What a tenant administrator sees of the mail queue (MT-5).
//!
//! It sees a queued message when any recipient is on one of the tenant's
//! domains, whoever sent it. It also sees a message one of its own people
//! sent, until the message leaves the queue: an authenticated sender whose
//! return path is on the tenant's domains. Nothing else in the queue is
//! visible to it.

use ahash::AHashSet;
use registry::schema::{prelude::ObjectType, structs::Domain};
use store::{RegistryStore, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;

/// The names a tenant's domains answer to, lowercased: each domain's name
/// and its aliases.
pub async fn tenant_domains(
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
            names.insert(domain.name.to_lowercase());
            for alias in domain.aliases.iter() {
                names.insert(alias.to_lowercase());
            }
        }
    }
    Ok(names)
}

fn domain_of(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_lowercase())
}

/// Whether a tenant with these domains sees a queued message (MT-5).
pub fn sees<'x>(
    domains: &AHashSet<String>,
    recipients: impl IntoIterator<Item = &'x str>,
    return_path: &str,
    from_authenticated: bool,
) -> bool {
    recipients
        .into_iter()
        .any(|rcpt| domain_of(rcpt).is_some_and(|d| domains.contains(&d)))
        || (from_authenticated && domain_of(return_path).is_some_and(|d| domains.contains(&d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> AHashSet<String> {
        ["t.example".to_string()].into_iter().collect()
    }

    #[test]
    fn addressed_to_the_tenant() {
        // Observed 4: mail to the tenant's domain from anyone.
        assert!(sees(&domains(), ["a@T.example"], "x@u.example", false));
        assert!(sees(
            &domains(),
            ["b@u.example", "a@t.example"],
            "x@u.example",
            true
        ));
    }

    #[test]
    fn sent_by_the_tenant() {
        assert!(sees(&domains(), ["b@u.example"], "a@t.example", true));
        // A return path on the tenant's domain from an unauthenticated sender
        // is anyone's claim, not the tenant's own mail.
        assert!(!sees(&domains(), ["b@u.example"], "a@t.example", false));
    }

    #[test]
    fn nothing_else() {
        assert!(!sees(&domains(), ["b@u.example"], "x@u.example", true));
        assert!(!sees(&domains(), ["b@u.example"], "<>", true));
    }
}
