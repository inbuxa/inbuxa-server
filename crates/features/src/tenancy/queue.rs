/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What a tenant administrator sees of the mail queue (MT-5).
//!
//! A message one of its own people sent (an authenticated sender whose
//! return path is on the tenant's domains) is the tenant's whole, until it
//! leaves the queue: every recipient, the content, and deleting it.
//! A message that only has recipients on the tenant's domains shows the
//! tenant those recipients and nothing of the others, who may be another
//! tenant's or the sender's blind copies; the tenant cancels or retries
//! delivery to its own recipients only, and can't download the content or
//! delete the message. Nothing else in the queue is visible to it.

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

/// How much of a queued message a tenant reaches (MT-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueReach {
    /// None of it: the message isn't shown.
    Nothing,
    /// Its own recipients only.
    OwnRecipients,
    /// All of it: one of the tenant's people sent it.
    Whole,
}

/// Whether a recipient address is on one of the tenant's domains.
pub fn is_own_recipient(domains: &AHashSet<String>, address: &str) -> bool {
    domain_of(address).is_some_and(|d| domains.contains(&d))
}

/// How much of a queued message a tenant with these domains reaches.
pub fn reach<'x>(
    domains: &AHashSet<String>,
    recipients: impl IntoIterator<Item = &'x str>,
    return_path: &str,
    from_authenticated: bool,
) -> QueueReach {
    if from_authenticated && is_own_recipient(domains, return_path) {
        QueueReach::Whole
    } else if recipients
        .into_iter()
        .any(|rcpt| is_own_recipient(domains, rcpt))
    {
        QueueReach::OwnRecipients
    } else {
        QueueReach::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> AHashSet<String> {
        ["t.example".to_string()].into_iter().collect()
    }

    #[test]
    fn addressed_to_the_tenant() {
        // Observed 4: mail to the tenant's domain from anyone, but only the
        // tenant's own recipients of it
        assert_eq!(
            reach(&domains(), ["a@T.example"], "x@u.example", false),
            QueueReach::OwnRecipients
        );
        assert_eq!(
            reach(
                &domains(),
                ["b@u.example", "a@t.example"],
                "x@u.example",
                true
            ),
            QueueReach::OwnRecipients
        );
        assert!(is_own_recipient(&domains(), "a@T.example"));
        assert!(!is_own_recipient(&domains(), "b@u.example"));
    }

    #[test]
    fn sent_by_the_tenant() {
        assert_eq!(
            reach(&domains(), ["b@u.example"], "a@t.example", true),
            QueueReach::Whole
        );
        // A return path on the tenant's domain from an unauthenticated sender
        // is anyone's claim, not the tenant's own mail.
        assert_eq!(
            reach(&domains(), ["b@u.example"], "a@t.example", false),
            QueueReach::Nothing
        );
        assert_eq!(
            reach(&domains(), ["a@t.example"], "a@t.example", false),
            QueueReach::OwnRecipients
        );
    }

    #[test]
    fn nothing_else() {
        assert_eq!(
            reach(&domains(), ["b@u.example"], "x@u.example", true),
            QueueReach::Nothing
        );
        assert_eq!(
            reach(&domains(), ["b@u.example"], "<>", true),
            QueueReach::Nothing
        );
    }
}
