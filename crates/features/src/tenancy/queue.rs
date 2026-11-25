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
//! A message whose recipients are all on the tenant's domains is the
//! tenant's whole too: nothing in it belongs to another tenant.
//! A message that also has recipients elsewhere shows the tenant its own
//! recipients and nothing of the others, who may be another tenant's or the
//! sender's blind copies; the tenant cancels or retries delivery to its own
//! recipients only, and can't download the content or delete the message.
//! Nothing else in the queue is visible to it.
//!
//! Where the sender connected from is shown only with the whole message,
//! and never when the sender was another tenant's signed-in person.

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
    /// All of it: one of the tenant's people sent it, or every recipient
    /// is the tenant's.
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
    if sent_by_tenant(domains, return_path, from_authenticated) {
        return QueueReach::Whole;
    }
    let (mut any_own, mut all_own) = (false, true);
    for rcpt in recipients {
        if is_own_recipient(domains, rcpt) {
            any_own = true;
        } else {
            all_own = false;
        }
    }
    match (any_own, all_own) {
        (true, true) => QueueReach::Whole,
        (true, false) => QueueReach::OwnRecipients,
        _ => QueueReach::Nothing,
    }
}

/// Whether one of the tenant's own people sent the message: an
/// authenticated sender whose return path is on the tenant's domains.
pub fn sent_by_tenant(
    domains: &AHashSet<String>,
    return_path: &str,
    from_authenticated: bool,
) -> bool {
    from_authenticated && is_own_recipient(domains, return_path)
}

/// Whether a tenant that reaches a message this far is shown where its
/// sender connected from: only with the whole message, and not when the
/// sender signed in here as someone outside the tenant, whose address that
/// is.
pub fn shows_client_ip(
    reach: QueueReach,
    domains: &AHashSet<String>,
    return_path: &str,
    from_authenticated: bool,
) -> bool {
    reach == QueueReach::Whole
        && (!from_authenticated || sent_by_tenant(domains, return_path, from_authenticated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> AHashSet<String> {
        ["t.example".to_string()].into_iter().collect()
    }

    #[test]
    fn addressed_to_the_tenant() {
        // Mail to the tenant's domains only is the tenant's whole, from
        // anyone
        assert_eq!(
            reach(&domains(), ["a@T.example"], "x@u.example", false),
            QueueReach::Whole
        );
        assert_eq!(
            reach(
                &domains(),
                ["a@t.example", "c@t.example"],
                "x@u.example",
                true
            ),
            QueueReach::Whole
        );
        // Observed 4: with recipients elsewhere too, only the tenant's own
        assert_eq!(
            reach(
                &domains(),
                ["a@t.example", "b@u.example"],
                "x@u.example",
                false
            ),
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
            reach(
                &domains(),
                ["a@t.example", "b@u.example"],
                "a@t.example",
                false
            ),
            QueueReach::OwnRecipients
        );
    }

    #[test]
    fn client_ip() {
        let d = domains();
        // The tenant's own sent mail, and mail from outside to it alone
        assert!(shows_client_ip(QueueReach::Whole, &d, "a@t.example", true));
        assert!(shows_client_ip(
            QueueReach::Whole,
            &d,
            "x@remote.example",
            false
        ));
        // Another tenant's signed-in person, even to the tenant alone
        assert!(!shows_client_ip(QueueReach::Whole, &d, "x@u.example", true));
        // Never with only some recipients
        assert!(!shows_client_ip(
            QueueReach::OwnRecipients,
            &d,
            "x@remote.example",
            false
        ));
        assert!(!shows_client_ip(
            QueueReach::Nothing,
            &d,
            "a@t.example",
            true
        ));
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
