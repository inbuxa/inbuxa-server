/*
 * SPDX-FileCopyrightText: 2026 John Coffey
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Which registry object types a principal in a tenant can reach (MT-2,
//! MT-11, MT-12).
//!
//! Inside a tenant, a principal reaches the object types that can belong to
//! a tenant (filtered to its own), its own account's settings and
//! credentials, the queue (filtered by `queue`), and, to read only, its own
//! tenant. Everything else is server-level and refused, whatever permissions
//! it holds.

use registry::schema::prelude::{OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, ObjectType};

/// Whether a principal in a tenant can read objects of this type.
pub fn can_read(object_type: ObjectType) -> bool {
    object_type.flags() & (OBJ_FILTER_TENANT | OBJ_FILTER_ACCOUNT) != 0
        || matches!(
            object_type,
            ObjectType::AccountSettings
                | ObjectType::AccountPassword
                | ObjectType::AppPassword
                | ObjectType::ApiKey
                | ObjectType::QueuedMessage
                | ObjectType::Tenant
        )
}

/// Whether a principal in a tenant can create, change or destroy objects of
/// this type. The tenant object itself is server-level (MT-12).
pub fn can_write(object_type: ObjectType) -> bool {
    can_read(object_type) && object_type != ObjectType::Tenant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_types() {
        for t in [
            ObjectType::Account,
            ObjectType::Domain,
            ObjectType::DkimSignature,
            ObjectType::AcmeProvider,
            ObjectType::DnsServer,
            ObjectType::Role,
            ObjectType::MailingList,
            ObjectType::OAuthClient,
            ObjectType::Directory,
            ObjectType::QueuedMessage,
        ] {
            assert!(can_read(t) && can_write(t), "{t:?}");
        }
    }

    #[test]
    fn own_tenant_is_read_only() {
        assert!(can_read(ObjectType::Tenant));
        assert!(!can_write(ObjectType::Tenant));
    }

    #[test]
    fn server_level_types() {
        // Observed 3: listeners, certificates and system settings.
        for t in [
            ObjectType::NetworkListener,
            ObjectType::Certificate,
            ObjectType::SystemSettings,
            ObjectType::Authentication,
            ObjectType::Bootstrap,
            ObjectType::Task,
        ] {
            assert!(!can_read(t), "{t:?}");
        }
    }
}
