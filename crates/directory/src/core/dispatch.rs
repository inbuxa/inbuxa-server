/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{Account, Credentials, Directory, Recipient, backend::oidc::OidcDiscovery};
use registry::schema::enums::DirectoryType;
use trc::AddContext;

impl Directory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        match &self {
            Directory::Ldap(store) => store.authenticate(credentials).await,
            Directory::Sql(store) => store.authenticate(credentials).await,
            Directory::OpenId(store) => store.authenticate(credentials).await,
            Directory::Unavailable(directory) => Err(directory.error()),
        }
        .caused_by(trc::location!())
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        match &self {
            Directory::Ldap(store) => store.recipient(address).await,
            Directory::Sql(store) => store.recipient(address).await,
            Directory::OpenId(_) => Ok(Recipient::Invalid), // OIDC directories do not support recipient lookups
            Directory::Unavailable(directory) => Err(directory.error()),
        }
        .caused_by(trc::location!())
    }

    /// inbuxa: #364: what a recipient lookup asks the directory (the LDAP
    /// mailbox filter for this address, or the SQL query), for the log line
    /// that explains a refused recipient.
    pub fn recipient_query(&self, address: &str) -> Option<String> {
        match &self {
            Directory::Ldap(store) => Some(store.recipient_query(address)),
            Directory::Sql(store) => Some(store.recipient_query()),
            Directory::OpenId(_) | Directory::Unavailable(_) => None,
        }
    }

    pub fn has_bearer_token_support(&self) -> bool {
        match &self {
            Directory::OpenId(_) => true,
            Directory::Unavailable(directory) => directory.directory_type() == DirectoryType::Oidc,
            _ => false,
        }
    }

    pub fn can_lookup_recipients(&self) -> bool {
        match &self {
            Directory::OpenId(_) => false,
            Directory::Unavailable(directory) => directory.directory_type() != DirectoryType::Oidc,
            _ => true,
        }
    }

    pub fn oidc_discovery_document(&self) -> Option<&OidcDiscovery> {
        match &self {
            Directory::OpenId(directory) => Some(&directory.discovery),
            _ => None,
        }
    }
}
