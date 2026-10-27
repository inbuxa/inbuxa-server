/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Account, Credentials, Directory, Recipient,
    backend::oidc::{ExternalToken, OidcDiscovery, TokenContext},
    core::verifier::PasswordVerifier,
};
use registry::schema::enums::DirectoryType;
use trc::AddContext;

impl Directory {
    pub async fn authenticate(
        &self,
        credentials: &Credentials,
        verifier: &PasswordVerifier,
    ) -> trc::Result<Account> {
        match &self {
            Directory::Ldap(store) => store.authenticate(credentials, verifier).await,
            Directory::Sql(store) => store.authenticate(credentials, verifier).await,
            Directory::OpenId(store) => store.authenticate(credentials).await,
            Directory::Unavailable(directory) => Err(directory.error()),
        }
        .caused_by(trc::location!())
    }

    pub async fn authenticate_token(
        &self,
        token: &str,
        ctx: &TokenContext<'_>,
    ) -> trc::Result<ExternalToken> {
        match &self {
            Directory::OpenId(store) => store.authenticate_token(token, ctx).await,
            Directory::Unavailable(directory) => Err(directory.error()),
            _ => Err(trc::AuthEvent::Error
                .into_err()
                .reason("Directory does not support bearer tokens")),
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

    pub fn accepts_oidc_issuer(&self, issuer: &str) -> bool {
        match &self {
            Directory::OpenId(directory) => directory.accepts_issuer(issuer),
            _ => false,
        }
    }

    pub fn oidc_discovery_document(&self) -> Option<&OidcDiscovery> {
        match &self {
            Directory::OpenId(directory) => Some(&directory.discovery),
            _ => None,
        }
    }
}
