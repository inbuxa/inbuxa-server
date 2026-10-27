/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    auth::{active_script::ActiveScriptSlot, oauth::scope::OAuthScopes},
    expr::if_block::IfBlock,
    network::limiter::AccountLimits,
    storage::{ObjectQuota, TenantQuota},
};
use compact_str::CompactString;
use directory::Credentials;
use quick_cache::Equivalent;
use registry::{
    schema::enums::{Locale, Permission},
    types::{EnumImpl, ipmask::IpAddrOrMask},
};
use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};
use tinyvec::TinyVec;
use trc::ipc::bitset::Bitset;
use types::collection::Collection;
use utils::{cache::CacheItemWeight, map::bitmap::Bitmap};

pub mod access_token;
pub mod active_script;
pub mod authentication;
pub mod credential;
pub mod oauth;
pub mod permissions;
pub mod rate_limit;
pub mod sasl;

pub const RECOVERY_ADMIN_ID: u32 = u32::MAX;
const PERMISSIONS_BITSET_SIZE: usize = Permission::COUNT.div_ceil(std::mem::size_of::<usize>() * 8);
pub type Permissions = Bitset<PERMISSIONS_BITSET_SIZE>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EmailAddress {
    pub local_part: CompactString,
    pub domain_id: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EmailAddressRef<'x> {
    local_part: &'x str,
    domain_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailCache {
    Account(u32),
    MailingList(u32),
    DisabledAccountAddress(u32),
    DisabledListAddress(u32),
}

#[derive(Debug, Clone)]
pub struct DomainCache {
    pub names: Box<[Box<str>]>,
    pub id: u32,
    // inbuxa: MT, DIR-1
    pub id_directory: Option<u32>,
    pub id_tenant: Option<u32>,
    pub catch_all: Option<Box<str>>,
    pub sub_addressing_custom: Option<Box<IfBlock>>,
    pub flags: u8,
}

pub const DOMAIN_FLAG_RELAY: u8 = 1;
pub const DOMAIN_FLAG_SUB_ADDRESSING: u8 = 1 << 1;
// inbuxa: SCIM-15, SCIM-58
pub const DOMAIN_FLAG_SCIM: u8 = 1 << 2;


#[derive(Debug, Clone, Default)]
pub struct AccountCache {
    pub name: Box<str>,
    pub id: u32,
    pub addresses: Box<[EmailAddress]>,
    // inbuxa: MT
    pub id_tenant: Option<u32>,
    pub id_member_of: Box<[u32]>,
    pub quota_disk: u64,
    pub description: Option<Box<str>>,
    pub storage: Option<Box<AccountStorage>>,
    pub locale: Locale,
    pub flags: u64,
    pub active_script: ActiveScriptSlot,
}

#[derive(Debug, Clone, Default)]
pub struct AccountStorage {
    pub quota_objects: Option<ObjectQuota>,
    pub encryption_key: Option<EncryptionKeys>,
}

const _: () = assert!(size_of::<AccountCache>() <= 112);

impl AccountStorage {
    pub fn boxed(
        quota_objects: Option<ObjectQuota>,
        encryption_key: Option<EncryptionKeys>,
    ) -> Option<Box<Self>> {
        (quota_objects.is_some() || encryption_key.is_some()).then(|| {
            Box::new(AccountStorage {
                quota_objects,
                encryption_key,
            })
        })
    }
}

pub type EncryptionKeys = Box<[Box<[u8]>]>;

pub const ACCOUNT_IS_USER: u64 = 1;
pub const ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER: u64 = 1 << 1;
pub const ACCOUNT_FLAG_ENCRYPT_METHOD_SMIME: u64 = 1 << 2;
pub const ACCOUNT_FLAG_ENCRYPT_METHOD_PGP: u64 = 1 << 3;
pub const ACCOUNT_FLAG_ENCRYPT_ALGO_AES256: u64 = 1 << 4;
pub const ACCOUNT_FLAG_ENCRYPT_ALGO_AES128: u64 = 1 << 5;
pub const ACCOUNT_FLAG_ENCRYPT_APPEND: u64 = 1 << 6;
pub const ACCOUNT_FLAG_ENCRYPT_ALGO_AES256_GCM: u64 = 1 << 7;
pub const ACCOUNT_FLAG_ENCRYPT_ALGO_CHACHA20_POLY1305: u64 = 1 << 8;

#[derive(Debug, Clone)]
pub struct RoleCache {
    pub id_roles: TinyVec<[u32; 3]>,
    pub permissions: PermissionsGroup,
}

#[derive(Debug, Clone)]
pub struct MailingListCache {
    pub addresses: Box<[EmailAddress]>,
    pub recipients: Arc<[Box<str>]>,
}


#[derive(Debug, Clone, Default)]
pub struct PermissionsGroup {
    pub enabled: Permissions,
    pub disabled: Permissions,
    pub merge: bool,
}

#[derive(Debug, Default, Clone)]
pub struct AccessToken {
    scope_idx: usize,
    inner: Arc<AccessTokenInner>,
    token_scope: Option<TokenScope>,
    // inbuxa: how this session signed in, for the audit log (AU-5)
    origin: Option<Arc<inbuxa_features::audit::Via>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Grant {
        grant_id: u64,
        scopes: OAuthScopes,
        client: GrantClient,
    },
    External {
        scopes: OAuthScopes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantClient {
    FirstParty,
    ThirdParty,
}

const _: () = assert!(size_of::<TokenScope>() <= 16);
const _: () = assert!(size_of::<Option<TokenScope>>() <= 16);

// inbuxa: MT
#[derive(Debug, Clone)]
pub struct TenantCache {
    pub id_roles: Box<[u32]>,
    pub quota_disk: u64,
    pub quota_objects: Option<Box<TenantQuota>>,
    pub permissions: Option<Box<PermissionsGroup>>,
}

#[derive(Debug, Default, Clone)]
pub struct AccessTokenInner {
    pub(crate) account_id: u32,
    // inbuxa: MT
    pub(crate) tenant_id: Option<u32>,
    pub(crate) obj_size: u32,
    pub(crate) member_of: Box<[u32]>,
    pub(crate) access_to: Box<[AccessTo]>,
    pub(crate) scopes: Box<[AccessScope]>,
    pub(crate) limits: Option<Arc<AccountLimits>>,
    pub(crate) revision_account: u64,
    pub(crate) revision: u64,
    pub(crate) credential_version: u64,
    // inbuxa: AL-2: the account is locked; it may not authenticate
    pub(crate) locked: bool,
    // inbuxa: MA-S: the lock is a shared mailbox
    pub(crate) shared_mailbox: bool,
    // inbuxa: AL-5: locked accounts handed to this one
    pub(crate) delegations: Box<[Delegation]>,
}

// inbuxa: 96 plus the lock flags, delegations and tenant
const _: () = assert!(size_of::<AccessTokenInner>() <= 120);

/// inbuxa: a locked account this one may open, and how (AL-5, AL-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The locked account.
    pub account_id: u32,
    pub access: inbuxa_features::lock::Access,
    pub send_as: bool,
    /// Seconds since the epoch.
    pub until: Option<u64>,
    /// MA-S: a locked account, or a shared mailbox.
    pub kind: inbuxa_features::lock::Kind,
}

#[derive(Debug, Default, Hash, Clone)]
pub struct AccessScope {
    pub permissions: Permissions,
    pub credential_id: u32,
    pub expires_at: u64,
    pub allowed_ips: Box<[IpAddrOrMask]>,
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Clone)]
pub(crate) struct AccessTo {
    pub account_id: u32,
    pub collections: Bitmap<Collection>,
    pub is_writable: bool,
}

#[derive(Clone)]
pub struct AccountInfo {
    pub account_id: u32,
    pub account: Arc<AccountCache>,
    pub addresses: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct ChangedBy {
    pub account_id: u32,
    // inbuxa: MT: tenant quotas follow the change
    pub tenant_id: Option<u32>,
}

pub struct AuthRequest {
    pub credentials: Credentials,
    pub session_id: u64,
    pub remote_ip: IpAddr,
}

impl CacheItemWeight for AccessTokenInner {
    fn weight(&self) -> u64 {
        u64::from(self.obj_size)
    }
}

impl CacheItemWeight for EmailAddress {
    fn weight(&self) -> u64 {
        std::mem::size_of::<EmailAddress>() as u64 + self.heap_size()
    }
}

impl CacheItemWeight for EmailCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<EmailCache>() as u64
    }
}

impl CacheItemWeight for DomainCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<DomainCache>() as u64
            + self
                .names
                .iter()
                .map(|s| s.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
                .sum::<u64>()
            + self.catch_all.as_ref().map_or(0, |s| s.len() as u64)
            + self
                .sub_addressing_custom
                .as_ref()
                .map_or(0, |s| s.weight())
    }
}

impl Equivalent<EmailAddress> for EmailAddressRef<'_> {
    fn equivalent(&self, key: &EmailAddress) -> bool {
        self.local_part == key.local_part.as_str() && self.domain_id == key.domain_id
    }
}

impl Hash for EmailAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.as_str().hash(state);
        self.domain_id.hash(state);
    }
}

impl Hash for EmailAddressRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_part.hash(state);
        self.domain_id.hash(state);
    }
}

impl CacheItemWeight for AccountCache {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<AccountCache>()
            + self.name.len()
            + std::mem::size_of_val::<[u32]>(&self.id_member_of)
            + self.description.as_ref().map_or(0, |s| s.len())) as u64
            + self
                .addresses
                .iter()
                .map(|address| address.weight())
                .sum::<u64>()
            + self.storage.as_ref().map_or(0, |storage| storage.weight())
    }
}

impl CacheItemWeight for AccountStorage {
    fn weight(&self) -> u64 {
        std::mem::size_of::<AccountStorage>() as u64
            + self.encryption_key.as_ref().map_or(0, |keys| {
                keys.iter()
                    .map(|k| k.len() as u64 + std::mem::size_of::<Box<[u8]>>() as u64)
                    .sum::<u64>()
            })
    }
}

impl CacheItemWeight for RoleCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<RoleCache>() as u64
    }
}

// inbuxa: MT
impl CacheItemWeight for TenantCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<TenantCache>() as u64
            + self.permissions.as_ref().map_or(0, |p| p.weight())
    }
}

impl CacheItemWeight for MailingListCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<MailingListCache>() as u64
            + self
                .addresses
                .iter()
                .map(|address| address.weight())
                .sum::<u64>()
            + self
                .recipients
                .iter()
                .map(|s| s.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
                .sum::<u64>()
    }
}


impl CacheItemWeight for PermissionsGroup {
    fn weight(&self) -> u64 {
        std::mem::size_of::<PermissionsGroup>() as u64
    }
}

pub trait BuildAccessToken {
    fn build(self) -> AccessToken;
}

impl BuildAccessToken for Arc<AccessTokenInner> {
    fn build(self) -> AccessToken {
        AccessToken {
            scope_idx: 0,
            inner: self,
            token_scope: None,
            origin: None,
        }
    }
}

impl EmailAddress {
    pub fn new(local_part: impl Into<CompactString>, domain_id: u32) -> Self {
        Self {
            local_part: local_part.into(),
            domain_id,
        }
    }

    #[inline]
    pub fn heap_size(&self) -> u64 {
        if self.local_part.is_heap_allocated() {
            self.local_part.capacity() as u64
        } else {
            0
        }
    }
}

impl<'x> EmailAddressRef<'x> {
    pub fn new(local_part: &'x str, domain_id: u32) -> Self {
        Self {
            local_part,
            domain_id,
        }
    }
}

impl AccountCache {
    pub fn domain_id(&self) -> Option<u32> {
        self.addresses.first().map(|address| address.domain_id)
    }

    /// inbuxa: MT: a tenant's token sees only its own tenant's accounts.
    #[inline]
    pub fn is_same_tenant(&self, access_token: &AccessToken) -> bool {
        access_token
            .tenant_id()
            .is_none_or(|tenant_id| self.id_tenant == Some(tenant_id))
    }
}

impl DomainCache {
    pub fn name(&self) -> &str {
        self.names.first().map(|s| s.as_ref()).unwrap_or_default()
    }

    // inbuxa: SCIM-15, SCIM-58
    pub fn allows_scim(&self) -> bool {
        self.flags & DOMAIN_FLAG_SCIM != 0
    }

    /// inbuxa: MT
    #[inline]
    pub fn is_same_tenant(&self, other: &DomainCache) -> bool {
        self.id_tenant == other.id_tenant
    }
}
