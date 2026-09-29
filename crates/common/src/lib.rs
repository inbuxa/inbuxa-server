/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: composite stores (sharded members, read replicas) nest store
// futures deeply enough to pass rustc's default query depth
#![recursion_limit = "512"]

#![warn(clippy::large_futures)]

use crate::auth::{AccessTokenInner, EmailAddress};
use crate::manager::application::WebApplications;
use crate::network::asn::AsnGeoLookupData;
use crate::{
    auth::{AccountCache, DomainCache, EmailCache, MailingListCache, RoleCache, TenantCache},
    config::{
        mailstore::{
            email::EmailConfig,
            imap::ImapConfig,
            scripts::Scripting,
            spamfilter::{IpResolver, SpamClassifier, SpamFilterConfig},
        },
        smtp::auth::DkimSigners,
    },
    ipc::TrainTaskController,
    network::security::BlockedIps,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use auth::oauth::config::OAuthConfig;
use calcard::common::timezone::Tz;
use config::{
    groupware::GroupwareConfig,
    mailstore::jmap::JmapConfig,
    network::Network,
    smtp::{
        SmtpConfig,
        resolver::{Policy, Tlsa},
    },
    storage::Storage,
    telemetry::Metrics,
};
use ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent};
use mail_auth::{MX, RecordSet, Txt};
use manager::application::Resource;
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use std::sync::atomic::AtomicU64;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use store::InMemoryStore;
use tinyvec::TinyVec;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use types::{acl::AclGrant, special_use::SpecialUse};
use utils::{
    cache::{Cache, CacheWithTtl},
    snowflake::SnowflakeIdGenerator,
};

pub mod auth;
pub mod cache;
pub mod audit; // inbuxa: the audit log (audit-hold-lock spec, AU)
pub mod hold; // inbuxa: legal holds (audit-hold-lock spec, LH)
pub mod privacy; // inbuxa: the personal-data catalog, evaluated
pub mod reachability; // inbuxa: whether the outside world reaches each node's ports
pub mod config;
pub mod expr;
pub mod i18n;
pub mod ipc;
pub mod manager;
pub mod network;
pub mod enterprise; // inbuxa: rebuilt features (AI spam classification)
pub mod scripts;
pub mod sharing;
pub mod storage;
pub mod telemetry;


pub use psl;

pub static VERSION_PRIVATE: &str = env!("CARGO_PKG_VERSION");
pub static VERSION_PUBLIC: &str = "1.0.0";

pub static USER_AGENT: &str = concat!(types::brand!(), "/1.0.0");
pub static DAEMON_NAME: &str = concat!(types::brand!(), " v", types::brand_version!(),);
pub static PROD_ID: &str = types::brand_prodid!();

/*

Schema history:

1 - v0.12.0
2 - v0.12.4
3 - v0.13.0
4 - v0.14.0
5 - v0.15.0
6 - v0.16.0

*/

pub const DATABASE_SCHEMA_VERSION: u32 = 6;

pub const LONG_1D_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);
pub const LONG_1Y_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

pub const KV_ACME: u8 = 0;
pub const KV_OAUTH: u8 = 1;
pub const KV_RATE_LIMIT_RCPT: u8 = 2;
pub const KV_RATE_LIMIT_SCAN: u8 = 3;
pub const KV_RATE_LIMIT_LOITER: u8 = 4;
pub const KV_RATE_LIMIT_AUTH: u8 = 5;
pub const KV_RATE_LIMIT_SMTP: u8 = 6;
pub const KV_RATE_LIMIT_CONTACT: u8 = 7;
pub const KV_RATE_LIMIT_HTTP_AUTHENTICATED: u8 = 8;
pub const KV_RATE_LIMIT_HTTP_ANONYMOUS: u8 = 9;
pub const KV_RATE_LIMIT_IMAP: u8 = 10;
pub const KV_QUOTA_BLOB: u8 = 11;
pub const KV_GREYLIST: u8 = 16;
pub const KV_LOCK_QUEUE_MESSAGE: u8 = 21;
pub const KV_LOCK_TASK: u8 = 23;
pub const KV_LOCK_DAV: u8 = 25;
pub const KV_SIEVE_ID: u8 = 26;
// inbuxa: far above upstream's prefixes, so a new one of theirs never collides
pub const KV_PORT_REACHABILITY: u8 = 200;

#[derive(Clone)]
pub struct Server {
    pub inner: Arc<Inner>,
    pub core: Arc<Core>,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
    pub data: Data,
    pub cache: Caches,
    pub ipc: Ipc,
}

#[allow(clippy::type_complexity)]
pub struct Data {
    pub spam_classifier: ArcSwap<SpamClassifier>,

    pub tls_certificates: ArcSwap<AHashMap<Box<str>, Arc<CertifiedKey>>>,
    pub tls_self_signed_cert: Option<Arc<CertifiedKey>>,

    pub blocked_ips: RwLock<BlockedIps>,
    pub lookup_stores: ArcSwap<AHashMap<Box<str>, InMemoryStore>>,

    // inbuxa: the running listeners and their shutdown switches, so one
    // protocol's ports can close while the rest keep accepting (LP-2)
    pub listener_control: crate::network::control::ListenerControl,

    pub asn_geo_data: AsnGeoLookupData,

    pub jmap_id_gen: SnowflakeIdGenerator,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: SnowflakeIdGenerator,
    pub registry_id_gen: SnowflakeIdGenerator,
    pub queue_status: AtomicBool,
    // inbuxa: coalesces the settings reloads registry writes trigger
    pub settings_reload: cache::reload::SettingsReloadGate,
    // inbuxa: the readiness probe's cached answer
    pub store_health: storage::ready::StoreHealth,

    pub applications: WebApplications,
    pub logos: Mutex<AHashMap<Box<str>, LogoCache>>,

    pub smtp_connectors: TlsConnectors,

    // inbuxa: the objects that failed to build when the running settings
    // were built, at boot or by the last applied reload (see reload_registry)
    pub build_errors: Mutex<AHashSet<registry::types::id::ObjectId>>,

    // inbuxa: the audit log's chain heads and recent-access marks (AU)
    pub audit: inbuxa_features::audit::AuditLog,
}

#[derive(Clone)]
pub struct LogoCache {
    domain_id: u32,
    tenant_id: Option<u32>,
    // inbuxa: read again when the /logo endpoint (per-tenant and per-domain
    // branding) is rebuilt; docs/spec/features/multi-tenancy.md MT-22.
    #[allow(dead_code)]
    data: Option<Resource<Vec<u8>>>,
}

pub struct Caches {
    pub access_tokens: Cache<u32, Arc<AccessTokenInner>>,
    pub http_auth: Cache<Box<str>, HttpAuthCache>,

    pub messages: Cache<u32, Arc<MessageStoreCache>>,
    pub files: Cache<u32, Arc<DavResources>>,
    pub contacts: Cache<u32, Arc<DavResources>>,
    pub events: Cache<u32, Arc<DavResources>>,
    pub scheduling: Cache<u32, Arc<DavResources>>,

    pub emails: Cache<EmailAddress, EmailCache>,
    pub emails_negative: CacheWithTtl<EmailAddress, ()>,
    pub domain_names: Cache<Box<str>, u32>,
    pub domain_names_negative: CacheWithTtl<Box<str>, ()>,

    pub domains: Cache<u32, Arc<DomainCache>>,
    pub accounts: Cache<u32, Arc<AccountCache>>,
    pub roles: Cache<u32, Arc<RoleCache>>,
    pub tenants: Cache<u32, Arc<TenantCache>>,
    pub lists: Cache<u32, Arc<MailingListCache>>,

    pub dkim_signers: Cache<u32, Arc<DkimSigners>>,

    pub dns_txt: CacheWithTtl<Box<str>, Txt>,
    pub dns_mx: CacheWithTtl<Box<str>, RecordSet<MX>>,
    pub dns_ptr: CacheWithTtl<IpAddr, RecordSet<Box<str>>>,
    pub dns_ipv4: CacheWithTtl<Box<str>, RecordSet<Ipv4Addr>>,
    pub dns_ipv6: CacheWithTtl<Box<str>, RecordSet<Ipv6Addr>>,
    pub dns_tlsa: CacheWithTtl<Box<str>, Arc<Tlsa>>,
    pub dns_mta_sts: CacheWithTtl<Box<str>, Arc<Policy>>,
    pub dns_rbl: CacheWithTtl<Box<str>, Option<Arc<IpResolver>>>,

    pub negative_cache_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct MessageStoreCache {
    pub emails: Arc<MessagesCache>,
    pub mailboxes: Arc<MailboxesCache>,
    pub update_lock: Arc<UpdateLock>,
    pub last_change_id: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MailboxesCache {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Box<[MailboxCache]>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessagesCache {
    pub change_id: u64,
    pub items: Box<[MessageCache]>,
    pub index: AHashMap<u32, u32>,
    pub keywords: Box<[Box<str>]>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessageCache {
    pub document_id: u32,
    pub mailboxes: TinyVec<[MessageUidCache; 2]>,
    pub keywords: u128,
    pub thread_id: u32,
    pub change_id: u64,
    pub size: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageUidCache {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct MailboxCache {
    pub document_id: u32,
    pub name: String,
    pub path: String,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: u32,
    pub subscribers: TinyVec<[u32; 4]>,
    pub uid_validity: u32,
    pub acls: TinyVec<[AclGrant; 2]>,
}

#[derive(Debug, Clone)]
pub struct HttpAuthCache {
    pub account_id: u32,
    pub revision: u64,
    pub credential_id: Option<u32>,
    pub expires: Instant,
    // inbuxa: how the cached credentials signed in (AU-5)
    pub origin: Option<Arc<inbuxa_features::audit::Via>>,
}

pub struct Ipc {
    pub push_tx: mpsc::Sender<PushEvent>,
    pub task_tx: Arc<Notify>,
    // inbuxa: task locks held by this node, released on a graceful stop
    pub task_locks: Arc<crate::ipc::TaskLocks>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
    pub broadcast_tx: Option<mpsc::Sender<BroadcastEvent>>,
    pub train_task_controller: Arc<TrainTaskController>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub struct NameWrapper(pub String);

#[derive(Debug, Clone)]
pub struct DavResources {
    pub base_path: String,
    pub paths: AHashSet<DavPath>,
    pub resources: Vec<DavResource>,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub highest_change_id: u64,
    pub size: u64,
    pub update_lock: Arc<UpdateLock>,
}

#[derive(Debug)]
pub struct UpdateLock {
    pub semaphore: Semaphore,
    pub revision: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct DavPath {
    pub path: String,
    pub parent_id: Option<u32>,
    pub hierarchy_seq: u32,
    pub resource_idx: usize,
}

#[derive(Debug, Clone)]
pub struct DavResource {
    pub document_id: u32,
    pub data: DavResourceMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct DavResourcePath<'x> {
    pub path: &'x DavPath,
    pub resource: &'x DavResource,
}

#[derive(Debug, Clone)]
pub enum DavResourceMetadata {
    File {
        name: String,
        size: Option<u32>,
        parent_id: Option<u32>,
        acls: TinyVec<[AclGrant; 2]>,
    },
    Calendar {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
        preferences: TinyVec<[TinyCalendarPreferences; 2]>,
    },
    CalendarEvent {
        names: TinyVec<[DavName; 2]>,
        start: i64,
        duration: u32,
    },
    CalendarEventNotification {
        names: TinyVec<[DavName; 2]>,
    },
    AddressBook {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
    },
    ContactCard {
        names: TinyVec<[DavName; 2]>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct TinyCalendarPreferences {
    pub account_id: u32,
    pub tz: Tz,
    pub flags: u16,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct DavName {
    pub name: String,
    pub parent_id: u32,
}

#[derive(Clone)]
pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub oauth: OAuthConfig,
    pub email: EmailConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    pub spam: SpamFilterConfig,
    pub groupware: GroupwareConfig,
    pub metrics: Metrics,

}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    pub hash: [u8; 32],
}

#[derive(Default)]
pub struct ThrottleKeyHasher {
    hash: u64,
}

#[derive(Clone, Default)]
pub struct ThrottleKeyHasherBuilder {}

/// The logo embedded in calendar emails when no custom logo is set: INBUXA's
/// compact lockup at 380x80, twice its 180-pixel display width. Base64 with
/// CRLF line breaks, ready for a base64 MIME part.
pub const DEFAULT_LOGO_BASE64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/branding/email-logo.png.b64"
));
