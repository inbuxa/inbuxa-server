/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#![warn(clippy::large_futures)]
// inbuxa: composite stores (sharded members, read replicas) nest store
// futures deeply enough to pass rustc's default query depth
#![recursion_limit = "512"]

use crate::auth::{AccessTokenInner, EmailAddress, TokenScope};
use crate::manager::application::WebApplications;
use crate::network::asn::AsnGeoLookupData;
use crate::network::memory::MemoryBudget;
use crate::{
    auth::{AccountCache, DomainCache, EmailCache, MailingListCache, RoleCache, TenantCache},
    cache::{
        email::{IdIndex, ThreadRange},
        http_auth::{GrantRevocations, HttpAuthEntries},
        large::{LargeMessageCaches, LargeResourceCaches},
        swap::evict::SwapEviction,
    },
    config::{
        mailstore::{
            email::EmailConfig,
            imap::ImapConfig,
            scripts::Scripting,
            spamfilter::{SpamClassifier, SpamFilterConfig, SpamLookup},
        },
        smtp::auth::DkimSigners,
    },
    ipc::TrainTaskController,
    network::security::BlockedIps,
    storage::metadata::MetadataViewerCache,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use auth::oauth::config::OAuthConfig;
use calcard::common::timezone::Tz;
use compact_str::CompactString;
use config::{
    groupware::GroupwareConfig,
    mailstore::jmap::JmapConfig,
    metadata::MetadataConfig,
    network::Network,
    smtp::{
        SmtpConfig,
        resolver::{MtaStsEntry, Tlsa},
    },
    storage::Storage,
    telemetry::Metrics,
};
use ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent, subscribers::PushSubscribers};
use mail_auth::{Mx, Negative, RecordSet, TxtRecord};
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use std::sync::atomic::AtomicU64;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock, Weak, atomic::AtomicBool},
    time::Duration,
};
use store::InMemoryStore;
use tinyvec::TinyVec;
use tokio::sync::{Notify, OnceCell, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use types::{acl::AclGrant, metadata::MetadataKinds, special_use::SpecialUse};
use utils::{
    cache::{Cache, CacheWithTtl, SpillCache},
    snowflake::SnowflakeIdGenerator,
};


pub mod audit; // inbuxa: the audit log (audit-hold-lock spec, AU)
pub mod auth;
pub mod cache;
pub mod config;
pub mod enterprise; // inbuxa: rebuilt features (AI spam classification)
pub mod expr;
pub mod hold; // inbuxa: legal holds (audit-hold-lock spec, LH)
pub mod i18n;
pub mod ipc;
pub mod manager;
pub mod network;
pub mod privacy; // inbuxa: the personal-data catalog, evaluated
pub mod reachability; // inbuxa: whether the outside world reaches each node's ports
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
7 - v1.0.0

*/

pub const DATABASE_SCHEMA_VERSION_BASE: u32 = 7;
pub const DATABASE_SCHEMA_OSS_FLAG: u32 = 1 << 31;

#[cfg(feature = "enterprise")]
pub const DATABASE_SCHEMA_VERSION: u32 = DATABASE_SCHEMA_VERSION_BASE;
#[cfg(not(feature = "enterprise"))]
pub const DATABASE_SCHEMA_VERSION: u32 = DATABASE_SCHEMA_VERSION_BASE | DATABASE_SCHEMA_OSS_FLAG;

// inbuxa: either edition's flag opens: the layout is the same, and a store
// moved over from an official Stalwart 1.0 build carries the other one
pub const fn is_current_schema(version: u32) -> bool {
    version & !DATABASE_SCHEMA_OSS_FLAG == DATABASE_SCHEMA_VERSION_BASE
}

// inbuxa: the format of what our own line adds to a store (the `_` subspace,
// permissions after upstream's last), kept beside the schema version so a
// store says which line wrote it. 1 = 27.1.
pub const INBUXA_STORE_VERSION: u32 = 1;

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
pub const KV_RATE_LIMIT_AVAILABILITY: u8 = 12;
pub const KV_GREYLIST: u8 = 13;
pub const KV_LOCK_QUEUE_MESSAGE: u8 = 14;
pub const KV_LOCK_TASK: u8 = 15;
pub const KV_LOCK_DAV: u8 = 16;
pub const KV_LOCK_SEARCH_INDEX: u8 = 17;
pub const KV_OAUTH_CIMD: u8 = 18;
pub const KV_RATE_LIMIT_CIMD: u8 = 19;
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
    pub password_verifier: directory::core::verifier::PasswordVerifier,

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
    pub memory_budget: MemoryBudget,

    // inbuxa: the objects that failed to build when the running settings
    // were built, at boot or by the last applied reload (see reload_registry)
    pub build_errors: Mutex<AHashSet<registry::types::id::ObjectId>>,

    // inbuxa: the audit log's chain heads and recent-access marks (AU)
    pub audit: inbuxa_features::audit::AuditLog,
}

#[derive(Clone)]
pub struct LogoCache {
    domain_id: u32,
    // inbuxa: MT
    tenant_id: Option<u32>,
    // inbuxa: read again when the /logo endpoint (per-tenant and per-domain
    // branding) is rebuilt; docs/spec/features/multi-tenancy.md MT-22.
    #[allow(dead_code)]
    data: Option<manager::application::Resource<Vec<u8>>>,
}

pub struct Caches {
    pub swap: crate::cache::swap::SwapTier,
    pub revalidate: crate::cache::RevalidateInterval,

    pub access_tokens: SpillCache<u32, Arc<AccessTokenInner>>,
    pub http_auth: HttpAuthEntries,
    pub grant_revocations: GrantRevocations,

    pub messages: Cache<u32, Arc<MessageStoreCache>, SwapEviction>,
    pub messages_large: LargeMessageCaches,
    pub resources_large: LargeResourceCaches,
    pub files: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub contacts: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub events: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub scheduling: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub metadata_viewers: MetadataViewerCache,

    pub emails: Cache<EmailAddress, EmailCache>,
    pub emails_negative: CacheWithTtl<EmailAddress, ()>,
    pub domain_names: Cache<CompactString, u32>,
    pub domain_names_negative: CacheWithTtl<CompactString, ()>,

    pub domains: Cache<u32, Arc<DomainCache>>,
    pub accounts: Cache<u32, Arc<AccountCache>>,
    pub roles: Cache<u32, Arc<RoleCache>>,
    // inbuxa: MT
    pub tenants: Cache<u32, Arc<TenantCache>>,
    pub lists: Cache<u32, Arc<MailingListCache>>,

    pub dkim_signers: Cache<u32, Arc<DkimSigners>>,

    /// inbuxa: message blobs this node wrote or read recently
    pub blobs: Option<storage::blob_cache::BlobCache>,

    pub dns_txt: CacheWithTtl<Box<str>, TxtRecord>,
    pub dns_mx: CacheWithTtl<Box<str>, Result<RecordSet<Mx>, Negative>>,
    pub dns_ptr: CacheWithTtl<IpAddr, Result<RecordSet<Box<str>>, Negative>>,
    pub dns_ipv4: CacheWithTtl<Box<str>, Result<RecordSet<Ipv4Addr>, Negative>>,
    pub dns_ipv6: CacheWithTtl<Box<str>, Result<RecordSet<Ipv6Addr>, Negative>>,
    pub dns_tlsa: CacheWithTtl<Box<str>, Option<Arc<Tlsa>>>,
    pub dns_mta_sts: CacheWithTtl<Box<str>, MtaStsEntry>,
    pub spam_lookup: CacheWithTtl<Box<str>, SpamLookup>,

    pub directory_recipients: CacheWithTtl<Box<str>, ()>,
    pub directory_recipients_ttl: Duration,

    pub negative_cache_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct MessageStoreCache {
    pub emails: Arc<MessagesCache>,
    pub mailboxes: Arc<MailboxesCache>,
    pub update_lock: Arc<MessageUpdateLock>,
    pub refresh: Arc<RefreshState>,
    pub last_change_id: u64,
    pub size: u64,
    pub verification: Verification,
}

#[derive(Debug, Default)]
pub struct RefreshState {
    pub deltas: Box<[ItemDelta]>,
    pub uid_next: UidNextMemo,
    pub mailbox_rows: Arc<MailboxRowsMemo>,
}

#[derive(Debug, Clone)]
pub struct ItemDelta {
    pub from_change_id: u64,
    pub to_change_id: u64,
    pub document_ids: Arc<[u32]>,
}

#[derive(Debug, Default)]
pub struct UidNextMemo {
    values: Mutex<Vec<(u32, Arc<OnceCell<u32>>)>>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MailboxRow {
    pub uid: u32,
    pub id: u32,
}

#[derive(Debug, Default)]
pub struct MailboxRowsMemo {
    entries: Mutex<Vec<SharedMailboxRows>>,
}

#[derive(Debug)]
struct SharedMailboxRows {
    mailbox_id: u32,
    emails: Weak<MessagesCache>,
    rows: Arc<Vec<MailboxRow>>,
}

#[derive(Debug, Clone)]
pub struct MailboxesCache {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Box<[MailboxCache]>,
    pub size: u64,
}

pub const CACHE_CHUNK: usize = 16384;

pub const MAX_RECEIVED_AT: u64 = u32::MAX as u64;

#[derive(Debug, Clone)]
pub struct ColBlock {
    pub(crate) document_ids: Arc<[u32]>,
    pub(crate) change_ids: Arc<[u64]>,
    pub(crate) received_at: Arc<[u32]>,
    pub(crate) sent_at: Arc<[i32]>,
    pub(crate) sizes: Arc<[u32]>,
    pub(crate) keywords: Arc<[u32]>,
    pub(crate) thread_ids: Arc<[u32]>,
    pub(crate) thread_range: ThreadRange,
    pub(crate) mb_offsets: Arc<[u32]>,
    pub(crate) mb_arena: Arc<[MessageUid]>,
}

#[derive(Debug, Clone)]
pub struct MessagesCache {
    pub change_id: u64,
    pub(crate) blocks: Vec<Arc<ColBlock>>,
    pub(crate) starts: Vec<u32>,
    pub(crate) index: IdIndex,
    pub(crate) keywords: Arc<[CustomKeywords]>,
    pub(crate) len: usize,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct CustomKeywords {
    pub names: Box<[CompactString]>,
    pub document_id: u32,
}

#[derive(Debug, Clone)]
pub struct MessageCache {
    pub(crate) document_id: u32,
    pub(crate) mailboxes: TinyVec<[MessageUid; 2]>,
    pub(crate) keywords: u32,
    pub(crate) thread_id: u32,
    pub(crate) change_id: u64,
    pub(crate) size: u32,
    pub(crate) received_at: u64,
    pub(crate) sent_at: i32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MessageUid {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct MailboxCache {
    pub document_id: u32,
    pub name: Arc<str>,
    pub path: Arc<str>,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: u32,
    pub subscribers: TinyVec<[u32; 4]>,
    pub uid_validity: u32,
    pub acls: TinyVec<[AclGrant; 2]>,
    pub metadata_kinds: MetadataKinds,
}

const _: () = assert!(size_of::<MailboxCache>() <= 136);

#[derive(Debug, Clone)]
pub struct HttpAuthCache {
    pub account_id: u32,
    pub expires: u32,
    pub credential_id: Option<u32>,
    pub revision: u64,
    pub token_scope: Option<TokenScope>,
    // inbuxa: how the cached credentials signed in (AU-5)
    pub origin: Option<Arc<inbuxa_features::audit::Via>>,
}

// inbuxa: 40 plus the audit origin pointer
const _: () = assert!(size_of::<HttpAuthCache>() <= 48);

pub struct Ipc {
    pub push_tx: mpsc::Sender<PushEvent>,
    pub push_subscribers: Arc<PushSubscribers>,
    pub task_tx: ipc::TaskQueueNotify,
    // inbuxa: task locks held by this node, released on a graceful stop
    pub task_locks: Arc<crate::ipc::TaskLocks>,
    pub index_tx: Arc<Notify>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
    pub broadcast_tx: Option<mpsc::Sender<BroadcastEvent>>,
    pub train_task_controller: Arc<TrainTaskController>,
}

impl Ipc {
    pub fn index_queue_notify(&self) -> ipc::IndexQueueNotify {
        ipc::IndexQueueNotify::new(self.index_tx.clone(), self.broadcast_tx.clone())
    }
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub struct NameWrapper(pub String);

#[derive(Debug)]
pub struct UpdateLock {
    pub semaphore: Semaphore,
    pub revision: AtomicU64,
    pub epoch: AtomicU64,
}

#[derive(Debug, Default)]
pub struct MessageUpdateLock {
    is_updating: AtomicBool,
    released: Notify,
    epoch: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Verification {
    verified_at: u64,
    epoch: u64,
}

pub const DAV_CHUNK: usize = 4096;
pub const NO_ID: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaRef {
    pub off: u32,
    pub len: u32,
}

impl ArenaRef {
    #[inline(always)]
    pub fn range(&self) -> std::ops::Range<usize> {
        self.off as usize..(self.off as usize + self.len as usize)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone)]
pub struct GroupwareResources {
    pub base_path: String,
    pub paths: Arc<PathIndex>,
    pub resources: ResourceStore,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub highest_change_id: u64,
    pub size: u64,
    pub update_lock: Arc<UpdateLock>,
    pub verification: Verification,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceStore {
    pub chunks: Vec<Arc<ResourceChunk>>,
    pub containers_end: usize,
    pub total: usize,
    pub unified_id_space: bool,
}

#[derive(Debug, Default)]
pub struct ResourceChunk {
    pub records: Box<[GroupwareResource]>,
    pub bytes: Box<[u8]>,
    pub names: Box<[CachedName]>,
    pub acls: Box<[AclGrant]>,
    pub prefs: Box<[TinyCalendarPreferences]>,
    pub principals: Box<[u32]>,
    pub uid_index: OnceLock<Box<[u64]>>,
    pub min_id: u32,
    pub max_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PathIndex {
    pub chunks: Vec<Arc<PathChunk>>,
    pub total: usize,
}

#[derive(Debug, Default)]
pub struct PathChunk {
    pub paths: Box<[DavPath]>,
    pub bytes: Box<[u8]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CachedName {
    pub name: ArenaRef,
    pub parent_id: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DavPath {
    pub path: ArenaRef,
    pub parent_id: u32,
    pub hierarchy_seq: u32,
    pub document_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupwareResource {
    pub document_id: u32,
    pub data: GroupwareResourceMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupwareResourceRef<'x> {
    pub chunk: &'x ResourceChunk,
    pub resource: &'x GroupwareResource,
}

#[derive(Debug, Clone, Copy)]
pub struct DavResourcePath<'x> {
    pub path: &'x DavPath,
    pub path_chunk: &'x PathChunk,
    pub resource: GroupwareResourceRef<'x>,
}

#[derive(Debug, Clone, Copy)]
pub enum GroupwareResourceMetadata {
    File {
        name: ArenaRef,
        size: u32,
        parent_id: u32,
        acls: ArenaRef,
        etag: u32,
        modified: i64,
        created_delta: i32,
        flags: FileFlags,
    },
    Calendar {
        name: ArenaRef,
        acls: ArenaRef,
        preferences: ArenaRef,
        etag: u32,
        metadata: MetadataKinds,
    },
    CalendarEvent {
        names: ArenaRef,
        start: i64,
        duration: u32,
        created_at: i64,
        modified_at: i32,
        uid: ArenaRef,
        etag: u32,
        flags: u16,
    },
    CalendarEventNotification {
        names: ArenaRef,
        created_at: i64,
        event_id: u32,
        etag: u32,
        changed_by: u32,
        principals: ArenaRef,
        calendar_ids_len: u16,
        flags: u16,
    },
    AddressBook {
        name: ArenaRef,
        acls: ArenaRef,
        etag: u32,
        metadata: MetadataKinds,
    },
    ContactCard {
        names: ArenaRef,
        created_at: i64,
        modified_at: i32,
        uid: ArenaRef,
        etag: u32,
        flags: u16,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileFlags(pub u32);

#[derive(Debug, Clone, Copy, Default)]
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
    pub metadata: MetadataConfig,
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

impl MessageUid {
    pub fn new(mailbox_id: u32, uid: u32) -> Self {
        MessageUid { mailbox_id, uid }
    }

    pub fn new_unassigned(mailbox_id: u32) -> Self {
        MessageUid { mailbox_id, uid: 0 }
    }
}

/// The logo embedded in calendar emails when no custom logo is set: INBUXA's
/// compact lockup at 380x80, twice its 180-pixel display width. Base64 with
/// CRLF line breaks, ready for a base64 MIME part.
pub const DEFAULT_LOGO_BASE64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/branding/email-logo.png.b64"
));
