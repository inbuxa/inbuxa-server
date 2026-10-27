/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    SCOPE_CALENDARS, SCOPE_CONTACTS, SCOPE_FILES, SCOPE_MAIL, SCOPE_OFFLINE_ACCESS, SCOPE_OPENID,
};
use crate::auth::{GrantClient, Permissions, TokenScope};
use directory::backend::oidc::ExternalScopes;
use registry::{
    schema::enums::{OAuthScope, Permission},
    types::map::Map,
};
use std::ops::{BitAnd, BitOr, BitOrAssign};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(transparent)]
pub struct OAuthScopes(u8);

const SCOPE_NAMES: [(OAuthScopes, &str); 6] = [
    (OAuthScopes::OPENID, SCOPE_OPENID),
    (OAuthScopes::OFFLINE_ACCESS, SCOPE_OFFLINE_ACCESS),
    (OAuthScopes::MAIL, SCOPE_MAIL),
    (OAuthScopes::CONTACTS, SCOPE_CONTACTS),
    (OAuthScopes::CALENDARS, SCOPE_CALENDARS),
    (OAuthScopes::FILES, SCOPE_FILES),
];

const INTEROPERABLE_SHIFT: u32 = 2;
const INTEROPERABLE_COMBINATIONS: usize = 1 << 4;

impl OAuthScopes {
    pub const NONE: Self = Self(0);
    pub const OPENID: Self = Self(1 << 0);
    pub const OFFLINE_ACCESS: Self = Self(1 << 1);
    pub const MAIL: Self = Self(1 << 2);
    pub const CONTACTS: Self = Self(1 << 3);
    pub const CALENDARS: Self = Self(1 << 4);
    pub const FILES: Self = Self(1 << 5);
    pub const ALWAYS_ALLOWED: Self = Self(Self::OPENID.0 | Self::OFFLINE_ACCESS.0);
    pub const INTEROPERABLE: Self =
        Self(Self::MAIL.0 | Self::CONTACTS.0 | Self::CALENDARS.0 | Self::FILES.0);
    pub const ALL: Self = Self(Self::ALWAYS_ALLOWED.0 | Self::INTEROPERABLE.0);
    pub const DAV: Self = Self(Self::CONTACTS.0 | Self::CALENDARS.0 | Self::FILES.0);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn from_external(scopes: ExternalScopes) -> Self {
        Self((scopes.bits() << INTEROPERABLE_SHIFT) & Self::INTEROPERABLE.0)
    }

    pub fn from_name(name: &str) -> Self {
        hashify::map!(
            name.as_bytes(),
            OAuthScopes,
            "openid" => OAuthScopes::OPENID,
            "offline_access" => OAuthScopes::OFFLINE_ACCESS,
            "urn:ietf:params:oauth:scope:mail" => OAuthScopes::MAIL,
            "urn:ietf:params:oauth:scope:contacts" => OAuthScopes::CONTACTS,
            "urn:ietf:params:oauth:scope:calendars" => OAuthScopes::CALENDARS,
            "urn:ietf:params:oauth:scope:files" => OAuthScopes::FILES,
        )
        .copied()
        .unwrap_or_default()
    }

    pub fn parse(scope: &str) -> Self {
        scope
            .split_ascii_whitespace()
            .fold(Self::NONE, |scopes, name| scopes | Self::from_name(name))
    }

    pub fn from_registry<'x>(scopes: impl IntoIterator<Item = &'x OAuthScope>) -> Self {
        scopes
            .into_iter()
            .fold(Self::NONE, |acc, scope| acc | Self::from(*scope))
    }

    pub fn to_registry(self) -> Map<OAuthScope> {
        Map::new(
            [
                (Self::MAIL, OAuthScope::Mail),
                (Self::CONTACTS, OAuthScope::Contacts),
                (Self::CALENDARS, OAuthScope::Calendars),
                (Self::FILES, OAuthScope::Files),
            ]
            .into_iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, scope)| scope)
            .collect(),
        )
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn interoperable(self) -> Self {
        Self(self.0 & Self::INTEROPERABLE.0)
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        SCOPE_NAMES
            .into_iter()
            .filter(move |(bit, _)| self.contains(*bit))
            .map(|(_, name)| name)
    }

    pub fn to_wire(self) -> String {
        let mut out = String::with_capacity(128);
        for name in self.names() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(name);
        }
        out
    }

    const fn interoperable_index(self) -> usize {
        ((self.0 & Self::INTEROPERABLE.0) >> INTEROPERABLE_SHIFT) as usize
    }
}

impl From<OAuthScope> for OAuthScopes {
    fn from(scope: OAuthScope) -> Self {
        match scope {
            OAuthScope::Mail => Self::MAIL,
            OAuthScope::Contacts => Self::CONTACTS,
            OAuthScope::Calendars => Self::CALENDARS,
            OAuthScope::Files => Self::FILES,
        }
    }
}

impl BitOr for OAuthScopes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for OAuthScopes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for OAuthScopes {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

macro_rules! permission_scopes {
    ($($scopes:expr => [$($permission:ident),+ $(,)?]),+ $(,)?) => {
        pub const fn permission_scopes(permission: Permission) -> OAuthScopes {
            match permission {
                $($(Permission::$permission)|+ => $scopes,)+
                _ => OAuthScopes::NONE,
            }
        }

        static SCOPE_PERMISSIONS: [Permissions; INTEROPERABLE_COMBINATIONS] = {
            let mut table = [const { Permissions::new() }; INTEROPERABLE_COMBINATIONS];
            $($(insert_scoped(&mut table, Permission::$permission as usize, $scopes);)+)+
            table
        };
    };
}

permission_scopes!(
    OAuthScopes::ALL => [
        Authenticate,
        AuthenticateWithAlias,
    ],
    OAuthScopes::MAIL => [
        EmailSend,
        EmailReceive,
        JmapMailboxGet,
        JmapMailboxChanges,
        JmapMailboxQuery,
        JmapMailboxQueryChanges,
        JmapMailboxCreate,
        JmapMailboxUpdate,
        JmapMailboxDestroy,
        JmapThreadGet,
        JmapThreadChanges,
        JmapEmailGet,
        JmapEmailChanges,
        JmapEmailQuery,
        JmapEmailQueryChanges,
        JmapEmailCreate,
        JmapEmailUpdate,
        JmapEmailDestroy,
        JmapEmailCopy,
        JmapEmailImport,
        JmapEmailParse,
        JmapSearchSnippetGet,
        JmapIdentityGet,
        JmapIdentityChanges,
        JmapIdentityCreate,
        JmapIdentityUpdate,
        JmapIdentityDestroy,
        JmapEmailSubmissionGet,
        JmapEmailSubmissionChanges,
        JmapEmailSubmissionQuery,
        JmapEmailSubmissionQueryChanges,
        JmapEmailSubmissionCreate,
        JmapEmailSubmissionUpdate,
        JmapEmailSubmissionDestroy,
        JmapVacationResponseGet,
        JmapVacationResponseCreate,
        JmapVacationResponseUpdate,
        JmapVacationResponseDestroy,
        JmapSieveScriptGet,
        JmapSieveScriptQuery,
        JmapSieveScriptValidate,
        JmapSieveScriptCreate,
        JmapSieveScriptUpdate,
        JmapSieveScriptDestroy,
        ImapAuthenticate,
        ImapAclGet,
        ImapAclSet,
        ImapMyRights,
        ImapListRights,
        ImapAppend,
        ImapCapability,
        ImapId,
        ImapCopy,
        ImapMove,
        ImapCreate,
        ImapDelete,
        ImapEnable,
        ImapExpunge,
        ImapFetch,
        ImapIdle,
        ImapList,
        ImapLsub,
        ImapNamespace,
        ImapRename,
        ImapSearch,
        ImapSort,
        ImapSelect,
        ImapExamine,
        ImapStatus,
        ImapStore,
        ImapSubscribe,
        ImapThread,
        ImapMetadataGet,
        ImapMetadataSet,
        ImapMetadataPrivate,
        Pop3Authenticate,
        Pop3List,
        Pop3Uidl,
        Pop3Stat,
        Pop3Retr,
        Pop3Dele,
        SieveAuthenticate,
        SieveListScripts,
        SieveSetActive,
        SieveGetScript,
        SievePutScript,
        SieveDeleteScript,
        SieveRenameScript,
        SieveCheckScript,
        SieveHaveSpace,
    ],
    OAuthScopes::CALENDARS => [
        CalendarAlarmsSend,
        CalendarSchedulingSend,
        CalendarSchedulingReceive,
        JmapPrincipalGetAvailability,
        JmapCalendarGet,
        JmapCalendarChanges,
        JmapCalendarCreate,
        JmapCalendarUpdate,
        JmapCalendarDestroy,
        JmapCalendarEventGet,
        JmapCalendarEventChanges,
        JmapCalendarEventQuery,
        JmapCalendarEventQueryChanges,
        JmapCalendarEventCreate,
        JmapCalendarEventUpdate,
        JmapCalendarEventDestroy,
        JmapCalendarEventCopy,
        JmapCalendarEventParse,
        JmapCalendarEventNotificationGet,
        JmapCalendarEventNotificationChanges,
        JmapCalendarEventNotificationQuery,
        JmapCalendarEventNotificationQueryChanges,
        JmapCalendarEventNotificationCreate,
        JmapCalendarEventNotificationUpdate,
        JmapCalendarEventNotificationDestroy,
        JmapParticipantIdentityGet,
        JmapParticipantIdentityChanges,
        JmapParticipantIdentityCreate,
        JmapParticipantIdentityUpdate,
        JmapParticipantIdentityDestroy,
        DavCalPropFind,
        DavCalPropPatch,
        DavCalGet,
        DavCalMkCol,
        DavCalDelete,
        DavCalPut,
        DavCalCopy,
        DavCalMove,
        DavCalLock,
        DavCalAcl,
        DavCalQuery,
        DavCalMultiGet,
        DavCalFreeBusyQuery,
    ],
    OAuthScopes::INTEROPERABLE => [
        JmapPushSubscriptionGet,
        JmapPushSubscriptionCreate,
        JmapPushSubscriptionUpdate,
        JmapPushSubscriptionDestroy,
        JmapPrincipalGet,
        JmapPrincipalQuery,
        JmapPrincipalChanges,
        JmapPrincipalQueryChanges,
        JmapQuotaGet,
        JmapQuotaChanges,
        JmapQuotaQuery,
        JmapQuotaQueryChanges,
        JmapBlobGet,
        JmapBlobCopy,
        JmapBlobLookup,
        JmapBlobUpload,
        JmapShareNotificationGet,
        JmapShareNotificationChanges,
        JmapShareNotificationQuery,
        JmapShareNotificationQueryChanges,
        JmapShareNotificationCreate,
        JmapShareNotificationUpdate,
        JmapShareNotificationDestroy,
        JmapCoreEcho,
        JmapMetadataGet,
        JmapMetadataSet,
        JmapMetadataPrivate,
    ],
    OAuthScopes::CONTACTS => [
        JmapAddressBookGet,
        JmapAddressBookChanges,
        JmapAddressBookCreate,
        JmapAddressBookUpdate,
        JmapAddressBookDestroy,
        JmapContactCardGet,
        JmapContactCardChanges,
        JmapContactCardQuery,
        JmapContactCardQueryChanges,
        JmapContactCardCreate,
        JmapContactCardUpdate,
        JmapContactCardDestroy,
        JmapContactCardCopy,
        JmapContactCardParse,
        DavCardPropFind,
        DavCardPropPatch,
        DavCardGet,
        DavCardMkCol,
        DavCardDelete,
        DavCardPut,
        DavCardCopy,
        DavCardMove,
        DavCardLock,
        DavCardAcl,
        DavCardQuery,
        DavCardMultiGet,
    ],
    OAuthScopes::FILES => [
        JmapFileNodeGet,
        JmapFileNodeChanges,
        JmapFileNodeQuery,
        JmapFileNodeQueryChanges,
        JmapFileNodeCreate,
        JmapFileNodeUpdate,
        JmapFileNodeDestroy,
        JmapFileNodeCopy,
        DavFilePropFind,
        DavFilePropPatch,
        DavFileGet,
        DavFileMkCol,
        DavFileDelete,
        DavFilePut,
        DavFileCopy,
        DavFileMove,
        DavFileLock,
        DavFileAcl,
    ],
    OAuthScopes::DAV => [
        DavSyncCollection,
        DavExpandProperty,
        DavPrincipalAcl,
        DavPrincipalList,
        DavPrincipalMatch,
        DavPrincipalSearch,
        DavPrincipalSearchPropSet,
    ],
);

const fn insert_scoped(
    table: &mut [Permissions; INTEROPERABLE_COMBINATIONS],
    permission: usize,
    scopes: OAuthScopes,
) {
    let always = scopes.intersects(OAuthScopes::OPENID);
    let mut idx = 0;
    while idx < INTEROPERABLE_COMBINATIONS {
        if always || OAuthScopes((idx as u8) << INTEROPERABLE_SHIFT).intersects(scopes) {
            table[idx].insert(permission);
        }
        idx += 1;
    }
}

pub fn scope_permissions(scopes: OAuthScopes) -> &'static Permissions {
    &SCOPE_PERMISSIONS[scopes.interoperable_index()]
}

impl TokenScope {
    #[inline]
    pub const fn grant_id(self) -> Option<u64> {
        match self {
            TokenScope::Grant { grant_id, .. } => Some(grant_id),
            TokenScope::External { .. } => None,
        }
    }

    #[inline]
    pub const fn restricted_scopes(self) -> Option<OAuthScopes> {
        match self {
            TokenScope::Grant {
                client: GrantClient::FirstParty,
                ..
            } => None,
            TokenScope::Grant { scopes, .. } | TokenScope::External { scopes } => Some(scopes),
        }
    }

    #[inline]
    pub fn permissions(self) -> Option<&'static Permissions> {
        self.restricted_scopes().map(scope_permissions)
    }
}

macro_rules! data_type_scopes {
    ($($scopes:expr => [$($data_type:ident),+ $(,)?]),+ $(,)?) => {
        pub const fn data_type_scopes(data_type: DataType) -> OAuthScopes {
            match data_type {
                $($(DataType::$data_type)|+ => $scopes,)+
                DataType::None => OAuthScopes::NONE,
            }
        }

        static SCOPE_DATA_TYPES: [u64; INTEROPERABLE_COMBINATIONS] = {
            let mut table = [0u64; INTEROPERABLE_COMBINATIONS];
            $($(insert_data_type(&mut table, DataType::$data_type as u64, $scopes);)+)+
            table
        };
    };
}

data_type_scopes!(
    OAuthScopes::MAIL => [
        Email,
        EmailDelivery,
        EmailSubmission,
        Mailbox,
        Thread,
        Identity,
        SearchSnippet,
        VacationResponse,
        Mdn,
        SieveScript,
    ],
    OAuthScopes::CALENDARS => [
        Calendar,
        CalendarEvent,
        CalendarEventNotification,
        ParticipantIdentity,
        CalendarAlert,
    ],
    OAuthScopes::CONTACTS => [AddressBook, ContactCard],
    OAuthScopes::FILES => [FileNode],
    OAuthScopes::INTEROPERABLE => [
        Core,
        PushSubscription,
        Quota,
        Principal,
        ShareNotification,
    ],
);

const fn insert_data_type(
    table: &mut [u64; INTEROPERABLE_COMBINATIONS],
    data_type: u64,
    scopes: OAuthScopes,
) {
    let mut idx = 0;
    while idx < INTEROPERABLE_COMBINATIONS {
        if OAuthScopes((idx as u8) << INTEROPERABLE_SHIFT).intersects(scopes) {
            table[idx] |= 1 << data_type;
        }
        idx += 1;
    }
}

pub fn scope_data_types(scopes: OAuthScopes) -> Bitmap<DataType> {
    Bitmap::from_bits(SCOPE_DATA_TYPES[scopes.interoperable_index()])
}

