/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod export;
pub mod ext;
pub mod import;
#[doc(hidden)]
pub mod overrides;
pub mod parser;
pub mod types;

use crate::{
    common::{
        CalendarScale, IanaString, LinkRelation, elements::Elements, jsprop::text::AsciiString,
    },
    icalendar::{
        ICalendarComponentType, ICalendarDuration, ICalendarFrequency, ICalendarMethod,
        ICalendarMonth, ICalendarSkip, ICalendarWeekday,
    },
};
use jmap_tools::{JsonPointer, Key, Map, Value};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::{borrow::Cow, fmt::Debug, fmt::Display, hash::Hash, str::FromStr};
use uuid::{Builder, fmt::Hyphenated};

pub const JSCALENDAR_VERSION: &str = "2.0";

pub(crate) const MAX_ICAL_COMPONENT_DEPTH: usize = 32;
const RFC3339_CAPACITY: usize = 21;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[repr(transparent)]
pub struct JSCalendar<'x, I: JSCalendarId, B: JSCalendarId>(
    pub Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
);

pub trait JSCalendarId:
    FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarValue<I: JSCalendarId, B: JSCalendarId> {
    Type(JSCalendarType),
    DateTime(JSCalendarDateTime),
    Duration(ICalendarDuration),
    AlertAction(JSCalendarAlertAction),
    FreeBusyStatus(JSCalendarFreeBusyStatus),
    ParticipantKind(JSCalendarParticipantKind),
    ParticipationStatus(JSCalendarParticipationStatus),
    Privacy(JSCalendarPrivacy),
    Progress(JSCalendarProgress),
    RelativeTo(JSCalendarRelativeTo),
    ScheduleAgent(JSCalendarScheduleAgent),
    EventStatus(JSCalendarEventStatus),
    LinkRelation(LinkRelation),
    Frequency(ICalendarFrequency),
    CalendarScale(CalendarScale),
    Skip(ICalendarSkip),
    Weekday(ICalendarWeekday),
    Month(ICalendarMonth),
    Method(ICalendarMethod),
    Id(I),
    BlobId(B),
    IdReference(String),
}

impl<I: JSCalendarId, B: JSCalendarId> Default for JSCalendarValue<I, B> {
    fn default() -> Self {
        JSCalendarValue::Type(JSCalendarType::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JSCalendarDateTime {
    pub timestamp: i64,
    pub is_local: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarProperty<I: JSCalendarId> {
    // JMAP for Calendar Properties
    Id,
    BaseEventId,
    CalendarIds,
    IsDraft,
    IsOrigin,
    UtcStart,
    UtcEnd,
    UseDefaultAlerts,
    MayInviteSelf,
    MayInviteOthers,
    HideAttendees,
    BlobId,
    Metadata,
    PrivateMetadata,

    // JSCalendar Properties
    #[default]
    Type,
    Acknowledged,
    Action,
    Alerts,
    ByDay,
    ByHour,
    ByMinute,
    ByMonth,
    ByMonthDay,
    BySecond,
    BySetPosition,
    ByWeekNo,
    ByYearDay,
    CalendarAddress,
    Categories,
    Color,
    ContentType,
    Coordinates,
    Count,
    Created,
    Day,
    DelegatedFrom,
    DelegatedTo,
    Description,
    DescriptionContentType,
    Display,
    Due,
    Duration,
    Email,
    Entries,
    EstimatedDuration,
    Excluded,
    ExpectReply,
    Features,
    FirstDayOfWeek,
    FreeBusyStatus,
    Frequency,
    Href,
    Interval,
    InvitedBy,
    Keywords,
    Kind,
    Links,
    Locale,
    Locations,
    LocationTypes,
    MemberOf,
    Method,
    Name,
    NthOfPeriod,
    Offset,
    Participants,
    ParticipationComment,
    ParticipationStatus,
    PercentComplete,
    Priority,
    Privacy,
    ProdId,
    Progress,
    RecurrenceId,
    RecurrenceIdTimeZone,
    RecurrenceOverrides,
    Rel,
    RelatedTo,
    Relation,
    RelativeTo,
    ReplyTo,
    RequestStatus,
    Roles,
    Rscale,
    SentBy,
    ScheduleAgent,
    ScheduleForceSend,
    ScheduleSequence,
    ScheduleStatus,
    ScheduleUpdated,
    SendTo,
    Sequence,
    ShowWithoutTime,
    Size,
    Skip,
    Source,
    Start,
    Status,
    TimeZone,
    Title,
    Trigger,
    Uid,
    Until,
    Updated,
    Uri,
    Version,
    VirtualLocations,
    When,
    EndTimeZone,
    MainLocationId,
    OrganizerCalendarAddress,
    RecurrenceRule,
    ICalendar,
    Properties,
    Parameters,
    ConvertedProperties,
    ValueType,
    Components,
    DateTime(JSCalendarDateTime),
    LinkDisplay(JSCalendarLinkDisplay),
    VirtualLocationFeature(JSCalendarVirtualLocationFeature),
    ParticipantRole(JSCalendarParticipantRole),
    RelationValue(JSCalendarRelation),
    LinkRelation(LinkRelation),
    Pointer(JsonPointer<JSCalendarProperty<I>>),
    IdValue(I),
    IdReference(String),
}

impl<T> JSCalendarId for T where
    T: FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

impl<I: JSCalendarId> From<I> for JSCalendarProperty<I> {
    fn from(id: I) -> Self {
        JSCalendarProperty::IdValue(id)
    }
}

impl<I: JSCalendarId, B: JSCalendarId> From<I> for JSCalendarValue<I, B> {
    fn from(id: I) -> Self {
        JSCalendarValue::Id(id)
    }
}

impl<'x, I: JSCalendarId, B: JSCalendarId> Default for JSCalendar<'x, I, B> {
    fn default() -> Self {
        Self(Value::Object(Map::from(vec![
            (
                Key::Property(JSCalendarProperty::Type),
                Value::Element(JSCalendarValue::Type(JSCalendarType::Group)),
            ),
            (
                Key::Property(JSCalendarProperty::Entries),
                Value::Array(vec![]),
            ),
        ])))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarType {
    #[default]
    Event,
    Task,
    Group,
    Alert,
    Boolean,
    Duration,
    Id,
    Int,
    LocalDateTime,
    Link,
    Location,
    NDay,
    Number,
    Participant,
    PatchObject,
    RecurrenceRule,
    Relation,
    SignedDuration,
    String,
    TimeZone,
    TimeZoneId,
    TimeZoneRule,
    UnsignedInt,
    UTCDateTime,
    VirtualLocation,
    ICalComponent,
    OffsetTrigger,
    AbsoluteTrigger,
}

// JSCalendar Enum Values for action (Context: Alert)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarAlertAction {
    Display,
    Email,
}

// JSCalendar Enum Values for display (Context: Link)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarLinkDisplay {
    Badge,
    Graphic,
    Fullsize,
    Thumbnail,
}

// JSCalendar Enum Values for features (Context: VirtualLocation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarVirtualLocationFeature {
    Audio,
    Chat,
    Feed,
    Moderator,
    Phone,
    Screen,
    Video,
}

// JSCalendar Enum Values for freeBusyStatus (Context: Event, Task)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarFreeBusyStatus {
    Free,
    Busy,
}

// JSCalendar Enum Values for kind (Context: Participant)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarParticipantKind {
    Individual,
    Group,
    Resource,
    Location,
}

// JSCalendar Enum Values for participationStatus (Context: Participant)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarParticipationStatus {
    NeedsAction,
    Accepted,
    Declined,
    Tentative,
    Delegated,
}

// JSCalendar Enum Values for privacy (Context: Event, Task)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarPrivacy {
    Public,
    Private,
    Secret,
}

// JSCalendar Enum Values for progress (Context: Task, Participant)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarProgress {
    NeedsAction,
    InProcess,
    Completed,
    Failed,
    Cancelled,
}

// JSCalendar Enum Values for relation (Context: Relation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarRelation {
    First,
    Next,
    Child,
    Parent,
    Snooze,
}

// JSCalendar Enum Values for relativeTo (Context: OffsetTrigger, Location)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarRelativeTo {
    Start,
    End,
}

// JSCalendar Enum Values for roles (Context: Participant)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarParticipantRole {
    Owner,
    Optional,
    Informational,
    Chair,
    Required,
}

// JSCalendar Enum Values for scheduleAgent (Context: Participant)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarScheduleAgent {
    Server,
    Client,
    None,
}

// JSCalendar Enum Values for status (Context: Event)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSCalendarEventStatus {
    Confirmed,
    Cancelled,
    Tentative,
}

impl JSCalendarDateTime {
    pub fn new(timestamp: i64, is_local: bool) -> Self {
        Self {
            timestamp,
            is_local,
        }
    }

    pub fn is_start_of_day(&self) -> bool {
        self.timestamp.rem_euclid(86400) == 0
    }

    pub fn to_rfc3339(&self) -> String {
        let mut text = AsciiString::with_capacity(RFC3339_CAPACITY);
        let _ = self.push_rfc3339(&mut text);
        text.into_string()
    }
}

impl<I: JSCalendarId, B: JSCalendarId> JSCalendar<'_, I, B> {
    pub fn blob_ids(&self) -> impl Iterator<Item = &B> {
        Elements::new(&self.0).filter_map(|element| match element {
            JSCalendarValue::BlobId(blob_id) => Some(blob_id),
            _ => None,
        })
    }
}

impl ICalendarComponentType {
    pub fn to_jscalendar_type(&self) -> Option<JSCalendarType> {
        match &self {
            ICalendarComponentType::VCalendar => Some(JSCalendarType::Group),
            ICalendarComponentType::VEvent => Some(JSCalendarType::Event),
            ICalendarComponentType::VTodo => Some(JSCalendarType::Task),
            ICalendarComponentType::VAlarm => Some(JSCalendarType::Alert),
            ICalendarComponentType::Participant => Some(JSCalendarType::Participant),
            ICalendarComponentType::VLocation => Some(JSCalendarType::Location),
            ICalendarComponentType::Standard
            | ICalendarComponentType::Daylight
            | ICalendarComponentType::VAvailability
            | ICalendarComponentType::Available
            | ICalendarComponentType::VResource
            | ICalendarComponentType::VStatus
            | ICalendarComponentType::VJournal
            | ICalendarComponentType::VFreebusy
            | ICalendarComponentType::VTimezone
            | ICalendarComponentType::Other(_) => None,
        }
    }
}

impl JSCalendarType {
    pub fn to_icalendar_component_type(&self) -> Option<ICalendarComponentType> {
        match &self {
            JSCalendarType::Group => Some(ICalendarComponentType::VCalendar),
            JSCalendarType::Event => Some(ICalendarComponentType::VEvent),
            JSCalendarType::Task => Some(ICalendarComponentType::VTodo),
            JSCalendarType::Alert => Some(ICalendarComponentType::VAlarm),
            JSCalendarType::Participant => Some(ICalendarComponentType::Participant),
            JSCalendarType::Location => Some(ICalendarComponentType::VLocation),
            _ => None,
        }
    }
}

// 7f1e1965-ae73-4454-b088-232c90730ce2
static JSCAL_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    127, 30, 25, 101, 174, 115, 68, 84, 176, 136, 35, 44, 144, 115, 12, 226,
]);

pub(crate) trait Uuid5 {
    fn uuid5_hyphenated<'b>(&self, buffer: &'b mut [u8; Hyphenated::LENGTH]) -> &'b str;
}

#[inline]
pub fn uuid5(text: impl AsRef<[u8]>) -> String {
    let mut buffer = [0u8; Hyphenated::LENGTH];
    text.as_ref().uuid5_hyphenated(&mut buffer).to_string()
}

impl Uuid5 for [u8] {
    #[inline]
    fn uuid5_hyphenated<'b>(&self, buffer: &'b mut [u8; Hyphenated::LENGTH]) -> &'b str {
        let digest: [u8; 20] = Sha1::new()
            .chain_update(JSCAL_NAMESPACE.as_bytes())
            .chain_update(self)
            .finalize()
            .into();
        let [bytes @ .., _, _, _, _] = digest;
        Builder::from_sha1_bytes(bytes)
            .into_uuid()
            .hyphenated()
            .encode_lower(buffer)
    }
}

#[cfg(all(test, stalwart_tests))]
impl<I: JSCalendarId, B: JSCalendarId> std::fmt::Display for JSCalendar<'_, I, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string_pretty(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s)
    }
}

impl<I: JSCalendarId> Display for JSCalendarProperty<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_ref())
    }
}

