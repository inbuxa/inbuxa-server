/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{Entry, Parser};
use jiff::civil::Weekday;
use std::borrow::Cow;

impl IanaParse for ICalendarProperty {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "CALSCALE" => Some(ICalendarProperty::Calscale),
            "METHOD" => Some(ICalendarProperty::Method),
            "PRODID" => Some(ICalendarProperty::Prodid),
            "VERSION" => Some(ICalendarProperty::Version),
            "ATTACH" => Some(ICalendarProperty::Attach),
            "CATEGORIES" => Some(ICalendarProperty::Categories),
            "CLASS" => Some(ICalendarProperty::Class),
            "COMMENT" => Some(ICalendarProperty::Comment),
            "DESCRIPTION" => Some(ICalendarProperty::Description),
            "GEO" => Some(ICalendarProperty::Geo),
            "LOCATION" => Some(ICalendarProperty::Location),
            "PERCENT-COMPLETE" => Some(ICalendarProperty::PercentComplete),
            "PRIORITY" => Some(ICalendarProperty::Priority),
            "RESOURCES" => Some(ICalendarProperty::Resources),
            "STATUS" => Some(ICalendarProperty::Status),
            "SUMMARY" => Some(ICalendarProperty::Summary),
            "COMPLETED" => Some(ICalendarProperty::Completed),
            "DTEND" => Some(ICalendarProperty::Dtend),
            "DUE" => Some(ICalendarProperty::Due),
            "DTSTART" => Some(ICalendarProperty::Dtstart),
            "DURATION" => Some(ICalendarProperty::Duration),
            "FREEBUSY" => Some(ICalendarProperty::Freebusy),
            "TRANSP" => Some(ICalendarProperty::Transp),
            "TZID" => Some(ICalendarProperty::Tzid),
            "TZNAME" => Some(ICalendarProperty::Tzname),
            "TZOFFSETFROM" => Some(ICalendarProperty::Tzoffsetfrom),
            "TZOFFSETTO" => Some(ICalendarProperty::Tzoffsetto),
            "TZURL" => Some(ICalendarProperty::Tzurl),
            "ATTENDEE" => Some(ICalendarProperty::Attendee),
            "CONTACT" => Some(ICalendarProperty::Contact),
            "ORGANIZER" => Some(ICalendarProperty::Organizer),
            "RECURRENCE-ID" => Some(ICalendarProperty::RecurrenceId),
            "RELATED-TO" => Some(ICalendarProperty::RelatedTo),
            "URL" => Some(ICalendarProperty::Url),
            "UID" => Some(ICalendarProperty::Uid),
            "EXDATE" => Some(ICalendarProperty::Exdate),
            "EXRULE" => Some(ICalendarProperty::Exrule),
            "RDATE" => Some(ICalendarProperty::Rdate),
            "RRULE" => Some(ICalendarProperty::Rrule),
            "ACTION" => Some(ICalendarProperty::Action),
            "REPEAT" => Some(ICalendarProperty::Repeat),
            "TRIGGER" => Some(ICalendarProperty::Trigger),
            "CREATED" => Some(ICalendarProperty::Created),
            "DTSTAMP" => Some(ICalendarProperty::Dtstamp),
            "LAST-MODIFIED" => Some(ICalendarProperty::LastModified),
            "SEQUENCE" => Some(ICalendarProperty::Sequence),
            "REQUEST-STATUS" => Some(ICalendarProperty::RequestStatus),
            "XML" => Some(ICalendarProperty::Xml),
            "TZUNTIL" => Some(ICalendarProperty::Tzuntil),
            "TZID-ALIAS-OF" => Some(ICalendarProperty::TzidAliasOf),
            "BUSYTYPE" => Some(ICalendarProperty::Busytype),
            "NAME" => Some(ICalendarProperty::Name),
            "REFRESH-INTERVAL" => Some(ICalendarProperty::RefreshInterval),
            "SOURCE" => Some(ICalendarProperty::Source),
            "COLOR" => Some(ICalendarProperty::Color),
            "IMAGE" => Some(ICalendarProperty::Image),
            "CONFERENCE" => Some(ICalendarProperty::Conference),
            "CALENDAR-ADDRESS" => Some(ICalendarProperty::CalendarAddress),
            "LOCATION-TYPE" => Some(ICalendarProperty::LocationType),
            "PARTICIPANT-TYPE" => Some(ICalendarProperty::ParticipantType),
            "RESOURCE-TYPE" => Some(ICalendarProperty::ResourceType),
            "STRUCTURED-DATA" => Some(ICalendarProperty::StructuredData),
            "STYLED-DESCRIPTION" => Some(ICalendarProperty::StyledDescription),
            "ACKNOWLEDGED" => Some(ICalendarProperty::Acknowledged),
            "PROXIMITY" => Some(ICalendarProperty::Proximity),
            "CONCEPT" => Some(ICalendarProperty::Concept),
            "LINK" => Some(ICalendarProperty::Link),
            "REFID" => Some(ICalendarProperty::Refid),
            "COORDINATES" => Some(ICalendarProperty::Coordinates),
            "SHOW-WITHOUT-TIME" => Some(ICalendarProperty::ShowWithoutTime),
            "JSID" => Some(ICalendarProperty::Jsid),
            "JSPROP" => Some(ICalendarProperty::Jsprop),
            "BEGIN" => Some(ICalendarProperty::Begin),
            "END" => Some(ICalendarProperty::End),
            "ESTIMATED-DURATION" => Some(ICalendarProperty::EstimatedDuration),
            "REASON" => Some(ICalendarProperty::Reason),
            "SUBSTATE" => Some(ICalendarProperty::Substate),
            "TASK-MODE" => Some(ICalendarProperty::TaskMode),
            _ => None,
        )
    }
}

impl ICalendarProperty {
    pub fn as_str(&self) -> &str {
        match self {
            ICalendarProperty::Calscale => "CALSCALE",
            ICalendarProperty::Method => "METHOD",
            ICalendarProperty::Prodid => "PRODID",
            ICalendarProperty::Version => "VERSION",
            ICalendarProperty::Attach => "ATTACH",
            ICalendarProperty::Categories => "CATEGORIES",
            ICalendarProperty::Class => "CLASS",
            ICalendarProperty::Comment => "COMMENT",
            ICalendarProperty::Description => "DESCRIPTION",
            ICalendarProperty::Geo => "GEO",
            ICalendarProperty::Location => "LOCATION",
            ICalendarProperty::PercentComplete => "PERCENT-COMPLETE",
            ICalendarProperty::Priority => "PRIORITY",
            ICalendarProperty::Resources => "RESOURCES",
            ICalendarProperty::Status => "STATUS",
            ICalendarProperty::Summary => "SUMMARY",
            ICalendarProperty::Completed => "COMPLETED",
            ICalendarProperty::Dtend => "DTEND",
            ICalendarProperty::Due => "DUE",
            ICalendarProperty::Dtstart => "DTSTART",
            ICalendarProperty::Duration => "DURATION",
            ICalendarProperty::Freebusy => "FREEBUSY",
            ICalendarProperty::Transp => "TRANSP",
            ICalendarProperty::Tzid => "TZID",
            ICalendarProperty::Tzname => "TZNAME",
            ICalendarProperty::Tzoffsetfrom => "TZOFFSETFROM",
            ICalendarProperty::Tzoffsetto => "TZOFFSETTO",
            ICalendarProperty::Tzurl => "TZURL",
            ICalendarProperty::Attendee => "ATTENDEE",
            ICalendarProperty::Contact => "CONTACT",
            ICalendarProperty::Organizer => "ORGANIZER",
            ICalendarProperty::RecurrenceId => "RECURRENCE-ID",
            ICalendarProperty::RelatedTo => "RELATED-TO",
            ICalendarProperty::Url => "URL",
            ICalendarProperty::Uid => "UID",
            ICalendarProperty::Exdate => "EXDATE",
            ICalendarProperty::Exrule => "EXRULE",
            ICalendarProperty::Rdate => "RDATE",
            ICalendarProperty::Rrule => "RRULE",
            ICalendarProperty::Action => "ACTION",
            ICalendarProperty::Repeat => "REPEAT",
            ICalendarProperty::Trigger => "TRIGGER",
            ICalendarProperty::Created => "CREATED",
            ICalendarProperty::Dtstamp => "DTSTAMP",
            ICalendarProperty::LastModified => "LAST-MODIFIED",
            ICalendarProperty::Sequence => "SEQUENCE",
            ICalendarProperty::RequestStatus => "REQUEST-STATUS",
            ICalendarProperty::Xml => "XML",
            ICalendarProperty::Tzuntil => "TZUNTIL",
            ICalendarProperty::TzidAliasOf => "TZID-ALIAS-OF",
            ICalendarProperty::Busytype => "BUSYTYPE",
            ICalendarProperty::Name => "NAME",
            ICalendarProperty::RefreshInterval => "REFRESH-INTERVAL",
            ICalendarProperty::Source => "SOURCE",
            ICalendarProperty::Color => "COLOR",
            ICalendarProperty::Image => "IMAGE",
            ICalendarProperty::Conference => "CONFERENCE",
            ICalendarProperty::CalendarAddress => "CALENDAR-ADDRESS",
            ICalendarProperty::LocationType => "LOCATION-TYPE",
            ICalendarProperty::ParticipantType => "PARTICIPANT-TYPE",
            ICalendarProperty::ResourceType => "RESOURCE-TYPE",
            ICalendarProperty::StructuredData => "STRUCTURED-DATA",
            ICalendarProperty::StyledDescription => "STYLED-DESCRIPTION",
            ICalendarProperty::Acknowledged => "ACKNOWLEDGED",
            ICalendarProperty::Proximity => "PROXIMITY",
            ICalendarProperty::Concept => "CONCEPT",
            ICalendarProperty::Link => "LINK",
            ICalendarProperty::Refid => "REFID",
            ICalendarProperty::Begin => "BEGIN",
            ICalendarProperty::End => "END",
            ICalendarProperty::Coordinates => "COORDINATES",
            ICalendarProperty::ShowWithoutTime => "SHOW-WITHOUT-TIME",
            ICalendarProperty::Jsid => "JSID",
            ICalendarProperty::Jsprop => "JSPROP",
            ICalendarProperty::EstimatedDuration => "ESTIMATED-DURATION",
            ICalendarProperty::Reason => "REASON",
            ICalendarProperty::Substate => "SUBSTATE",
            ICalendarProperty::TaskMode => "TASK-MODE",
            ICalendarProperty::Other(s) => s.as_str(),
        }
    }

    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ICalendarProperty::Calscale => "CALSCALE",
            ICalendarProperty::Method => "METHOD",
            ICalendarProperty::Prodid => "PRODID",
            ICalendarProperty::Version => "VERSION",
            ICalendarProperty::Attach => "ATTACH",
            ICalendarProperty::Categories => "CATEGORIES",
            ICalendarProperty::Class => "CLASS",
            ICalendarProperty::Comment => "COMMENT",
            ICalendarProperty::Description => "DESCRIPTION",
            ICalendarProperty::Geo => "GEO",
            ICalendarProperty::Location => "LOCATION",
            ICalendarProperty::PercentComplete => "PERCENT-COMPLETE",
            ICalendarProperty::Priority => "PRIORITY",
            ICalendarProperty::Resources => "RESOURCES",
            ICalendarProperty::Status => "STATUS",
            ICalendarProperty::Summary => "SUMMARY",
            ICalendarProperty::Completed => "COMPLETED",
            ICalendarProperty::Dtend => "DTEND",
            ICalendarProperty::Due => "DUE",
            ICalendarProperty::Dtstart => "DTSTART",
            ICalendarProperty::Duration => "DURATION",
            ICalendarProperty::Freebusy => "FREEBUSY",
            ICalendarProperty::Transp => "TRANSP",
            ICalendarProperty::Tzid => "TZID",
            ICalendarProperty::Tzname => "TZNAME",
            ICalendarProperty::Tzoffsetfrom => "TZOFFSETFROM",
            ICalendarProperty::Tzoffsetto => "TZOFFSETTO",
            ICalendarProperty::Tzurl => "TZURL",
            ICalendarProperty::Attendee => "ATTENDEE",
            ICalendarProperty::Contact => "CONTACT",
            ICalendarProperty::Organizer => "ORGANIZER",
            ICalendarProperty::RecurrenceId => "RECURRENCE-ID",
            ICalendarProperty::RelatedTo => "RELATED-TO",
            ICalendarProperty::Url => "URL",
            ICalendarProperty::Uid => "UID",
            ICalendarProperty::Exdate => "EXDATE",
            ICalendarProperty::Exrule => "EXRULE",
            ICalendarProperty::Rdate => "RDATE",
            ICalendarProperty::Rrule => "RRULE",
            ICalendarProperty::Action => "ACTION",
            ICalendarProperty::Repeat => "REPEAT",
            ICalendarProperty::Trigger => "TRIGGER",
            ICalendarProperty::Created => "CREATED",
            ICalendarProperty::Dtstamp => "DTSTAMP",
            ICalendarProperty::LastModified => "LAST-MODIFIED",
            ICalendarProperty::Sequence => "SEQUENCE",
            ICalendarProperty::RequestStatus => "REQUEST-STATUS",
            ICalendarProperty::Xml => "XML",
            ICalendarProperty::Tzuntil => "TZUNTIL",
            ICalendarProperty::TzidAliasOf => "TZID-ALIAS-OF",
            ICalendarProperty::Busytype => "BUSYTYPE",
            ICalendarProperty::Name => "NAME",
            ICalendarProperty::RefreshInterval => "REFRESH-INTERVAL",
            ICalendarProperty::Source => "SOURCE",
            ICalendarProperty::Color => "COLOR",
            ICalendarProperty::Image => "IMAGE",
            ICalendarProperty::Conference => "CONFERENCE",
            ICalendarProperty::CalendarAddress => "CALENDAR-ADDRESS",
            ICalendarProperty::LocationType => "LOCATION-TYPE",
            ICalendarProperty::ParticipantType => "PARTICIPANT-TYPE",
            ICalendarProperty::ResourceType => "RESOURCE-TYPE",
            ICalendarProperty::StructuredData => "STRUCTURED-DATA",
            ICalendarProperty::StyledDescription => "STYLED-DESCRIPTION",
            ICalendarProperty::Acknowledged => "ACKNOWLEDGED",
            ICalendarProperty::Proximity => "PROXIMITY",
            ICalendarProperty::Concept => "CONCEPT",
            ICalendarProperty::Link => "LINK",
            ICalendarProperty::Refid => "REFID",
            ICalendarProperty::Begin => "BEGIN",
            ICalendarProperty::End => "END",
            ICalendarProperty::Coordinates => "COORDINATES",
            ICalendarProperty::ShowWithoutTime => "SHOW-WITHOUT-TIME",
            ICalendarProperty::Jsid => "JSID",
            ICalendarProperty::Jsprop => "JSPROP",
            ICalendarProperty::EstimatedDuration => "ESTIMATED-DURATION",
            ICalendarProperty::Reason => "REASON",
            ICalendarProperty::Substate => "SUBSTATE",
            ICalendarProperty::TaskMode => "TASK-MODE",
            ICalendarProperty::Other(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl ICalendarParameterName {
    pub fn try_parse(input: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(input,
                b"ALTREP" => Some(ICalendarParameterName::Altrep),
                b"CN" => Some(ICalendarParameterName::Cn),
                b"CUTYPE" => Some(ICalendarParameterName::Cutype),
                b"DELEGATED-FROM" => Some(ICalendarParameterName::DelegatedFrom),
                b"DELEGATED-TO" => Some(ICalendarParameterName::DelegatedTo),
                b"DIR" => Some(ICalendarParameterName::Dir),
                b"FMTTYPE" => Some(ICalendarParameterName::Fmttype),
                b"FBTYPE" => Some(ICalendarParameterName::Fbtype),
                b"LANGUAGE" => Some(ICalendarParameterName::Language),
                b"MEMBER" => Some(ICalendarParameterName::Member),
                b"PARTSTAT" => Some(ICalendarParameterName::Partstat),
                b"RANGE" => Some(ICalendarParameterName::Range),
                b"RELATED" => Some(ICalendarParameterName::Related),
                b"RELTYPE" => Some(ICalendarParameterName::Reltype),
                b"ROLE" => Some(ICalendarParameterName::Role),
                b"RSVP" => Some(ICalendarParameterName::Rsvp),
                b"SCHEDULE-AGENT" => Some(ICalendarParameterName::ScheduleAgent),
                b"SCHEDULE-FORCE-SEND" => Some(ICalendarParameterName::ScheduleForceSend),
                b"SCHEDULE-STATUS" => Some(ICalendarParameterName::ScheduleStatus),
                b"SENT-BY" => Some(ICalendarParameterName::SentBy),
                b"TZID" => Some(ICalendarParameterName::Tzid),
                b"VALUE" => Some(ICalendarParameterName::Value),
                b"DISPLAY" => Some(ICalendarParameterName::Display),
                b"EMAIL" => Some(ICalendarParameterName::Email),
                b"FEATURE" => Some(ICalendarParameterName::Feature),
                b"LABEL" => Some(ICalendarParameterName::Label),
                b"SIZE" => Some(ICalendarParameterName::Size),
                b"FILENAME" => Some(ICalendarParameterName::Filename),
                b"MANAGED-ID" => Some(ICalendarParameterName::ManagedId),
                b"ORDER" => Some(ICalendarParameterName::Order),
                b"SCHEMA" => Some(ICalendarParameterName::Schema),
                b"DERIVED" => Some(ICalendarParameterName::Derived),
                b"GAP" => Some(ICalendarParameterName::Gap),
                b"LINKREL" => Some(ICalendarParameterName::Linkrel),
                b"JSPTR" => Some(ICalendarParameterName::Jsptr),
                b"JSID" => Some(ICalendarParameterName::Jsid),
                _ => None,
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            ICalendarParameterName::Altrep => "ALTREP",
            ICalendarParameterName::Cn => "CN",
            ICalendarParameterName::Cutype => "CUTYPE",
            ICalendarParameterName::DelegatedFrom => "DELEGATED-FROM",
            ICalendarParameterName::DelegatedTo => "DELEGATED-TO",
            ICalendarParameterName::Dir => "DIR",
            ICalendarParameterName::Fmttype => "FMTTYPE",
            ICalendarParameterName::Fbtype => "FBTYPE",
            ICalendarParameterName::Language => "LANGUAGE",
            ICalendarParameterName::Member => "MEMBER",
            ICalendarParameterName::Partstat => "PARTSTAT",
            ICalendarParameterName::Range => "RANGE",
            ICalendarParameterName::Related => "RELATED",
            ICalendarParameterName::Reltype => "RELTYPE",
            ICalendarParameterName::Role => "ROLE",
            ICalendarParameterName::Rsvp => "RSVP",
            ICalendarParameterName::ScheduleAgent => "SCHEDULE-AGENT",
            ICalendarParameterName::ScheduleForceSend => "SCHEDULE-FORCE-SEND",
            ICalendarParameterName::ScheduleStatus => "SCHEDULE-STATUS",
            ICalendarParameterName::SentBy => "SENT-BY",
            ICalendarParameterName::Tzid => "TZID",
            ICalendarParameterName::Value => "VALUE",
            ICalendarParameterName::Display => "DISPLAY",
            ICalendarParameterName::Email => "EMAIL",
            ICalendarParameterName::Feature => "FEATURE",
            ICalendarParameterName::Label => "LABEL",
            ICalendarParameterName::Size => "SIZE",
            ICalendarParameterName::Filename => "FILENAME",
            ICalendarParameterName::ManagedId => "MANAGED-ID",
            ICalendarParameterName::Order => "ORDER",
            ICalendarParameterName::Schema => "SCHEMA",
            ICalendarParameterName::Derived => "DERIVED",
            ICalendarParameterName::Gap => "GAP",
            ICalendarParameterName::Linkrel => "LINKREL",
            ICalendarParameterName::Jsptr => "JSPTR",
            ICalendarParameterName::Jsid => "JSID",
            ICalendarParameterName::Other(name) => name.as_str(),
        }
    }

    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ICalendarParameterName::Altrep => "ALTREP",
            ICalendarParameterName::Cn => "CN",
            ICalendarParameterName::Cutype => "CUTYPE",
            ICalendarParameterName::DelegatedFrom => "DELEGATED-FROM",
            ICalendarParameterName::DelegatedTo => "DELEGATED-TO",
            ICalendarParameterName::Dir => "DIR",
            ICalendarParameterName::Fmttype => "FMTTYPE",
            ICalendarParameterName::Fbtype => "FBTYPE",
            ICalendarParameterName::Language => "LANGUAGE",
            ICalendarParameterName::Member => "MEMBER",
            ICalendarParameterName::Partstat => "PARTSTAT",
            ICalendarParameterName::Range => "RANGE",
            ICalendarParameterName::Related => "RELATED",
            ICalendarParameterName::Reltype => "RELTYPE",
            ICalendarParameterName::Role => "ROLE",
            ICalendarParameterName::Rsvp => "RSVP",
            ICalendarParameterName::ScheduleAgent => "SCHEDULE-AGENT",
            ICalendarParameterName::ScheduleForceSend => "SCHEDULE-FORCE-SEND",
            ICalendarParameterName::ScheduleStatus => "SCHEDULE-STATUS",
            ICalendarParameterName::SentBy => "SENT-BY",
            ICalendarParameterName::Tzid => "TZID",
            ICalendarParameterName::Value => "VALUE",
            ICalendarParameterName::Display => "DISPLAY",
            ICalendarParameterName::Email => "EMAIL",
            ICalendarParameterName::Feature => "FEATURE",
            ICalendarParameterName::Label => "LABEL",
            ICalendarParameterName::Size => "SIZE",
            ICalendarParameterName::Filename => "FILENAME",
            ICalendarParameterName::ManagedId => "MANAGED-ID",
            ICalendarParameterName::Order => "ORDER",
            ICalendarParameterName::Schema => "SCHEMA",
            ICalendarParameterName::Derived => "DERIVED",
            ICalendarParameterName::Gap => "GAP",
            ICalendarParameterName::Linkrel => "LINKREL",
            ICalendarParameterName::Jsptr => "JSPTR",
            ICalendarParameterName::Jsid => "JSID",
            ICalendarParameterName::Other(name) => return Cow::Owned(name),
        }
        .into()
    }

    pub fn parse(input: &str) -> Self {
        Self::try_parse(input.as_bytes())
            .unwrap_or_else(|| ICalendarParameterName::Other(input.to_string()))
    }
}

impl IanaParse for ICalendarFrequency {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, ICalendarFrequency,
            b"SECONDLY" => ICalendarFrequency::Secondly,
            b"MINUTELY" => ICalendarFrequency::Minutely,
            b"HOURLY" => ICalendarFrequency::Hourly,
            b"DAILY" => ICalendarFrequency::Daily,
            b"WEEKLY" => ICalendarFrequency::Weekly,
            b"MONTHLY" => ICalendarFrequency::Monthly,
            b"YEARLY" => ICalendarFrequency::Yearly,
        )
        .copied()
    }
}

impl IanaString for ICalendarFrequency {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarFrequency::Secondly => "SECONDLY",
            ICalendarFrequency::Minutely => "MINUTELY",
            ICalendarFrequency::Hourly => "HOURLY",
            ICalendarFrequency::Daily => "DAILY",
            ICalendarFrequency::Weekly => "WEEKLY",
            ICalendarFrequency::Monthly => "MONTHLY",
            ICalendarFrequency::Yearly => "YEARLY",
        }
    }
}

impl IanaParse for ICalendarSkip {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, ICalendarSkip,
            b"OMIT" => ICalendarSkip::Omit,
            b"BACKWARD" => ICalendarSkip::Backward,
            b"FORWARD" => ICalendarSkip::Forward,
        )
        .copied()
    }
}

impl IanaString for ICalendarSkip {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarSkip::Omit => "OMIT",
            ICalendarSkip::Backward => "BACKWARD",
            ICalendarSkip::Forward => "FORWARD",
        }
    }
}

impl IanaParse for ICalendarWeekday {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, ICalendarWeekday,
            b"SU" => ICalendarWeekday::Sunday,
            b"MO" => ICalendarWeekday::Monday,
            b"TU" => ICalendarWeekday::Tuesday,
            b"WE" => ICalendarWeekday::Wednesday,
            b"TH" => ICalendarWeekday::Thursday,
            b"FR" => ICalendarWeekday::Friday,
            b"SA" => ICalendarWeekday::Saturday,
        )
        .copied()
    }
}

impl IanaString for ICalendarWeekday {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarWeekday::Sunday => "SU",
            ICalendarWeekday::Monday => "MO",
            ICalendarWeekday::Tuesday => "TU",
            ICalendarWeekday::Wednesday => "WE",
            ICalendarWeekday::Thursday => "TH",
            ICalendarWeekday::Friday => "FR",
            ICalendarWeekday::Saturday => "SA",
        }
    }
}

impl From<ICalendarWeekday> for Weekday {
    fn from(value: ICalendarWeekday) -> Self {
        match value {
            ICalendarWeekday::Sunday => Weekday::Sunday,
            ICalendarWeekday::Monday => Weekday::Monday,
            ICalendarWeekday::Tuesday => Weekday::Tuesday,
            ICalendarWeekday::Wednesday => Weekday::Wednesday,
            ICalendarWeekday::Thursday => Weekday::Thursday,
            ICalendarWeekday::Friday => Weekday::Friday,
            ICalendarWeekday::Saturday => Weekday::Saturday,
        }
    }
}

impl IanaParse for ICalendarAction {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "AUDIO" => Some(ICalendarAction::Audio),
            "DISPLAY" => Some(ICalendarAction::Display),
            "EMAIL" => Some(ICalendarAction::Email),
            "PROCEDURE" => Some(ICalendarAction::Procedure),
            _ => None,
        )
    }
}

impl IanaString for ICalendarAction {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarAction::Audio => "AUDIO",
            ICalendarAction::Display => "DISPLAY",
            ICalendarAction::Email => "EMAIL",
            ICalendarAction::Procedure => "PROCEDURE",
        }
    }
}

impl IanaParse for ICalendarUserTypes {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "INDIVIDUAL" => Some(ICalendarUserTypes::Individual),
            "GROUP" => Some(ICalendarUserTypes::Group),
            "RESOURCE" => Some(ICalendarUserTypes::Resource),
            "ROOM" => Some(ICalendarUserTypes::Room),
            "UNKNOWN" => Some(ICalendarUserTypes::Unknown),
            _ => None,
        )
    }
}

impl IanaString for ICalendarUserTypes {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarUserTypes::Individual => "INDIVIDUAL",
            ICalendarUserTypes::Group => "GROUP",
            ICalendarUserTypes::Resource => "RESOURCE",
            ICalendarUserTypes::Room => "ROOM",
            ICalendarUserTypes::Unknown => "UNKNOWN",
        }
    }
}

impl IanaParse for ICalendarClassification {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "PUBLIC" => Some(ICalendarClassification::Public),
            "PRIVATE" => Some(ICalendarClassification::Private),
            "CONFIDENTIAL" => Some(ICalendarClassification::Confidential),
            _ => None,
        )
    }
}

impl IanaString for ICalendarClassification {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarClassification::Public => "PUBLIC",
            ICalendarClassification::Private => "PRIVATE",
            ICalendarClassification::Confidential => "CONFIDENTIAL",
        }
    }
}

impl IanaParse for ICalendarComponentType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "VCALENDAR" => Some(ICalendarComponentType::VCalendar),
            "VEVENT" => Some(ICalendarComponentType::VEvent),
            "VTODO" => Some(ICalendarComponentType::VTodo),
            "VJOURNAL" => Some(ICalendarComponentType::VJournal),
            "VFREEBUSY" => Some(ICalendarComponentType::VFreebusy),
            "VTIMEZONE" => Some(ICalendarComponentType::VTimezone),
            "VALARM" => Some(ICalendarComponentType::VAlarm),
            "STANDARD" => Some(ICalendarComponentType::Standard),
            "DAYLIGHT" => Some(ICalendarComponentType::Daylight),
            "VAVAILABILITY" => Some(ICalendarComponentType::VAvailability),
            "AVAILABLE" => Some(ICalendarComponentType::Available),
            "PARTICIPANT" => Some(ICalendarComponentType::Participant),
            "VLOCATION" => Some(ICalendarComponentType::VLocation),
            "VRESOURCE" => Some(ICalendarComponentType::VResource),
            "VSTATUS" => Some(ICalendarComponentType::VStatus),
            _ => None
        )
    }
}

impl ICalendarComponentType {
    pub(crate) fn entry_capacity(&self) -> usize {
        match self {
            ICalendarComponentType::VCalendar
            | ICalendarComponentType::VTimezone
            | ICalendarComponentType::VAlarm
            | ICalendarComponentType::Standard
            | ICalendarComponentType::Daylight
            | ICalendarComponentType::Available => 8,
            ICalendarComponentType::VEvent
            | ICalendarComponentType::VTodo
            | ICalendarComponentType::VJournal
            | ICalendarComponentType::VFreebusy
            | ICalendarComponentType::VAvailability
            | ICalendarComponentType::Participant
            | ICalendarComponentType::VLocation
            | ICalendarComponentType::VResource
            | ICalendarComponentType::VStatus
            | ICalendarComponentType::Other(_) => 16,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ICalendarComponentType::VCalendar => "VCALENDAR",
            ICalendarComponentType::VEvent => "VEVENT",
            ICalendarComponentType::VTodo => "VTODO",
            ICalendarComponentType::VJournal => "VJOURNAL",
            ICalendarComponentType::VFreebusy => "VFREEBUSY",
            ICalendarComponentType::VTimezone => "VTIMEZONE",
            ICalendarComponentType::VAlarm => "VALARM",
            ICalendarComponentType::Standard => "STANDARD",
            ICalendarComponentType::Daylight => "DAYLIGHT",
            ICalendarComponentType::VAvailability => "VAVAILABILITY",
            ICalendarComponentType::Available => "AVAILABLE",
            ICalendarComponentType::Participant => "PARTICIPANT",
            ICalendarComponentType::VLocation => "VLOCATION",
            ICalendarComponentType::VResource => "VRESOURCE",
            ICalendarComponentType::VStatus => "VSTATUS",
            ICalendarComponentType::Other(s) => s.as_str(),
        }
    }

    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ICalendarComponentType::VCalendar => "VCALENDAR",
            ICalendarComponentType::VEvent => "VEVENT",
            ICalendarComponentType::VTodo => "VTODO",
            ICalendarComponentType::VJournal => "VJOURNAL",
            ICalendarComponentType::VFreebusy => "VFREEBUSY",
            ICalendarComponentType::VTimezone => "VTIMEZONE",
            ICalendarComponentType::VAlarm => "VALARM",
            ICalendarComponentType::Standard => "STANDARD",
            ICalendarComponentType::Daylight => "DAYLIGHT",
            ICalendarComponentType::VAvailability => "VAVAILABILITY",
            ICalendarComponentType::Available => "AVAILABLE",
            ICalendarComponentType::Participant => "PARTICIPANT",
            ICalendarComponentType::VLocation => "VLOCATION",
            ICalendarComponentType::VResource => "VRESOURCE",
            ICalendarComponentType::VStatus => "VSTATUS",
            ICalendarComponentType::Other(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl IanaParse for ICalendarDisplayType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "BADGE" => Some(ICalendarDisplayType::Badge),
            "GRAPHIC" => Some(ICalendarDisplayType::Graphic),
            "FULLSIZE" => Some(ICalendarDisplayType::Fullsize),
            "THUMBNAIL" => Some(ICalendarDisplayType::Thumbnail),
            _ => None,
        )
    }
}

impl IanaString for ICalendarDisplayType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarDisplayType::Badge => "BADGE",
            ICalendarDisplayType::Graphic => "GRAPHIC",
            ICalendarDisplayType::Fullsize => "FULLSIZE",
            ICalendarDisplayType::Thumbnail => "THUMBNAIL",
        }
    }
}

impl IanaParse for ICalendarFeatureType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "AUDIO" => Some(ICalendarFeatureType::Audio),
            "CHAT" => Some(ICalendarFeatureType::Chat),
            "FEED" => Some(ICalendarFeatureType::Feed),
            "MODERATOR" => Some(ICalendarFeatureType::Moderator),
            "PHONE" => Some(ICalendarFeatureType::Phone),
            "SCREEN" => Some(ICalendarFeatureType::Screen),
            "VIDEO" => Some(ICalendarFeatureType::Video),
            _ => None,
        )
    }
}

impl IanaString for ICalendarFeatureType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarFeatureType::Audio => "AUDIO",
            ICalendarFeatureType::Chat => "CHAT",
            ICalendarFeatureType::Feed => "FEED",
            ICalendarFeatureType::Moderator => "MODERATOR",
            ICalendarFeatureType::Phone => "PHONE",
            ICalendarFeatureType::Screen => "SCREEN",
            ICalendarFeatureType::Video => "VIDEO",
        }
    }
}

impl IanaParse for ICalendarFreeBusyType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "FREE" => Some(ICalendarFreeBusyType::Free),
            "BUSY" => Some(ICalendarFreeBusyType::Busy),
            "BUSY-UNAVAILABLE" => Some(ICalendarFreeBusyType::BusyUnavailable),
            "BUSY-TENTATIVE" => Some(ICalendarFreeBusyType::BusyTentative),
            _ => None,
        )
    }
}

impl IanaString for ICalendarFreeBusyType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarFreeBusyType::Free => "FREE",
            ICalendarFreeBusyType::Busy => "BUSY",
            ICalendarFreeBusyType::BusyUnavailable => "BUSY-UNAVAILABLE",
            ICalendarFreeBusyType::BusyTentative => "BUSY-TENTATIVE",
        }
    }
}

impl IanaParse for ICalendarMethod {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "PUBLISH" => Some(ICalendarMethod::Publish),
            "REQUEST" => Some(ICalendarMethod::Request),
            "REPLY" => Some(ICalendarMethod::Reply),
            "ADD" => Some(ICalendarMethod::Add),
            "CANCEL" => Some(ICalendarMethod::Cancel),
            "REFRESH" => Some(ICalendarMethod::Refresh),
            "COUNTER" => Some(ICalendarMethod::Counter),
            "DECLINECOUNTER" => Some(ICalendarMethod::Declinecounter),
            _ => None,
        )
    }
}

impl IanaString for ICalendarMethod {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarMethod::Publish => "PUBLISH",
            ICalendarMethod::Request => "REQUEST",
            ICalendarMethod::Reply => "REPLY",
            ICalendarMethod::Add => "ADD",
            ICalendarMethod::Cancel => "CANCEL",
            ICalendarMethod::Refresh => "REFRESH",
            ICalendarMethod::Counter => "COUNTER",
            ICalendarMethod::Declinecounter => "DECLINECOUNTER",
        }
    }
}

impl IanaParse for ICalendarRelated {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "START" => Some(ICalendarRelated::Start),
            "END" => Some(ICalendarRelated::End),
            _ => None,
        )
    }
}

impl IanaString for ICalendarRelated {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarRelated::Start => "START",
            ICalendarRelated::End => "END",
        }
    }
}

impl IanaParse for ICalendarParticipantType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "ACTIVE" => Some(ICalendarParticipantType::Active),
            "INACTIVE" => Some(ICalendarParticipantType::Inactive),
            "SPONSOR" => Some(ICalendarParticipantType::Sponsor),
            "CONTACT" => Some(ICalendarParticipantType::Contact),
            "BOOKING-CONTACT" => Some(ICalendarParticipantType::BookingContact),
            "EMERGENCY-CONTACT" => Some(ICalendarParticipantType::EmergencyContact),
            "PUBLICITY-CONTACT" => Some(ICalendarParticipantType::PublicityContact),
            "PLANNER-CONTACT" => Some(ICalendarParticipantType::PlannerContact),
            "PERFORMER" => Some(ICalendarParticipantType::Performer),
            "SPEAKER" => Some(ICalendarParticipantType::Speaker),
            _ => None,
        )
    }
}

impl IanaString for ICalendarParticipantType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarParticipantType::Active => "ACTIVE",
            ICalendarParticipantType::Inactive => "INACTIVE",
            ICalendarParticipantType::Sponsor => "SPONSOR",
            ICalendarParticipantType::Contact => "CONTACT",
            ICalendarParticipantType::BookingContact => "BOOKING-CONTACT",
            ICalendarParticipantType::EmergencyContact => "EMERGENCY-CONTACT",
            ICalendarParticipantType::PublicityContact => "PUBLICITY-CONTACT",
            ICalendarParticipantType::PlannerContact => "PLANNER-CONTACT",
            ICalendarParticipantType::Performer => "PERFORMER",
            ICalendarParticipantType::Speaker => "SPEAKER",
        }
    }
}

impl IanaParse for ICalendarParticipationRole {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "CHAIR" => Some(ICalendarParticipationRole::Chair),
            "REQ-PARTICIPANT" => Some(ICalendarParticipationRole::ReqParticipant),
            "OPT-PARTICIPANT" => Some(ICalendarParticipationRole::OptParticipant),
            "NON-PARTICIPANT" => Some(ICalendarParticipationRole::NonParticipant),
            "OWNER" => Some(ICalendarParticipationRole::Owner),
            _ => None,
        )
    }
}

impl IanaString for ICalendarParticipationRole {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarParticipationRole::Chair => "CHAIR",
            ICalendarParticipationRole::ReqParticipant => "REQ-PARTICIPANT",
            ICalendarParticipationRole::OptParticipant => "OPT-PARTICIPANT",
            ICalendarParticipationRole::NonParticipant => "NON-PARTICIPANT",
            ICalendarParticipationRole::Owner => "OWNER",
        }
    }
}

impl IanaParse for ICalendarStatus {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "TENTATIVE" => Some(ICalendarStatus::Tentative),
            "CONFIRMED" => Some(ICalendarStatus::Confirmed),
            "CANCELLED" => Some(ICalendarStatus::Cancelled),
            "NEEDS-ACTION" => Some(ICalendarStatus::NeedsAction),
            "COMPLETED" => Some(ICalendarStatus::Completed),
            "IN-PROCESS" => Some(ICalendarStatus::InProcess),
            "DRAFT" => Some(ICalendarStatus::Draft),
            "FINAL" => Some(ICalendarStatus::Final),
            "FAILED" => Some(ICalendarStatus::Failed),
            "PENDING" => Some(ICalendarStatus::Pending),
            _ => None
        )
    }
}

impl IanaString for ICalendarStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarStatus::Tentative => "TENTATIVE",
            ICalendarStatus::Confirmed => "CONFIRMED",
            ICalendarStatus::Cancelled => "CANCELLED",
            ICalendarStatus::NeedsAction => "NEEDS-ACTION",
            ICalendarStatus::Completed => "COMPLETED",
            ICalendarStatus::InProcess => "IN-PROCESS",
            ICalendarStatus::Draft => "DRAFT",
            ICalendarStatus::Final => "FINAL",
            ICalendarStatus::Failed => "FAILED",
            ICalendarStatus::Pending => "PENDING",
        }
    }
}

impl IanaParse for ICalendarParticipationStatus {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "NEEDS-ACTION" => Some(ICalendarParticipationStatus::NeedsAction),
            "ACCEPTED" => Some(ICalendarParticipationStatus::Accepted),
            "DECLINED" => Some(ICalendarParticipationStatus::Declined),
            "TENTATIVE" => Some(ICalendarParticipationStatus::Tentative),
            "DELEGATED" => Some(ICalendarParticipationStatus::Delegated),
            "COMPLETED" => Some(ICalendarParticipationStatus::Completed),
            "IN-PROCESS" => Some(ICalendarParticipationStatus::InProcess),
            "FAILED" => Some(ICalendarParticipationStatus::Failed),
            _ => None
        )
    }
}

impl IanaString for ICalendarParticipationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarParticipationStatus::NeedsAction => "NEEDS-ACTION",
            ICalendarParticipationStatus::Accepted => "ACCEPTED",
            ICalendarParticipationStatus::Declined => "DECLINED",
            ICalendarParticipationStatus::Tentative => "TENTATIVE",
            ICalendarParticipationStatus::Delegated => "DELEGATED",
            ICalendarParticipationStatus::Completed => "COMPLETED",
            ICalendarParticipationStatus::InProcess => "IN-PROCESS",
            ICalendarParticipationStatus::Failed => "FAILED",
        }
    }
}

impl IanaParse for ICalendarProximityValue {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "ARRIVE" => Some(ICalendarProximityValue::Arrive),
            "DEPART" => Some(ICalendarProximityValue::Depart),
            "CONNECT" => Some(ICalendarProximityValue::Connect),
            "DISCONNECT" => Some(ICalendarProximityValue::Disconnect),
            _ => None,
        )
    }
}

impl IanaString for ICalendarProximityValue {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarProximityValue::Arrive => "ARRIVE",
            ICalendarProximityValue::Depart => "DEPART",
            ICalendarProximityValue::Connect => "CONNECT",
            ICalendarProximityValue::Disconnect => "DISCONNECT",
        }
    }
}

impl IanaParse for ICalendarRelationshipType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "CHILD" => Some(ICalendarRelationshipType::Child),
            "PARENT" => Some(ICalendarRelationshipType::Parent),
            "SIBLING" => Some(ICalendarRelationshipType::Sibling),
            "SNOOZE" => Some(ICalendarRelationshipType::Snooze),
            "CONCEPT" => Some(ICalendarRelationshipType::Concept),
            "DEPENDS-ON" => Some(ICalendarRelationshipType::DependsOn),
            "FINISHTOFINISH" => Some(ICalendarRelationshipType::Finishtofinish),
            "FINISHTOSTART" => Some(ICalendarRelationshipType::Finishtostart),
            "FIRST" => Some(ICalendarRelationshipType::First),
            "NEXT" => Some(ICalendarRelationshipType::Next),
            "REFID" => Some(ICalendarRelationshipType::Refid),
            "STARTTOFINISH" => Some(ICalendarRelationshipType::Starttofinish),
            "STARTTOSTART" => Some(ICalendarRelationshipType::Starttostart),
            _ => None,
        )
    }
}

impl IanaString for ICalendarRelationshipType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarRelationshipType::Child => "CHILD",
            ICalendarRelationshipType::Parent => "PARENT",
            ICalendarRelationshipType::Sibling => "SIBLING",
            ICalendarRelationshipType::Snooze => "SNOOZE",
            ICalendarRelationshipType::Concept => "CONCEPT",
            ICalendarRelationshipType::DependsOn => "DEPENDS-ON",
            ICalendarRelationshipType::Finishtofinish => "FINISHTOFINISH",
            ICalendarRelationshipType::Finishtostart => "FINISHTOSTART",
            ICalendarRelationshipType::First => "FIRST",
            ICalendarRelationshipType::Next => "NEXT",
            ICalendarRelationshipType::Refid => "REFID",
            ICalendarRelationshipType::Starttofinish => "STARTTOFINISH",
            ICalendarRelationshipType::Starttostart => "STARTTOSTART",
        }
    }
}

impl IanaParse for ICalendarResourceType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "PROJECTOR" => Some(ICalendarResourceType::Projector),
            "ROOM" => Some(ICalendarResourceType::Room),
            "REMOTE-CONFERENCE-AUDIO" => Some(ICalendarResourceType::RemoteConferenceAudio),
            "REMOTE-CONFERENCE-VIDEO" => Some(ICalendarResourceType::RemoteConferenceVideo),
            _ => None,
        )
    }
}

impl IanaString for ICalendarResourceType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarResourceType::Projector => "PROJECTOR",
            ICalendarResourceType::Room => "ROOM",
            ICalendarResourceType::RemoteConferenceAudio => "REMOTE-CONFERENCE-AUDIO",
            ICalendarResourceType::RemoteConferenceVideo => "REMOTE-CONFERENCE-VIDEO",
        }
    }
}

impl IanaParse for ICalendarScheduleAgentValue {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "SERVER" => Some(ICalendarScheduleAgentValue::Server),
            "CLIENT" => Some(ICalendarScheduleAgentValue::Client),
            "NONE" => Some(ICalendarScheduleAgentValue::None),
            _ => None,
        )
    }
}

impl IanaString for ICalendarScheduleAgentValue {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarScheduleAgentValue::Server => "SERVER",
            ICalendarScheduleAgentValue::Client => "CLIENT",
            ICalendarScheduleAgentValue::None => "NONE",
        }
    }
}

impl IanaParse for ICalendarScheduleForceSendValue {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "REQUEST" => Some(ICalendarScheduleForceSendValue::Request),
            "REPLY" => Some(ICalendarScheduleForceSendValue::Reply),
            _ => None,
        )
    }
}

impl IanaString for ICalendarScheduleForceSendValue {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarScheduleForceSendValue::Request => "REQUEST",
            ICalendarScheduleForceSendValue::Reply => "REPLY",
        }
    }
}

impl IanaParse for ICalendarValueType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, ICalendarValueType,
            "BINARY" => ICalendarValueType::Binary,
            "BOOLEAN" => ICalendarValueType::Boolean,
            "CAL-ADDRESS" => ICalendarValueType::CalAddress,
            "DATE" => ICalendarValueType::Date,
            "DATE-TIME" => ICalendarValueType::DateTime,
            "DURATION" => ICalendarValueType::Duration,
            "FLOAT" => ICalendarValueType::Float,
            "INTEGER" => ICalendarValueType::Integer,
            "PERIOD" => ICalendarValueType::Period,
            "RECUR" => ICalendarValueType::Recur,
            "TEXT" => ICalendarValueType::Text,
            "TIME" => ICalendarValueType::Time,
            "UNKNOWN" => ICalendarValueType::Unknown,
            "URI" => ICalendarValueType::Uri,
            "UTC-OFFSET" => ICalendarValueType::UtcOffset,
            "XML-REFERENCE" => ICalendarValueType::XmlReference,
            "UID" => ICalendarValueType::Uid,
        )
        .copied()
    }
}

impl IanaString for ICalendarValueType {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarValueType::Binary => "BINARY",
            ICalendarValueType::Boolean => "BOOLEAN",
            ICalendarValueType::CalAddress => "CAL-ADDRESS",
            ICalendarValueType::Date => "DATE",
            ICalendarValueType::DateTime => "DATE-TIME",
            ICalendarValueType::Duration => "DURATION",
            ICalendarValueType::Float => "FLOAT",
            ICalendarValueType::Integer => "INTEGER",
            ICalendarValueType::Period => "PERIOD",
            ICalendarValueType::Recur => "RECUR",
            ICalendarValueType::Text => "TEXT",
            ICalendarValueType::Time => "TIME",
            ICalendarValueType::Unknown => "UNKNOWN",
            ICalendarValueType::Uri => "URI",
            ICalendarValueType::UtcOffset => "UTC-OFFSET",
            ICalendarValueType::XmlReference => "XML-REFERENCE",
            ICalendarValueType::Uid => "UID",
        }
    }
}

impl IanaParse for ICalendarTransparency {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "OPAQUE" => Some(ICalendarTransparency::Opaque),
            "TRANSPARENT" => Some(ICalendarTransparency::Transparent),
            _ => None,
        )
    }
}

impl IanaString for ICalendarTransparency {
    fn as_str(&self) -> &'static str {
        match self {
            ICalendarTransparency::Opaque => "OPAQUE",
            ICalendarTransparency::Transparent => "TRANSPARENT",
        }
    }
}

impl ICalendarProperty {
    pub(crate) fn parameter_capacity(&self) -> usize {
        match self {
            ICalendarProperty::Attendee => 8,
            _ => 0,
        }
    }

    // Returns the default value type and whether the property is multi-valued.
    pub(crate) fn default_types(&self) -> (ValueType, ValueSeparator) {
        match self {
            ICalendarProperty::Calscale => (ValueType::CalendarScale, ValueSeparator::None),
            ICalendarProperty::Method => (ValueType::Method, ValueSeparator::None),
            ICalendarProperty::Prodid => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Version => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Attach => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Categories => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::Class => (ValueType::Classification, ValueSeparator::None),
            ICalendarProperty::Comment => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Description => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Geo => (
                ValueType::Ical(ICalendarValueType::Float),
                ValueSeparator::Semicolon,
            ),
            ICalendarProperty::Location => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::PercentComplete => (
                ValueType::Ical(ICalendarValueType::Integer),
                ValueSeparator::None,
            ),
            ICalendarProperty::Priority => (
                ValueType::Ical(ICalendarValueType::Integer),
                ValueSeparator::None,
            ),
            ICalendarProperty::Resources => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::Status => (ValueType::Status, ValueSeparator::None),
            ICalendarProperty::Summary => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Completed => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Dtend => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Due => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Dtstart => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Duration => (
                ValueType::Ical(ICalendarValueType::Duration),
                ValueSeparator::None,
            ),
            ICalendarProperty::Freebusy => (
                ValueType::Ical(ICalendarValueType::Period),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::Transp => (ValueType::Transparency, ValueSeparator::None),
            ICalendarProperty::Tzid => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Tzname => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Tzoffsetfrom => (
                ValueType::Ical(ICalendarValueType::UtcOffset),
                ValueSeparator::None,
            ),
            ICalendarProperty::Tzoffsetto => (
                ValueType::Ical(ICalendarValueType::UtcOffset),
                ValueSeparator::None,
            ),
            ICalendarProperty::Tzurl => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Attendee => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Contact => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Organizer => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::RecurrenceId => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::RelatedTo => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Url => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Uid => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Exdate => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::Exrule => (
                ValueType::Ical(ICalendarValueType::Recur),
                ValueSeparator::None,
            ),
            ICalendarProperty::Rdate => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::Rrule => (
                ValueType::Ical(ICalendarValueType::Recur),
                ValueSeparator::None,
            ),
            ICalendarProperty::Action => (ValueType::Action, ValueSeparator::None),
            ICalendarProperty::Repeat => (
                ValueType::Ical(ICalendarValueType::Integer),
                ValueSeparator::None,
            ),
            ICalendarProperty::Trigger => (
                ValueType::Ical(ICalendarValueType::Duration),
                ValueSeparator::None,
            ),
            ICalendarProperty::Created => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Dtstamp => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::LastModified => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Sequence => (
                ValueType::Ical(ICalendarValueType::Integer),
                ValueSeparator::None,
            ),
            ICalendarProperty::RequestStatus => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::Semicolon,
            ),
            ICalendarProperty::Xml => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Tzuntil => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::TzidAliasOf => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Busytype => (ValueType::BusyType, ValueSeparator::None),
            ICalendarProperty::Name => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::RefreshInterval => (
                ValueType::Ical(ICalendarValueType::Duration),
                ValueSeparator::None,
            ),
            ICalendarProperty::Source => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Color => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Image => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Conference => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::CalendarAddress => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::LocationType => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::Comma,
            ),
            ICalendarProperty::ParticipantType => {
                (ValueType::ParticipantType, ValueSeparator::None)
            }
            ICalendarProperty::ResourceType => (ValueType::ResourceType, ValueSeparator::None),
            ICalendarProperty::StructuredData => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::StyledDescription => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Acknowledged => (
                ValueType::Ical(ICalendarValueType::DateTime),
                ValueSeparator::None,
            ),
            ICalendarProperty::Proximity => (ValueType::Proximity, ValueSeparator::None),
            ICalendarProperty::Concept => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Link => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Refid => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Begin => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::End => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::Other(_) => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::Semicolon,
            ),
            ICalendarProperty::Coordinates => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::ShowWithoutTime => (
                ValueType::Ical(ICalendarValueType::Boolean),
                ValueSeparator::None,
            ),
            ICalendarProperty::Jsid | ICalendarProperty::Jsprop => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::EstimatedDuration => (
                ValueType::Ical(ICalendarValueType::Duration),
                ValueSeparator::None,
            ),
            ICalendarProperty::Reason => (
                ValueType::Ical(ICalendarValueType::Uri),
                ValueSeparator::None,
            ),
            ICalendarProperty::Substate => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
            ICalendarProperty::TaskMode => (
                ValueType::Ical(ICalendarValueType::Text),
                ValueSeparator::None,
            ),
        }
    }
}

impl ValueType {
    pub fn unwrap_ical(self) -> ICalendarValueType {
        match self {
            ValueType::Ical(value) => value,
            _ => ICalendarValueType::Text,
        }
    }
}

impl ICalendar {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, Entry> {
        let mut parser = Parser::new(value.as_ref());
        match parser.entry() {
            Entry::ICalendar(icalendar) => Ok(icalendar),
            other => Err(other),
        }
    }
}

impl Hash for ICalendarValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            ICalendarValue::Binary(value) => {
                state.write_u8(0);
                value.hash(state);
            }
            ICalendarValue::Boolean(value) => {
                state.write_u8(1);
                value.hash(state);
            }
            ICalendarValue::Uri(value) => {
                state.write_u8(2);
                value.hash(state);
            }
            ICalendarValue::PartialDateTime(value) => {
                state.write_u8(3);
                value.hash(state);
            }
            ICalendarValue::Duration(value) => {
                state.write_u8(4);
                value.hash(state);
            }
            ICalendarValue::RecurrenceRule(value) => {
                state.write_u8(5);
                value.hash(state);
            }
            ICalendarValue::Period(value) => {
                state.write_u8(6);
                value.hash(state);
            }
            ICalendarValue::Float(value) => {
                state.write_u8(7);
                value.to_bits().hash(state);
            }
            ICalendarValue::Integer(value) => {
                state.write_u8(8);
                value.hash(state);
            }
            ICalendarValue::Text(value) => {
                state.write_u8(9);
                value.hash(state);
            }
            ICalendarValue::CalendarScale(value) => {
                state.write_u8(10);
                value.hash(state);
            }
            ICalendarValue::Method(value) => {
                state.write_u8(11);
                value.hash(state);
            }
            ICalendarValue::Classification(value) => {
                state.write_u8(12);
                value.hash(state);
            }
            ICalendarValue::Status(value) => {
                state.write_u8(13);
                value.hash(state);
            }
            ICalendarValue::Transparency(value) => {
                state.write_u8(14);
                value.hash(state);
            }
            ICalendarValue::Action(value) => {
                state.write_u8(15);
                value.hash(state);
            }
            ICalendarValue::BusyType(value) => {
                state.write_u8(16);
                value.hash(state);
            }
            ICalendarValue::ParticipantType(value) => {
                state.write_u8(17);
                value.hash(state);
            }
            ICalendarValue::ResourceType(value) => {
                state.write_u8(18);
                value.hash(state);
            }
            ICalendarValue::Proximity(value) => {
                state.write_u8(19);
                value.hash(state);
            }
        }
    }
}

impl Eq for ICalendarValue {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for ICalendarValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(std::cmp::Ordering::Equal)
    }
}
