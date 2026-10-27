/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::*;

impl IanaParse for VCardProperty {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "BEGIN" => Some(VCardProperty::Begin),
            "END" => Some(VCardProperty::End),
            "SOURCE" => Some(VCardProperty::Source),
            "KIND" => Some(VCardProperty::Kind),
            "XML" => Some(VCardProperty::Xml),
            "FN" => Some(VCardProperty::Fn),
            "N" => Some(VCardProperty::N),
            "NICKNAME" => Some(VCardProperty::Nickname),
            "PHOTO" => Some(VCardProperty::Photo),
            "BDAY" => Some(VCardProperty::Bday),
            "ANNIVERSARY" => Some(VCardProperty::Anniversary),
            "GENDER" => Some(VCardProperty::Gender),
            "ADR" => Some(VCardProperty::Adr),
            "TEL" => Some(VCardProperty::Tel),
            "EMAIL" => Some(VCardProperty::Email),
            "IMPP" => Some(VCardProperty::Impp),
            "LANG" => Some(VCardProperty::Lang),
            "TZ" => Some(VCardProperty::Tz),
            "GEO" => Some(VCardProperty::Geo),
            "TITLE" => Some(VCardProperty::Title),
            "ROLE" => Some(VCardProperty::Role),
            "LOGO" => Some(VCardProperty::Logo),
            "ORG" => Some(VCardProperty::Org),
            "MEMBER" => Some(VCardProperty::Member),
            "RELATED" => Some(VCardProperty::Related),
            "CATEGORIES" => Some(VCardProperty::Categories),
            "NOTE" => Some(VCardProperty::Note),
            "PRODID" => Some(VCardProperty::Prodid),
            "REV" => Some(VCardProperty::Rev),
            "SOUND" => Some(VCardProperty::Sound),
            "UID" => Some(VCardProperty::Uid),
            "CLIENTPIDMAP" => Some(VCardProperty::Clientpidmap),
            "URL" => Some(VCardProperty::Url),
            "VERSION" => Some(VCardProperty::Version),
            "KEY" => Some(VCardProperty::Key),
            "FBURL" => Some(VCardProperty::Fburl),
            "CALADRURI" => Some(VCardProperty::Caladruri),
            "CALURI" => Some(VCardProperty::Caluri),
            "BIRTHPLACE" => Some(VCardProperty::Birthplace),
            "DEATHPLACE" => Some(VCardProperty::Deathplace),
            "DEATHDATE" => Some(VCardProperty::Deathdate),
            "EXPERTISE" => Some(VCardProperty::Expertise),
            "HOBBY" => Some(VCardProperty::Hobby),
            "INTEREST" => Some(VCardProperty::Interest),
            "ORG-DIRECTORY" => Some(VCardProperty::OrgDirectory),
            "CONTACT-URI" => Some(VCardProperty::ContactUri),
            "CREATED" => Some(VCardProperty::Created),
            "GRAMGENDER" => Some(VCardProperty::Gramgender),
            "LANGUAGE" => Some(VCardProperty::Language),
            "PRONOUNS" => Some(VCardProperty::Pronouns),
            "SOCIALPROFILE" => Some(VCardProperty::Socialprofile),
            "JSPROP" => Some(VCardProperty::Jsprop),
            _ => None,
        )
    }
}

impl VCardProperty {
    pub fn as_str(&self) -> &str {
        match self {
            VCardProperty::Source => "SOURCE",
            VCardProperty::Kind => "KIND",
            VCardProperty::Xml => "XML",
            VCardProperty::Fn => "FN",
            VCardProperty::N => "N",
            VCardProperty::Nickname => "NICKNAME",
            VCardProperty::Photo => "PHOTO",
            VCardProperty::Bday => "BDAY",
            VCardProperty::Anniversary => "ANNIVERSARY",
            VCardProperty::Gender => "GENDER",
            VCardProperty::Adr => "ADR",
            VCardProperty::Tel => "TEL",
            VCardProperty::Email => "EMAIL",
            VCardProperty::Impp => "IMPP",
            VCardProperty::Lang => "LANG",
            VCardProperty::Tz => "TZ",
            VCardProperty::Geo => "GEO",
            VCardProperty::Title => "TITLE",
            VCardProperty::Role => "ROLE",
            VCardProperty::Logo => "LOGO",
            VCardProperty::Org => "ORG",
            VCardProperty::Member => "MEMBER",
            VCardProperty::Related => "RELATED",
            VCardProperty::Categories => "CATEGORIES",
            VCardProperty::Note => "NOTE",
            VCardProperty::Prodid => "PRODID",
            VCardProperty::Rev => "REV",
            VCardProperty::Sound => "SOUND",
            VCardProperty::Uid => "UID",
            VCardProperty::Clientpidmap => "CLIENTPIDMAP",
            VCardProperty::Url => "URL",
            VCardProperty::Version => "VERSION",
            VCardProperty::Key => "KEY",
            VCardProperty::Fburl => "FBURL",
            VCardProperty::Caladruri => "CALADRURI",
            VCardProperty::Caluri => "CALURI",
            VCardProperty::Birthplace => "BIRTHPLACE",
            VCardProperty::Deathplace => "DEATHPLACE",
            VCardProperty::Deathdate => "DEATHDATE",
            VCardProperty::Expertise => "EXPERTISE",
            VCardProperty::Hobby => "HOBBY",
            VCardProperty::Interest => "INTEREST",
            VCardProperty::OrgDirectory => "ORG-DIRECTORY",
            VCardProperty::ContactUri => "CONTACT-URI",
            VCardProperty::Created => "CREATED",
            VCardProperty::Gramgender => "GRAMGENDER",
            VCardProperty::Language => "LANGUAGE",
            VCardProperty::Pronouns => "PRONOUNS",
            VCardProperty::Socialprofile => "SOCIALPROFILE",
            VCardProperty::Jsprop => "JSPROP",
            VCardProperty::Begin => "BEGIN",
            VCardProperty::End => "END",
            VCardProperty::Other(v) => v.as_str(),
        }
    }

    pub(crate) fn legacy_max_values(&self) -> usize {
        match self {
            VCardProperty::N => LEGACY_N_COMPONENTS,
            VCardProperty::Adr => LEGACY_ADR_COMPONENTS,
            _ => usize::MAX,
        }
    }
}

pub(crate) const LEGACY_N_COMPONENTS: usize = 5;
pub(crate) const LEGACY_ADR_COMPONENTS: usize = 7;

impl VCardProperty {
    // Returns the default value type and whether the property is multi-valued.
    pub(crate) fn default_types(&self) -> (ValueType, ValueSeparator) {
        match self {
            VCardProperty::Source => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Kind => (ValueType::Kind, ValueSeparator::None),
            VCardProperty::Xml => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Fn => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::N => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::SemicolonAndComma,
            ),
            VCardProperty::Nickname => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::Comma,
            ),
            VCardProperty::Photo => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Bday => (
                ValueType::Vcard(VCardValueType::DateAndOrTime),
                ValueSeparator::None,
            ),
            VCardProperty::Anniversary => (
                ValueType::Vcard(VCardValueType::DateAndOrTime),
                ValueSeparator::None,
            ),
            VCardProperty::Gender => (ValueType::Sex, ValueSeparator::Semicolon),
            VCardProperty::Adr => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::SemicolonAndComma,
            ),
            VCardProperty::Tel => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Email => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Impp => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Lang => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Tz => (
                ValueType::Vcard(VCardValueType::UtcOffset),
                ValueSeparator::None,
            ),
            VCardProperty::Geo => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Title => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Role => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Logo => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Org => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::Semicolon,
            ),
            VCardProperty::Member => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Related => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Categories => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::Comma,
            ),
            VCardProperty::Note => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Prodid => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Rev => (
                ValueType::Vcard(VCardValueType::Timestamp),
                ValueSeparator::None,
            ),
            VCardProperty::Sound => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Uid => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Clientpidmap => (
                ValueType::Vcard(VCardValueType::Text),
                ValueSeparator::Semicolon,
            ),
            VCardProperty::Url => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Version => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Key => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Fburl => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Caladruri => {
                (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None)
            }
            VCardProperty::Caluri => (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None),
            VCardProperty::Birthplace => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Deathplace => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Deathdate => (
                ValueType::Vcard(VCardValueType::DateAndOrTime),
                ValueSeparator::None,
            ),
            VCardProperty::Expertise => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Hobby => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Interest => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::OrgDirectory => {
                (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None)
            }
            VCardProperty::ContactUri => {
                (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None)
            }
            VCardProperty::Created => (
                ValueType::Vcard(VCardValueType::Timestamp),
                ValueSeparator::None,
            ),
            VCardProperty::Gramgender => (ValueType::GramGender, ValueSeparator::None),
            VCardProperty::Language => (
                ValueType::Vcard(VCardValueType::LanguageTag),
                ValueSeparator::None,
            ),
            VCardProperty::Pronouns => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Socialprofile => {
                (ValueType::Vcard(VCardValueType::Uri), ValueSeparator::None)
            }
            VCardProperty::Jsprop => (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None),
            VCardProperty::Other(_) => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::None)
            }
            VCardProperty::Begin | VCardProperty::End => {
                (ValueType::Vcard(VCardValueType::Text), ValueSeparator::Skip)
            }
        }
    }
}

impl Eq for VCardValue {}

impl IanaString for VCardValueType {
    fn as_str(&self) -> &'static str {
        match self {
            VCardValueType::Boolean => "BOOLEAN",
            VCardValueType::Date => "DATE",
            VCardValueType::DateAndOrTime => "DATE-AND-OR-TIME",
            VCardValueType::DateTime => "DATE-TIME",
            VCardValueType::Float => "FLOAT",
            VCardValueType::Integer => "INTEGER",
            VCardValueType::LanguageTag => "LANGUAGE-TAG",
            VCardValueType::Text => "TEXT",
            VCardValueType::Time => "TIME",
            VCardValueType::Timestamp => "TIMESTAMP",
            VCardValueType::Uri => "URI",
            VCardValueType::UtcOffset => "UTC-OFFSET",
        }
    }
}

impl IanaParse for VCardValueType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, VCardValueType,
            "BOOLEAN" => VCardValueType::Boolean,
            "DATE" => VCardValueType::Date,
            "DATE-AND-OR-TIME" => VCardValueType::DateAndOrTime,
            "DATE-TIME" => VCardValueType::DateTime,
            "FLOAT" => VCardValueType::Float,
            "INTEGER" => VCardValueType::Integer,
            "LANGUAGE-TAG" => VCardValueType::LanguageTag,
            "TEXT" => VCardValueType::Text,
            "TIME" => VCardValueType::Time,
            "TIMESTAMP" => VCardValueType::Timestamp,
            "URI" => VCardValueType::Uri,
            "UTC-OFFSET" => VCardValueType::UtcOffset,
        )
        .copied()
    }
}

impl IanaParse for VCardLevel {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, VCardLevel,
            "beginner" => VCardLevel::Beginner,
            "average" => VCardLevel::Average,
            "expert" => VCardLevel::Expert,
            "high" => VCardLevel::High,
            "medium" => VCardLevel::Medium,
            "low" => VCardLevel::Low,
        )
        .copied()
    }
}

impl IanaString for VCardLevel {
    fn as_str(&self) -> &'static str {
        match self {
            VCardLevel::Beginner => "BEGINNER",
            VCardLevel::Average => "AVERAGE",
            VCardLevel::Expert => "EXPERT",
            VCardLevel::High => "HIGH",
            VCardLevel::Medium => "MEDIUM",
            VCardLevel::Low => "LOW",
        }
    }
}

impl IanaParse for VCardPhonetic {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "ipa" => Some(VCardPhonetic::Ipa),
            "jyut" => Some(VCardPhonetic::Jyut),
            "piny" => Some(VCardPhonetic::Piny),
            "script" => Some(VCardPhonetic::Script),
            _ => None,
        )
    }
}

impl IanaString for VCardPhonetic {
    fn as_str(&self) -> &'static str {
        match self {
            VCardPhonetic::Ipa => "IPA",
            VCardPhonetic::Jyut => "JYUT",
            VCardPhonetic::Piny => "PINY",
            VCardPhonetic::Script => "SCRIPT",
        }
    }
}

impl IanaParse for VCardType {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "work" => Some(VCardType::Work),
            "home" => Some(VCardType::Home),
            "billing" => Some(VCardType::Billing),
            "delivery" => Some(VCardType::Delivery),
            "contact" => Some(VCardType::Contact),
            "acquaintance" => Some(VCardType::Acquaintance),
            "friend" => Some(VCardType::Friend),
            "met" => Some(VCardType::Met),
            "co-worker" => Some(VCardType::CoWorker),
            "colleague" => Some(VCardType::Colleague),
            "co-resident" => Some(VCardType::CoResident),
            "neighbor" => Some(VCardType::Neighbor),
            "child" => Some(VCardType::Child),
            "parent" => Some(VCardType::Parent),
            "sibling" => Some(VCardType::Sibling),
            "spouse" => Some(VCardType::Spouse),
            "kin" => Some(VCardType::Kin),
            "muse" => Some(VCardType::Muse),
            "crush" => Some(VCardType::Crush),
            "date" => Some(VCardType::Date),
            "sweetheart" => Some(VCardType::Sweetheart),
            "me" => Some(VCardType::Me),
            "agent" => Some(VCardType::Agent),
            "emergency" => Some(VCardType::Emergency),
            "text" => Some(VCardType::Text),
            "voice" => Some(VCardType::Voice),
            "fax" => Some(VCardType::Fax),
            "cell" => Some(VCardType::Cell),
            "video" => Some(VCardType::Video),
            "pager" => Some(VCardType::Pager),
            "textphone" => Some(VCardType::Textphone),
            "main-number" => Some(VCardType::MainNumber),
            _ => None,
        )
    }
}

impl IanaString for VCardType {
    fn as_str(&self) -> &'static str {
        match self {
            VCardType::Work => "WORK",
            VCardType::Home => "HOME",
            VCardType::Billing => "BILLING",
            VCardType::Delivery => "DELIVERY",
            VCardType::Contact => "CONTACT",
            VCardType::Acquaintance => "ACQUAINTANCE",
            VCardType::Friend => "FRIEND",
            VCardType::Met => "MET",
            VCardType::CoWorker => "CO-WORKER",
            VCardType::Colleague => "COLLEAGUE",
            VCardType::CoResident => "CO-RESIDENT",
            VCardType::Neighbor => "NEIGHBOR",
            VCardType::Child => "CHILD",
            VCardType::Parent => "PARENT",
            VCardType::Sibling => "SIBLING",
            VCardType::Spouse => "SPOUSE",
            VCardType::Kin => "KIN",
            VCardType::Muse => "MUSE",
            VCardType::Crush => "CRUSH",
            VCardType::Date => "DATE",
            VCardType::Sweetheart => "SWEETHEART",
            VCardType::Me => "ME",
            VCardType::Agent => "AGENT",
            VCardType::Emergency => "EMERGENCY",
            VCardType::Text => "TEXT",
            VCardType::Voice => "VOICE",
            VCardType::Fax => "FAX",
            VCardType::Cell => "CELL",
            VCardType::Video => "VIDEO",
            VCardType::Pager => "PAGER",
            VCardType::Textphone => "TEXTPHONE",
            VCardType::MainNumber => "MAIN-NUMBER",
        }
    }
}

impl IanaParse for VCardGramGender {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, VCardGramGender,
            "animate" => VCardGramGender::Animate,
            "common" => VCardGramGender::Common,
            "feminine" => VCardGramGender::Feminine,
            "inanimate" => VCardGramGender::Inanimate,
            "masculine" => VCardGramGender::Masculine,
            "neuter" => VCardGramGender::Neuter,
        )
        .copied()
    }
}

impl IanaString for VCardGramGender {
    fn as_str(&self) -> &'static str {
        match self {
            VCardGramGender::Animate => "ANIMATE",
            VCardGramGender::Common => "COMMON",
            VCardGramGender::Feminine => "FEMININE",
            VCardGramGender::Inanimate => "INANIMATE",
            VCardGramGender::Masculine => "MASCULINE",
            VCardGramGender::Neuter => "NEUTER",
        }
    }
}

impl IanaParse for VCardSex {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, VCardSex,
            "M" => VCardSex::Male,
            "F" => VCardSex::Female,
            "O" => VCardSex::Other,
            "N" => VCardSex::NoneOrNotApplicable,
            "U" => VCardSex::Unknown,
        )
        .copied()
    }
}

impl IanaString for VCardSex {
    fn as_str(&self) -> &'static str {
        match self {
            VCardSex::Male => "M",
            VCardSex::Female => "F",
            VCardSex::Other => "O",
            VCardSex::NoneOrNotApplicable => "N",
            VCardSex::Unknown => "U",
        }
    }
}

impl IanaParse for VCardKind {
    fn parse(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, VCardKind,
            "individual" => VCardKind::Individual,
            "group" => VCardKind::Group,
            "org" => VCardKind::Org,
            "location" => VCardKind::Location,
            "application" => VCardKind::Application,
            "device" => VCardKind::Device,
        )
        .copied()
    }
}

impl IanaString for VCardKind {
    fn as_str(&self) -> &'static str {
        match self {
            VCardKind::Individual => "INDIVIDUAL",
            VCardKind::Group => "GROUP",
            VCardKind::Org => "ORG",
            VCardKind::Location => "LOCATION",
            VCardKind::Application => "APPLICATION",
            VCardKind::Device => "DEVICE",
        }
    }
}

impl VCardParameterName {
    pub fn try_parse(input: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(input,
            b"LANGUAGE" => Some(VCardParameterName::Language),
            b"VALUE" => Some(VCardParameterName::Value),
            b"PREF" => Some(VCardParameterName::Pref),
            b"ALTID" => Some(VCardParameterName::Altid),
            b"PID" => Some(VCardParameterName::Pid),
            b"TYPE" => Some(VCardParameterName::Type),
            b"MEDIATYPE" => Some(VCardParameterName::Mediatype),
            b"CALSCALE" => Some(VCardParameterName::Calscale),
            b"SORT-AS" => Some(VCardParameterName::SortAs),
            b"GEO" => Some(VCardParameterName::Geo),
            b"TZ" => Some(VCardParameterName::Tz),
            b"INDEX" => Some(VCardParameterName::Index),
            b"LEVEL" => Some(VCardParameterName::Level),
            b"GROUP" => Some(VCardParameterName::Group),
            b"CC" => Some(VCardParameterName::Cc),
            b"AUTHOR" => Some(VCardParameterName::Author),
            b"AUTHOR-NAME" => Some(VCardParameterName::AuthorName),
            b"CREATED" => Some(VCardParameterName::Created),
            b"DERIVED" => Some(VCardParameterName::Derived),
            b"LABEL" => Some(VCardParameterName::Label),
            b"PHONETIC" => Some(VCardParameterName::Phonetic),
            b"PROP-ID" => Some(VCardParameterName::PropId),
            b"SCRIPT" => Some(VCardParameterName::Script),
            b"SERVICE-TYPE" => Some(VCardParameterName::ServiceType),
            b"USERNAME" => Some(VCardParameterName::Username),
            b"JSPTR" => Some(VCardParameterName::Jsptr),
            b"JSCOMPS" => Some(VCardParameterName::Jscomps),
            _ => None,
        )
    }

    pub fn parse(input: &str) -> Self {
        Self::try_parse(input.as_bytes()).unwrap_or_else(|| VCardParameterName::Other(input.into()))
    }

    pub fn as_str(&self) -> &str {
        match self {
            VCardParameterName::Language => "LANGUAGE",
            VCardParameterName::Value => "VALUE",
            VCardParameterName::Pref => "PREF",
            VCardParameterName::Altid => "ALTID",
            VCardParameterName::Pid => "PID",
            VCardParameterName::Type => "TYPE",
            VCardParameterName::Mediatype => "MEDIATYPE",
            VCardParameterName::Calscale => "CALSCALE",
            VCardParameterName::SortAs => "SORT-AS",
            VCardParameterName::Geo => "GEO",
            VCardParameterName::Tz => "TZ",
            VCardParameterName::Index => "INDEX",
            VCardParameterName::Level => "LEVEL",
            VCardParameterName::Group => "GROUP",
            VCardParameterName::Cc => "CC",
            VCardParameterName::Author => "AUTHOR",
            VCardParameterName::AuthorName => "AUTHOR-NAME",
            VCardParameterName::Created => "CREATED",
            VCardParameterName::Derived => "DERIVED",
            VCardParameterName::Label => "LABEL",
            VCardParameterName::Phonetic => "PHONETIC",
            VCardParameterName::PropId => "PROP-ID",
            VCardParameterName::Script => "SCRIPT",
            VCardParameterName::ServiceType => "SERVICE-TYPE",
            VCardParameterName::Username => "USERNAME",
            VCardParameterName::Jsptr => "JSPTR",
            VCardParameterName::Jscomps => "JSCOMPS",
            VCardParameterName::Other(name) => name,
        }
    }

    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            VCardParameterName::Language => "LANGUAGE".into(),
            VCardParameterName::Value => "VALUE".into(),
            VCardParameterName::Pref => "PREF".into(),
            VCardParameterName::Altid => "ALTID".into(),
            VCardParameterName::Pid => "PID".into(),
            VCardParameterName::Type => "TYPE".into(),
            VCardParameterName::Mediatype => "MEDIATYPE".into(),
            VCardParameterName::Calscale => "CALSCALE".into(),
            VCardParameterName::SortAs => "SORT-AS".into(),
            VCardParameterName::Geo => "GEO".into(),
            VCardParameterName::Tz => "TZ".into(),
            VCardParameterName::Index => "INDEX".into(),
            VCardParameterName::Level => "LEVEL".into(),
            VCardParameterName::Group => "GROUP".into(),
            VCardParameterName::Cc => "CC".into(),
            VCardParameterName::Author => "AUTHOR".into(),
            VCardParameterName::AuthorName => "AUTHOR-NAME".into(),
            VCardParameterName::Created => "CREATED".into(),
            VCardParameterName::Derived => "DERIVED".into(),
            VCardParameterName::Label => "LABEL".into(),
            VCardParameterName::Phonetic => "PHONETIC".into(),
            VCardParameterName::PropId => "PROP-ID".into(),
            VCardParameterName::Script => "SCRIPT".into(),
            VCardParameterName::ServiceType => "SERVICE-TYPE".into(),
            VCardParameterName::Username => "USERNAME".into(),
            VCardParameterName::Jsptr => "JSPTR".into(),
            VCardParameterName::Jscomps => "JSCOMPS".into(),
            VCardParameterName::Other(name) => name.into(),
        }
    }
}

impl VCardVersion {
    pub fn try_parse(input: &str) -> Option<Self> {
        hashify::map!(input.as_bytes(), VCardVersion,
            b"4.0" => VCardVersion::V4_0,
            b"3.0" => VCardVersion::V3_0,
            b"2.1" => VCardVersion::V2_1,
            b"2.0" => VCardVersion::V2_0,
        )
        .copied()
    }
}
