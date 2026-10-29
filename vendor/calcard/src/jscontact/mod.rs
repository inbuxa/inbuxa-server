/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::common::CalendarScale;
use jmap_tools::{JsonPointer, Value};
use serde::Serialize;
use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

pub mod export;
pub mod import;
pub mod parser;
pub mod types;

#[cfg(test)]
thread_local! {
    static FN_DERIVATION_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fn_derivation_disabled() -> bool {
    FN_DERIVATION_DISABLED.with(|flag| flag.get())
}

#[cfg(test)]
pub(crate) fn set_fn_derivation_disabled(disabled: bool) {
    FN_DERIVATION_DISABLED.with(|flag| flag.set(disabled));
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[repr(transparent)]
pub struct JSContact<'x, I, B>(pub Value<'x, JSContactProperty<I>, JSContactValue<I, B>>)
where
    I: JSContactId,
    B: JSContactId;

pub trait JSContactId:
    FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactValue<I: JSContactId, B: JSContactId> {
    Id(I),
    BlobId(B),
    IdReference(String),
    Timestamp(i64),
    Type(JSContactType),
    GrammaticalGender(JSContactGrammaticalGender),
    Kind(JSContactKind),
    Level(JSContactLevel),
    Relation(JSContactRelation),
    PhoneticSystem(JSContactPhoneticSystem),
    CalendarScale(CalendarScale),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactProperty<I: JSContactId> {
    Type,
    Address,
    AddressBookIds,
    Addresses,
    Anniversaries,
    Author,
    BlobId,
    Calendars,
    CalendarScale,
    Components,
    Contexts,
    ConvertedProperties,
    Coordinates,
    CountryCode,
    Created,
    CryptoKeys,
    Date,
    Day,
    DefaultSeparator,
    Directories,
    Emails,
    Extra,
    Features,
    Full,
    GrammaticalGender,
    Id,
    IsOrdered,
    Keywords,
    Kind,
    Label,
    Language,
    Level,
    Links,
    ListAs,
    Localizations,
    Media,
    MediaType,
    Members,
    Month,
    Name,
    Nicknames,
    Note,
    Notes,
    Number,
    OnlineServices,
    OrganizationId,
    Organizations,
    Parameters,
    PersonalInfo,
    Phones,
    Phonetic,
    PhoneticScript,
    PhoneticSystem,
    Place,
    Pref,
    PreferredLanguages,
    ProdId,
    Pronouns,
    Properties,
    RelatedTo,
    Relation,
    SchedulingAddresses,
    Service,
    SortAs,
    SpeakToAs,
    TimeZone,
    Titles,
    Uid,
    Units,
    Updated,
    Uri,
    User,
    Utc,
    VCard,
    Value,
    Version,
    Year,
    IdValue(I),
    IdReference(String),
    Context(Context),
    Feature(Feature),
    SortAsKind(JSContactKind),
    Pointer(JsonPointer<JSContactProperty<I>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactType {
    Address,
    AddressComponent,
    Anniversary,
    Author,
    Boolean,
    Calendar,
    Card,
    CryptoKey,
    Directory,
    EmailAddress,
    Id,
    Int,
    JCardProp,
    LanguagePref,
    Link,
    Media,
    Name,
    NameComponent,
    Nickname,
    Note,
    Number,
    OnlineService,
    Organization,
    OrgUnit,
    PartialDate,
    PatchObject,
    PersonalInfo,
    Phone,
    Pronouns,
    Relation,
    Resource,
    SchedulingAddress,
    SpeakToAs,
    String,
    Timestamp,
    Title,
    UnsignedInt,
    UTCDateTime,
}

impl FromStr for JSContactType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hashify::map!(s.as_bytes(), JSContactType,
            "Address" => JSContactType::Address,
            "AddressComponent" => JSContactType::AddressComponent,
            "Anniversary" => JSContactType::Anniversary,
            "Author" => JSContactType::Author,
            "Boolean" => JSContactType::Boolean,
            "Calendar" => JSContactType::Calendar,
            "Card" => JSContactType::Card,
            "CryptoKey" => JSContactType::CryptoKey,
            "Directory" => JSContactType::Directory,
            "EmailAddress" => JSContactType::EmailAddress,
            "Id" => JSContactType::Id,
            "Int" => JSContactType::Int,
            "JCardProp" => JSContactType::JCardProp,
            "LanguagePref" => JSContactType::LanguagePref,
            "Link" => JSContactType::Link,
            "Media" => JSContactType::Media,
            "Name" => JSContactType::Name,
            "NameComponent" => JSContactType::NameComponent,
            "Nickname" => JSContactType::Nickname,
            "Note" => JSContactType::Note,
            "Number" => JSContactType::Number,
            "OnlineService" => JSContactType::OnlineService,
            "Organization" => JSContactType::Organization,
            "OrgUnit" => JSContactType::OrgUnit,
            "PartialDate" => JSContactType::PartialDate,
            "PatchObject" => JSContactType::PatchObject,
            "PersonalInfo" => JSContactType::PersonalInfo,
            "Phone" => JSContactType::Phone,
            "Pronouns" => JSContactType::Pronouns,
            "Relation" => JSContactType::Relation,
            "Resource" => JSContactType::Resource,
            "SchedulingAddress" => JSContactType::SchedulingAddress,
            "SpeakToAs" => JSContactType::SpeakToAs,
            "String" => JSContactType::String,
            "Timestamp" => JSContactType::Timestamp,
            "Title" => JSContactType::Title,
            "UnsignedInt" => JSContactType::UnsignedInt,
            "UTCDateTime" => JSContactType::UTCDateTime,
        )
        .copied()
        .ok_or(())
    }
}

impl JSContactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            JSContactType::Address => "Address",
            JSContactType::AddressComponent => "AddressComponent",
            JSContactType::Anniversary => "Anniversary",
            JSContactType::Author => "Author",
            JSContactType::Boolean => "Boolean",
            JSContactType::Calendar => "Calendar",
            JSContactType::Card => "Card",
            JSContactType::CryptoKey => "CryptoKey",
            JSContactType::Directory => "Directory",
            JSContactType::EmailAddress => "EmailAddress",
            JSContactType::Id => "Id",
            JSContactType::Int => "Int",
            JSContactType::JCardProp => "JCardProp",
            JSContactType::LanguagePref => "LanguagePref",
            JSContactType::Link => "Link",
            JSContactType::Media => "Media",
            JSContactType::Name => "Name",
            JSContactType::NameComponent => "NameComponent",
            JSContactType::Nickname => "Nickname",
            JSContactType::Note => "Note",
            JSContactType::Number => "Number",
            JSContactType::OnlineService => "OnlineService",
            JSContactType::Organization => "Organization",
            JSContactType::OrgUnit => "OrgUnit",
            JSContactType::PartialDate => "PartialDate",
            JSContactType::PatchObject => "PatchObject",
            JSContactType::PersonalInfo => "PersonalInfo",
            JSContactType::Phone => "Phone",
            JSContactType::Pronouns => "Pronouns",
            JSContactType::Relation => "Relation",
            JSContactType::Resource => "Resource",
            JSContactType::SchedulingAddress => "SchedulingAddress",
            JSContactType::SpeakToAs => "SpeakToAs",
            JSContactType::String => "String",
            JSContactType::Timestamp => "Timestamp",
            JSContactType::Title => "Title",
            JSContactType::UnsignedInt => "UnsignedInt",
            JSContactType::UTCDateTime => "UTCDateTime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Context {
    Billing,
    Delivery,
    Private,
    Work,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    Fax,
    MainNumber,
    Mobile,
    Pager,
    Text,
    TextPhone,
    Video,
    Voice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactGrammaticalGender {
    Animate,
    Common,
    Feminine,
    Inanimate,
    Masculine,
    Neuter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactKind {
    Apartment,
    Block,
    Building,
    Country,
    Direction,
    District,
    Floor,
    Landmark,
    Locality,
    Name,
    Number,
    Postcode,
    PostOfficeBox,
    Region,
    Room,
    Separator,
    Subdistrict,
    Birth,
    Death,
    Wedding,
    Calendar,
    FreeBusy,
    Application,
    Device,
    Group,
    Individual,
    Location,
    Org,
    Directory,
    Entry,
    Contact,
    Logo,
    Photo,
    Sound,
    Credential,
    Generation,
    Given,
    Given2,
    Surname,
    Surname2,
    Title,
    Expertise,
    Hobby,
    Interest,
    Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactLevel {
    High,
    Low,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactRelation {
    Acquaintance,
    Agent,
    Child,
    Colleague,
    Contact,
    CoResident,
    CoWorker,
    Crush,
    Date,
    Emergency,
    Friend,
    Kin,
    Me,
    Met,
    Muse,
    Neighbor,
    Parent,
    Sibling,
    Spouse,
    Sweetheart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactPhoneticSystem {
    Ipa,
    Jyut,
    Piny,
    Script,
}

#[cfg(test)]
impl<I, B> std::fmt::Display for JSContact<'_, I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string_pretty(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s)
    }
}

impl<T> JSContactId for T where
    T: FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

impl<I: JSContactId> From<I> for JSContactProperty<I> {
    fn from(id: I) -> Self {
        JSContactProperty::IdValue(id)
    }
}

impl<I: JSContactId, B: JSContactId> From<I> for JSContactValue<I, B> {
    fn from(id: I) -> Self {
        JSContactValue::Id(id)
    }
}

impl<'x, I: JSContactId, B: JSContactId> Default for JSContact<'x, I, B> {
    fn default() -> Self {
        Self(Value::Object(jmap_tools::Map::new()))
    }
}

impl<I: JSContactId> Display for JSContactProperty<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use jmap_tools::{Key, Value};

    use crate::{
        jscontact::{JSContact, JSContactProperty, JSContactValue},
        vcard::{VCard, VCardProperty},
    };

    #[derive(Debug, Default)]
    struct Test {
        comment: String,
        test: String,
        expect: String,
        roundtrip: String,
        line_num: usize,
    }

    #[test]
    fn convert_jscontact() {
        // Read all test files in the test directory
        for entry in std::fs::read_dir("resources/jscontact").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let input = std::fs::read_to_string(&path).unwrap();
            super::set_fn_derivation_disabled(
                path.file_name().and_then(|name| name.to_str()) != Some("003_names.txt"),
            );
            let mut test = Test::default();
            let mut cur_command = "";
            let mut cur_value = &mut test.test;

            for (line_num, line) in input.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(line) = line.strip_prefix("> ") {
                    let (command, comment) = line.split_once(' ').unwrap_or((line, ""));

                    match (command, cur_command) {
                        ("test", _) => {
                            if !test.test.is_empty() {
                                test.run();
                            }
                            test = Test::default();
                            cur_value = &mut test.test;
                            cur_command = "test";
                            test.comment = comment.to_string();
                            test.line_num = line_num + 1;
                        }
                        ("convert", "test") => {
                            cur_command = "convert";
                            cur_value = &mut test.expect;
                        }
                        ("convert", "convert") => {
                            cur_command = "convert";
                            cur_value = &mut test.roundtrip;
                        }
                        _ => {
                            panic!(
                                "Unexpected command '{}' in file '{}' at line {}",
                                command,
                                path.display(),
                                line_num + 1
                            );
                        }
                    }
                } else {
                    cur_value.push_str(line);
                    cur_value.push('\n');
                }
            }

            if !test.test.is_empty() {
                test.run();
            }
        }
    }

    impl Test {
        fn run(mut self) {
            if self.expect.is_empty() {
                panic!(
                    "Test '{}' at line {} has no expected output",
                    self.comment, self.line_num
                );
            }

            println!("Running test '{}' at line {}", self.comment, self.line_num);

            if is_jscontact(&self.test) {
                fix_jscontact(&mut self.test);
                fix_vcard(&mut self.expect);
                let source =
                    sanitize_jscontact(parse_jscontact(&self.comment, self.line_num, &self.test));
                let expect =
                    sanitize_vcard(parse_vcard(&self.comment, self.line_num, &self.expect));
                let roundtrip = if !self.roundtrip.is_empty() {
                    fix_jscontact(&mut self.roundtrip);
                    sanitize_jscontact(parse_jscontact(
                        &self.comment,
                        self.line_num,
                        &self.roundtrip,
                    ))
                } else {
                    source.clone()
                };

                let first_convert = sanitize_vcard(source.into_vcard().unwrap_or_else(|| {
                    panic!(
                        "Failed to convert JSContact to vCard: test {} on line {}: {}",
                        self.comment, self.line_num, self.test
                    )
                }));
                if first_convert != expect {
                    let first_convert =
                        sanitize_vcard(VCard::parse(first_convert.to_string()).unwrap());

                    if first_convert != expect {
                        panic!(
                            "JSContact to vCard conversion failed: test {} on line {}, expected: {}, got: {}",
                            self.comment, self.line_num, expect, first_convert
                        );
                    }
                }
                let roundtrip_convert = sanitize_jscontact(first_convert.into_jscontact());
                if roundtrip_convert != roundtrip {
                    let roundtrip_convert = roundtrip_convert.to_string();
                    let roundtrip = roundtrip.to_string();

                    if roundtrip_convert != roundtrip {
                        panic!(
                            "vCard to JSContact conversion failed: test {} on line {}, expected: {}, got: {}",
                            self.comment, self.line_num, roundtrip, roundtrip_convert
                        );
                    }
                }
            } else {
                fix_vcard(&mut self.test);
                fix_jscontact(&mut self.expect);
                let source = sanitize_vcard(parse_vcard(&self.comment, self.line_num, &self.test));
                let expect =
                    sanitize_jscontact(parse_jscontact(&self.comment, self.line_num, &self.expect));
                let roundtrip = if !self.roundtrip.is_empty() {
                    fix_vcard(&mut self.roundtrip);
                    sanitize_vcard(parse_vcard(&self.comment, self.line_num, &self.roundtrip))
                } else {
                    source.clone()
                };
                let first_convert = sanitize_jscontact(source.into_jscontact());
                if first_convert != expect {
                    let first_convert = first_convert.to_string();
                    let expect = expect.to_string();

                    if first_convert != expect {
                        panic!(
                            "vCard to JSContact conversion failed: test {} on line {}, expected: {}, got: {}",
                            self.comment, self.line_num, expect, first_convert
                        );
                    }
                }
                let roundtrip_convert =
                    sanitize_vcard(first_convert.into_vcard().unwrap_or_else(|| {
                        panic!(
                            "Failed to convert JSContact to vCard: test {} on line {}: {}",
                            self.comment, self.line_num, self.test
                        )
                    }));
                if roundtrip_convert != roundtrip {
                    let roundtrip_convert =
                        sanitize_vcard(VCard::parse(roundtrip_convert.to_string()).unwrap());
                    if roundtrip_convert != roundtrip {
                        panic!(
                            "JSContact to vCard conversion failed: test {} on line {}, expected: {}, got: {}",
                            self.comment, self.line_num, roundtrip, roundtrip_convert
                        );
                    }
                }
            }
        }
    }

    fn is_jscontact(s: &str) -> bool {
        s.starts_with("{") || s.starts_with("\"")
    }

    fn fix_vcard(s: &mut String) {
        if !s.starts_with("BEGIN:VCARD") {
            let mut v = "BEGIN:VCARD\nVERSION:4.0\n".to_string();
            v.push_str(s);
            v.push_str("END:VCARD\n");
            *s = v;
        }
    }

    fn fix_jscontact(s: &mut String) {
        if !s.starts_with("{") {
            let mut v = "{\"@type\": \"Card\", \"version\": \"1.0\",\n".to_string();
            v.push_str(s);
            v.push_str("\n}\n");
            *s = v;
        }
    }

    fn parse_vcard(test_name: &str, line_num: usize, s: &str) -> VCard {
        VCard::parse(s).unwrap_or_else(|_| {
            panic!(
                "Failed to parse vCard: {} on line {}, test {}",
                s, line_num, test_name
            )
        })
    }

    fn parse_jscontact<'x>(
        test_name: &str,
        line_num: usize,
        s: &'x str,
    ) -> JSContact<'x, String, String> {
        JSContact::parse(s).unwrap_or_else(|_| {
            panic!(
                "Failed to parse JSContact: {} on line {}, test {}",
                s, line_num, test_name
            )
        })
    }

    fn sanitize_vcard(mut vcard: VCard) -> VCard {
        vcard
            .entries
            .retain(|e| !matches!(e.name, VCardProperty::Version));
        vcard.entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        vcard
    }

    fn sanitize_jscontact(
        mut jscontact: JSContact<'_, String, String>,
    ) -> JSContact<'_, String, String> {
        sort_jscontact_properties(&mut jscontact.0);
        jscontact
    }

    fn sort_jscontact_properties(
        value: &mut Value<'_, JSContactProperty<String>, JSContactValue<String, String>>,
    ) {
        match value {
            Value::Array(value) => {
                for item in value {
                    sort_jscontact_properties(item);
                }
            }
            Value::Object(obj) => {
                obj.as_mut_vec()
                    .retain(|(k, _)| !matches!(k, Key::Property(JSContactProperty::Type)));
                obj.as_mut_vec()
                    .sort_unstable_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
                for (_, item) in obj.as_mut_vec() {
                    sort_jscontact_properties(item);
                }
            }
            _ => {}
        }
    }
}
