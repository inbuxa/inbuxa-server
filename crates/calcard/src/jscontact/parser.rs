/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        CalendarScale, IanaParse, IdReference,
        jsprop::text::{DisplayEq, IdReferenceText, PointerText, PointerTextExt},
    },
    jscalendar::{
        JSCalendarDateTime,
        parser::{BLOB_ID_SUFFIX, KEY_TEXT, StackText, VALUE_TEXT},
    },
    jscontact::{
        Context, Feature, JSContact, JSContactGrammaticalGender, JSContactId, JSContactKind,
        JSContactLevel, JSContactPhoneticSystem, JSContactProperty, JSContactRelation,
        JSContactType, JSContactValue,
    },
};
use jiff::Timestamp;
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, PointerDepth, Property as _, Value};
use serde::Serializer;
use std::{
    borrow::Cow,
    fmt::{self, Write},
    mem::discriminant,
    str::FromStr,
};

impl<'x, I, B> JSContact<'x, I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    pub fn parse(json: &'x str) -> Result<Self, String> {
        Value::parse_json(json).map(JSContact)
    }

    pub fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.0).unwrap_or_default()
    }
}

impl<I, B> Element for JSContactValue<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    type Property = JSContactProperty<I>;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                JSContactProperty::Type => JSContactType::from_str(value)
                    .ok()
                    .map(JSContactValue::Type),
                JSContactProperty::CalendarScale => {
                    CalendarScale::parse(value.as_bytes()).map(JSContactValue::CalendarScale)
                }
                JSContactProperty::Created
                | JSContactProperty::Updated
                | JSContactProperty::Utc => value
                    .parse::<Timestamp>()
                    .map(|dt| JSContactValue::Timestamp(dt.as_second()))
                    .ok(),
                JSContactProperty::Kind => JSContactKind::from_str(value)
                    .ok()
                    .map(JSContactValue::Kind),
                JSContactProperty::GrammaticalGender => JSContactGrammaticalGender::from_str(value)
                    .ok()
                    .map(JSContactValue::GrammaticalGender),
                JSContactProperty::PhoneticSystem => JSContactPhoneticSystem::from_str(value)
                    .ok()
                    .map(JSContactValue::PhoneticSystem),
                JSContactProperty::Relation => JSContactRelation::from_str(value)
                    .ok()
                    .map(JSContactValue::Relation),
                JSContactProperty::Level => JSContactLevel::from_str(value)
                    .ok()
                    .map(JSContactValue::Level),
                JSContactProperty::BlobId => match IdReference::parse(value) {
                    IdReference::Value(value) => JSContactValue::BlobId(value).into(),
                    IdReference::Reference(value) => JSContactValue::IdReference(value).into(),
                    IdReference::Error => None,
                },
                JSContactProperty::Id => match IdReference::parse(value) {
                    IdReference::Value(value) => JSContactValue::Id(value).into(),
                    IdReference::Reference(value) => JSContactValue::IdReference(value).into(),
                    IdReference::Error => None,
                },
                _ => None,
            }
        } else if key
            .as_string_key()
            .is_some_and(|name| name.ends_with(BLOB_ID_SUFFIX))
        {
            match IdReference::parse(value) {
                IdReference::Value(value) => JSContactValue::BlobId(value).into(),
                IdReference::Reference(value) => JSContactValue::IdReference(value).into(),
                IdReference::Error => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JSContactValue::Type(v) => v.as_str().into(),
            JSContactValue::GrammaticalGender(v) => v.as_str().into(),
            JSContactValue::Kind(v) => v.as_str().into(),
            JSContactValue::Level(v) => v.as_str().into(),
            JSContactValue::Relation(v) => v.as_str().into(),
            JSContactValue::PhoneticSystem(v) => v.as_str().into(),
            JSContactValue::Timestamp(v) => JSCalendarDateTime::new(*v, false).to_rfc3339().into(),
            JSContactValue::CalendarScale(v) => v.as_js_str().into(),
            JSContactValue::Id(v) => v.to_string().into(),
            JSContactValue::BlobId(v) => v.to_string().into(),
            JSContactValue::IdReference(s) => s.to_id_reference().into(),
        }
    }

    #[inline]
    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JSContactValue::Timestamp(_)
            | JSContactValue::Id(_)
            | JSContactValue::BlobId(_)
            | JSContactValue::IdReference(_) => self.serialize_data_text(serializer),
            _ => serializer.serialize_str(&self.to_cow()),
        }
    }
}

impl<I: JSContactId, B: JSContactId> JSContactValue<I, B> {
    #[inline(never)]
    fn serialize_data_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StackText::<VALUE_TEXT>::serialize(
            serializer,
            |text| match self {
                JSContactValue::Timestamp(timestamp) => {
                    JSCalendarDateTime::new(*timestamp, false).push_rfc3339(text)
                }
                JSContactValue::Id(id) => write!(text, "{id}"),
                JSContactValue::BlobId(id) => write!(text, "{id}"),
                JSContactValue::IdReference(id) => text.push_id_reference(id),
                _ => Err(fmt::Error),
            },
            || self.to_cow(),
        )
    }
}

impl<I: JSContactId> jmap_tools::Property for JSContactProperty<I> {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        Self::try_parse_nested(key, value, PointerDepth::default())
    }

    fn try_parse_nested(
        key: Option<&Key<'_, Self>>,
        value: &str,
        depth: PointerDepth,
    ) -> Option<Self> {
        match key {
            Some(Key::Property(key)) if key.is_metadata() => None,
            Some(Key::Property(key)) => match key.patch_or_prop() {
                JSContactProperty::Contexts => Context::from_str(value)
                    .ok()
                    .map(JSContactProperty::Context),
                JSContactProperty::Features => Feature::from_str(value)
                    .ok()
                    .map(JSContactProperty::Feature),
                JSContactProperty::SortAs => JSContactKind::from_str(value)
                    .ok()
                    .map(JSContactProperty::SortAsKind),
                JSContactProperty::ConvertedProperties | JSContactProperty::Localizations => {
                    JsonPointer::parse_nested(value, depth).map(JSContactProperty::Pointer)
                }
                JSContactProperty::AddressBookIds => match IdReference::parse(value) {
                    IdReference::Value(value) => JSContactProperty::IdValue(value).into(),
                    IdReference::Reference(value) => JSContactProperty::IdReference(value).into(),
                    IdReference::Error => None,
                },
                JSContactProperty::Pointer(language)
                    if matches!(
                        language.as_slice(),
                        [JsonPointerItem::Key(Key::Borrowed(_) | Key::Owned(_))]
                    ) =>
                {
                    JSContactProperty::parse_name(value)
                }
                _ => JSContactProperty::parse_nested_name(value),
            },
            None if value.contains('/') => {
                JsonPointer::parse_nested(value, depth).map(JSContactProperty::Pointer)
            }
            None => JSContactProperty::parse_name(value),
            Some(_) => JSContactProperty::parse_nested_name(value),
        }
    }

    fn is_opaque(&self) -> bool {
        self.is_metadata()
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JSContactProperty::Pointer(pointer) => pointer.to_text().into(),
            JSContactProperty::IdReference(id) => id.to_id_reference().into(),
            _ => self.to_string(),
        }
    }

    #[inline]
    fn key_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (a, b) if !a.has_data() && !b.has_data() => discriminant(a) == discriminant(b),
            _ => self.data_key_eq(other),
        }
    }

    #[inline]
    fn key_eq_str(&self, other: &str) -> bool {
        if !self.has_data() {
            self.to_string() == other
        } else {
            self.data_key_eq_str(other)
        }
    }

    #[inline]
    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JSContactProperty::Pointer(_)
            | JSContactProperty::IdValue(_)
            | JSContactProperty::IdReference(_) => self.serialize_data_text(serializer),
            _ => serializer.serialize_str(&self.to_cow()),
        }
    }
}

impl<I: JSContactId> JSContactProperty<I> {
    #[inline(never)]
    fn serialize_data_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StackText::<KEY_TEXT>::serialize(
            serializer,
            |text| match self {
                JSContactProperty::Pointer(pointer) => {
                    text.push_pointer(pointer, |key, text| text.push_pointer_token(&key.to_cow()))
                }
                JSContactProperty::IdValue(id) => write!(text, "{id}"),
                JSContactProperty::IdReference(id) => text.push_id_reference(id),
                _ => Err(fmt::Error),
            },
            || self.to_cow(),
        )
    }

    #[inline(never)]
    fn data_key_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JSContactProperty::Pointer(a), JSContactProperty::Pointer(b)) if a == b => true,
            _ => match (self.static_name(), other.static_name()) {
                (Some(a), Some(b)) => a == b,
                (Some(a), None) => other.data_key_eq_str(a),
                (None, Some(b)) => self.data_key_eq_str(b),
                (None, None) => other.data_key_eq_str(&self.to_string()),
            },
        }
    }

    #[inline(never)]
    fn data_key_eq_str(&self, other: &str) -> bool {
        match self {
            JSContactProperty::IdValue(id) => id.display_eq(other),
            JSContactProperty::Pointer(pointer) => pointer.text_eq(other),
            JSContactProperty::IdReference(reference) => {
                other.strip_prefix('#') == Some(reference.as_str())
            }
            _ => self.to_string() == other,
        }
    }

    #[inline]
    fn has_data(&self) -> bool {
        match self {
            JSContactProperty::IdValue(_)
            | JSContactProperty::IdReference(_)
            | JSContactProperty::Context(_)
            | JSContactProperty::Feature(_)
            | JSContactProperty::SortAsKind(_)
            | JSContactProperty::Pointer(_) => true,
            JSContactProperty::Type
            | JSContactProperty::Address
            | JSContactProperty::AddressBookIds
            | JSContactProperty::Addresses
            | JSContactProperty::Anniversaries
            | JSContactProperty::Author
            | JSContactProperty::BlobId
            | JSContactProperty::Calendars
            | JSContactProperty::CalendarScale
            | JSContactProperty::Components
            | JSContactProperty::Contexts
            | JSContactProperty::ConvertedProperties
            | JSContactProperty::Coordinates
            | JSContactProperty::CountryCode
            | JSContactProperty::Created
            | JSContactProperty::CryptoKeys
            | JSContactProperty::Date
            | JSContactProperty::Day
            | JSContactProperty::DefaultSeparator
            | JSContactProperty::Directories
            | JSContactProperty::Emails
            | JSContactProperty::Extra
            | JSContactProperty::Features
            | JSContactProperty::Full
            | JSContactProperty::GrammaticalGender
            | JSContactProperty::Id
            | JSContactProperty::IsOrdered
            | JSContactProperty::Keywords
            | JSContactProperty::Kind
            | JSContactProperty::Label
            | JSContactProperty::Language
            | JSContactProperty::Level
            | JSContactProperty::Links
            | JSContactProperty::ListAs
            | JSContactProperty::Localizations
            | JSContactProperty::Media
            | JSContactProperty::MediaType
            | JSContactProperty::Members
            | JSContactProperty::Month
            | JSContactProperty::Name
            | JSContactProperty::Nicknames
            | JSContactProperty::Note
            | JSContactProperty::Notes
            | JSContactProperty::Number
            | JSContactProperty::OnlineServices
            | JSContactProperty::OrganizationId
            | JSContactProperty::Organizations
            | JSContactProperty::Parameters
            | JSContactProperty::PersonalInfo
            | JSContactProperty::Phones
            | JSContactProperty::Phonetic
            | JSContactProperty::PhoneticScript
            | JSContactProperty::PhoneticSystem
            | JSContactProperty::Place
            | JSContactProperty::Pref
            | JSContactProperty::PreferredLanguages
            | JSContactProperty::ProdId
            | JSContactProperty::Pronouns
            | JSContactProperty::Properties
            | JSContactProperty::RelatedTo
            | JSContactProperty::Relation
            | JSContactProperty::SchedulingAddresses
            | JSContactProperty::Service
            | JSContactProperty::SortAs
            | JSContactProperty::SpeakToAs
            | JSContactProperty::TimeZone
            | JSContactProperty::Titles
            | JSContactProperty::Uid
            | JSContactProperty::Units
            | JSContactProperty::Updated
            | JSContactProperty::Uri
            | JSContactProperty::User
            | JSContactProperty::Utc
            | JSContactProperty::VCard
            | JSContactProperty::Value
            | JSContactProperty::Version
            | JSContactProperty::Year
            | JSContactProperty::Metadata
            | JSContactProperty::PrivateMetadata => false,
        }
    }

    fn static_name(&self) -> Option<&'static str> {
        match self {
            JSContactProperty::Pointer(_)
            | JSContactProperty::IdValue(_)
            | JSContactProperty::IdReference(_) => None,
            _ => match self.to_string() {
                Cow::Borrowed(name) => Some(name),
                Cow::Owned(_) => None,
            },
        }
    }

    fn patch_or_prop(&self) -> &JSContactProperty<I> {
        if let JSContactProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

