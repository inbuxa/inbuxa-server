/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{IanaType, jsprop::text::IntoAsciiLowercase},
    jscontact::{
        Context, Feature, JSContactId, JSContactKind, JSContactLevel, JSContactPhoneticSystem,
        JSContactProperty, JSContactValue,
        import::{ExtractedParams, Member, VCardParams},
    },
    vcard::{
        VCardLevel, VCardParameter, VCardParameterName, VCardParameterValue, VCardPhonetic,
        VCardProperty, VCardType,
    },
};
use jmap_tools::{Key, Map, Value};
use std::{mem, str::FromStr};

impl Feature {
    pub(crate) fn from_vcard_type(property: &VCardProperty, typ: &VCardType) -> Option<Self> {
        match (property, typ) {
            (VCardProperty::Tel, VCardType::Cell) => Some(Feature::Mobile),
            (VCardProperty::Tel, VCardType::Fax) => Some(Feature::Fax),
            (VCardProperty::Tel, VCardType::MainNumber) => Some(Feature::MainNumber),
            (VCardProperty::Tel, VCardType::Pager) => Some(Feature::Pager),
            (VCardProperty::Tel, VCardType::Text) => Some(Feature::Text),
            (VCardProperty::Tel, VCardType::Textphone) => Some(Feature::TextPhone),
            (VCardProperty::Tel, VCardType::Video) => Some(Feature::Video),
            (VCardProperty::Tel, VCardType::Voice) => Some(Feature::Voice),
            _ => None,
        }
    }
}

impl<I: JSContactId> JSContactProperty<I> {
    pub(crate) fn from_vcard_type(
        property: &VCardProperty,
        typ: IanaType<VCardType, String>,
    ) -> (Self, Key<'static, Self>) {
        let feature = match &typ {
            IanaType::Iana(typ) => Feature::from_vcard_type(property, typ),
            IanaType::Other(_) => None,
        };
        if let Some(feature) = feature {
            return (
                JSContactProperty::Features,
                Key::Property(JSContactProperty::Feature(feature)),
            );
        }

        let key = match typ {
            IanaType::Iana(VCardType::Home) => {
                Key::Property(JSContactProperty::Context(Context::Private))
            }
            IanaType::Iana(VCardType::Work) => {
                Key::Property(JSContactProperty::Context(Context::Work))
            }
            IanaType::Iana(VCardType::Billing) => {
                Key::Property(JSContactProperty::Context(Context::Billing))
            }
            IanaType::Iana(VCardType::Delivery) => {
                Key::Property(JSContactProperty::Context(Context::Delivery))
            }
            IanaType::Iana(VCardType::Cell) => Key::Borrowed("mobile"),
            typ => {
                let key = typ.into_string().to_ascii_lowercase();
                match Context::from_str(&key) {
                    Ok(context) => Key::Property(JSContactProperty::Context(context)),
                    Err(()) => Key::Owned(key),
                }
            }
        };
        (JSContactProperty::Contexts, key)
    }
}

impl VCardParameter {
    pub(super) fn take_value(&mut self) -> VCardParameterValue {
        mem::replace(&mut self.value, VCardParameterValue::Null)
    }

    pub(super) fn as_media_type(&self) -> Option<&str> {
        match (&self.name, &self.value) {
            (VCardParameterName::Mediatype, VCardParameterValue::Text(media_type))
                if !media_type.is_empty() =>
            {
                Some(media_type)
            }
            _ => None,
        }
    }
}

impl ExtractedParams {
    pub(super) fn prop_id(&mut self) -> Option<String> {
        self.prop_id.take()
    }

    pub(super) fn alt_id(&mut self) -> Option<String> {
        self.alt_id.take()
    }

    pub(super) fn language(&mut self) -> Option<String> {
        self.language.take()
    }

    pub(super) fn types(&mut self) -> Vec<IanaType<VCardType, String>> {
        std::mem::take(&mut self.types)
    }

    pub(super) fn members<I: JSContactId, B: JSContactId>(
        &mut self,
        property: &VCardProperty,
    ) -> ParamMembers<'_, I, B> {
        let mut contexts: Option<Vec<Member<I, B>>> = None;
        let mut features: Option<Vec<Member<I, B>>> = None;

        for typ in std::mem::take(&mut self.types) {
            let (bucket, key) = JSContactProperty::<I>::from_vcard_type(property, typ);
            let keys = if bucket == JSContactProperty::Features {
                features.get_or_insert_default()
            } else {
                contexts.get_or_insert_default()
            };
            if keys.iter().all(|(existing, _)| existing != &key) {
                keys.push((key, Value::Bool(true)));
            }
        }

        ParamMembers {
            contexts,
            features,
            is_name: matches!(property, VCardProperty::N),
            is_address: matches!(property, VCardProperty::Adr),
            params: self,
        }
    }
}

pub(super) struct ParamMembers<'x, I: JSContactId, B: JSContactId> {
    contexts: Option<Vec<Member<I, B>>>,
    features: Option<Vec<Member<I, B>>>,
    is_name: bool,
    is_address: bool,
    params: &'x mut ExtractedParams,
}

impl<I: JSContactId, B: JSContactId> ParamMembers<'_, I, B> {
    pub(super) fn len(&self) -> usize {
        let p = &*self.params;
        [
            self.contexts.is_some(),
            self.features.is_some(),
            p.language.is_some(),
            p.pref.is_some(),
            p.author.is_some() || p.author_name.is_some(),
            p.media_type.is_some(),
            p.phonetic_system.is_some(),
            p.phonetic_script.is_some(),
            p.calscale.is_some(),
            p.sort_as.is_some(),
            p.geo.is_some(),
            p.tz.is_some(),
            p.index.is_some(),
            p.level.is_some(),
            p.country_code.is_some(),
            p.created.is_some(),
            p.label.is_some(),
            p.service_type.is_some(),
            p.username.is_some(),
        ]
        .into_iter()
        .filter(|&present| present)
        .count()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn append_to(self, members: &mut Vec<Member<I, B>>) {
        self.for_each(|key, value| members.push((key, value)));
    }

    pub(super) fn for_each(
        self,
        mut emit: impl FnMut(
            Key<'static, JSContactProperty<I>>,
            Value<'static, JSContactProperty<I>, JSContactValue<I, B>>,
        ),
    ) {
        let p = self.params;

        if let Some(contexts) = self.contexts {
            emit(
                Key::Property(JSContactProperty::Contexts),
                Value::Object(Map::from(contexts)),
            );
        }
        if let Some(features) = self.features {
            emit(
                Key::Property(JSContactProperty::Features),
                Value::Object(Map::from(features)),
            );
        }
        if let Some(language) = p.language.take() {
            emit(
                Key::Property(JSContactProperty::Language),
                Value::Str(language.into()),
            );
        }
        if let Some(pref) = p.pref.take() {
            emit(
                Key::Property(JSContactProperty::Pref),
                Value::Number((pref as u64).into()),
            );
        }
        if p.author.is_some() || p.author_name.is_some() {
            emit(
                Key::Property(JSContactProperty::Author),
                Value::Object(Map::from_iter(
                    [
                        p.author_name.take().map(|name| {
                            (
                                Key::Property(JSContactProperty::Name),
                                Value::Str(name.into()),
                            )
                        }),
                        p.author.take().map(|author| {
                            (
                                Key::Property(JSContactProperty::Uri),
                                Value::Str(author.into()),
                            )
                        }),
                    ]
                    .into_iter()
                    .flatten(),
                )),
            );
        }
        if let Some(media_type) = p.media_type.take() {
            emit(
                Key::Property(JSContactProperty::MediaType),
                Value::Str(media_type.into()),
            );
        }
        if let Some(phonetic_system) = p.phonetic_system.take() {
            emit(
                Key::Property(JSContactProperty::PhoneticSystem),
                match phonetic_system {
                    IanaType::Iana(value) => {
                        Value::Element(JSContactValue::PhoneticSystem(match value {
                            VCardPhonetic::Ipa => JSContactPhoneticSystem::Ipa,
                            VCardPhonetic::Jyut => JSContactPhoneticSystem::Jyut,
                            VCardPhonetic::Piny => JSContactPhoneticSystem::Piny,
                            VCardPhonetic::Script => JSContactPhoneticSystem::Script,
                        }))
                    }
                    IanaType::Other(value) => Value::Str(value.into()),
                },
            );
        }
        if let Some(phonetic_script) = p.phonetic_script.take() {
            emit(
                Key::Property(JSContactProperty::PhoneticScript),
                Value::Str(phonetic_script.into()),
            );
        }
        if let Some(calscale) = p.calscale.take() {
            emit(
                Key::Property(JSContactProperty::CalendarScale),
                match calscale {
                    IanaType::Iana(value) => Value::Element(JSContactValue::CalendarScale(value)),
                    IanaType::Other(value) => Value::Str(value.into()),
                },
            );
        }
        if let Some(sort_as) = p.sort_as.take() {
            emit(
                Key::Property(JSContactProperty::SortAs),
                if self.is_name {
                    if let Some((surname, given)) =
                        sort_as.split_once(',').and_then(|(surname, given)| {
                            let surname = surname.trim();
                            let given = given.trim();

                            if surname.is_empty() || given.is_empty() {
                                None
                            } else {
                                Some((surname.to_string(), given.to_string()))
                            }
                        })
                    {
                        Value::Object(Map::from_iter(vec![
                            (
                                Key::Property(JSContactProperty::SortAsKind(
                                    JSContactKind::Surname,
                                )),
                                Value::Str(surname.into()),
                            ),
                            (
                                Key::Property(JSContactProperty::SortAsKind(JSContactKind::Given)),
                                Value::Str(given.into()),
                            ),
                        ]))
                    } else {
                        Value::Object(Map::from_iter(vec![(
                            Key::Property(JSContactProperty::SortAsKind(JSContactKind::Surname)),
                            Value::Str(sort_as.into()),
                        )]))
                    }
                } else {
                    Value::Str(sort_as.into())
                },
            );
        }
        if let Some(geo) = p.geo.take() {
            emit(
                Key::Property(JSContactProperty::Coordinates),
                Value::Str(geo.into()),
            );
        }
        if let Some(tz) = p.tz.take() {
            emit(
                Key::Property(JSContactProperty::TimeZone),
                Value::Str(tz.into()),
            );
        }
        if let Some(index) = p.index.take() {
            emit(
                Key::Property(JSContactProperty::ListAs),
                Value::Number((index as u64).into()),
            );
        }
        if let Some(level) = p.level.take() {
            emit(
                Key::Property(JSContactProperty::Level),
                match level {
                    IanaType::Iana(value) => Value::Element(JSContactValue::Level(match value {
                        VCardLevel::Beginner | VCardLevel::Low => JSContactLevel::Low,
                        VCardLevel::Average | VCardLevel::Medium => JSContactLevel::Medium,
                        VCardLevel::Expert | VCardLevel::High => JSContactLevel::High,
                    })),
                    IanaType::Other(value) => Value::Str(value.into()),
                },
            );
        }
        if let Some(country_code) = p.country_code.take() {
            emit(
                Key::Property(JSContactProperty::CountryCode),
                Value::Str(country_code.into()),
            );
        }
        if let Some(created) = p.created.take() {
            emit(
                Key::Property(JSContactProperty::Created),
                Value::Element(JSContactValue::Timestamp(created)),
            );
        }
        if let Some(label) = p.label.take() {
            emit(
                Key::Property(if self.is_address {
                    JSContactProperty::Full
                } else {
                    JSContactProperty::Label
                }),
                Value::Str(label.into()),
            );
        }
        if let Some(service_type) = p.service_type.take() {
            emit(
                Key::Property(JSContactProperty::Service),
                Value::Str(service_type.into()),
            );
        }
        if let Some(username) = p.username.take() {
            emit(
                Key::Property(JSContactProperty::User),
                Value::Str(username.into()),
            );
        }
    }
}

impl<I: JSContactId, B: JSContactId> VCardParams<I, B> {
    pub(super) fn into_jscontact_value(
        self,
    ) -> Option<Map<'static, JSContactProperty<I>, JSContactValue<I, B>>> {
        if !self.0.is_empty() {
            let mut obj = Map::from(Vec::with_capacity(self.0.len()));

            for (param, value) in self.0 {
                let value = match <[_; 1]>::try_from(value) {
                    Ok([value]) => value,
                    Err(values) => Value::Array(values),
                };
                obj.insert_unchecked(
                    Key::Owned(param.into_string().into_ascii_lowercase()),
                    value,
                );
            }
            Some(obj)
        } else {
            None
        }
    }
}
