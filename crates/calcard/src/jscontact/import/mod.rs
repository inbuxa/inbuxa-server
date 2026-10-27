/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        CalendarScale, IanaType,
        blob::{BlobIdFn, BlobIdGenerator, BlobIds, BlobOptions, NoBlobIds},
        jsprop::ordered::OrderedMap,
    },
    jscontact::{JSContactId, JSContactProperty, JSContactValue},
    vcard::{
        Jscomp, VCardEntry, VCardLevel, VCardParameterName, VCardPhonetic, VCardProperty, VCardType,
    },
};
use jmap_tools::{Element, JsonPointer, Key, Map, Property, Value};

pub mod convert;
pub mod entry;
pub mod params;
pub mod props;

type JSValue<I, B> = Value<'static, JSContactProperty<I>, JSContactValue<I, B>>;

type Member<I, B> = (Key<'static, JSContactProperty<I>>, JSValue<I, B>);

type PatchObject<I, B> = (JsonPointer<JSContactProperty<I>>, JSValue<I, B>);

type Localization<I, B> = Vec<(String, JSValue<I, B>)>;

struct CardProperties<I, B>(Vec<Member<I, B>>)
where
    I: JSContactId,
    B: JSContactId;

struct State<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    entries: CardProperties<I, B>,
    vcard_converted_properties: OrderedMap<String, VCardConvertedProperty<I, B>>,
    vcard_properties: Vec<JSValue<I, B>>,
    patch_objects: Vec<PatchObject<I, B>>,
    localizations: OrderedMap<String, Localization<I, B>>,
    default_language: Option<String>,
    prop_ids: PropIds<I>,
    name_alt_id: Option<String>,
    has_fn: bool,
    has_fn_localization: bool,
    has_n: bool,
    has_n_localization: bool,
    has_gram_gender: bool,
    include_vcard_converted: bool,
}

#[derive(Debug, Clone)]
struct EntryState {
    entry: VCardEntry,
    converted_to: Option<String>,
    map_name: bool,
    keep_converted_path: bool,
}

struct PropIdKey<I>
where
    I: JSContactId,
{
    prop: VCardProperty,
    prop_js: JSContactProperty<I>,
    group: Option<String>,
    alt_id: Option<String>,
    prop_id: String,
}

struct PropIds<I>
where
    I: JSContactId,
{
    keys: Vec<PropIdKey<I>>,
    is_enabled: bool,
}

#[derive(Debug, Default)]
struct VCardConvertedProperty<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    name: Option<VCardProperty>,
    params: VCardParams<I, B>,
}

#[derive(Debug, Default)]
struct VCardParams<I, B>(OrderedMap<VCardParameterName, Vec<JSValue<I, B>>>)
where
    I: JSContactId,
    B: JSContactId;

#[derive(Default)]
struct ExtractedParams {
    language: Option<String>,
    pref: Option<u32>,
    author: Option<String>,
    author_name: Option<String>,
    phonetic_system: Option<IanaType<VCardPhonetic, String>>,
    phonetic_script: Option<String>,
    media_type: Option<String>,
    calscale: Option<IanaType<CalendarScale, String>>,
    sort_as: Option<String>,
    prop_id: Option<String>,
    alt_id: Option<String>,
    types: Vec<IanaType<VCardType, String>>,
    geo: Option<String>,
    tz: Option<String>,
    index: Option<u32>,
    level: Option<IanaType<VCardLevel, String>>,
    country_code: Option<String>,
    created: Option<i64>,
    label: Option<String>,
    service_type: Option<String>,
    username: Option<String>,
    jscomps: Vec<Jscomp>,
}

impl<I, B> CardProperties<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn position(&self, property: &JSContactProperty<I>) -> Option<usize> {
        self.0
            .iter()
            .position(|(key, _)| matches!(key, Key::Property(existing) if existing == property))
    }

    fn contains(&self, property: &JSContactProperty<I>) -> bool {
        self.position(property).is_some()
    }

    fn get_mut(&mut self, property: &JSContactProperty<I>) -> Option<&mut JSValue<I, B>> {
        self.0.iter_mut().find_map(|(key, value)| {
            matches!(key, Key::Property(existing) if existing == property).then_some(value)
        })
    }

    fn insert(&mut self, property: JSContactProperty<I>, value: JSValue<I, B>) {
        match self.get_mut(&property) {
            Some(existing) => *existing = value,
            None => self.0.push((Key::Property(property), value)),
        }
    }

    fn get_mut_object_or_insert(
        &mut self,
        property: JSContactProperty<I>,
    ) -> &mut Map<'static, JSContactProperty<I>, JSContactValue<I, B>> {
        let index = self.position(&property).unwrap_or_else(|| {
            self.0.push((
                Key::Property(property),
                Value::Object(Map::from(Vec::new())),
            ));
            self.0.len() - 1
        });
        self.0[index].1.object_or_replace()
    }

    fn into_map(self) -> Map<'static, JSContactProperty<I>, JSContactValue<I, B>> {
        Map::from(self.0)
    }
}

impl<I, B> VCardParams<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    fn push(&mut self, name: VCardParameterName, value: JSValue<I, B>) {
        match self.0.get_mut(&name) {
            Some(values) => values.push(value),
            None => self.0.push(name, vec![value]),
        }
    }

    fn set(&mut self, name: VCardParameterName, values: Vec<JSValue<I, B>>) {
        self.0.insert(name, values);
    }
}

trait ObjectValue<'x, P: Property, E: Element> {
    fn object_or_replace(&mut self) -> &mut Map<'x, P, E>;
}

impl<'x, P: Property, E: Element> ObjectValue<'x, P, E> for Value<'x, P, E> {
    #[inline]
    fn object_or_replace(&mut self) -> &mut Map<'x, P, E> {
        match self {
            Value::Object(object) => object,
            value => {
                *value = Value::Object(Map::from(Vec::new()));
                value.object_or_replace()
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ImportOptions<G = NoBlobIds> {
    include_vcard_parameters: bool,
    blobs: BlobOptions<G>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            include_vcard_parameters: true,
            blobs: BlobOptions::default(),
        }
    }
}

impl ImportOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<G> ImportOptions<G> {
    pub fn include_vcard_parameters(mut self, include: bool) -> Self {
        self.include_vcard_parameters = include;
        self
    }

    pub fn with_blob_ids<B, F>(self, blob_ids: F) -> ImportOptions<BlobIdFn<F>>
    where
        F: FnMut(&[u8]) -> Option<B>,
    {
        self.with_blob_id_generator(BlobIdFn(blob_ids))
    }

    pub fn with_blob_id_generator<T>(self, blob_id_generator: T) -> ImportOptions<T> {
        ImportOptions {
            include_vcard_parameters: self.include_vcard_parameters,
            blobs: self.blobs.with_handler(blob_id_generator),
        }
    }

    pub(super) fn blob_ids<B: Clone>(&mut self) -> Option<BlobIds<'_, B>>
    where
        G: BlobIdGenerator<B>,
    {
        self.blobs.blob_ids()
    }
}
