/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Property, Value};
use serde::de::{Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::{borrow::Cow, fmt, str::FromStr};

macro_rules! property_names {
    ($property:ident, $($name:literal => $value:expr,)*) => {
        fn parse_name(value: &str) -> Option<Self> {
            hashify::fnc_map!(value.as_bytes(),
                $($name => Some($value),)*
                "metadata" => Some($property::Metadata),
                "privateMetadata" => Some($property::PrivateMetadata),
                _ => None,
            )
        }

        fn parse_nested_name(value: &str) -> Option<Self> {
            hashify::fnc_map!(value.as_bytes(),
                $($name => Some($value),)*
                _ => None,
            )
        }
    };
}

pub(crate) use property_names;

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
pub enum MetadataRoot {
    Shared,
    Private,
}

pub trait MetadataProperty: Property {
    fn as_metadata_root(&self) -> Option<MetadataRoot>;

    fn as_pointer(&self) -> Option<&JsonPointer<Self>>;

    fn from_metadata_root(root: MetadataRoot) -> Self;

    fn metadata_pointer(&self) -> Option<(MetadataRoot, &JsonPointer<Self>)> {
        let pointer = self.as_pointer()?;
        let root = pointer.first()?.as_property_key()?.as_metadata_root()?;
        Some((root, pointer))
    }

    fn metadata_root(&self) -> Option<MetadataRoot> {
        self.as_metadata_root()
            .or_else(|| self.metadata_pointer().map(|(root, _)| root))
    }

    fn has_metadata<E: Element<Property = Self>>(object: &Value<'_, Self, E>) -> bool {
        object.as_object().is_some_and(|object| {
            object
                .keys()
                .any(|key| key.as_property().and_then(Self::metadata_root).is_some())
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Selection {
    #[default]
    None,
    All,
    Namespaces(Vec<Box<str>>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataSelection {
    pub shared: Selection,
    pub private: Selection,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetadataPath {
    pub namespace: Box<str>,
    pub keys: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataFilter {
    Condition {
        root: MetadataRoot,
        path: MetadataPath,
        condition: MetadataCondition,
    },
    Invalid {
        root: MetadataRoot,
        name: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataCondition {
    Exists,
    TextContains(String),
    TextEquals(String),
}

enum FilterArgument<'de> {
    String(Cow<'de, str>),
    TextMatch(Result<(MetadataPath, String), &'static str>),
    Other,
}

struct FilterArgumentVisitor;

impl MetadataRoot {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"metadata" => Some(MetadataRoot::Shared),
            b"privateMetadata" => Some(MetadataRoot::Private),
            _ => None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataRoot::Shared => "metadata",
            MetadataRoot::Private => "privateMetadata",
        }
    }

    pub fn from_selector(value: &str) -> Option<Self> {
        value
            .split_once('/')
            .and_then(|(root, _)| MetadataRoot::parse(root))
    }
}

impl Selection {
    pub fn is_none(&self) -> bool {
        matches!(self, Selection::None)
    }

    pub fn contains(&self, namespace: &str) -> bool {
        match self {
            Selection::None => false,
            Selection::All => true,
            Selection::Namespaces(namespaces) => namespaces
                .binary_search_by(|ns| (**ns).cmp(namespace))
                .is_ok(),
        }
    }

    fn select_all(&mut self) {
        *self = Selection::All;
    }

    fn select_namespace(&mut self, namespace: Box<str>) {
        match self {
            Selection::None => *self = Selection::Namespaces(vec![namespace]),
            Selection::All => {}
            Selection::Namespaces(namespaces) => namespaces.push(namespace),
        }
    }

    fn normalize(&mut self) {
        if let Selection::Namespaces(namespaces) = self {
            namespaces.sort_unstable();
            namespaces.dedup();
        }
    }
}

impl MetadataSelection {
    pub fn all() -> Self {
        MetadataSelection {
            shared: Selection::All,
            private: Selection::All,
        }
    }

    pub fn is_none(&self) -> bool {
        self.shared.is_none() && self.private.is_none()
    }

    pub fn extract<P: MetadataProperty>(properties: &mut Vec<P>) -> trc::Result<Self> {
        let mut selection = MetadataSelection::default();
        let mut result = Ok(());

        properties.retain(|property| {
            if let Some(root) = property.as_metadata_root() {
                selection.root_mut(root).select_all();
                false
            } else if let Some((root, pointer)) = property.metadata_pointer() {
                match MetadataSelection::namespace(pointer) {
                    Ok(namespace) => selection.root_mut(root).select_namespace(namespace),
                    Err(err) => result = Err(err),
                }
                false
            } else {
                true
            }
        });

        result.map(|_| {
            selection.shared.normalize();
            selection.private.normalize();
            selection
        })
    }

    pub fn root(&self, root: MetadataRoot) -> &Selection {
        match root {
            MetadataRoot::Shared => &self.shared,
            MetadataRoot::Private => &self.private,
        }
    }

    fn root_mut(&mut self, root: MetadataRoot) -> &mut Selection {
        match root {
            MetadataRoot::Shared => &mut self.shared,
            MetadataRoot::Private => &mut self.private,
        }
    }

    fn namespace<P: Property>(pointer: &JsonPointer<P>) -> trc::Result<Box<str>> {
        let [_, namespace] = pointer.as_slice() else {
            return Err(trc::JmapEvent::InvalidArguments.into_err().details(format!(
                "Metadata subselector {pointer} must have exactly two segments"
            )));
        };
        let JsonPointerItem::Key(key) = namespace else {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details(format!("Invalid metadata subselector {pointer}")));
        };

        Ok(key.to_string().into())
    }
}

impl MetadataPath {
    fn unescape(segment: &str) -> Option<Box<str>> {
        let Some((literal, mut rest)) = segment.split_once('~') else {
            return Some(segment.into());
        };
        let mut unescaped = String::with_capacity(segment.len());
        unescaped.push_str(literal);

        loop {
            let (escaped, tail) = rest
                .strip_prefix('0')
                .map(|tail| ('~', tail))
                .or_else(|| rest.strip_prefix('1').map(|tail| ('/', tail)))?;
            unescaped.push(escaped);
            rest = tail;

            match rest.split_once('~') {
                Some((literal, tail)) => {
                    unescaped.push_str(literal);
                    rest = tail;
                }
                None => {
                    unescaped.push_str(rest);
                    return Some(unescaped.into_boxed_str());
                }
            }
        }
    }
}

impl FromStr for MetadataPath {
    type Err = &'static str;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let unescape =
            |segment| MetadataPath::unescape(segment).ok_or("invalid escape in metadata path");
        let (namespace, keys) = match path.split_once('/') {
            Some((namespace, keys)) => (namespace, keys.split('/').map(unescape).collect()),
            None => (path, Ok(Box::default())),
        };

        Ok(MetadataPath {
            namespace: unescape(namespace)?,
            keys: keys?,
        })
    }
}

impl MetadataFilter {
    pub fn try_deserialize<'de, A>(key: &str, map: &mut A) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"metadataExists" => MetadataFilter::deserialize_exists(
                MetadataRoot::Shared,
                "metadataExists",
                map,
            ),
            b"privateMetadataExists" => MetadataFilter::deserialize_exists(
                MetadataRoot::Private,
                "privateMetadataExists",
                map,
            ),
            b"metadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                "metadataTextContains",
                MetadataCondition::TextContains,
                map,
            ),
            b"privateMetadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                "privateMetadataTextContains",
                MetadataCondition::TextContains,
                map,
            ),
            b"metadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                "metadataTextEquals",
                MetadataCondition::TextEquals,
                map,
            ),
            b"privateMetadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                "privateMetadataTextEquals",
                MetadataCondition::TextEquals,
                map,
            ),
            _ => Ok(None),
        )
    }

    fn deserialize_exists<'de, A>(
        root: MetadataRoot,
        name: &'static str,
        map: &mut A,
    ) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        let filter = match map.next_value::<FilterArgument>()? {
            FilterArgument::String(path) => {
                MetadataPath::from_str(&path).map(|path| MetadataFilter::Condition {
                    root,
                    path,
                    condition: MetadataCondition::Exists,
                })
            }
            FilterArgument::TextMatch(_) | FilterArgument::Other => {
                Err("expected a metadata path string")
            }
        };
        Ok(Some(filter.unwrap_or_else(|reason| {
            MetadataFilter::Invalid { root, name, reason }
        })))
    }

    fn deserialize_text<'de, A>(
        root: MetadataRoot,
        name: &'static str,
        condition: fn(String) -> MetadataCondition,
        map: &mut A,
    ) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        let filter = match map.next_value::<FilterArgument>()? {
            FilterArgument::TextMatch(text_match) => {
                text_match.map(|(path, value)| MetadataFilter::Condition {
                    root,
                    path,
                    condition: condition(value),
                })
            }
            FilterArgument::String(_) | FilterArgument::Other => {
                Err("expected a MetadataTextMatch object")
            }
        };
        Ok(Some(filter.unwrap_or_else(|reason| {
            MetadataFilter::Invalid { root, name, reason }
        })))
    }

    pub fn root(&self) -> MetadataRoot {
        match self {
            MetadataFilter::Condition { root, .. } | MetadataFilter::Invalid { root, .. } => *root,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataFilter::Invalid { name, .. } => name,
            MetadataFilter::Condition {
                root, condition, ..
            } => match (root, condition) {
                (MetadataRoot::Shared, MetadataCondition::Exists) => "metadataExists",
                (MetadataRoot::Shared, MetadataCondition::TextContains(_)) => {
                    "metadataTextContains"
                }
                (MetadataRoot::Shared, MetadataCondition::TextEquals(_)) => "metadataTextEquals",
                (MetadataRoot::Private, MetadataCondition::Exists) => "privateMetadataExists",
                (MetadataRoot::Private, MetadataCondition::TextContains(_)) => {
                    "privateMetadataTextContains"
                }
                (MetadataRoot::Private, MetadataCondition::TextEquals(_)) => {
                    "privateMetadataTextEquals"
                }
            },
        }
    }
}

impl<'de> serde::Deserialize<'de> for FilterArgument<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FilterArgumentVisitor)
    }
}

impl<'de> Visitor<'de> for FilterArgumentVisitor {
    type Value = FilterArgument<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a metadata filter argument")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Borrowed(value)))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Owned(value.into())))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Owned(value)))
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        IgnoredAny.visit_seq(seq).map(|_| FilterArgument::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut path = None;
        let mut value = None;
        let mut error = None;

        while let Some(key) = map.next_key::<FilterArgument>()? {
            let argument = map.next_value::<FilterArgument>()?;
            let field = match &key {
                FilterArgument::String(key) => hashify::fnc_map!(key.as_bytes(),
                    b"path" => Some(&mut path),
                    b"value" => Some(&mut value),
                    _ => None,
                ),
                FilterArgument::TextMatch(_) | FilterArgument::Other => None,
            };
            match (field, argument) {
                (Some(field), FilterArgument::String(text)) if field.is_none() => {
                    *field = Some(text);
                }
                (Some(field), _) if field.is_none() => {
                    error.get_or_insert("MetadataTextMatch path and value must be strings");
                }
                _ => {
                    error.get_or_insert("unexpected or duplicate MetadataTextMatch field");
                }
            }
        }

        Ok(FilterArgument::TextMatch(match (error, path, value) {
            (Some(reason), _, _) => Err(reason),
            (None, Some(path), Some(value)) => {
                MetadataPath::from_str(&path).map(|path| (path, value.into_owned()))
            }
            (None, _, _) => Err("MetadataTextMatch requires a path and a value"),
        }))
    }
}

