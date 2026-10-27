/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::{borrow::Cow, fmt, marker::PhantomData};

pub(crate) struct CowStr<'x>(pub Cow<'x, str>);

impl<'de> Deserialize<'de> for CowStr<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CowStrVisitor;

        impl<'de> Visitor<'de> for CowStrVisitor {
            type Value = CowStr<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Borrowed(value)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(value)))
            }
        }

        deserializer.deserialize_str(CowStrVisitor)
    }
}

pub(crate) fn next_lowercase_value<'de, A>(map: &mut A) -> Result<String, A::Error>
where
    A: MapAccess<'de>,
{
    Ok(utils::text::lowercase(&map.next_value::<CowStr<'de>>()?.0).into_owned())
}

pub trait DeserializeArguments<'de> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>;
}

impl<'de> DeserializeArguments<'de> for () {
    fn deserialize_argument<A>(&mut self, _key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let _: de::IgnoredAny = map.next_value()?;
        Ok(())
    }
}

#[derive(Default)]
struct ArgumentForms(u16);

impl ArgumentForms {
    #[inline]
    fn insert(&mut self, key: &str) -> bool {
        !matches!(
            key.as_bytes().first(),
            Some(b'#' | b'd' | b'e' | b'i' | b'm' | b'p')
        ) || self.insert_named(key)
    }

    #[inline]
    fn insert_named(&mut self, key: &str) -> bool {
        let Some(&(form, conflict)) = hashify::map!(key.as_bytes(), (u16, u16),
            "ids" => (1 << 0, 1 << 1),
            "#ids" => (1 << 1, 1 << 0),
            "properties" => (1 << 2, 1 << 3),
            "#properties" => (1 << 3, 1 << 2),
            "destroy" => (1 << 4, 1 << 5),
            "#destroy" => (1 << 5, 1 << 4),
            "emailIds" => (1 << 6, 1 << 7),
            "#emailIds" => (1 << 7, 1 << 6),
            "mailboxIds" => (1 << 8, 1 << 9),
            "#mailboxIds" => (1 << 9, 1 << 8),
        ) else {
            return true;
        };
        self.0 |= form;
        self.0 & conflict == 0
    }
}

pub(crate) fn deserialize_request<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeArguments<'de> + Default,
    D: Deserializer<'de>,
{
    struct DirectArgumentsVisitor<T> {
        _phantom: PhantomData<T>,
    }

    impl<T> DirectArgumentsVisitor<T> {
        fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    impl<'de, T> Visitor<'de> for DirectArgumentsVisitor<T>
    where
        T: DeserializeArguments<'de> + Default,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a JMAP request object")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut target = T::default();
            let mut forms = ArgumentForms::default();

            while let Some(key) = map.next_key::<&str>()? {
                if !forms.insert(key) {
                    return Err(de::Error::custom(format_args!(
                        "Argument {key:?} cannot be given in both normal and referenced form."
                    )));
                }
                target
                    .deserialize_argument(key, &mut map)
                    .map_err(de::Error::custom)?;
            }

            Ok(target)
        }
    }

    deserializer.deserialize_map(DirectArgumentsVisitor::<T>::new())
}
