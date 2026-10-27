/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rkyv::{
    Archive, Archived, Deserialize, Place, Serialize,
    rancor::Fallible,
    ser::{Allocator, Writer},
    vec::{ArchivedVec, VecResolver},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
};
use smallvec::{Array, SmallVec};

pub struct Unboxed;

impl<T: Archive> ArchiveWith<Box<T>> for Unboxed {
    type Archived = T::Archived;
    type Resolver = T::Resolver;

    fn resolve_with(field: &Box<T>, resolver: Self::Resolver, out: Place<Self::Archived>) {
        T::resolve(field, resolver, out);
    }
}

impl<T: Serialize<S>, S: Fallible + ?Sized> SerializeWith<Box<T>, S> for Unboxed {
    fn serialize_with(field: &Box<T>, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        T::serialize(field, serializer)
    }
}

impl<T, D> DeserializeWith<T::Archived, Box<T>, D> for Unboxed
where
    T: Archive,
    T::Archived: Deserialize<T, D>,
    D: Fallible + ?Sized,
{
    fn deserialize_with(field: &T::Archived, deserializer: &mut D) -> Result<Box<T>, D::Error> {
        field.deserialize(deserializer).map(Box::new)
    }
}

pub struct InlineVec;

impl<A> ArchiveWith<SmallVec<A>> for InlineVec
where
    A: Array,
    A::Item: Archive,
{
    type Archived = ArchivedVec<Archived<A::Item>>;
    type Resolver = VecResolver;

    fn resolve_with(field: &SmallVec<A>, resolver: Self::Resolver, out: Place<Self::Archived>) {
        ArchivedVec::resolve_from_slice(field.as_slice(), resolver, out);
    }
}

impl<A, S> SerializeWith<SmallVec<A>, S> for InlineVec
where
    A: Array,
    A::Item: Serialize<S>,
    S: Fallible + Allocator + Writer + ?Sized,
{
    fn serialize_with(field: &SmallVec<A>, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        ArchivedVec::serialize_from_slice(field.as_slice(), serializer)
    }
}

impl<A, D> DeserializeWith<ArchivedVec<Archived<A::Item>>, SmallVec<A>, D> for InlineVec
where
    A: Array,
    A::Item: Archive,
    Archived<A::Item>: Deserialize<A::Item, D>,
    D: Fallible + ?Sized,
{
    fn deserialize_with(
        field: &ArchivedVec<Archived<A::Item>>,
        deserializer: &mut D,
    ) -> Result<SmallVec<A>, D::Error> {
        let mut items = SmallVec::with_capacity(field.len());
        for item in field.iter() {
            items.push(item.deserialize(deserializer)?);
        }
        Ok(items)
    }
}

