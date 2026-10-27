/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, IterateParams, Key, RegistryStore, Store, U16_LEN, U64_LEN, ValueKey,
    registry::write::TEXT_TERMINATOR,
    registry::{
        RegistryFilter, RegistryFilterOp, RegistryFilterValue, RegistryObjectCounter,
        RegistryOrder, RegistryPage, RegistryQuery, RegistryQueryStart,
    },
    write::{RegistryClass, ValueClass, key::DeserializeBigEndian},
};
use ahash::AHashSet;
use registry::{
    schema::prelude::{OBJ_FILTER_ACCOUNT, OBJ_SINGLETON, ObjectType, Property},
    types::{EnumImpl, id::ObjectId},
};
use roaring::RoaringBitmap;
use std::ops::{BitAndAssign, Bound, RangeBounds};
use trc::AddContext;
use types::id::Id;

impl RegistryStore {
    pub async fn query<T: RegistryQueryResults>(&self, query: RegistryQuery) -> trc::Result<T> {
        self.query_page(query).await.map(|page| page.ids)
    }

    pub async fn query_page<T: RegistryQueryResults>(
        &self,
        query: RegistryQuery,
    ) -> trc::Result<RegistryPage<T>> {
        if query.filters.is_empty() {
            return all_ids::<T>(&self.0.store, query).await;
        }

        let mut u64_buffer;
        let mut u16_buffer;
        let mut bool_buffer = [0u8; 1];
        let mut text_buffer = Vec::new();

        let mut results = ResultsPagination::<T>::new(&query);
        let mut merged = 0u64;
        for (position, filter) in query.filters.iter().enumerate() {
            if position < u64::BITS as usize && merged & (1 << position) != 0 {
                continue;
            }
            if filter.op == RegistryFilterOp::TextMatch {
                if let RegistryFilterValue::String(text) = &filter.value {
                    let mut matches = ResultsPagination::<T>::new(&query);

                    for word in text
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|s| s.len() > 1)
                    {
                        text_buffer.clear();
                        if word
                            .chars()
                            .all(|ch| ch.is_lowercase() || !ch.is_alphabetic())
                        {
                            text_buffer.extend_from_slice(word.as_bytes());
                        } else {
                            text_buffer.extend_from_slice(word.to_lowercase().as_bytes());
                        }
                        text_buffer.push(TEXT_TERMINATOR);

                        let mut result = ResultsPagination::<T>::new(&query);

                        index_range(
                            &self.0.store,
                            query.object_type,
                            filter.property.to_id(),
                            &text_buffer,
                            RegistryFilterOp::Equal,
                            RangeKeys::Matching,
                            &mut result,
                        )
                        .await?;

                        if !matches.list.has_items() {
                            matches = result;
                        } else {
                            matches.list.intersect(&result.list);
                        }
                        if !matches.list.has_items() {
                            break;
                        }
                    }

                    if !results.list.has_items() {
                        results = matches;
                    } else {
                        results.list.intersect(&matches.list);
                    }
                } else {
                    return Err(trc::EventType::Registry(trc::RegistryEvent::NotSupported)
                        .into_err()
                        .details("TextMatch operator only supports string values"));
                }
            } else {
                let value = match &filter.value {
                    RegistryFilterValue::String(v) if !filter.is_pk => {
                        text_buffer.clear();
                        text_buffer.extend_from_slice(v.as_bytes());
                        text_buffer.push(TEXT_TERMINATOR);
                        &text_buffer
                    }
                    RegistryFilterValue::String(v) => v.as_bytes(),
                    RegistryFilterValue::Bytes(v) => v.as_slice(),
                    RegistryFilterValue::U64(v) => {
                        u64_buffer = v.to_be_bytes();
                        &u64_buffer
                    }
                    RegistryFilterValue::U16(v) => {
                        u16_buffer = v.to_be_bytes();
                        &u16_buffer
                    }
                    RegistryFilterValue::Boolean(v) => {
                        bool_buffer[0] = *v as u8;
                        &bool_buffer
                    }
                };

                let keys = if filter.op == RegistryFilterOp::Equal
                    && match filter.value {
                        RegistryFilterValue::U64(_)
                        | RegistryFilterValue::U16(_)
                        | RegistryFilterValue::Boolean(_) => true,
                        RegistryFilterValue::String(_) => !filter.is_pk,
                        RegistryFilterValue::Bytes(_) => false,
                    } {
                    RangeKeys::Matching
                } else {
                    RangeKeys::Filtered
                };
                let mut result = ResultsPagination::<T>::new(&query);
                if !filter.is_pk {
                    index_range(
                        &self.0.store,
                        query.object_type,
                        filter.property.to_id(),
                        value,
                        filter.op,
                        keys,
                        &mut result,
                    )
                    .await?
                } else {
                    let mut bounds = op_bounds(filter.op, value);
                    if let Some((upper_position, upper)) = upper_bound_of(&query.filters, position)
                        && upper_position < u64::BITS as usize
                        && merged & (1 << upper_position) == 0
                    {
                        bounds.1 = upper;
                        merged |= 1 << upper_position;
                    }
                    pk_range(
                        &self.0.store,
                        query.object_type,
                        filter.property.to_id(),
                        bounds,
                        keys,
                        &mut result,
                    )
                    .await?
                };

                if !results.list.has_items() {
                    results = result;
                } else {
                    results.list.intersect(&result.list);
                }
            }

            if !results.list.has_items() {
                break;
            }
        }

        Ok(results.finalize())
    }

    pub async fn count_object(&self, object_type: ObjectType) -> trc::Result<usize> {
        if object_type.flags() & OBJ_SINGLETON == 0 {
            self.query::<RegistryObjectCounter>(RegistryQuery::new(object_type))
                .await
                .map(|r| r.0)
        } else {
            self.store()
                .key_exists(ValueKey::from(RegistryClass::Item {
                    object_id: object_type.to_id(),
                    item_id: Id::singleton().id(),
                }))
                .await
                .caused_by(trc::location!())
                .map(|exists| if exists { 1 } else { 0 })
        }
    }

    pub async fn primary_key(
        &self,
        object_type: Option<ObjectType>,
        property: Property,
        key: Vec<u8>,
    ) -> trc::Result<Option<ObjectId>> {
        self.store()
            .get_value::<ObjectId>(ValueKey::from(ValueClass::Registry(
                RegistryClass::PrimaryKey {
                    object_id: object_type.map(|obj| obj.to_id()),
                    index_id: property.to_id(),
                    key,
                },
            )))
            .await
    }

    pub async fn first_primary_key(
        &self,
        object_type: Option<ObjectType>,
        lookups: &[(Property, &[u8])],
    ) -> trc::Result<Option<(usize, ObjectId)>> {
        if let [(property, key)] = lookups {
            return self
                .primary_key(object_type, *property, key.to_vec())
                .await
                .map(|found| found.map(|object_id| (0, object_id)));
        }

        let object_id = object_type.map(|object| object.to_id());
        let mut points = lookups
            .iter()
            .enumerate()
            .map(|(position, (property, key))| {
                let key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
                    object_id,
                    index_id: property.to_id(),
                    key: key.to_vec(),
                }));
                (key.serialize(0), key, position)
            })
            .collect::<Vec<_>>();
        points.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        points.dedup_by(|next, kept| next.0 == kept.0);

        let ranges = points
            .iter()
            .map(|(_, key, _)| IterateParams::new(key.clone(), key.clone()))
            .collect();
        let mut found: Option<(usize, ObjectId)> = None;
        self.store()
            .iterate_many(ranges, |key, value| {
                if let Ok(index) = points.binary_search_by(|(point, ..)| point.as_slice().cmp(key))
                    && let Some((_, _, position)) = points.get(index)
                    && found.is_none_or(|(first, _)| *position < first)
                {
                    found = Some((*position, ObjectId::deserialize(value)?));
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(found)
    }

    pub async fn sort_by_index(
        &self,
        object: ObjectType,
        property: Property,
        ids: Option<Vec<Id>>,
        ascending: bool,
    ) -> trc::Result<Vec<Id>> {
        let mut ids = ids.map(|ids| ids.into_iter().collect::<AHashSet<_>>());
        let mut ids_sorted = Vec::with_capacity(ids.as_ref().map_or(0, |ids| ids.len()));

        let object_id = object.to_id();
        let index_id = property.to_id();
        let (begin, end) = RegistryClass::index_range(
            object_id,
            (index_id, &[], None),
            (index_id, &[], Some(u64::MAX)),
        );

        self.0
            .store
            .iterate(
                IterateParams::new(begin, end)
                    .no_values()
                    .set_ascending(ascending),
                |key, _| {
                    let id = Id::from(key.deserialize_be_u64(key.len() - U64_LEN)?);
                    if let Some(ids) = ids.as_mut() {
                        if ids.remove(&id) {
                            ids_sorted.push(id);
                        }
                        Ok(!ids.is_empty())
                    } else {
                        ids_sorted.push(id);
                        Ok(true)
                    }
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| {
                if let Some(mut ids) = ids
                    && !ids.is_empty()
                {
                    ids_sorted.extend(ids.drain());
                }

                ids_sorted
            })
    }

    pub async fn sort_by_pk(
        &self,
        object: ObjectType,
        property: Property,
        ids: Option<Vec<Id>>,
        ascending: bool,
    ) -> trc::Result<Vec<Id>> {
        let mut ids = ids.map(|ids| ids.into_iter().collect::<AHashSet<_>>());
        let mut ids_sorted = Vec::with_capacity(ids.as_ref().map_or(0, |ids| ids.len()));

        let object_id = object.to_id();
        let index_id = property.to_id();
        let (begin, end) = RegistryClass::pk_range(
            object_id,
            (index_id, &[], None),
            (index_id, &[], Some(u64::MAX)),
        );

        self.0
            .store
            .iterate(
                IterateParams::new(begin, end).set_ascending(ascending),
                |_, value| {
                    let id = Id::from(value.deserialize_be_u64(U16_LEN)?);

                    if let Some(ids) = ids.as_mut() {
                        if ids.remove(&id) {
                            ids_sorted.push(id);
                        }
                        Ok(!ids.is_empty())
                    } else {
                        ids_sorted.push(id);
                        Ok(true)
                    }
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| {
                if let Some(mut ids) = ids
                    && !ids.is_empty()
                {
                    ids_sorted.extend(ids.drain());
                }

                ids_sorted
            })
    }
}

async fn all_ids<T: RegistryQueryResults>(
    store: &Store,
    query: RegistryQuery,
) -> trc::Result<RegistryPage<T>> {
    let object_id = query.object_type.to_id();
    let mut results = ResultsPagination::<T>::new(&query);
    let params = results.bounded(
        IterateParams::new(
            ValueKey::from(ValueClass::Registry(RegistryClass::IndexId {
                object_id,
                item_id: 0,
            })),
            ValueKey::from(ValueClass::Registry(RegistryClass::IndexId {
                object_id,
                item_id: u64::MAX,
            })),
        )
        .no_values(),
        RangeKeys::Matching,
    );

    store
        .iterate(params, |key, _| {
            Ok(results.push(key.deserialize_be_u64(U16_LEN * 2)?))
        })
        .await
        .caused_by(trc::location!())?;

    Ok(results.finalize())
}

#[derive(Clone, Copy)]
enum RangeKeys {
    Matching,
    Filtered,
}

async fn index_range<T: RegistryQueryResults>(
    store: &Store,
    object: ObjectType,
    index_id: u16,
    match_value: &[u8],
    op: RegistryFilterOp,
    keys: RangeKeys,
    results: &mut ResultsPagination<T>,
) -> trc::Result<()> {
    let ((from_value, from_doc_id, from_index_id), (end_value, end_doc_id, end_index_id)) = match op
    {
        RegistryFilterOp::LowerThan => ((&[][..], 0, index_id), (match_value, 0, index_id)),
        RegistryFilterOp::LowerEqualThan => {
            ((&[][..], 0, index_id), (match_value, u64::MAX, index_id))
        }
        RegistryFilterOp::GreaterThan => (
            (match_value, u64::MAX, index_id),
            (&[][..], u64::MAX, index_id + 1),
        ),
        RegistryFilterOp::GreaterEqualThan => (
            (match_value, 0, index_id),
            (&[][..], u64::MAX, index_id + 1),
        ),
        RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => (
            (match_value, 0, index_id),
            (match_value, u64::MAX, index_id),
        ),
    };

    let object_id = object.to_id();
    let (begin, end) = RegistryClass::index_range(
        object_id,
        (from_index_id, from_value, Some(from_doc_id)),
        (end_index_id, end_value, Some(end_doc_id)),
    );
    let prefix = RegistryClass::prefix(object_id, index_id);
    let params = results.bounded(IterateParams::new(begin, end).no_values(), keys);

    store
        .iterate(params, |key, _| {
            if !key.starts_with(&prefix) {
                return Ok(false);
            }

            let id_pos = key.len() - U64_LEN;
            let value = key
                .get(U16_LEN * 2..id_pos)
                .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

            let matches = match op {
                RegistryFilterOp::LowerThan => value < match_value,
                RegistryFilterOp::LowerEqualThan => value <= match_value,
                RegistryFilterOp::GreaterThan => value > match_value,
                RegistryFilterOp::GreaterEqualThan => value >= match_value,
                RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => value == match_value,
            };

            if matches {
                Ok(results.push(key.deserialize_be_u64(id_pos)?))
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())
        .inspect(|_| results.scanned())
}

fn op_bounds(op: RegistryFilterOp, value: &[u8]) -> (Bound<&[u8]>, Bound<&[u8]>) {
    match op {
        RegistryFilterOp::LowerThan => (Bound::Unbounded, Bound::Excluded(value)),
        RegistryFilterOp::LowerEqualThan => (Bound::Unbounded, Bound::Included(value)),
        RegistryFilterOp::GreaterThan => (Bound::Excluded(value), Bound::Unbounded),
        RegistryFilterOp::GreaterEqualThan => (Bound::Included(value), Bound::Unbounded),
        RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => {
            (Bound::Included(value), Bound::Included(value))
        }
    }
}

fn upper_bound_of(filters: &[RegistryFilter], lower: usize) -> Option<(usize, Bound<&[u8]>)> {
    let filter = filters.get(lower)?;
    if !filter.is_pk
        || !matches!(
            filter.op,
            RegistryFilterOp::GreaterThan | RegistryFilterOp::GreaterEqualThan
        )
    {
        return None;
    }
    filters
        .iter()
        .enumerate()
        .skip(lower + 1)
        .filter(|(_, upper)| upper.is_pk && upper.property == filter.property)
        .find_map(|(position, upper)| {
            let value = match &upper.value {
                RegistryFilterValue::String(value) => value.as_bytes(),
                RegistryFilterValue::Bytes(value) => value.as_slice(),
                _ => return None,
            };
            match upper.op {
                RegistryFilterOp::LowerThan => Some((position, Bound::Excluded(value))),
                RegistryFilterOp::LowerEqualThan => Some((position, Bound::Included(value))),
                _ => None,
            }
        })
}

async fn pk_range<T: RegistryQueryResults>(
    store: &Store,
    object: ObjectType,
    index_id: u16,
    bounds: (Bound<&[u8]>, Bound<&[u8]>),
    keys: RangeKeys,
    results: &mut ResultsPagination<T>,
) -> trc::Result<()> {
    if match bounds {
        (Bound::Included(from), Bound::Included(to)) => from > to,
        (
            Bound::Included(from) | Bound::Excluded(from),
            Bound::Included(to) | Bound::Excluded(to),
        ) => from >= to,
        _ => false,
    } {
        return Ok(());
    }

    let (from_value, from_index_id) = match bounds.0 {
        Bound::Included(value) | Bound::Excluded(value) => (value, index_id),
        Bound::Unbounded => (&[][..], index_id),
    };
    let (end_value, end_index_id) = match bounds.1 {
        Bound::Included(value) | Bound::Excluded(value) => (value, index_id),
        Bound::Unbounded => (&[][..], index_id + 1),
    };

    let object_id = object.to_id();
    let (begin, end) = RegistryClass::pk_range(
        object_id,
        (from_index_id, from_value, None),
        (end_index_id, end_value, None),
    );
    let prefix = RegistryClass::prefix(object_id, index_id);
    let params = results.bounded(IterateParams::new(begin, end), keys);

    store
        .iterate(params, |key, value| {
            if !key.starts_with(&prefix) {
                return Ok(false);
            }

            let key = key
                .get(U16_LEN * 2..)
                .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

            if RangeBounds::<[u8]>::contains(&bounds, key) {
                Ok(results.push(value.deserialize_be_u64(U16_LEN)?))
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())
        .inspect(|_| results.scanned())
}

pub trait RegistryQueryResults: Default + Sized + Sync + Send {
    fn push(&mut self, id: u64);
    fn has_items(&self) -> bool;
    fn intersect(&mut self, other: &Self);
    fn count(&self) -> usize;
    fn sort(&mut self);
    fn into_list(self) -> impl DoubleEndedIterator<Item = u64>;
}

impl RegistryQueryResults for Vec<Id> {
    fn push(&mut self, id: u64) {
        self.push(Id::new(id));
    }

    fn has_items(&self) -> bool {
        !self.is_empty()
    }

    fn intersect(&mut self, other: &Self) {
        let a = self;
        let b = other;
        let mut i = 0;
        let mut j = 0;
        let mut write = 0;

        while i < a.len() && j < b.len() {
            if a[i] < b[j] {
                let target = b[j];
                let remain = &a[i..];
                i += remain.partition_point(|&x| x < target);
            } else if a[i] > b[j] {
                let target = a[i];
                let remain = &b[j..];
                j += remain.partition_point(|&x| x < target);
            } else {
                a[write] = a[i];
                write += 1;
                i += 1;
                j += 1;
            }
        }
        a.truncate(write);
    }

    fn count(&self) -> usize {
        self.len()
    }

    fn sort(&mut self) {
        match self.len() {
            0 | 1 => {}
            ..3000 => self.sort_unstable(),
            _ => radsort::sort_by_key(self, |id| id.id()),
        }
    }

    fn into_list(self) -> impl DoubleEndedIterator<Item = u64> {
        self.into_iter().map(|id| id.id())
    }
}

impl RegistryQueryResults for RoaringBitmap {
    fn push(&mut self, id: u64) {
        self.insert(id as u32);
    }

    fn has_items(&self) -> bool {
        !self.is_empty()
    }

    fn intersect(&mut self, other: &Self) {
        self.bitand_assign(other);
    }

    fn count(&self) -> usize {
        self.len() as usize
    }

    fn sort(&mut self) {}

    fn into_list(self) -> impl DoubleEndedIterator<Item = u64> {
        self.into_iter().map(|id| id as u64)
    }
}

impl RegistryQueryResults for RegistryObjectCounter {
    fn push(&mut self, _: u64) {
        self.0 += 1;
    }

    fn has_items(&self) -> bool {
        self.0 > 0
    }

    fn intersect(&mut self, _: &Self) {
        unimplemented!()
    }

    fn count(&self) -> usize {
        self.0
    }

    fn sort(&mut self) {}

    fn into_list(self) -> impl DoubleEndedIterator<Item = u64> {
        Vec::new().into_iter()
    }
}

struct ResultsPagination<T: RegistryQueryResults> {
    list: T,
    start: RegistryQueryStart,
    offset: usize,
    anchor: Option<u64>,
    skipped: usize,
    limit: Option<usize>,
    order: RegistryOrder,
    deferred_pagination: bool,
}

impl<T: RegistryQueryResults> ResultsPagination<T> {
    fn new(query: &RegistryQuery) -> Self {
        let (anchor, offset) = match query.start {
            RegistryQueryStart::Index(index) => {
                (None, usize::try_from(index).unwrap_or(usize::MAX))
            }
            RegistryQueryStart::Anchor(anchor) => (Some(anchor), 0),
            RegistryQueryStart::None => (None, 0),
        };

        Self {
            list: T::default(),
            start: query.start,
            offset,
            anchor,
            skipped: 0,
            limit: query.limit,
            order: query.order,
            deferred_pagination: query.filters.len() > 1
                || query
                    .filters
                    .first()
                    .is_some_and(|f| match (&f.op, &f.value) {
                        (RegistryFilterOp::TextMatch, RegistryFilterValue::String(value)) => {
                            value.chars().any(|c| !c.is_alphanumeric()) && value.len() > 1
                        }
                        (RegistryFilterOp::TextMatch | RegistryFilterOp::Equal, _) => false,
                        _ => query.order != RegistryOrder::Any,
                    }),
        }
    }

    fn bounded<K: Key>(&self, params: IterateParams<K>, keys: RangeKeys) -> IterateParams<K> {
        let params = params
            .set_ascending(self.deferred_pagination || self.order != RegistryOrder::Descending);
        match (self.rows_needed(), keys) {
            (Some(rows), RangeKeys::Matching) => params.limit(rows),
            (_, RangeKeys::Matching | RangeKeys::Filtered) => params,
        }
    }

    fn rows_needed(&self) -> Option<usize> {
        if self.deferred_pagination || self.anchor.is_some() {
            None
        } else {
            self.limit.map(|limit| self.offset.saturating_add(limit))
        }
    }

    fn push(&mut self, id: u64) -> bool {
        if self.deferred_pagination {
            self.list.push(id);
            true
        } else if self.offset > 0 {
            self.offset -= 1;
            true
        } else if self.anchor.is_some_and(|anchor| anchor != id) {
            self.skipped += 1;
            true
        } else {
            self.anchor = None;
            match self.limit {
                Some(limit) if self.list.count() >= limit => false,
                limit => {
                    self.list.push(id);
                    limit.is_none_or(|limit| self.list.count() < limit)
                }
            }
        }
    }

    fn scanned(&mut self) {
        if self.deferred_pagination || self.order != RegistryOrder::Descending {
            self.list.sort();
        }
    }

    fn paginate(&mut self, ids: impl Iterator<Item = u64>) {
        for id in ids {
            if !self.push(id) {
                break;
            }
        }
    }

    fn finalize(mut self) -> RegistryPage<T> {
        if self.deferred_pagination
            && (self.limit.is_some()
                || self.anchor.is_some()
                || self.offset > 0
                || self.order == RegistryOrder::Descending)
        {
            self.deferred_pagination = false;
            let ids = std::mem::take(&mut self.list).into_list();
            if self.order == RegistryOrder::Descending {
                self.paginate(ids.rev());
            } else {
                self.paginate(ids);
            }
        }

        RegistryPage {
            position: match self.start {
                RegistryQueryStart::Index(_) if self.offset > 0 => Some(0),
                RegistryQueryStart::Index(index) => {
                    Some(usize::try_from(index).unwrap_or(usize::MAX))
                }
                RegistryQueryStart::Anchor(_) => self.anchor.is_none().then_some(self.skipped),
                RegistryQueryStart::None => Some(0),
            },
            ids: self.list,
        }
    }
}

impl RegistryQuery {
    pub fn new(object_type: ObjectType) -> Self {
        Self {
            object_type,
            filters: Vec::new(),
            start: RegistryQueryStart::None,
            limit: None,
            order: RegistryOrder::Any,
        }
    }

    pub fn with_ascending(mut self) -> Self {
        self.order = RegistryOrder::Ascending;
        self
    }

    pub fn with_descending(mut self) -> Self {
        self.order = RegistryOrder::Descending;
        self
    }

    pub fn with_anchor(mut self, anchor: u64) -> Self {
        self.start = RegistryQueryStart::Anchor(anchor);
        self
    }

    pub fn with_index_start(mut self, index: u64) -> Self {
        self.start = RegistryQueryStart::Index(index);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_account(mut self, account_id: u32) -> Self {
        if self.object_type.flags() & OBJ_FILTER_ACCOUNT != 0 {
            let filter = RegistryFilter::equal(Property::AccountId, account_id, false);
            if self.filters.is_empty() {
                self.filters.push(filter);
            } else {
                self.filters.insert(0, filter);
            }
        }
        self
    }

    pub fn with_account_opt(self, account_id: Option<u32>) -> Self {
        if let Some(account_id) = account_id {
            self.with_account(account_id)
        } else {
            self
        }
    }


    pub fn filter(mut self, filter: RegistryFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn equal(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::equal(property, value, false));
        self
    }

    pub fn equal_pk(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        self.filters
            .push(RegistryFilter::equal(property, value, is_pk));
        self
    }

    pub fn push_equal_pk(
        &mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) {
        self.filters
            .push(RegistryFilter::equal(property, value, is_pk));
    }

    pub fn equal_opt(
        mut self,
        property: Property,
        value: Option<impl Into<RegistryFilterValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.filters
                .push(RegistryFilter::equal(property, value, false));
        }
        self
    }

    pub fn greater_than(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than(property, value, false));
        self
    }

    pub fn less_than(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::less_than(property, value, false));
        self
    }

    pub fn greater_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters.push(RegistryFilter::greater_than_or_equal(
            property, value, false,
        ));
        self
    }

    pub fn less_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::less_than_or_equal(property, value, false));
        self
    }

    pub fn text(mut self, property: Property, value: impl Into<String>) -> Self {
        self.filters.push(RegistryFilter::text(property, value));
        self
    }

    pub fn text_opt(mut self, property: Property, value: Option<impl Into<String>>) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::text(property, value));
        }
        self
    }

    pub fn push_text(&mut self, property: Property, value: impl Into<String>) {
        self.filters.push(RegistryFilter::text(property, value));
    }

    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
    }
}

impl RegistryFilter {
    pub fn text(property: Property, value: impl Into<String>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::TextMatch,
            value: RegistryFilterValue::String(value.into()),
            is_pk: false,
        }
    }

    pub fn equal(property: Property, value: impl Into<RegistryFilterValue>, is_pk: bool) -> Self {
        Self {
            property,
            op: RegistryFilterOp::Equal,
            value: value.into(),
            is_pk,
        }
    }

    pub fn greater_than(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn less_than(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn greater_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterEqualThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn less_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerEqualThan,
            value: value.into(),
            is_pk,
        }
    }
}

impl From<String> for RegistryFilterValue {
    fn from(value: String) -> Self {
        RegistryFilterValue::String(value)
    }
}

impl From<&str> for RegistryFilterValue {
    fn from(value: &str) -> Self {
        RegistryFilterValue::String(value.to_string())
    }
}

impl From<u64> for RegistryFilterValue {
    fn from(value: u64) -> Self {
        RegistryFilterValue::U64(value)
    }
}

impl From<u32> for RegistryFilterValue {
    fn from(value: u32) -> Self {
        RegistryFilterValue::U64(value as u64)
    }
}

impl From<u16> for RegistryFilterValue {
    fn from(value: u16) -> Self {
        RegistryFilterValue::U16(value)
    }
}

impl From<bool> for RegistryFilterValue {
    fn from(value: bool) -> Self {
        RegistryFilterValue::Boolean(value)
    }
}

