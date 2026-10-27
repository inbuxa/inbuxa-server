/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use store::{
    Deserialize, IterateParams, Key, U32_LEN, ValueKey,
    dispatch::{DocumentSet, POINT_SCAN_GAP, ReadShape, ScanShape},
    write::{AnyKey, Archive, ArchiveBytes, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::Field};

impl Server {
    pub async fn archives<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        field: Field,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, Archive<ArchiveBytes>) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = collection.into();
        let field: u8 = field.into();
        let property = PropertyRange {
            account_id,
            collection,
            field,
        };
        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                <Archive<ArchiveBytes> as Deserialize>::deserialize(value)
                    .and_then(|archive| cb(document_id, archive))
            } else {
                Ok(true)
            }
        };
        let store = &self.core.storage.data;

        match documents.scan_shape(store.scan_gap()) {
            ScanShape::Range(from_document_id, to_document_id) => {
                let Some(to_document_id) = last_member(documents, from_document_id, to_document_id)
                else {
                    return Ok(());
                };
                store
                    .iterate(
                        property.range(from_document_id, to_document_id),
                        &mut collect,
                    )
                    .await
            }
            ScanShape::Ranges(ranges) => {
                store
                    .iterate_many(
                        ranges
                            .into_iter()
                            .map(|(from_document_id, to_document_id)| {
                                property.read(from_document_id, to_document_id)
                            })
                            .collect(),
                        &mut collect,
                    )
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })
    }

    pub async fn archives_fields<S, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        shape: ReadShape,
        fields: &[(Field, &S)],
        mut cb: CB,
    ) -> trc::Result<()>
    where
        S: DocumentSet,
        CB: FnMut(Field, u32, Archive<ArchiveBytes>) -> trc::Result<bool> + Send + Sync,
    {
        debug_assert!(
            fields.windows(2).all(|pair| match pair {
                [(previous, _), (next, _)] => u8::from(*previous) < u8::from(*next),
                _ => true,
            }),
            "archives_fields expects fields in ascending order"
        );
        let collection: u8 = collection.into();
        let store = &self.core.storage.data;
        let mut ranges = Vec::new();
        for (field, documents) in fields {
            let property = PropertyRange {
                account_id,
                collection,
                field: u8::from(*field),
            };
            let gap = match shape {
                ReadShape::Ranges(gap) => gap,
                ReadShape::Keys if documents.len() == 0 => POINT_SCAN_GAP,
                ReadShape::Keys => {
                    ranges.extend(
                        documents
                            .iterate()
                            .map(|document_id| property.read(document_id, document_id)),
                    );
                    continue;
                }
            };
            match documents.scan_shape(gap) {
                ScanShape::Range(from_document_id, to_document_id) => {
                    ranges.extend(
                        last_member(*documents, from_document_id, to_document_id)
                            .map(|to_document_id| property.range(from_document_id, to_document_id)),
                    );
                }
                ScanShape::Ranges(shape) => {
                    ranges.extend(shape.into_iter().map(|(from_document_id, to_document_id)| {
                        property.read(from_document_id, to_document_id)
                    }));
                }
            }
        }
        if ranges.is_empty() {
            return Ok(());
        }

        let mut pending = fields.iter();
        let mut current = pending.next();
        store
            .iterate_many(ranges, |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                let field = key
                    .get(U32_LEN + 1)
                    .copied()
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                while let Some((pending_field, _)) = current
                    && u8::from(*pending_field) < field
                {
                    current = pending.next();
                }
                match current {
                    Some((pending_field, documents))
                        if u8::from(*pending_field) == field && documents.contains(document_id) =>
                    {
                        <Archive<ArchiveBytes> as Deserialize>::deserialize(value)
                            .and_then(|archive| cb(*pending_field, document_id, archive))
                    }
                    _ => Ok(true),
                }
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn archive_and_field(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        field: Field,
    ) -> trc::Result<(Option<Archive<ArchiveBytes>>, Option<Archive<ArchiveBytes>>)> {
        let mut archive = None;
        let mut value = None;
        self.archives_fields(
            account_id,
            collection,
            ReadShape::Keys,
            &[(field, &document_id), (Field::ARCHIVE, &document_id)],
            |read_field, _, read| {
                if read_field == Field::ARCHIVE {
                    archive = Some(read);
                } else {
                    value = Some(read);
                }
                Ok(true)
            },
        )
        .await
        .map(|_| (archive, value))
    }

    pub async fn all_values<T, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        class: ValueClass,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        T: Deserialize,
        CB: FnMut(u32, T) -> trc::Result<()> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: 0,
                        class: class.clone(),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: u32::MAX,
                        class,
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    cb(document_id, T::deserialize(value)?)?;

                    Ok(true)
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn values_window<T, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        class: &ValueClass,
        from_document_id: u32,
        limit: Option<usize>,
        mut cb: CB,
    ) -> trc::Result<Option<u32>>
    where
        T: Deserialize,
        CB: FnMut(u32, T) -> trc::Result<()> + Send + Sync,
    {
        let collection: u8 = collection.into();
        let mut rows = 0;
        let mut last_document_id = from_document_id;
        let params = IterateParams::new(
            ValueKey {
                account_id,
                collection,
                document_id: from_document_id,
                class: class.clone(),
            },
            ValueKey {
                account_id,
                collection,
                document_id: u32::MAX,
                class: class.clone(),
            },
        );
        let params = match limit {
            Some(limit) => params.limit(limit),
            None => params,
        };

        self.core
            .storage
            .data
            .iterate(params, |key, value| {
                last_document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                cb(last_document_id, T::deserialize(value)?)?;
                rows += 1;
                Ok(limit.is_none_or(|limit| rows < limit))
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })?;

        Ok(limit
            .filter(|limit| rows == *limit)
            .and_then(|_| last_document_id.checked_add(1)))
    }
}

struct PropertyRange {
    account_id: u32,
    collection: u8,
    field: u8,
}

impl PropertyRange {
    fn key(&self, document_id: u32) -> Vec<u8> {
        ValueKey {
            account_id: self.account_id,
            collection: self.collection,
            document_id,
            class: ValueClass::Property(self.field),
        }
        .serialize(0)
    }

    fn range(&self, from_document_id: u32, to_document_id: u32) -> IterateParams<AnyKey<Vec<u8>>> {
        let mut end = self.key(to_document_id);
        end.push(u8::MAX);
        self.params(self.key(from_document_id), end)
    }

    fn read(&self, from_document_id: u32, to_document_id: u32) -> IterateParams<AnyKey<Vec<u8>>> {
        if from_document_id == to_document_id {
            let key = self.key(from_document_id);
            self.params(key.clone(), key)
        } else {
            self.range(from_document_id, to_document_id)
        }
    }

    fn params(&self, begin: Vec<u8>, end: Vec<u8>) -> IterateParams<AnyKey<Vec<u8>>> {
        let subspace = ValueClass::Property(self.field).subspace(self.collection);
        IterateParams::new(
            AnyKey {
                subspace,
                key: begin,
            },
            AnyKey { subspace, key: end },
        )
    }
}

pub(super) fn last_member(
    documents: &impl DocumentSet,
    from_document_id: u32,
    to_document_id: u32,
) -> Option<u32> {
    if documents.contains(to_document_id) {
        Some(to_document_id)
    } else if to_document_id > from_document_id {
        Some(to_document_id - 1)
    } else {
        None
    }
}
