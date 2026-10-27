/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindContext, PropFindItem};
use crate::common::{ArchivedResource, CacheFit};
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::{CalDavProperty, CardDavProperty, DavProperty, WebDavProperty};
use groupware::calendar::{
    EVENT_HAS_ALARMS, EVENT_PRIVATE, EVENT_SECRET, EVENT_USES_DEFAULT_ALERTS,
};
use store::{
    ahash::AHashMap,
    dispatch::ReadShape,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, CalendarNotificationField, ContactField, Field},
};


pub(super) const PROPFIND_BATCH_SIZE: usize = 256;

type ArchiveKey = (u32, u8, u32);

pub(super) struct ArchiveLoader {
    collection_container: Collection,
    collection_children: Collection,
    is_scheduling: bool,
    needs_content: bool,
    needs_content_length: bool,
    needs_media_type: bool,
    content_field: Option<Field>,
    cached_items: bool,
}

pub(super) struct BatchArchives {
    metadata: AHashMap<ArchiveKey, Archive<ArchiveBytes>>,
    contents: AHashMap<ArchiveKey, Archive<ArchiveBytes>>,
}

struct ContentDemand {
    is_owner: bool,
}

struct ArchiveGroup {
    metadata: RoaringBitmap,
    contents: RoaringBitmap,
    demand: ContentDemand,
}

impl ArchiveLoader {
    pub fn new(ctx: &PropFindContext<'_>, has_filter: bool) -> Self {
        let properties = ctx.properties;
        ArchiveLoader {
            cached_items: !has_filter
                && !ctx.is_scheduling
                && matches!(
                    ctx.collection_children,
                    Collection::CalendarEvent | Collection::ContactCard | Collection::FileNode
                )
                && properties
                    .iter()
                    .all(|property| is_cache_answerable(ctx.collection_children, property)),
            collection_container: ctx.collection_container,
            collection_children: ctx.collection_children,
            is_scheduling: ctx.is_scheduling,
            needs_content: has_filter
                || properties.iter().any(|property| {
                    matches!(
                        property,
                        DavProperty::CardDav(CardDavProperty::AddressData { .. })
                            | DavProperty::CalDav(CalDavProperty::CalendarData(_))
                    )
                }),
            needs_content_length: ctx.collection_children == Collection::CalendarEvent
                && properties.iter().any(|property| {
                    matches!(
                        property,
                        DavProperty::WebDav(WebDavProperty::GetContentLength)
                    )
                }),
            needs_media_type: properties.iter().any(|property| {
                matches!(
                    property,
                    DavProperty::WebDav(WebDavProperty::GetContentType)
                )
            }),
            content_field: match ctx.collection_children {
                Collection::CalendarEvent => Some(CalendarEventField::Content.field()),
                Collection::CalendarEventNotification => {
                    Some(CalendarNotificationField::Content.field())
                }
                Collection::ContactCard => Some(ContactField::Content.field()),
                _ => None,
            },
        }
    }

    pub fn needs_event_view(&self) -> bool {
        self.collection_children == Collection::CalendarEvent
            && (self.needs_content || self.needs_content_length)
    }

    pub fn is_cached(&self, item: &PropFindItem) -> bool {
        self.cached_items
            && !item.is_container
            && match item.cache_fit {
                CacheFit::Exact => true,
                CacheFit::InexactMediaType => !self.needs_media_type,
                CacheFit::Inexact => false,
            }
    }

    pub fn collection_of(&self, item: &PropFindItem) -> Collection {
        if item.is_container {
            self.collection_container
        } else {
            self.collection_children
        }
    }

    pub async fn load(
        &self,
        server: &Server,
        access_token: &AccessToken,
        batch: &[PropFindItem],
    ) -> trc::Result<BatchArchives> {
        let content_field = self
            .content_field
            .filter(|_| self.needs_content || self.needs_content_length);
        let mut groups: AHashMap<(u32, Collection), ArchiveGroup> = AHashMap::with_capacity(4);
        for item in batch {
            if (self.is_scheduling && item.is_container) || self.is_cached(item) {
                continue;
            }
            let collection = self.collection_of(item);
            let group = groups
                .entry((item.account_id, collection))
                .or_insert_with(|| ArchiveGroup {
                    metadata: RoaringBitmap::new(),
                    contents: RoaringBitmap::new(),
                    demand: ContentDemand {
                        is_owner: access_token.is_member(item.account_id),
                    },
                });
            group.metadata.insert(item.document_id);
            if content_field.is_some()
                && collection == self.collection_children
                && (self.needs_content || group.demand.is_met_by(item.event_flags))
            {
                group.contents.insert(item.document_id);
            }
        }

        let mut metadata = AHashMap::with_capacity(batch.len());
        let mut contents = AHashMap::new();
        for (&(account_id, collection), group) in &groups {
            let collection_id = u8::from(collection);
            match content_field.filter(|_| !group.contents.is_empty()) {
                Some(content_field) => {
                    server
                        .archives_fields(
                            account_id,
                            collection,
                            ReadShape::Ranges(server.core.storage.data.scan_gap()),
                            &[
                                (content_field, &group.contents),
                                (Field::ARCHIVE, &group.metadata),
                            ],
                            |field, document_id, archive| {
                                if field == Field::ARCHIVE {
                                    metadata
                                        .insert((account_id, collection_id, document_id), archive);
                                } else {
                                    contents
                                        .insert((account_id, collection_id, document_id), archive);
                                }
                                Ok(true)
                            },
                        )
                        .await
                }
                None => {
                    server
                        .archives(
                            account_id,
                            collection,
                            Field::ARCHIVE,
                            &group.metadata,
                            |document_id, archive| {
                                metadata.insert((account_id, collection_id, document_id), archive);
                                Ok(true)
                            },
                        )
                        .await
                }
            }
            .caused_by(trc::location!())?;
        }

        Ok(BatchArchives { metadata, contents })
    }
}

fn is_cache_answerable(collection: Collection, property: &DavProperty) -> bool {
    match property {
        DavProperty::WebDav(WebDavProperty::DisplayName | WebDavProperty::GetContentLength) => {
            collection == Collection::FileNode
        }
        DavProperty::WebDav(WebDavProperty::Acl) => collection != Collection::FileNode,
        DavProperty::WebDav(_) | DavProperty::Dead(_) => true,
        _ => false,
    }
}

impl BatchArchives {
    pub fn resource(
        &self,
        collection: Collection,
        item: &PropFindItem,
    ) -> trc::Result<Option<ArchivedResource<'_>>> {
        let key = (item.account_id, collection.into(), item.document_id);
        self.metadata
            .get(&key)
            .map(|archive| {
                ArchivedResource::from_archive(archive, self.contents.get(&key), collection)
            })
            .transpose()
    }
}

impl ContentDemand {
    fn view_flags(&self) -> u16 {
        if self.is_owner {
            EVENT_USES_DEFAULT_ALERTS
        } else {
            EVENT_HAS_ALARMS | EVENT_PRIVATE | EVENT_SECRET
        }
    }

    fn is_met_by(&self, event_flags: u16) -> bool {
        event_flags & self.view_flags() != 0
    }
}
