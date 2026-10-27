/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ChunkAccumulator;
use crate::{
    DavResourceName,
    file::{ArchivedFileNode, FileNode, FileNodeRole},
};
use common::{
    ArenaRef, DavPath, FileFlags, GroupwareResource, GroupwareResourceMetadata, GroupwareResources,
    NO_ID, PathIndex, ResourceStore, Server, UpdateLock,
    storage::dav::{CONTAINER_FLAG, ResourceChunkBuilder, canonical_path_segment},
};
use std::sync::Arc;
use store::ahash::AHashMap;
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
    field::Field,
    media_type::media_type_essence,
};
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

pub(super) async fn build_file_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<UpdateLock>,
) -> trc::Result<GroupwareResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::FileNode.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let account_info = server.account(account_id).await?;

    let mut nodes = ChunkAccumulator::default();
    server
        .archives(
            account_id,
            Collection::FileNode,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                push_file(
                    nodes.current(),
                    archive.unarchive::<FileNode>()?,
                    document_id,
                );
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    update_lock.set_revision(last_change_id);
    let resources = ResourceStore::from_sorted(nodes.finish(), Vec::new(), true);
    let paths = build_nested_hierarchy(&resources);
    let mut files = GroupwareResources {
        base_path: DavResourceName::File.account_base_path(account_info.name()),
        size: 0,
        paths: Arc::new(paths),
        resources,
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        update_lock,
        verification: Default::default(),
    };
    files.recompute_size();

    Ok(files)
}

pub(super) fn build_nested_hierarchy(resources: &ResourceStore) -> PathIndex {
    let mut topological_sort = TopologicalSort::with_capacity(resources.len());
    let mut names: AHashMap<u32, (String, u32, u32, bool)> =
        AHashMap::with_capacity(resources.len());

    for resource in resources.iter() {
        if let GroupwareResourceMetadata::File { parent_id, .. } = resource.resource.data {
            topological_sort.insert(
                if parent_id != NO_ID { parent_id + 1 } else { 0 },
                resource.document_id() + 1,
            );
            names.insert(
                resource.document_id(),
                (
                    canonical_path_segment(resource.container_name().unwrap_or_default())
                        .into_owned(),
                    parent_id,
                    0,
                    resource.is_container(),
                ),
            );
        }
    }

    for (hierarchy_sequence, folder_id) in topological_sort.into_iterator().enumerate() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            let path = names
                .get(&folder_id)
                .filter(|(_, parent_id, _, _)| *parent_id != NO_ID)
                .and_then(|(name, parent_id, _, _)| {
                    names
                        .get(parent_id)
                        .map(|(parent, _, _, _)| format!("{parent}/{name}"))
                });

            if let Some(folder) = names.get_mut(&folder_id) {
                if let Some(path) = path {
                    folder.0 = path;
                }
                folder.2 = hierarchy_sequence as u32;
            }
        }
    }

    let entries = names
        .into_iter()
        .map(
            |(document_id, (path, parent_id, hierarchy_seq, is_container))| {
                (
                    path,
                    DavPath {
                        path: ArenaRef::default(),
                        parent_id,
                        hierarchy_seq: hierarchy_seq
                            | if is_container { CONTAINER_FLAG } else { 0 },
                        document_id,
                    },
                )
            },
        )
        .collect::<Vec<_>>();

    PathIndex::pack(entries)
}

pub fn push_file(builder: &mut ResourceChunkBuilder, node: &ArchivedFileNode, document_id: u32) {
    let parent_id = node.parent_id.to_native();
    let file = node.file();
    let stored_media_type = file.and_then(|file| file.media_type.as_deref());
    let media_type = stored_media_type.and_then(media_type_essence);
    let (name, media_type_id, extra_len) =
        builder.push_file_name(node.name.as_str(), media_type.as_deref());
    let is_media_type_exact = stored_media_type
        .is_none_or(|stored| !media_type_id.is_none() && media_type.as_deref() == Some(stored));
    let acls = builder.push_acls(
        &node
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect::<Vec<_>>(),
    );
    let modified = node.modified.to_native();
    let flags = FileFlags::new(
        node.kind_id(),
        file.is_some_and(|f| f.executable),
        node.role().map_or(0, FileNodeRole::id),
        media_type_id,
        extra_len,
    )
    .with_presence(node.presence());
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::File {
            name,
            size: file.map_or(NO_ID, |f| f.size.to_native()),
            parent_id: if parent_id > 0 { parent_id - 1 } else { NO_ID },
            acls,
            etag: node.etag.to_native(),
            modified,
            created_delta: node
                .created
                .to_native()
                .saturating_sub(modified)
                .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            flags: if is_media_type_exact {
                flags.with_exact_media_type()
            } else {
                flags
            },
        },
    });
}

