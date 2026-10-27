/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use compact_str::format_compact;
use utils::map::vec_map::VecMap;

pub mod eval;
pub mod jsptr;
pub mod resolve;

pub(crate) enum Graph<'x> {
    Some {
        child_id: &'x str,
        graph: &'x mut AHashMap<String, Vec<String>>,
    },
    None,
}

fn topological_sort<T>(
    create: &mut VecMap<String, T>,
    graph: AHashMap<String, Vec<String>>,
) -> trc::Result<VecMap<String, T>> {
    // Make sure all references exist
    for (from_id, to_ids) in graph.iter() {
        for to_id in to_ids {
            if !create.contains_key(to_id) {
                return Err(trc::JmapEvent::InvalidResultReference.into_err().details(
                    format_compact!(
                        "Invalid reference to non-existing object {to_id:?} from {from_id:?}"
                    ),
                ));
            }
        }
    }

    let mut sorted_create = VecMap::with_capacity(create.len());
    let mut placed = AHashSet::with_capacity(create.len());
    let mut it_stack = Vec::new();

    'main: for root in graph.keys() {
        let mut it = std::slice::from_ref(root).iter();
        loop {
            while let Some(from_id) = it.next() {
                if placed.contains(from_id.as_str()) {
                    continue;
                }
                if let Some(to_ids) = graph.get(from_id) {
                    it_stack.push((it, from_id));
                    if it_stack.len() > 1000 {
                        return Err(trc::JmapEvent::InvalidArguments
                            .into_err()
                            .details("Cyclical references are not allowed."));
                    }
                    it = to_ids.iter();
                } else if placed.insert(from_id.as_str())
                    && let Some((id, value)) = create.remove_entry(from_id)
                {
                    sorted_create.append(id, value);
                    if create.is_empty() {
                        break 'main;
                    }
                }
            }

            if let Some((prev_it, from_id)) = it_stack.pop() {
                it = prev_it;
                if placed.insert(from_id.as_str())
                    && let Some((id, value)) = create.remove_entry(from_id)
                {
                    sorted_create.append(id, value);
                    if create.is_empty() {
                        break 'main;
                    }
                }
            } else {
                break;
            }
        }
    }

    // Add remaining items
    if !create.is_empty() {
        for (id, value) in std::mem::take(create) {
            sorted_create.append(id, value);
        }
    }
    Ok(sorted_create)
}

