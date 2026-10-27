/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SplitFilter {
    Internal(SearchFilter),
    External(Vec<SearchFilter>),
}

pub(crate) fn split_filters(filters_in: Vec<SearchFilter>) -> Option<Vec<SplitFilter>> {
    let mut account_id = u64::MAX;
    let mut filters: Vec<SearchFilter> = Vec::with_capacity(filters_in.len());
    let mut op_stack = Vec::new();
    let mut document_sets: AHashMap<usize, RoaringBitmap> = AHashMap::new();
    let mut operators: AHashMap<usize, Vec<SearchFilter>> = AHashMap::new();

    for filter in filters_in {
        match filter {
            op @ (SearchFilter::And | SearchFilter::Or | SearchFilter::Not) => {
                op_stack.push(op.clone());
                filters.push(op);
            }
            SearchFilter::End => {
                if let Some(ops) = operators.remove(&op_stack.len()) {
                    filters.extend(ops);
                }
                if let Some(docs) = document_sets.remove(&op_stack.len()) {
                    filters.push(SearchFilter::DocumentSet(docs));
                }
                filters.push(SearchFilter::End);
                op_stack.pop()?;
            }
            SearchFilter::Integer {
                field: SearchField::AccountId,
                value,
                ..
            } => {
                account_id = value;
            }
            SearchFilter::Text { .. }
            | SearchFilter::KeyValue { .. }
            | SearchFilter::Integer { .. } => {
                operators.entry(op_stack.len()).or_default().push(filter);
            }
            SearchFilter::DocumentSet(docs) => match document_sets.entry(op_stack.len()) {
                Entry::Occupied(mut entry) => {
                    if matches!(op_stack.last(), Some(SearchFilter::Or | SearchFilter::Not)) {
                        entry.get_mut().bitor_assign(&docs);
                    } else {
                        entry.get_mut().bitand_assign(&docs);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(docs);
                }
            },
        }
    }

    if let Some(ops) = operators.remove(&0) {
        filters.extend(ops);
    }
    if let Some(docs) = document_sets.remove(&0) {
        filters.push(SearchFilter::DocumentSet(docs));
    }

    if account_id == u64::MAX {
        return None;
    }

    let mut split: Vec<SplitFilter> = Vec::new();
    let mut i = 0;

    'outer: while i < filters.len() {
        let mut j = i;
        let mut depth = 0;

        while j < filters.len() {
            match &filters[j] {
                SearchFilter::And | SearchFilter::Or | SearchFilter::Not => {
                    depth += 1;
                }
                SearchFilter::End => {
                    depth -= 1;
                    if depth < 0 {
                        if j > i {
                            break;
                        } else {
                            split.push(SplitFilter::Internal(SearchFilter::End));
                            i += 1;
                            continue 'outer;
                        }
                    }
                }
                SearchFilter::Text { .. }
                | SearchFilter::Integer { .. }
                | SearchFilter::KeyValue { .. } => {}
                SearchFilter::DocumentSet(_) => {
                    if depth == 0 && j > i {
                        break;
                    } else {
                        split.push(SplitFilter::Internal(std::mem::take(&mut filters[i])));
                        i += 1;
                        continue 'outer;
                    }
                }
            }
            j += 1;
        }

        let mut external_filters = vec![SearchFilter::Integer {
            field: SearchField::AccountId,
            op: Ordering::Equal,
            value: account_id,
        }];
        let add_or = matches!(
            split.last(),
            Some(SplitFilter::Internal(SearchFilter::Or | SearchFilter::Not))
        ) && j > i + 1;
        if add_or {
            external_filters.push(SearchFilter::Or);
        }
        external_filters.extend(&mut filters[i..j].iter_mut().map(std::mem::take));
        if add_or {
            external_filters.push(SearchFilter::End);
        }
        split.push(SplitFilter::External(external_filters));

        i = j;
    }

    Some(split)
}

// Test cases
