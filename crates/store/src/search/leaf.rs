/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::{
    KeyValueMatch, MAX_PLANNED_TOKENS, MAX_QUERY_LEAVES, MAX_QUERY_PLANNED_TOKENS, SearchField,
    SearchFilter, TextMatch,
    tokenize::{integer_term, key_value_term, stem_term, tokenize},
};
use ahash::AHashSet;
use nlp::language::Language;
use roaring::RoaringBitmap;
use std::{borrow::Cow, cmp::Ordering, mem, ops::Range};
use utils::cheeky_hash::{CheekyHash, CheekyHashSet};

pub(crate) type Probe = (u8, CheekyHash);

pub(crate) enum Leaf {
    Empty,
    Groups {
        field: u8,
        groups: Vec<[Option<CheekyHash>; 4]>,
    },
    Terms {
        field: u8,
        terms: Vec<CheekyHash>,
    },
    Phrase {
        field: u8,
        words: Vec<CheekyHash>,
    },
    Prefix {
        field: u8,
        prefix: Box<[u8]>,
    },
    Resolved(RoaringBitmap),
    UnsupportedRange,
}

pub(crate) fn single_term_prefix(value: &str) -> Cow<'_, str> {
    if value.chars().any(char::is_uppercase) {
        Cow::Owned(value.to_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

impl Leaf {
    pub(crate) fn plan(filter: &SearchFilter) -> Self {
        match filter {
            SearchFilter::Text {
                field,
                op,
                value,
                language,
            } => {
                let field = field.u8_id();
                match op {
                    TextMatch::Standard => {
                        let stemmed = !matches!(language, Language::None | Language::Unknown);
                        let mut groups: Vec<[Option<CheekyHash>; 4]> = Vec::new();
                        let mut distinct = DistinctTerms::default();
                        let mut buf = String::new();
                        tokenize(value, *language, |token| {
                            let word = CheekyHash::new(token.word.as_bytes());
                            if !distinct.is_new(word) {
                                return true;
                            }
                            let mut group = [Some(word), None, None, None];
                            if stemmed {
                                group[1] = Some(stem_term(&token.word, &mut buf));
                                if let Some(stem) = &token.stem {
                                    group[2] = Some(CheekyHash::new(stem.as_bytes()));
                                    group[3] = Some(stem_term(stem, &mut buf));
                                }
                            }
                            groups.push(group);
                            distinct.has_room(&mut groups, |group| group[0])
                        });
                        if groups.is_empty() {
                            Leaf::Empty
                        } else {
                            Leaf::Groups { field, groups }
                        }
                    }
                    TextMatch::Exact => {
                        let mut words = Vec::new();
                        tokenize(value, *language, |token| {
                            words.push(CheekyHash::new(token.word.as_bytes()));
                            words.len() < MAX_PLANNED_TOKENS
                        });
                        match words.len() {
                            0 => Leaf::Empty,
                            1 => Leaf::Terms {
                                field,
                                terms: words,
                            },
                            _ => Leaf::Phrase { field, words },
                        }
                    }
                    TextMatch::Prefix => {
                        let prefix = single_term_prefix(value);
                        let prefix = prefix.as_bytes();
                        if prefix.is_empty() || prefix.len() > CheekyHash::HASH_SIZE {
                            Leaf::Empty
                        } else {
                            Leaf::Prefix {
                                field,
                                prefix: prefix.into(),
                            }
                        }
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if *op == Ordering::Equal {
                    Leaf::Terms {
                        field: field.u8_id(),
                        terms: vec![integer_term(*value)],
                    }
                } else {
                    Leaf::UnsupportedRange
                }
            }
            SearchFilter::KeyValue { field, key, op } => {
                let key = key
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .map(|ch| ch.to_ascii_lowercase())
                    .collect::<String>();
                let value = match op {
                    KeyValueMatch::Equals(value) | KeyValueMatch::Contains(value) => value.as_str(),
                    KeyValueMatch::Exists => "",
                };
                let mut terms = Vec::new();
                let mut distinct = DistinctTerms::default();
                let mut buf = String::new();
                tokenize(value, Language::None, |token| {
                    let term = key_value_term(&key, &token.word, &mut buf);
                    if !distinct.is_new(term) {
                        return true;
                    }
                    terms.push(term);
                    distinct.has_room(&mut terms, |term| Some(*term))
                });
                if terms.is_empty() {
                    terms.push(CheekyHash::new(key.as_bytes()));
                }
                Leaf::Terms {
                    field: field.u8_id(),
                    terms,
                }
            }
            SearchFilter::DocumentSet(_)
            | SearchFilter::And
            | SearchFilter::Or
            | SearchFilter::Not
            | SearchFilter::End => Leaf::Empty,
        }
    }

    fn planned_terms(&self) -> usize {
        match self {
            Leaf::Groups { groups, .. } => groups.len(),
            Leaf::Terms { terms, .. } => terms.len(),
            Leaf::Phrase { words, .. } => words.len(),
            Leaf::Prefix { .. } => 1,
            Leaf::Empty | Leaf::Resolved(_) | Leaf::UnsupportedRange => 0,
        }
    }

    pub(crate) fn add_probes(&self, probes: &mut AHashSet<Probe>) {
        match self {
            Leaf::Groups { field, groups } => {
                probes.extend(
                    groups
                        .iter()
                        .flatten()
                        .flatten()
                        .map(|hash| (*field, *hash)),
                );
            }
            Leaf::Terms { field, terms } => {
                probes.extend(terms.iter().map(|hash| (*field, *hash)));
            }
            Leaf::Phrase { field, words } => {
                probes.extend(words.iter().map(|hash| (*field, *hash)));
            }
            Leaf::Empty | Leaf::Prefix { .. } | Leaf::Resolved(_) | Leaf::UnsupportedRange => {}
        }
    }
}

#[cold]
fn query_too_large() -> trc::Error {
    trc::LimitEvent::SizeRequest
        .into_err()
        .details("Too many search terms in one query")
}

#[derive(Default)]
struct DistinctTerms(CheekyHashSet);

impl DistinctTerms {
    fn is_new(&mut self, term: CheekyHash) -> bool {
        self.0.is_empty() || self.0.insert(term)
    }

    fn has_room<T>(
        &mut self,
        planned: &mut Vec<T>,
        planned_term: impl Fn(&T) -> Option<CheekyHash>,
    ) -> bool {
        if planned.len() == MAX_PLANNED_TOKENS && self.0.is_empty() {
            self.0.reserve(MAX_PLANNED_TOKENS);
            planned.retain(|item| planned_term(item).is_some_and(|term| self.0.insert(term)));
        }
        planned.len() < MAX_PLANNED_TOKENS
    }
}

pub(crate) struct LeafPlan {
    leaves: Vec<Leaf>,
    units: Vec<Range<usize>>,
    leaf_units: Vec<usize>,
    fetched: Vec<bool>,
}

impl LeafPlan {
    pub(crate) fn new(filters: &[SearchFilter]) -> trc::Result<Self> {
        let mut planned = 0usize;
        let mut leaves = Vec::new();
        let mut units: Vec<Range<usize>> = Vec::new();
        let mut leaf_units = Vec::new();
        let mut depth = 0usize;
        let mut open_unit: Option<(usize, usize)> = None;
        for filter in filters {
            match filter {
                SearchFilter::And => depth += 1,
                SearchFilter::Or | SearchFilter::Not => {
                    depth += 1;
                    if open_unit.is_none() {
                        units.push(leaves.len()..leaves.len());
                        open_unit = Some((depth, units.len() - 1));
                    }
                }
                SearchFilter::End => {
                    if open_unit.is_some_and(|(unit_depth, _)| unit_depth == depth) {
                        open_unit = None;
                    }
                    depth = depth.saturating_sub(1);
                }
                SearchFilter::DocumentSet(_) => {}
                filter if !is_leaf(filter) => {}
                filter => {
                    if leaves.len() == MAX_QUERY_LEAVES {
                        return Err(query_too_large());
                    }
                    let leaf = Leaf::plan(filter);
                    planned += leaf.planned_terms();
                    if planned > MAX_QUERY_PLANNED_TOKENS {
                        return Err(query_too_large());
                    }
                    let unit = match open_unit {
                        Some((_, unit)) => unit,
                        None => {
                            units.push(leaves.len()..leaves.len());
                            units.len() - 1
                        }
                    };
                    leaves.push(leaf);
                    if let Some(range) = units.get_mut(unit) {
                        range.end = leaves.len();
                    }
                    leaf_units.push(unit);
                }
            }
        }
        let fetched = vec![false; units.len()];
        Ok(LeafPlan {
            leaves,
            units,
            leaf_units,
            fetched,
        })
    }

    pub(crate) fn unfetched_unit(&mut self, leaf: usize) -> Option<Range<usize>> {
        let unit = *self.leaf_units.get(leaf)?;
        let fetched = self.fetched.get_mut(unit)?;
        if *fetched {
            None
        } else {
            *fetched = true;
            self.units.get(unit).cloned()
        }
    }

    pub(crate) fn leaves(&self, unit: Range<usize>) -> &[Leaf] {
        self.leaves.get(unit).unwrap_or_default()
    }

    pub(crate) fn leaves_mut(&mut self, unit: Range<usize>) -> &mut [Leaf] {
        self.leaves.get_mut(unit).unwrap_or_default()
    }

    pub(crate) fn take(&mut self, leaf: usize) -> Leaf {
        self.leaves
            .get_mut(leaf)
            .map_or(Leaf::Empty, |leaf| mem::replace(leaf, Leaf::Empty))
    }
}

pub(crate) fn is_leaf(filter: &SearchFilter) -> bool {
    matches!(
        filter,
        SearchFilter::Text { .. } | SearchFilter::Integer { .. } | SearchFilter::KeyValue { .. }
    ) && !matches!(
        filter,
        SearchFilter::Integer {
            field: SearchField::AccountId,
            op: Ordering::Equal,
            ..
        }
    )
}

