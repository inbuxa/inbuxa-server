/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::propfind::PropFindItem;
use common::{DavResourcePath, GroupwareResourceRef, GroupwareResources, Server};
use dav_proto::schema::{MatchType, request::TextMatch};
use groupware::strip_mailto_scheme;
use nlp::language::Language;
use store::{
    ahash::AHashSet,
    roaring::RoaringBitmap,
    search::{SearchField, SearchFilter, SearchQuery, TextMatch as IndexMatch, tokenize::tokenize},
    write::SearchIndex,
};
use utils::cheeky_hash::CheekyHash;

pub(crate) enum Candidates {
    All,
    Set(RoaringBitmap),
    Text(SearchFilter),
    And(Vec<Candidates>),
    Or(Vec<Candidates>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexedText {
    Plain,
    Identifier,
    Stemmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchBackend {
    Internal,
    External,
}

#[derive(Clone, Copy)]
pub(crate) struct TextIndex<'x> {
    fields: Option<&'x AHashSet<SearchField>>,
    default_language: Language,
    backend: SearchBackend,
    splits_identifiers: bool,
}

pub(crate) struct QueryScope<'x> {
    items: Vec<DavResourcePath<'x>>,
    document_ids: RoaringBitmap,
}

impl<'x> TextIndex<'x> {
    pub fn new(server: &'x Server, index: SearchIndex) -> Self {
        let search_store = server.search_store();
        TextIndex {
            fields: if search_store.is_meilisearch() {
                None
            } else {
                server.core.email.index_fields.get(&index)
            },
            default_language: server.core.email.default_language,
            backend: if search_store.internal_fts().is_some() {
                SearchBackend::Internal
            } else {
                SearchBackend::External
            },
            splits_identifiers: search_store.splits_identifiers(),
        }
    }

    pub fn candidates(
        &self,
        field: SearchField,
        text: IndexedText,
        text_match: &TextMatch,
    ) -> Candidates {
        if text_match.negate
            || !self.contains(&field)
            || (text == IndexedText::Identifier && !self.splits_identifiers)
        {
            return Candidates::All;
        }
        let (value, has_scheme) = if text == IndexedText::Identifier {
            let address = strip_mailto_scheme(&text_match.value);
            (address, address.len() != text_match.value.len())
        } else {
            (text_match.value.as_str(), false)
        };
        let language = if text == IndexedText::Stemmed {
            Language::detect(value.to_string(), self.default_language).1
        } else {
            Language::None
        };
        let starts_at_word = has_scheme
            || matches!(
                text_match.match_type,
                MatchType::Equals | MatchType::StartsWith
            )
            || value.starts_with(|ch: char| !ch.is_alphanumeric());
        let ends_at_word = matches!(
            text_match.match_type,
            MatchType::Equals | MatchType::EndsWith
        ) || value.ends_with(|ch: char| !ch.is_alphanumeric());

        let mut words = Vec::with_capacity(4);
        tokenize(value, Language::None, |token| {
            words.push(token.word);
            true
        });

        let term = |word: &str, op: IndexMatch| {
            Candidates::Text(SearchFilter::Text {
                field: field.clone(),
                op,
                value: word.to_string(),
                language,
            })
        };
        let last = words.len().saturating_sub(1);
        let is_single = words.len() == 1;

        Candidates::and(words.iter().enumerate().filter_map(|(position, word)| {
            let partial_start = position == 0 && !starts_at_word;
            let partial_end = position == last && !ends_at_word;
            match (partial_start, partial_end) {
                (true, false) if !is_single => None,
                (_, false) => Some(term(word, IndexMatch::Standard)),
                (_, true) => Some(Candidates::or([
                    term(word, IndexMatch::Standard),
                    term(self.prefix_of(word), IndexMatch::Prefix),
                ])),
            }
        }))
    }

    fn prefix_of<'w>(&self, word: &'w str) -> &'w str {
        word.get(..word.floor_char_boundary(self.backend.max_prefix_len()))
            .unwrap_or(word)
    }

    fn contains(&self, field: &SearchField) -> bool {
        self.fields
            .is_some_and(|fields| fields.is_empty() || fields.contains(field))
    }
}

impl SearchBackend {
    fn max_prefix_len(self) -> usize {
        match self {
            SearchBackend::Internal => CheekyHash::HASH_SIZE,
            SearchBackend::External => usize::MAX,
        }
    }
}

impl<'x> QueryScope<'x> {
    pub fn new(items: impl Iterator<Item = DavResourcePath<'x>>) -> Self {
        let items = items.collect::<Vec<_>>();
        let document_ids = items.iter().map(DavResourcePath::document_id).collect();
        QueryScope {
            items,
            document_ids,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn matching(&self, predicate: impl Fn(&GroupwareResourceRef<'x>) -> bool) -> Candidates {
        Candidates::Set(
            self.items
                .iter()
                .filter(|item| predicate(&item.resource))
                .map(DavResourcePath::document_id)
                .collect(),
        )
    }

    pub async fn resolve(
        self,
        server: &Server,
        index: SearchIndex,
        account_id: u32,
        candidates: Candidates,
        resources: &GroupwareResources,
    ) -> Vec<PropFindItem> {
        let QueryScope {
            items,
            document_ids,
        } = self;
        let matches = candidates
            .resolve(server, index, account_id, document_ids)
            .await;

        items
            .into_iter()
            .filter(|item| matches.contains(item.document_id()))
            .map(|item| PropFindItem::new(resources.format_resource(item), account_id, item))
            .collect()
    }

    pub fn into_items(self, resources: &GroupwareResources, account_id: u32) -> Vec<PropFindItem> {
        self.items
            .into_iter()
            .map(|item| PropFindItem::new(resources.format_resource(item), account_id, item))
            .collect()
    }
}

impl Candidates {
    pub fn and(items: impl IntoIterator<Item = Candidates>) -> Self {
        let mut set: Option<RoaringBitmap> = None;
        let mut children = Vec::new();
        for item in items {
            match item {
                Candidates::All => {}
                Candidates::Set(items) => match &mut set {
                    Some(set) => *set &= items,
                    None => set = Some(items),
                },
                Candidates::And(items) => children.extend(items),
                item => children.push(item),
            }
        }
        if let Some(set) = set {
            if set.is_empty() {
                return Candidates::Set(set);
            }
            children.push(Candidates::Set(set));
        }
        if children.len() > 1 {
            Candidates::And(children)
        } else {
            children.pop().unwrap_or(Candidates::All)
        }
    }

    pub fn or(items: impl IntoIterator<Item = Candidates>) -> Self {
        let mut set: Option<RoaringBitmap> = None;
        let mut children = Vec::new();
        for item in items {
            match item {
                Candidates::All => return Candidates::All,
                Candidates::Set(items) => match &mut set {
                    Some(set) => *set |= items,
                    None => set = Some(items),
                },
                Candidates::Or(items) => children.extend(items),
                item => children.push(item),
            }
        }
        if let Some(set) = set.filter(|set| !set.is_empty()) {
            children.push(Candidates::Set(set));
        }
        if children.len() > 1 {
            Candidates::Or(children)
        } else {
            children
                .pop()
                .unwrap_or_else(|| Candidates::Set(RoaringBitmap::new()))
        }
    }

    pub async fn resolve(
        self,
        server: &Server,
        index: SearchIndex,
        account_id: u32,
        scope: RoaringBitmap,
    ) -> RoaringBitmap {
        match self {
            Candidates::All => scope,
            candidates if candidates.has_text() => {
                let mut filters = Vec::with_capacity(8);
                candidates.into_filters(&mut filters);
                match server
                    .search_store()
                    .filter_account(
                        SearchQuery::new(index)
                            .with_account_id(account_id)
                            .with_mask(scope.clone())
                            .with_filters(filters),
                    )
                    .await
                {
                    Ok(matches) => matches,
                    Err(err) => {
                        trc::error!(err.caused_by(trc::location!()));
                        scope
                    }
                }
            }
            candidates => {
                let mut matches = candidates.evaluate(&scope);
                matches &= &scope;
                matches
            }
        }
    }

    fn has_text(&self) -> bool {
        match self {
            Candidates::Text(_) => true,
            Candidates::And(items) | Candidates::Or(items) => {
                items.iter().any(Candidates::has_text)
            }
            Candidates::All | Candidates::Set(_) => false,
        }
    }

    fn into_filters(self, filters: &mut Vec<SearchFilter>) {
        match self {
            Candidates::All => {}
            Candidates::Set(set) => filters.push(SearchFilter::is_in_set(set)),
            Candidates::Text(filter) => filters.push(filter),
            Candidates::And(items) => {
                filters.push(SearchFilter::And);
                for item in items {
                    item.into_filters(filters);
                }
                filters.push(SearchFilter::End);
            }
            Candidates::Or(items) => {
                filters.push(SearchFilter::Or);
                for item in items {
                    item.into_filters(filters);
                }
                filters.push(SearchFilter::End);
            }
        }
    }

    fn evaluate(self, scope: &RoaringBitmap) -> RoaringBitmap {
        match self {
            Candidates::All | Candidates::Text(_) => scope.clone(),
            Candidates::Set(set) => set,
            Candidates::And(items) => items
                .into_iter()
                .map(|item| item.evaluate(scope))
                .reduce(|a, b| a & b)
                .unwrap_or_else(|| scope.clone()),
            Candidates::Or(items) => items
                .into_iter()
                .map(|item| item.evaluate(scope))
                .reduce(|a, b| a | b)
                .unwrap_or_default(),
        }
    }
}

