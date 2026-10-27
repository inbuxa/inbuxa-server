/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "postgres")]
use crate::backend::postgres::search::DENSE_ACCOUNT_DOCUMENTS;
use crate::{
    SearchStore, Store,
    search::{
        IndexDocument, QueryResults, SearchField, SearchFilter, SearchQuery,
        split::{SplitFilter, split_filters},
    },
    write::SearchIndex,
};
use roaring::{RoaringBitmap, RoaringTreemap};
use std::cmp::Ordering;
use trc::AddContext;

pub const MAX_FILTER_CANDIDATES: usize = 16_384;
#[cfg(feature = "postgres")]
const DENSE_QUERY_FIXED_ROWS: f64 = 12_000.0;
#[cfg(feature = "postgres")]
const DENSE_QUERY_ROWS_PER_DOCUMENT: f64 = 0.011;

impl SearchStore {
    pub async fn query_account(&self, mut query: SearchQuery) -> trc::Result<Vec<u32>> {
        let comparators = std::mem::take(&mut query.comparators);
        let results = self.filter_account(query).await?;

        Ok(match results.len().cmp(&1) {
            Ordering::Equal => vec![results.min().unwrap()],
            Ordering::Less => vec![],
            Ordering::Greater if !comparators.is_empty() => {
                QueryResults::new(results, comparators).into_sorted()
            }
            Ordering::Greater => results.iter().collect(),
        })
    }

    pub async fn filter_account(&self, query: SearchQuery) -> trc::Result<RoaringBitmap> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_search_query();

        debug_assert!(query.comparators.is_empty());

        // Pre-filter by mask
        if query.mask.is_empty() {
            return Ok(RoaringBitmap::new());
        }

        // If the store does not support FTS, use the internal FTS store
        if let Some(store) = self.internal_fts() {
            return store.query_account(query).await;
        }

        // If all filters are external, delegate to the underlying store
        let mut account_id = u32::MAX;
        let mut has_local_filters = false;
        let mut has_external_filters = false;
        for filter in &query.filters {
            match filter {
                SearchFilter::Integer {
                    value,
                    field: SearchField::AccountId,
                    ..
                } => {
                    account_id = *value as u32;
                }
                SearchFilter::DocumentSet(_) => {
                    has_local_filters = true;
                }
                SearchFilter::Text { .. }
                | SearchFilter::KeyValue { .. }
                | SearchFilter::Integer { .. } => {
                    has_external_filters = true;
                }
                _ => (),
            }
        }

        if account_id == u32::MAX {
            return Err(trc::StoreEvent::UnexpectedError
                .reason("Account ID filter is required for account queries")
                .caused_by(trc::location!()));
        }

        if !has_local_filters && !has_external_filters {
            return Ok(query.mask);
        }

        if !has_local_filters {
            return self
                .sub_query(query.index, &query.filters, &query.mask)
                .await
                .map(|results| results & query.mask)
                .caused_by(trc::location!());
        }

        let filters = if has_external_filters {
            // Split filters
            let split_filters = split_filters(query.filters).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .reason("Invalid filter query")
                    .caused_by(trc::location!())
            })?;

            let mut filters = Vec::with_capacity(split_filters.len());
            for split_filter in split_filters {
                match split_filter {
                    SplitFilter::External(external) => {
                        // Execute sub-query
                        filters.push(SearchFilter::DocumentSet(
                            self.sub_query(query.index, &external, &query.mask).await?,
                        ));
                    }
                    SplitFilter::Internal(filter) => {
                        filters.push(filter);
                    }
                }
            }

            filters
        } else {
            query.filters
        };

        // Merge results locally
        Ok(SearchQuery::new(query.index)
            .with_filters(filters)
            .with_mask(query.mask)
            .filter()
            .into_bitmap())
    }

    #[cfg_attr(not(feature = "postgres"), allow(unused_variables))]
    pub fn account_query_rows(&self, documents: u64) -> Option<f64> {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(_) if documents >= DENSE_ACCOUNT_DOCUMENTS => {
                Some(DENSE_QUERY_FIXED_ROWS + DENSE_QUERY_ROWS_PER_DOCUMENT * documents as f64)
            }
            _ => None,
        }
    }

    pub fn supports_windowed_walk(&self) -> bool {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(_) => true,
            _ => false,
        }
    }

    pub fn supports_candidate_filter(&self) -> bool {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(_) => true,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(_) => true,
            _ => false,
        }
    }

    pub async fn filter_candidates(
        &self,
        query: &SearchQuery,
        candidates: &[u32],
    ) -> trc::Result<RoaringBitmap> {
        debug_assert!(candidates.len() <= MAX_FILTER_CANDIDATES);

        if self.supports_candidate_filter() && has_external_filters_only(&query.filters) {
            #[cfg(stalwart_tests)]
            crate::dispatch::StoreOps::count_search_query();

            self.sub_query_candidates(query.index, &query.filters, candidates)
                .await
                .caused_by(trc::location!())
        } else {
            self.filter_account(SearchQuery {
                index: query.index,
                filters: query.filters.clone(),
                comparators: Vec::new(),
                mask: candidates.iter().copied().collect(),
            })
            .await
        }
    }

    #[cfg_attr(
        not(any(feature = "postgres", feature = "mysql")),
        allow(unused_variables)
    )]
    async fn sub_query_candidates(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        candidates: &[u32],
    ) -> trc::Result<RoaringBitmap> {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => {
                store.filter_candidates(index, filters, candidates).await
            }
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.filter_candidates(index, filters, candidates).await,
            _ => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    #[cfg_attr(not(feature = "postgres"), allow(unused_variables))]
    async fn sub_query(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        mask: &RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => store.query_account(index, filters, mask).await,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.query(index, filters).await,
            SearchStore::ElasticSearch(store) => store.query(index, filters).await,
            SearchStore::MeiliSearch(store) => store.query(index, filters).await,
            SearchStore::Store(_) => unreachable!(),
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<RoaringTreemap> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_search_query();

        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => store.query(query.index, &query.filters).await,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.query(query.index, &query.filters).await,
            SearchStore::Store(store) => store.query_global(query).await,
            SearchStore::ElasticSearch(store) => store.query(query.index, &query.filters).await,
            SearchStore::MeiliSearch(store) => store.query(query.index, &query.filters).await,
        }
    }

    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_search_index();

        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => store.index(documents).await,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.index(documents).await,
            SearchStore::ElasticSearch(store) => store.index(documents).await,
            SearchStore::MeiliSearch(store) => store.index(documents).await,
            SearchStore::Store(_) => unreachable!(),
        }
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<u64> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_search_unindex();

        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => store.unindex(query).await,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.unindex(query).await,
            SearchStore::ElasticSearch(store) => store.unindex(query).await,
            SearchStore::MeiliSearch(store) => store.unindex(query).await,
            SearchStore::Store(_) => unreachable!(),
        }
    }

    pub fn internal_fts(&self) -> Option<&Store> {
        match self {
            SearchStore::Store(store) => Some(store),
            _ => None,
        }
    }

    pub fn splits_identifiers(&self) -> bool {
        match self {
            SearchStore::Store(_) => true,
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(_) => true,
            _ => false,
        }
    }

    pub fn is_mysql(&self) -> bool {
        match self {
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(_) => true,
            _ => false,
        }
    }

    pub fn is_postgres(&self) -> bool {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(_) => true,
            _ => false,
        }
    }

    pub fn is_elasticsearch(&self) -> bool {
        matches!(self, SearchStore::ElasticSearch(_))
    }

    pub fn is_meilisearch(&self) -> bool {
        matches!(self, SearchStore::MeiliSearch(_))
    }

    pub async fn create_indexes(&self) -> trc::Result<()> {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::PostgreSQL(store) => store.create_search_tables().await,
            #[cfg(feature = "mysql")]
            SearchStore::MySQL(store) => store.create_search_tables().await,
            SearchStore::Store(_) => Ok(()),
            SearchStore::ElasticSearch(store) => store.create_indexes().await,
            SearchStore::MeiliSearch(store) => store.create_indexes().await,
        }
    }
}

fn has_external_filters_only(filters: &[SearchFilter]) -> bool {
    let mut has_external_filters = false;
    for filter in filters {
        match filter {
            SearchFilter::DocumentSet(_) => return false,
            SearchFilter::Integer {
                field: SearchField::AccountId,
                ..
            } => (),
            SearchFilter::Text { .. }
            | SearchFilter::KeyValue { .. }
            | SearchFilter::Integer { .. } => has_external_filters = true,
            SearchFilter::And | SearchFilter::Or | SearchFilter::Not | SearchFilter::End => (),
        }
    }
    has_external_filters
}

impl SearchFilter {
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            SearchFilter::Text { .. } | SearchFilter::KeyValue { .. }
        )
    }
}
