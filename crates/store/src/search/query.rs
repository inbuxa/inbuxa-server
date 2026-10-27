/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U16_LEN, U32_LEN,
    search::{
        ACCOUNT_BLOCK_SHIFT, GLOBAL_BUCKET_SHIFT, KeyValueMatch, SearchField, SearchFilter,
        SearchQuery, TERM_GROUP_KEY_VALUE, TERM_GROUP_TEXT, TextMatch, codec,
        leaf::{Leaf, LeafPlan, Probe, single_term_prefix},
        term::matches_phrase,
        tokenize::{integer_term, key_value_term, tokenize},
    },
    write::{
        AnyKey, SearchIndex,
        lazybitmap::{LazyBitmap, LazyTreemap},
    },
};
use ahash::{AHashMap, AHashSet};
use compact_str::format_compact;
use nlp::language::Language;
use roaring::{RoaringBitmap, RoaringTreemap};
use std::{cmp::Ordering, iter, mem};
use utils::cheeky_hash::CheekyHash;

const PHRASE_DOCUMENT_BATCH: usize = 1024;
const MAX_WINDOW_RUNS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    And,
    Or,
    Not,
}

impl Store {
    pub async fn query_account(&self, query: SearchQuery) -> trc::Result<RoaringBitmap> {
        self.query_account_in(query, None).await
    }

    pub async fn query_account_window(
        &self,
        mut query: SearchQuery,
        window: RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let mask_blocks = blocks(&query.mask).count();
        query.mask &= &window;
        if query.mask.is_empty() {
            return Ok(RoaringBitmap::new());
        }
        let window = BlockWindow::new(&query.mask, mask_blocks);
        self.query_account_in(query, window).await
    }

    async fn query_account_in(
        &self,
        query: SearchQuery,
        window: Option<BlockWindow>,
    ) -> trc::Result<RoaringBitmap> {
        let mut account_id = None;
        for filter in &query.filters {
            if let SearchFilter::Integer {
                field: SearchField::AccountId,
                op: Ordering::Equal,
                value,
            } = filter
            {
                account_id = Some(*value as u32);
            }
        }
        let Some(account_id) = account_id else {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Account ID filter is required for account queries"));
        };

        let mut filters = query.filters;
        let mut plan = LeafPlan::new(&filters)?;
        let mut ctx = AccountContext {
            store: self,
            index: query.index,
            account_id,
            mask: &query.mask,
            window,
            terms: AHashMap::new(),
            prefixes: AHashMap::new(),
        };

        let mut next_leaf = 0usize;
        let mut groups: Vec<Group> = Vec::new();
        let mut skip_depth: Option<usize> = None;
        let mut has_filters = false;

        for filter in filters.iter_mut() {
            match filter {
                SearchFilter::And => groups.push(Group::And),
                SearchFilter::Or => groups.push(Group::Or),
                SearchFilter::Not => groups.push(Group::Not),
                SearchFilter::End => {
                    groups.pop();
                    if skip_depth.is_some_and(|depth| groups.len() < depth) {
                        skip_depth = None;
                    }
                }
                SearchFilter::Integer {
                    field: SearchField::AccountId,
                    op: Ordering::Equal,
                    ..
                } => {}
                SearchFilter::DocumentSet(set) => {
                    has_filters = true;
                    if skip_depth.is_none()
                        && set.is_empty()
                        && !matches!(groups.last(), Some(Group::Or | Group::Not))
                    {
                        skip_depth = Some(groups.len());
                    }
                }
                SearchFilter::Text { .. }
                | SearchFilter::Integer { .. }
                | SearchFilter::KeyValue { .. } => {
                    has_filters = true;
                    let leaf = next_leaf;
                    next_leaf += 1;
                    let result = if skip_depth.is_none() {
                        if let Some(unit) = plan.unfetched_unit(leaf) {
                            ctx.prefetch(plan.leaves(unit.clone())).await?;
                            ctx.verify_phrases(plan.leaves_mut(unit)).await?;
                        }
                        ctx.evaluate(plan.take(leaf))?
                    } else {
                        RoaringBitmap::new()
                    };
                    if skip_depth.is_none()
                        && result.is_empty()
                        && !matches!(groups.last(), Some(Group::Or | Group::Not))
                    {
                        skip_depth = Some(groups.len());
                    }
                    *filter = SearchFilter::DocumentSet(result);
                }
            }
        }

        if has_filters {
            Ok(SearchQuery::new(query.index)
                .with_filters(filters)
                .with_mask(query.mask)
                .filter()
                .into_bitmap())
        } else {
            Ok(query.mask)
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<RoaringTreemap> {
        let mut from_id = 0u64;
        let mut until_id = u64::MAX;
        let mut has_filters = false;
        let mut groups: Vec<Group> = Vec::new();

        for filter in &query.filters {
            match filter {
                SearchFilter::And => groups.push(Group::And),
                SearchFilter::Or => groups.push(Group::Or),
                SearchFilter::End => {
                    groups.pop();
                }
                SearchFilter::Integer {
                    field: SearchField::Id,
                    op,
                    value,
                } => {
                    if groups.contains(&Group::Or) {
                        return Err(trc::StoreEvent::NotSupported
                            .into_err()
                            .details("Id filters are only supported as conjunctions"));
                    }
                    match op {
                        Ordering::Greater => match value.checked_add(1) {
                            Some(value) => from_id = from_id.max(value),
                            None => {
                                from_id = 1;
                                until_id = 0;
                            }
                        },
                        Ordering::Less => match value.checked_sub(1) {
                            Some(value) => until_id = until_id.min(value),
                            None => {
                                from_id = 1;
                                until_id = 0;
                            }
                        },
                        Ordering::Equal => {
                            from_id = from_id.max(*value);
                            until_id = until_id.min(*value);
                        }
                    }
                }
                SearchFilter::Text { .. }
                | SearchFilter::KeyValue { .. }
                | SearchFilter::Integer { .. } => {
                    has_filters = true;
                }
                filter @ (SearchFilter::Not | SearchFilter::DocumentSet(_)) => {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details(format_compact!(
                            "Unsupported global query filter {filter:?}"
                        )));
                }
            }
        }

        if from_id > until_id {
            return Ok(RoaringTreemap::new());
        }

        let mut ctx = GlobalContext {
            store: self,
            index: query.index,
            from_block: (from_id >> GLOBAL_BUCKET_SHIFT) as u16,
            until_block: (until_id >> GLOBAL_BUCKET_SHIFT) as u16,
            terms: AHashMap::new(),
            prefixes: AHashMap::new(),
        };

        let mut results = if has_filters {
            struct State {
                op: Group,
                acc: Option<RoaringTreemap>,
            }
            let mut state = State {
                op: Group::And,
                acc: None,
            };
            let mut stack = Vec::new();
            let mut skip_depth: Option<usize> = None;

            for filter in query.filters {
                let result = match filter {
                    SearchFilter::And => {
                        stack.push(state);
                        state = State {
                            op: Group::And,
                            acc: None,
                        };
                        continue;
                    }
                    SearchFilter::Or => {
                        stack.push(state);
                        state = State {
                            op: Group::Or,
                            acc: None,
                        };
                        continue;
                    }
                    SearchFilter::End => {
                        if let Some(prev_state) = stack.pop() {
                            let result = state.acc.unwrap_or_default();
                            state = prev_state;
                            if skip_depth.is_some_and(|depth| stack.len() < depth) {
                                skip_depth = None;
                            }
                            result
                        } else {
                            break;
                        }
                    }
                    SearchFilter::Integer {
                        field: SearchField::Id,
                        ..
                    } => continue,
                    filter @ (SearchFilter::Text { .. }
                    | SearchFilter::Integer { .. }
                    | SearchFilter::KeyValue { .. }) => {
                        if skip_depth.is_none() {
                            ctx.resolve(filter).await?
                        } else {
                            RoaringTreemap::new()
                        }
                    }
                    SearchFilter::Not | SearchFilter::DocumentSet(_) => unreachable!(),
                };

                match state.op {
                    Group::And => {
                        if let Some(acc) = &mut state.acc {
                            *acc &= result;
                        } else {
                            state.acc = Some(result);
                        }
                        if skip_depth.is_none() && state.acc.as_ref().unwrap().is_empty() {
                            skip_depth = Some(stack.len());
                        }
                    }
                    Group::Or => {
                        if let Some(acc) = &mut state.acc {
                            *acc |= result;
                        } else {
                            state.acc = Some(result);
                        }
                    }
                    Group::Not => unreachable!(),
                }
            }

            while let Some(mut prev_state) = stack.pop() {
                let result = state.acc.unwrap_or_default();
                match prev_state.op {
                    Group::And => {
                        if let Some(acc) = &mut prev_state.acc {
                            *acc &= result;
                        } else {
                            prev_state.acc = Some(result);
                        }
                    }
                    Group::Or => {
                        if let Some(acc) = &mut prev_state.acc {
                            *acc |= result;
                        } else {
                            prev_state.acc = Some(result);
                        }
                    }
                    Group::Not => unreachable!(),
                }
                state = prev_state;
            }

            state.acc.unwrap_or_default()
        } else {
            ctx.document_ids().await?
        };

        if from_id > 0 {
            results.remove_range(..from_id);
        }
        if until_id < u64::MAX {
            results.remove_range(until_id + 1..);
        }

        Ok(results)
    }
}

struct AccountContext<'x> {
    store: &'x Store,
    index: SearchIndex,
    account_id: u32,
    mask: &'x RoaringBitmap,
    window: Option<BlockWindow>,
    terms: AHashMap<Probe, RoaringBitmap>,
    prefixes: AHashMap<Probe, RoaringBitmap>,
}

struct BlockWindow {
    runs: Vec<(u16, u16)>,
}

impl BlockWindow {
    fn new(masked: &RoaringBitmap, mask_blocks: usize) -> Option<Self> {
        let mut runs: Vec<(u16, u16)> = Vec::new();
        let mut window_blocks = 0;
        for block in blocks(masked) {
            window_blocks += 1;
            if let Some((_, last)) = runs.last_mut()
                && last.checked_add(1) == Some(block)
            {
                *last = block;
            } else if runs.len() == MAX_WINDOW_RUNS {
                return None;
            } else {
                runs.push((block, block));
            }
        }
        (window_blocks < mask_blocks).then_some(BlockWindow { runs })
    }
}

fn blocks(documents: &RoaringBitmap) -> impl Iterator<Item = u16> + '_ {
    let mut documents = documents.iter();
    let mut exhausted = false;
    iter::from_fn(move || {
        if exhausted {
            return None;
        }
        let block = documents.next()? >> ACCOUNT_BLOCK_SHIFT;
        match (block + 1).checked_mul(1 << ACCOUNT_BLOCK_SHIFT) {
            Some(next_block) => documents.advance_to(next_block),
            None => exhausted = true,
        }
        Some(block as u16)
    })
}

struct PhraseCheck {
    leaf: usize,
    field: u8,
    words: Vec<CheekyHash>,
    candidates: RoaringBitmap,
    matched: RoaringBitmap,
}

fn probe_order(index: SearchIndex, probe: &Probe) -> (u8, &[u8], usize, u8) {
    (
        index.term_group(probe.0),
        probe.1.as_key(),
        probe.1.len(),
        probe.0,
    )
}

fn is_stem_term_of(stem: &CheekyHash, word: &CheekyHash) -> bool {
    stem.len() == word.len() + 1
        && stem.len() <= CheekyHash::HASH_SIZE
        && stem
            .as_key()
            .strip_suffix(b"*")
            .is_some_and(|stem| stem == word.as_key())
}

fn into_disjoint(ranges: &mut Vec<IterateParams<AnyKey<Vec<u8>>>>) {
    ranges.sort_unstable_by(|a, b| a.begin.key.cmp(&b.begin.key));
    ranges.dedup_by(|next, kept| {
        if next.begin.key <= kept.end.key {
            if next.end.key > kept.end.key {
                mem::swap(&mut kept.end, &mut next.end);
            }
            true
        } else {
            false
        }
    });
}

struct TermRanges {
    index: SearchIndex,
    account_id: u32,
}

type TermRange = IterateParams<AnyKey<Vec<u8>>>;

impl TermRanges {
    fn same_term(&self, a: &Probe, b: &Probe) -> bool {
        a.1 == b.1 && self.index.term_group(a.0) == self.index.term_group(b.0)
    }

    fn windowed(&self, wanted: &[Probe], window: &BlockWindow, ranges: &mut Vec<TermRange>) {
        for (field, term) in wanted {
            for (from_block, until_block) in &window.runs {
                let (begin, end) = if from_block == until_block {
                    let key = codec::account_term_block_key(
                        self.index,
                        self.account_id,
                        *field,
                        term,
                        *from_block,
                    );
                    (key.clone(), key)
                } else {
                    codec::account_term_block_range(
                        self.index,
                        self.account_id,
                        *field,
                        term,
                        *from_block,
                        *until_block,
                    )
                };
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
            }
        }
    }

    fn full(&self, leaves: &[Leaf], wanted: &[Probe], ranges: &mut Vec<TermRange>) {
        let wide = self.wide_terms(leaves, wanted);
        let mut all_fields_term: Option<(u8, CheekyHash)> = None;
        for run in wanted.chunk_by(|a, b| self.same_term(a, b)) {
            let Some((field, term)) = run.first().copied() else {
                continue;
            };
            let group = self.index.term_group(field);
            if !wide.contains(&(group, term)) {
                all_fields_term = None;
                for (field, term) in run {
                    let (begin, end) =
                        codec::account_term_range(self.index, self.account_id, *field, term);
                    ranges.push(IterateParams::new(
                        codec::term_key(begin),
                        codec::term_key(end),
                    ));
                }
                continue;
            }
            let first = match all_fields_term {
                Some((previous_group, previous))
                    if previous_group == group && is_stem_term_of(&term, &previous) =>
                {
                    ranges.pop();
                    previous
                }
                _ => term,
            };
            let (begin, end) =
                codec::account_terms_range(self.index, self.account_id, group, &first, &term);
            ranges.push(IterateParams::new(
                codec::term_key(begin),
                codec::term_key(end),
            ));
            all_fields_term = Some((group, term));
        }
    }

    fn wide_terms(&self, leaves: &[Leaf], wanted: &[Probe]) -> AHashSet<(u8, CheekyHash)> {
        let text_fields = self.index.group_fields(TERM_GROUP_TEXT);
        let key_value_fields = self.index.group_fields(TERM_GROUP_KEY_VALUE);
        let mut wide = AHashSet::new();
        for run in wanted.chunk_by(|a, b| self.same_term(a, b)) {
            let Some((field, term)) = run.first() else {
                continue;
            };
            let group = self.index.term_group(*field);
            let group_fields = match group {
                TERM_GROUP_TEXT => text_fields,
                _ => key_value_fields,
            };
            let fields = run
                .iter()
                .fold(0u32, |fields, (field, _)| fields | (1 << field));
            if fields == group_fields {
                wide.insert((group, *term));
            }
        }
        if !wide.is_empty() {
            for leaf in leaves {
                if let Leaf::Groups { field, groups } = leaf {
                    let group = self.index.term_group(*field);
                    for [word, variants @ ..] in groups {
                        if word.is_some_and(|word| wide.contains(&(group, word))) {
                            wide.extend(variants.iter().flatten().map(|variant| (group, *variant)));
                        }
                    }
                }
            }
        }
        wide
    }
}

impl AccountContext<'_> {
    async fn prefetch(&mut self, leaves: &[Leaf]) -> trc::Result<()> {
        let mut probes = AHashSet::new();
        let mut prefixes = Vec::new();
        for leaf in leaves {
            leaf.add_probes(&mut probes);
            if let Leaf::Prefix { field, prefix } = leaf
                && !prefixes.iter().any(|(other_field, other): &(u8, &[u8])| {
                    other_field == field && *other == &prefix[..]
                })
            {
                prefixes.push((*field, &prefix[..]));
            }
        }
        self.fetch(leaves, probes, &prefixes).await
    }

    fn evaluate(&self, leaf: Leaf) -> trc::Result<RoaringBitmap> {
        match leaf {
            Leaf::Empty => Ok(RoaringBitmap::new()),
            Leaf::Groups { field, groups } => {
                let mut result: Option<RoaringBitmap> = None;
                for group in &groups {
                    let mut matches = RoaringBitmap::new();
                    for hash in group.iter().flatten() {
                        if let Some(bitmap) = self.terms.get(&(field, *hash)) {
                            matches |= bitmap;
                        }
                    }
                    let result = match &mut result {
                        Some(result) => {
                            *result &= matches;
                            result
                        }
                        None => result.insert(matches),
                    };
                    if result.is_empty() {
                        return Ok(RoaringBitmap::new());
                    }
                }
                Ok(result.unwrap_or_default())
            }
            Leaf::Terms { field, terms } => Ok(self.intersect(field, &terms)),
            Leaf::Prefix { field, prefix } => Ok(self
                .prefixes
                .get(&(field, CheekyHash::new(&prefix)))
                .cloned()
                .unwrap_or_default()),
            Leaf::Resolved(bitmap) => Ok(bitmap),
            Leaf::Phrase { .. } => Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Unverified phrase")),
            Leaf::UnsupportedRange => Err(trc::StoreEvent::NotSupported
                .into_err()
                .details("Integer range filters are not supported")),
        }
    }

    fn intersect(&self, field: u8, terms: &[CheekyHash]) -> RoaringBitmap {
        let Some((first, rest)) = terms.split_first() else {
            return RoaringBitmap::new();
        };
        let Some(first) = self
            .terms
            .get(&(field, *first))
            .filter(|first| !first.is_empty())
        else {
            return RoaringBitmap::new();
        };
        let mut result: Option<RoaringBitmap> = None;
        for term in rest {
            let Some(matches) = self.terms.get(&(field, *term)) else {
                return RoaringBitmap::new();
            };
            let result = match &mut result {
                Some(result) => {
                    *result &= matches;
                    result
                }
                None => result.insert(first & matches),
            };
            if result.is_empty() {
                return RoaringBitmap::new();
            }
        }
        result.unwrap_or_else(|| first.clone())
    }

    async fn verify_phrases(&self, leaves: &mut [Leaf]) -> trc::Result<()> {
        let mut checks = Vec::new();
        let mut documents = RoaringBitmap::new();
        for (index, leaf) in leaves.iter_mut().enumerate() {
            if let Leaf::Phrase { field, words } = leaf {
                let mut candidates = self.intersect(*field, words);
                candidates &= self.mask;
                if candidates.is_empty() {
                    *leaf = Leaf::Resolved(candidates);
                } else {
                    documents |= &candidates;
                    checks.push(PhraseCheck {
                        leaf: index,
                        field: *field,
                        words: mem::take(words),
                        candidates,
                        matched: RoaringBitmap::new(),
                    });
                }
            }
        }
        if checks.is_empty() {
            return Ok(());
        }

        let mut ordinals = Vec::new();
        let mut failure = Vec::new();
        let mut scratch = Vec::new();
        let mut documents = documents.iter().peekable();
        while documents.peek().is_some() {
            let ranges = documents
                .by_ref()
                .take(PHRASE_DOCUMENT_BATCH)
                .map(|document_id| {
                    let key = codec::account_document_key(self.index, self.account_id, document_id);
                    IterateParams::new(codec::document_key(key.clone()), codec::document_key(key))
                })
                .collect::<Vec<_>>();
            let mut corrupted = None;

            self.store
                .iterate_many(ranges, |key, value| {
                    let verified = key
                        .get(key.len().wrapping_sub(U32_LEN)..)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u32::from_be_bytes)
                        .zip(codec::read_document(value, &mut scratch))
                        .and_then(|(document_id, document)| {
                            for check in checks
                                .iter_mut()
                                .filter(|check| check.candidates.contains(document_id))
                            {
                                if matches_phrase(
                                    document,
                                    check.field,
                                    &check.words,
                                    &mut ordinals,
                                    &mut failure,
                                )? {
                                    check.matched.insert(document_id);
                                }
                            }
                            Some(())
                        });
                    if verified.is_some() {
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        Ok(false)
                    }
                })
                .await?;

            if let Some(err) = corrupted {
                return Err(err);
            }
        }

        for check in checks {
            if let Some(leaf) = leaves.get_mut(check.leaf) {
                *leaf = Leaf::Resolved(check.matched);
            }
        }
        Ok(())
    }

    async fn fetch(
        &mut self,
        leaves: &[Leaf],
        mut probes: AHashSet<Probe>,
        prefixes: &[(u8, &[u8])],
    ) -> trc::Result<()> {
        let index = self.index;
        probes.retain(|probe| !self.terms.contains_key(probe));
        let mut wanted = Vec::with_capacity(probes.len());
        for probe in &probes {
            self.terms.insert(*probe, RoaringBitmap::new());
            wanted.push(*probe);
        }
        wanted.sort_unstable_by(|a, b| probe_order(index, a).cmp(&probe_order(index, b)));

        let mut ranges = Vec::with_capacity(wanted.len() + prefixes.len());
        let planner = TermRanges {
            index,
            account_id: self.account_id,
        };
        match &self.window {
            Some(window) => planner.windowed(&wanted, window, &mut ranges),
            None => planner.full(leaves, &wanted, &mut ranges),
        }
        let mut fetch_prefixes = Vec::new();
        for (field, prefix) in prefixes {
            let cache_key = (*field, CheekyHash::new(prefix));
            if !self.prefixes.contains_key(&cache_key) {
                let (begin, end) = codec::account_term_prefix_range(
                    index,
                    self.account_id,
                    index.term_group(*field),
                    prefix,
                );
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                fetch_prefixes.push((*field, *prefix, cache_key, RoaringBitmap::new()));
            }
        }
        if ranges.is_empty() {
            return Ok(());
        }
        into_disjoint(&mut ranges);

        let terms = &mut self.terms;
        let mut corrupted = None;

        self.store
            .iterate_many(ranges, |key, value| {
                let Some((hash, parsed)) = codec::parse_account_term_key(key).and_then(|parsed| {
                    CheekyHash::from_key_bytes(parsed.term, parsed.len).map(|hash| (hash, parsed))
                }) else {
                    corrupted = Some(trc::Error::corrupted_key(
                        key,
                        Some(value),
                        trc::location!(),
                    ));
                    return Ok(false);
                };
                let field = parsed.field;

                let probe = (field, hash);
                let is_probe = probes.contains(&probe);
                let is_prefix_term = parsed.len as usize <= CheekyHash::HASH_SIZE
                    && parsed.term.last() != Some(&b'*');
                let mut prefix_matches = fetch_prefixes
                    .iter_mut()
                    .filter(|(prefix_field, prefix, _, _)| {
                        is_prefix_term && *prefix_field == field && parsed.term.starts_with(prefix)
                    })
                    .peekable();

                if is_probe || prefix_matches.peek().is_some() {
                    match LazyBitmap::deserialize_delta(
                        value,
                        (parsed.block_id as u32) << ACCOUNT_BLOCK_SHIFT,
                    ) {
                        Ok(bitmap) => {
                            for (_, _, _, matches) in prefix_matches {
                                *matches |= &bitmap.0;
                            }
                            if is_probe && let Some(term) = terms.get_mut(&probe) {
                                *term |= bitmap.0;
                            }
                        }
                        Err(err) => {
                            corrupted = Some(err);
                            return Ok(false);
                        }
                    }
                }

                Ok(true)
            })
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        for (_, _, cache_key, matches) in fetch_prefixes {
            self.prefixes.insert(cache_key, matches);
        }

        Ok(())
    }
}

struct GlobalContext<'x> {
    store: &'x Store,
    index: SearchIndex,
    from_block: u16,
    until_block: u16,
    terms: AHashMap<(u8, CheekyHash), RoaringTreemap>,
    prefixes: AHashMap<(u8, CheekyHash), RoaringTreemap>,
}

impl GlobalContext<'_> {
    async fn resolve(&mut self, filter: SearchFilter) -> trc::Result<RoaringTreemap> {
        match filter {
            SearchFilter::Text {
                field,
                op,
                value,
                language,
            } => {
                let field = field.u8_id();
                match op {
                    TextMatch::Exact | TextMatch::Standard => {
                        let mut probes = Vec::new();
                        tokenize(&value, language, |token| {
                            probes.push((field, CheekyHash::new(token.word.as_bytes())));
                            true
                        });
                        if probes.is_empty() {
                            return Ok(RoaringTreemap::new());
                        }
                        self.fetch(probes.iter().copied(), None).await?;
                        Ok(self.intersect(probes.iter().copied()))
                    }
                    TextMatch::Prefix => {
                        let prefix = single_term_prefix(&value);
                        let prefix = prefix.as_bytes();
                        if prefix.is_empty() || prefix.len() > CheekyHash::HASH_SIZE {
                            return Ok(RoaringTreemap::new());
                        }
                        self.fetch(std::iter::empty(), Some((field, prefix)))
                            .await?;
                        Ok(self.prefix(field, prefix).clone())
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if op == Ordering::Equal {
                    let probe = (field.u8_id(), integer_term(value));
                    self.fetch(std::iter::once(probe), None).await?;
                    Ok(self.term(&probe).clone())
                } else {
                    Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Integer range filters are not supported"))
                }
            }
            SearchFilter::KeyValue { field, key, op } => {
                let field = field.u8_id();
                let key = key
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .map(|ch| ch.to_ascii_lowercase())
                    .collect::<String>();
                let value = match &op {
                    KeyValueMatch::Equals(value) | KeyValueMatch::Contains(value) => value.as_str(),
                    KeyValueMatch::Exists => "",
                };
                let mut probes = Vec::new();
                let mut buf = String::new();
                tokenize(value, Language::None, |token| {
                    probes.push((field, key_value_term(&key, &token.word, &mut buf)));
                    true
                });
                if probes.is_empty() {
                    let probe = (field, CheekyHash::new(key.as_bytes()));
                    self.fetch(std::iter::once(probe), None).await?;
                    return Ok(self.term(&probe).clone());
                }
                self.fetch(probes.iter().copied(), None).await?;
                Ok(self.intersect(probes.iter().copied()))
            }
            _ => unreachable!(),
        }
    }

    fn intersect(&self, mut probes: impl Iterator<Item = (u8, CheekyHash)>) -> RoaringTreemap {
        let Some(first) = probes.next() else {
            return RoaringTreemap::new();
        };
        let first = self.term(&first);
        if first.is_empty() {
            return RoaringTreemap::new();
        }
        let mut result: Option<RoaringTreemap> = None;
        for probe in probes {
            let matches = self.term(&probe);
            if let Some(result) = &mut result {
                *result &= matches;
            } else {
                result = Some(first & matches);
            }
            if result.as_ref().unwrap().is_empty() {
                return RoaringTreemap::new();
            }
        }
        result.unwrap_or_else(|| first.clone())
    }

    async fn fetch(
        &mut self,
        probes: impl Iterator<Item = (u8, CheekyHash)>,
        prefix: Option<(u8, &[u8])>,
    ) -> trc::Result<()> {
        let mut ranges = Vec::new();
        let mut fetch_probes: AHashSet<(u8, CheekyHash)> = AHashSet::new();
        for probe in probes {
            if !self.terms.contains_key(&probe) && fetch_probes.insert(probe) {
                let (begin, end) = codec::global_term_block_range(
                    self.index,
                    probe.0,
                    &probe.1,
                    self.from_block,
                    self.until_block,
                );
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                self.terms.insert(probe, RoaringTreemap::new());
            }
        }
        let mut fetch_prefix = None;
        if let Some((field, prefix)) = prefix {
            let cache_key = (field, CheekyHash::new(prefix));
            if !self.prefixes.contains_key(&cache_key) {
                let (begin, end) = codec::global_term_prefix_range(self.index, field, prefix);
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                fetch_prefix = Some((field, prefix, cache_key));
            }
        }
        if ranges.is_empty() {
            return Ok(());
        }
        into_disjoint(&mut ranges);

        let mut prefix_matches = RoaringTreemap::new();
        let terms = &mut self.terms;
        let mut corrupted = None;

        self.store
            .iterate_many(ranges, |key, value| {
                let Some((field, hash, parsed)) = key
                    .get(codec::GLOBAL_TERM_BASE_LEN - 1)
                    .copied()
                    .zip(codec::parse_prefix_key(
                        key,
                        codec::GLOBAL_TERM_BASE_LEN,
                        U16_LEN,
                    ))
                    .and_then(|(field, parsed)| {
                        CheekyHash::from_key_bytes(parsed.term, parsed.len)
                            .map(|hash| (field, hash, parsed))
                    })
                else {
                    corrupted = Some(trc::Error::corrupted_key(
                        key,
                        Some(value),
                        trc::location!(),
                    ));
                    return Ok(false);
                };

                let probe = (field, hash);
                let is_probe = fetch_probes.contains(&probe);
                let has_prefix = fetch_prefix.is_some_and(|(prefix_field, prefix, _)| {
                    prefix_field == field
                        && parsed.len as usize <= CheekyHash::HASH_SIZE
                        && parsed.term.last() != Some(&b'*')
                        && parsed.term.starts_with(prefix)
                });

                if is_probe || has_prefix {
                    match LazyTreemap::deserialize_delta(
                        value,
                        (parsed.block_id as u64) << GLOBAL_BUCKET_SHIFT,
                    ) {
                        Ok(treemap) => {
                            if has_prefix {
                                prefix_matches |= &treemap.0;
                            }
                            if is_probe {
                                *terms.get_mut(&probe).unwrap() |= treemap.0;
                            }
                        }
                        Err(err) => {
                            corrupted = Some(err);
                            return Ok(false);
                        }
                    }
                }

                Ok(true)
            })
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        if let Some((_, _, cache_key)) = fetch_prefix {
            self.prefixes.insert(cache_key, prefix_matches);
        }

        Ok(())
    }

    async fn document_ids(&self) -> trc::Result<RoaringTreemap> {
        let (begin, end) =
            codec::global_document_id_range(self.index, self.from_block, self.until_block);
        let mut results = RoaringTreemap::new();
        let mut corrupted = None;

        self.store
            .iterate(
                IterateParams::new(codec::term_key(begin), codec::term_key(end)),
                |key, value| {
                    let decoded = codec::parse_block_id(key).and_then(|block_id| {
                        LazyTreemap::deserialize_delta(
                            value,
                            (block_id as u64) << GLOBAL_BUCKET_SHIFT,
                        )
                        .ok()
                    });
                    if let Some(treemap) = decoded {
                        results |= treemap.0;
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        Ok(false)
                    }
                },
            )
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        Ok(results)
    }

    fn term(&self, probe: &(u8, CheekyHash)) -> &RoaringTreemap {
        &self.terms[probe]
    }

    fn prefix(&self, field: u8, prefix: &[u8]) -> &RoaringTreemap {
        &self.prefixes[&(field, CheekyHash::new(prefix))]
    }
}


