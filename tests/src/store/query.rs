/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{store::deflate_test_resource, utils::server::TestServer};
use ahash::AHashSet;
use nlp::language::Language;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Instant,
};
use store::{
    SearchStore,
    ahash::AHashMap,
    rand::{self, RngExt, distr::Alphanumeric},
    roaring::RoaringBitmap,
    search::{
        EmailSearchField, IndexDocument, KeyValueMatch, SearchComparator, SearchField,
        SearchFilter, SearchQuery, SearchValue, TracingSearchField,
    },
    write::SearchIndex,
};

pub const FIELDS: [&str; 20] = [
    "id",
    "accession_number",
    "artist",
    "artistRole",
    "artistId",
    "title",
    "dateText",
    "medium",
    "creditLine",
    "year",
    "acquisitionYear",
    "dimensions",
    "width",
    "height",
    "depth",
    "units",
    "inscription",
    "thumbnailCopyright",
    "thumbnailUrl",
    "url",
];

/*
 "title", // Subject
 "year".   // ReceivedAt
 "width",  // Size
 "height", // SentAt
 "artist" // Headers
 "artistRole" // Cc
 "medium",  // From
 "creditLine" // Body
 "acquisitionYear" // Bcc
 "accession_number" // To
*/

// inbuxa: 1.0's email index holds text only. ReceivedAt, Size and SentAt
// left it (the server filters and sorts on them from the message cache and
// hands the search store document sets and ranks), so the test keeps those
// columns itself, in `Docs`, and turns them into the same sets and ranks.
#[derive(Clone, PartialEq, Eq)]
enum Column {
    Text(EmailSearchField),
    ReceivedAt,
    Size,
    SentAt,
    Skip,
}

const FIELD_MAPPINGS: [Column; 20] = [
    Column::Skip,                            // "id",
    Column::Text(EmailSearchField::To),      // "accession_number",
    Column::Text(EmailSearchField::Headers), // "artist",
    Column::Text(EmailSearchField::Cc),      // "artistRole",
    Column::Skip,                            // "artistId",
    Column::Text(EmailSearchField::Subject), // "title",
    Column::Skip,                            // "dateText",
    Column::Text(EmailSearchField::From),    // "medium",
    Column::Text(EmailSearchField::Body),    // "creditLine",
    Column::ReceivedAt,                      // "year",
    Column::Text(EmailSearchField::Bcc),     // "acquisitionYear",
    Column::Skip,                            // "dimensions",
    Column::Size,                            // "width",
    Column::SentAt,                          // "height",
    Column::Skip,                            // "depth",
    Column::Skip,                            // "units",
    Column::Skip,                            // "inscription",
    Column::Skip,                            // "thumbnailCopyright",
    Column::Skip,                            // "thumbnailUrl",
    Column::Skip,                            // "url",
];

/// The sortable columns of one test document.
#[derive(Debug, Default, Clone)]
struct Doc {
    from: String,
    to: String,
    cc: String,
    bcc: String,
    received_at: u64,
    size: u64,
    sent_at: u64,
}

#[derive(Default)]
struct Docs(AHashMap<u32, Doc>);

impl Docs {
    fn to(&self, document_id: u32) -> &str {
        &self.0.get(&document_id).unwrap().to
    }

    /// The documents a cache-side filter would pass to the search store.
    fn matching(&self, filter: impl Fn(&Doc) -> bool) -> SearchFilter {
        SearchFilter::is_in_set(
            self.0
                .iter()
                .filter(|(_, doc)| filter(doc))
                .map(|(document_id, _)| *document_id)
                .collect(),
        )
    }

    /// A cache-side sort, as dense ranks of the column.
    fn sort<K: Ord>(&self, key: impl Fn(&Doc) -> K, ascending: bool) -> SearchComparator {
        let mut sorted = self
            .0
            .iter()
            .map(|(document_id, doc)| (key(doc), *document_id))
            .collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let mut ranks = AHashMap::with_capacity(sorted.len());
        let mut rank = 0u32;
        let mut prev: Option<&K> = None;
        for (value, document_id) in &sorted {
            if prev.is_none_or(|prev| prev != value) {
                rank += 1;
            }
            ranks.insert(*document_id, rank);
            prev = Some(value);
        }

        SearchComparator::sorted_set(ranks, ascending)
    }
}

/// `field >= value`, which 1.0's integer filters spell as `>` or `=`.
fn integer_ge(field: impl Into<SearchField>, value: impl Into<u64>) -> Vec<SearchFilter> {
    let field = field.into();
    let value = value.into();
    vec![
        SearchFilter::Or,
        SearchFilter::integer_gt(field.clone(), value),
        SearchFilter::integer_eq(field, value),
        SearchFilter::End,
    ]
}

// inbuxa: 1.0's global search takes Id filters only as conjunctions (no Or
// group), so ">= value" becomes "> value - 1", or "< i64::MAX" for 0 (the
// SQL backends store ids as BIGINT).
fn id_ge(value: u64) -> SearchFilter {
    match value.checked_sub(1) {
        Some(prev) => SearchFilter::integer_gt(SearchField::Id, prev),
        None => SearchFilter::integer_lt(SearchField::Id, i64::MAX as u64),
    }
}

// inbuxa: 1.0's built-in index drops an account's documents by range; the
// other backends take a query.
async fn unindex_account(store: &SearchStore, index: SearchIndex, account_id: u32) {
    if let Some(internal) = store.internal_fts() {
        internal.unindex_account(index, account_id).await.unwrap();
    } else {
        store
            .unindex(
                SearchQuery::new(index)
                    .with_filter(SearchFilter::integer_eq(SearchField::AccountId, account_id)),
            )
            .await
            .unwrap();
    }
}

const ALL_IDS: &[&str] = &[
    "p11293", "p79426", "p79427", "p79428", "p79429", "p79430", "d05503", "d00399", "d05352",
    "p01764", "t05843", "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721",
    "n04739", "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
    "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155", "ar00039",
    "t12600", "p80203", "t13209", "t13560", "t13561", "t13655", "t13811", "p13352", "p13351",
    "p13350", "p13349", "p13348", "p13347", "p13346", "p13345", "p13344", "p13342", "p13341",
    "p13340", "p13339", "p13338", "p13337", "p13336", "p13335", "p13334", "p13333", "p13332",
    "p13331", "p13330", "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323",
    "t13786", "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
    "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444", "ar01154",
    "ar01153", "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
    "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855", "t01355",
    "t12800", "t12557", "t02078", "ar00052", "ar00627", "t00352", "t07275", "t12318", "t04931",
    "t13683", "t13686", "t13687", "t13688", "t13689", "t13690", "t13691", "t13769", "t13773",
    "t07151", "t13684", "t07523", "t12369", "t12567", "ar00627", "ar00052", "t00352", "t07275",
    "t12318", "t04931", "t13683", "t13686", "t13687", "t13688", "t13689", "t13690", "t13691",
    "t07766", "t07918", "t12993", "ar00044", "t13326", "t07614", "t12414",
];

#[allow(clippy::mutex_atomic)]
pub async fn test(test: &TestServer) {
    let store = test.server.search_store().clone();
    println!("Running Store query tests...");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    let now = Instant::now();
    let documents = Arc::new(Mutex::new(Vec::new()));
    let mut mask = RoaringBitmap::new();
    let mut docs = Docs::default();

    // Global ids test
    println!("Running global id filtering tests...");
    test_global(store.clone()).await;

    // inbuxa: trace documents as the index task builds them
    println!("Running trace document tests...");
    test_trace_documents(store.clone()).await;

    // inbuxa: address fields match by full address, local part, domain and
    // display name on every backend
    println!("Running address search tests...");
    test_address_search(store.clone()).await;

    // inbuxa: words inside URLs, host names and file names in body text
    // are found on every backend
    println!("Running URL word search tests...");
    test_url_word_search(store.clone()).await;

    // Large document insert test
    println!("Running large document insert tests...");
    let mut large_text = String::with_capacity(20 * 1024 * 1024);
    while large_text.len() < 20 * 1024 * 1024 {
        let word = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(rand::rng().random_range(3..10))
            .map(char::from)
            .collect::<String>();
        large_text.push_str(&word);
        large_text.push(' ');
    }
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(1)
        .with_document_id(1);
    for field in [
        EmailSearchField::From,
        EmailSearchField::To,
        EmailSearchField::Cc,
        EmailSearchField::Bcc,
        EmailSearchField::Subject,
    ] {
        document.index_text(field, &large_text[..10 * 1024], Language::English);
    }
    for field in [EmailSearchField::Body, EmailSearchField::Attachment] {
        document.index_text(field, &large_text, Language::English);
    }
    store.index(vec![document]).await.unwrap();
    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    println!("Running account filtering tests...");
    let filter_ids = std::env::var("QUICK_TEST").is_ok().then(|| {
        let mut ids = AHashSet::new();
        for &id in ALL_IDS {
            ids.insert(id.to_string());
            let id = id.as_bytes();
            if id.last().unwrap() > &b'0' {
                let mut alt_id = id.to_vec();
                *alt_id.last_mut().unwrap() -= 1;
                ids.insert(String::from_utf8(alt_id).unwrap());
            }
            if id.last().unwrap() < &b'9' {
                let mut alt_id = id.to_vec();
                *alt_id.last_mut().unwrap() += 1;
                ids.insert(String::from_utf8(alt_id).unwrap());
            }
        }

        ids
    });

    pool.scope_fifo(|s| {
        for (document_id, record) in csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(&deflate_test_resource("artwork_data.csv.gz")[..])
            .records()
            .enumerate()
        {
            let record = record.unwrap();
            let documents = documents.clone();

            if let Some(filter_ids) = &filter_ids {
                let id = record.get(1).unwrap().to_lowercase();
                if !filter_ids.contains(&id) {
                    continue;
                }
            }

            s.spawn_fifo(move |_| {
                let mut document = IndexDocument::new(SearchIndex::Email)
                    .with_account_id(0)
                    .with_document_id(document_id as u32);
                let mut doc = Doc::default();
                for (pos, field) in record.iter().enumerate() {
                    match &FIELD_MAPPINGS[pos] {
                        Column::Text(
                            text_field @ (EmailSearchField::From
                            | EmailSearchField::To
                            | EmailSearchField::Cc
                            | EmailSearchField::Bcc),
                        ) => {
                            let value = field.to_lowercase();
                            document.index_text(text_field.clone(), &value, Language::None);
                            *match text_field {
                                EmailSearchField::From => &mut doc.from,
                                EmailSearchField::To => &mut doc.to,
                                EmailSearchField::Cc => &mut doc.cc,
                                _ => &mut doc.bcc,
                            } = value;
                        }
                        Column::Text(
                            text_field @ (EmailSearchField::Subject
                            | EmailSearchField::Body
                            | EmailSearchField::Attachment),
                        ) => {
                            document.index_text(
                                text_field.clone(),
                                &field
                                    .replace(|ch: char| !ch.is_alphanumeric(), " ")
                                    .to_lowercase(),
                                Language::English,
                            );
                        }
                        Column::Text(EmailSearchField::Headers) => {
                            document.insert_key_value(
                                EmailSearchField::Headers,
                                "artist",
                                field.to_lowercase(),
                            );
                        }
                        Column::ReceivedAt => {
                            doc.received_at = field.parse::<u64>().unwrap_or(0);
                        }
                        Column::Size => {
                            doc.size = field.parse::<u64>().unwrap_or(0);
                        }
                        Column::SentAt => {
                            doc.sent_at = field.parse::<u64>().unwrap_or(0);
                        }
                        Column::Skip => {
                            continue;
                        }
                    };
                }

                documents
                    .lock()
                    .unwrap()
                    .push((document_id as u32, document, doc));
            });
        }
    });

    println!(
        "Parsed {} entries in {} ms.",
        documents.lock().unwrap().len(),
        now.elapsed().as_millis()
    );

    let now = Instant::now();
    let batches = documents.lock().unwrap().drain(..).collect::<Vec<_>>();

    print!("Inserting... ",);
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    for (document_id, document, doc) in batches {
        let mut to_field = None;

        for (key, value) in document.fields() {
            if key == &SearchField::DocumentId {
                if let SearchValue::Uint(id) = value {
                    assert_eq!(*id as u32, document_id);
                }
            } else if key == &SearchField::Email(EmailSearchField::To)
                && let SearchValue::Text { value, .. } = value
            {
                to_field = Some(value.to_string());
            }
        }
        assert_eq!(to_field.unwrap(), doc.to);
        mask.insert(document_id);
        docs.0.insert(document_id, doc);

        chunk.push(document);
        if chunk.len() == 10 {
            chunks.push(chunk);
            chunk = Vec::new();
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }

    if test.is_reset() {
        let mut tasks = Vec::new();
        for chunk in chunks {
            let chunk_instance = Instant::now();
            tasks.push({
                let db = store.clone();
                tokio::spawn(async move { db.index(chunk).await })
            });

            if tasks.len() == 100 {
                for handle in tasks {
                    handle.await.unwrap().unwrap();
                }
                print!(" [{} ms]", chunk_instance.elapsed().as_millis());
                std::io::stdout().flush().unwrap();
                tasks = Vec::new();
            }
        }

        if !tasks.is_empty() {
            for handle in tasks {
                handle.await.unwrap().unwrap();
            }
        }

        // Refresh
        if let SearchStore::ElasticSearch(store) = &store {
            store.refresh_index(SearchIndex::Email).await.unwrap();
        }

        println!("\nInsert took {} ms.", now.elapsed().as_millis());
    }

    if store.internal_fts().is_none() {
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![SearchFilter::integer_eq(SearchField::AccountId, 0u32)])
                    .with_comparator(docs.sort(|doc| doc.received_at, true))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<RoaringBitmap>();
        assert_eq!(ids, mask);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![SearchFilter::integer_eq(SearchField::AccountId, 0u32)])
                    .with_filters(integer_ge(SearchField::DocumentId, 0u32))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<RoaringBitmap>();
        assert_eq!(ids, mask);
    }

    println!("Running account filter tests...");
    let now = Instant::now();
    test_filter(store.clone(), &docs, &mask).await;
    println!("Filtering took {} ms.", now.elapsed().as_millis());

    println!("Running account sort tests...");
    let now = Instant::now();
    test_sort(store.clone(), &docs, &mask).await;
    println!("Sorting took {} ms.", now.elapsed().as_millis());

    println!("Running unindex tests...");
    let now = Instant::now();
    test_unindex(store.clone(), &docs).await;
    println!("Unindexing took {} ms.", now.elapsed().as_millis());
}

async fn test_filter(store: SearchStore, docs: &Docs, mask: &RoaringBitmap) {
    let can_stem = !store.is_mysql();
    let can_negate_text = !store.is_meilisearch();

    let tests = [
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "water"),
                docs.matching(|doc| doc.received_at == 1979),
            ],
            vec!["p11293"],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
                docs.matching(|doc| doc.received_at > 2000),
                docs.matching(|doc| doc.size < 180),
                docs.matching(|doc| doc.size > 0),
            ],
            vec!["p79426", "p79427", "p79428", "p79429", "p79430"],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "'rustic bridge'"),
            ],
            vec!["d05503"],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "'rustic'"),
                SearchFilter::has_english_text(
                    EmailSearchField::Subject,
                    if can_stem { "study" } else { "studies" },
                ),
            ],
            vec!["d00399", "d05352"],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::KeyValue {
                    field: EmailSearchField::Headers.into(),
                    key: "artist".to_string(),
                    op: KeyValueMatch::Contains("kunst, mauro".to_string()),
                },
                SearchFilter::has_keyword(EmailSearchField::Cc, "artist"),
                SearchFilter::Or,
                docs.matching(|doc| doc.received_at == 1969),
                docs.matching(|doc| doc.received_at == 1971),
                SearchFilter::End,
            ],
            vec!["p01764", "t05843"],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "oil"),
                SearchFilter::End,
                SearchFilter::has_english_text(
                    EmailSearchField::Body,
                    if can_stem { "bequeath" } else { "bequeathed" },
                ),
                SearchFilter::Or,
                SearchFilter::And,
                docs.matching(|doc| doc.received_at >= 1900),
                docs.matching(|doc| doc.received_at < 1910),
                SearchFilter::End,
                SearchFilter::And,
                docs.matching(|doc| doc.received_at >= 2000),
                docs.matching(|doc| doc.received_at < 2010),
                SearchFilter::End,
                SearchFilter::End,
            ],
            vec![
                "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721", "n04739",
                "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
                "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155",
            ],
        ),
        (
            vec![
                SearchFilter::And,
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                SearchFilter::KeyValue {
                    field: EmailSearchField::Headers.into(),
                    key: "artist".to_string(),
                    op: KeyValueMatch::Contains("warhol".to_string()),
                },
                SearchFilter::Not,
                SearchFilter::has_english_text(EmailSearchField::Subject, "'campbell'"),
                SearchFilter::End,
                SearchFilter::Not,
                SearchFilter::Or,
                docs.matching(|doc| doc.received_at > 1980),
                SearchFilter::And,
                docs.matching(|doc| doc.size > 500),
                docs.matching(|doc| doc.sent_at > 500),
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::text_eq(EmailSearchField::Bcc, "2008"),
                SearchFilter::End,
            ],
            vec!["ar00039", "t12600"],
        ),
        (
            if can_stem {
                vec![
                    SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
                    SearchFilter::has_keyword(EmailSearchField::From, "paper"),
                    SearchFilter::has_english_text(EmailSearchField::Body, "'purchased'"),
                    SearchFilter::Not,
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'anatomical'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'discarded'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'untitled'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'girl'"),
                    SearchFilter::End,
                    SearchFilter::End,
                    docs.matching(|doc| doc.received_at > 1900),
                    docs.matching(|doc| doc.bcc.as_str() > "2008"),
                ]
            } else {
                vec![
                    SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "studies"),
                    SearchFilter::End,
                    SearchFilter::has_keyword(EmailSearchField::From, "paper"),
                    SearchFilter::has_english_text(EmailSearchField::Body, "'purchased'"),
                    SearchFilter::Not,
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'anatomical'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'discarded'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'untitled'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'girl'"),
                    SearchFilter::End,
                    SearchFilter::End,
                    docs.matching(|doc| doc.received_at > 1900),
                    docs.matching(|doc| doc.bcc.as_str() > "2008"),
                ]
            },
            vec!["p80203", "t13209", "t13560", "t13561"],
        ),
    ];

    for (filters, expected_results) in tests {
        if !can_negate_text && has_negated_text(&filters) {
            continue;
        }

        //println!("Running test: {:?}", filter);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparator(docs.sort(|doc| doc.to.clone(), true))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids {
            results.push(docs.to(document_id));
        }
        assert_eq!(results, expected_results);
    }
}

fn has_negated_text(filters: &[SearchFilter]) -> bool {
    let mut stack = Vec::new();
    let mut negated = 0;

    for filter in filters {
        match filter {
            SearchFilter::Not => {
                stack.push(true);
                negated += 1;
            }
            SearchFilter::And | SearchFilter::Or => {
                stack.push(false);
            }
            SearchFilter::End => {
                if stack.pop().unwrap_or(false) {
                    negated -= 1;
                }
            }
            SearchFilter::Text { .. } if negated > 0 => {
                return true;
            }
            _ => (),
        }
    }

    false
}

// inbuxa: in 1.0 the search store only filters; sorting is done on ranks the
// caller supplies (from the message cache on a real server), so the order no
// longer depends on the backend and PostgreSQL's reversed order is gone.
async fn test_sort(store: SearchStore, docs: &Docs, mask: &RoaringBitmap) {
    let tests = [
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                docs.matching(|doc| doc.received_at > 0),
                docs.matching(|doc| doc.bcc.as_str() > "0000"),
                docs.matching(|doc| doc.size > 0),
            ],
            vec![
                docs.sort(|doc| doc.received_at, false),
                docs.sort(|doc| doc.bcc.clone(), true),
                docs.sort(|doc| doc.size, true),
                docs.sort(|doc| doc.to.clone(), false),
            ],
            vec![
                "t13655", "t13811", "p13352", "p13351", "p13350", "p13349", "p13348", "p13347",
                "p13346", "p13345", "p13344", "p13342", "p13341", "p13340", "p13339", "p13338",
                "p13337", "p13336", "p13335", "p13334", "p13333", "p13332", "p13331", "p13330",
                "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323", "t13786",
                "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
                "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444",
                "ar01154", "ar01153",
            ],
        ),
        (
            vec![
                SearchFilter::integer_eq(SearchField::AccountId, 0u32),
                docs.matching(|doc| doc.size > 0),
                docs.matching(|doc| doc.sent_at > 0),
            ],
            vec![
                docs.sort(|doc| doc.size, false),
                docs.sort(|doc| doc.sent_at, true),
            ],
            vec![
                "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
                "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855",
                "t01355", "t12800", "t12557", "t02078",
            ],
        ),
        (
            vec![SearchFilter::integer_eq(SearchField::AccountId, 0u32)],
            vec![
                docs.sort(|doc| doc.from.clone(), false),
                docs.sort(|doc| doc.cc.clone(), false),
                docs.sort(|doc| doc.to.clone(), true),
            ],
            vec![
                "ar00627", "ar00052", "t00352", "t07275", "t12318", "t04931", "t13683", "t13686",
                "t13687", "t13688", "t13689", "t13690", "t13691", "t07766", "t07918", "t12993",
                "ar00044", "t13326", "t07614", "t12414",
            ],
        ),
    ];

    for (filters, comparators, expected_results) in tests {
        //println!("Running test: {:?}", sort);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids.into_iter().take(expected_results.len()) {
            results.push(docs.to(document_id));
        }
        assert_eq!(results, expected_results);
    }
}

async fn test_unindex(store: SearchStore, docs: &Docs) {
    let gelatin_filters = || {
        vec![
            SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
            docs.matching(|doc| doc.received_at > 2000),
            docs.matching(|doc| doc.size < 180),
            docs.matching(|doc| doc.size > 0),
        ]
    };
    let ids = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_mask(RoaringBitmap::from_iter(docs.0.keys().copied()))
                .with_filters(gelatin_filters())
                .with_account_id(0),
        )
        .await
        .unwrap();
    assert!(!ids.is_empty());
    let expected_count = ids.len().saturating_sub(10);

    let unindex_ids = ids.into_iter().take(10).collect::<Vec<_>>();
    if let Some(internal) = store.internal_fts() {
        // inbuxa: 1.0's built-in index has no query-based unindex; the
        // index task drops documents by id, one account at a time
        internal
            .index_account_documents(0, SearchIndex::Email, vec![], unindex_ids)
            .await
            .unwrap();
    } else {
        let mut query = SearchQuery::new(SearchIndex::Email)
            .with_account_id(0)
            .with_filter(SearchFilter::Or);
        for id in unindex_ids {
            query = query.with_filter(SearchFilter::integer_eq(SearchField::DocumentId, id));
        }
        query = query.with_filter(SearchFilter::End);

        store.unindex(query).await.unwrap();
    }

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    assert_eq!(
        store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(gelatin_filters())
                    .with_account_id(0)
                    .with_mask(RoaringBitmap::from_iter(docs.0.keys().copied())),
            )
            .await
            .unwrap()
            .len(),
        expected_count
    );
}

async fn test_global(store: SearchStore) {
    // Insert global ids
    for (id, queue_id, etyp, keywords) in [
        (0, 1000u64, 1u64, "init start"),
        (1, 1000u64, 2u64, "init complete"),
        (2, 1001u64, 1u64, "process start"),
        (3, 1001u64, 2u64, "process complete"),
        (4, 1002u64, 1u64, "cleanup start"),
        (5, 1002u64, 2u64, "cleanup complete"),
    ] {
        let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(id);
        document.index_unsigned(TracingSearchField::QueueId, queue_id);
        document.index_unsigned(TracingSearchField::EventType, etyp);
        document.index_text(TracingSearchField::Keywords, keywords, Language::None);
        store.index(vec![document]).await.unwrap();
    }

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Tracing).await.unwrap();
    }

    // Query all
    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(id_ge(0u64))
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([0, 1, 2, 3, 4, 5])
    );

    // Query with filter
    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::integer_gt(SearchField::Id, 1u64))
                    .with_filter(SearchFilter::integer_lt(SearchField::Id, 5u64))
                    .with_filter(SearchFilter::has_keyword(
                        TracingSearchField::Keywords,
                        "start",
                    )),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([2, 4])
    );

    // inbuxa: 1.0's built-in index has no query-based unindex; it drops
    // traces in whole id buckets (retention), and ids 0-5 share the first
    if let Some(internal) = store.internal_fts() {
        internal.unindex_traces(u64::MAX).await.unwrap();
        assert!(
            store
                .query_global(SearchQuery::new(SearchIndex::Tracing).with_filter(id_ge(0u64)))
                .await
                .unwrap()
                .is_empty()
        );
        return;
    }

    // Delete by filter
    store
        .unindex(
            SearchQuery::new(SearchIndex::Tracing)
                .with_filter(SearchFilter::integer_lt(SearchField::Id, 3u64)),
        )
        .await
        .unwrap();

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Tracing).await.unwrap();
    }

    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(id_ge(0u64))
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([3, 4, 5])
    );
}

// inbuxa: MON-16: documents built by the index task from stored traces go
// into every search backend (the SQL backends type etyp and qid as BIGINT)
// and are found again by queue id and keyword.
async fn test_trace_documents(store: SearchStore) {
    use registry::schema::structs::{
        Trace, TraceEvent, TraceKeyValue, TraceValue, TraceValueString, TraceValueUnsignedInt,
    };
    use services::index_queue::document::trace_search_document;
    use trc::{DeliveryEvent, EventType, Key, SmtpEvent};

    let kv_u = |key: Key, value: u64| TraceKeyValue {
        key,
        value: TraceValue::UnsignedInt(TraceValueUnsignedInt { value }),
    };
    let kv_s = |key: Key, value: &str| TraceKeyValue {
        key,
        value: TraceValue::String(TraceValueString {
            value: value.to_string(),
        }),
    };
    let event = |event: EventType, key_values: Vec<TraceKeyValue>| TraceEvent {
        event,
        key_values: key_values.into(),
        ..Default::default()
    };
    let fields = [
        TracingSearchField::EventType,
        TracingSearchField::QueueId,
        TracingSearchField::Keywords,
    ];

    // An SMTP session that queued two messages, and a delivery attempt
    let session = Trace {
        events: vec![
            event(
                EventType::Smtp(SmtpEvent::ConnectionStart),
                vec![kv_s(Key::RemoteIp, "192.0.2.7")],
            ),
            event(
                EventType::Smtp(SmtpEvent::MailFrom),
                vec![kv_s(Key::From, "Sender@Example.org")],
            ),
            event(
                EventType::Smtp(SmtpEvent::RcptTo),
                vec![
                    kv_u(Key::QueueId, 9_000_000_001),
                    kv_s(Key::To, "rcpt@example.net"),
                ],
            ),
            event(
                EventType::Smtp(SmtpEvent::RcptTo),
                vec![kv_u(Key::QueueId, 9_000_000_002)],
            ),
        ]
        .into(),
        ..Default::default()
    };
    let delivery = Trace {
        events: vec![event(
            EventType::Delivery(DeliveryEvent::AttemptStart),
            vec![
                kv_u(Key::QueueId, 9_000_000_003),
                kv_s(Key::Hostname, "relay.example.net"),
            ],
        )]
        .into(),
        ..Default::default()
    };
    let documents = vec![
        trace_search_document(100, &session, &fields),
        trace_search_document(101, &delivery, &fields),
    ];
    assert!(
        documents.iter().all(
            |d| d.has_field(&SearchField::Tracing(TracingSearchField::QueueId))
                && d.has_field(&SearchField::Tracing(TracingSearchField::EventType))
        ),
        "trace documents carry a queue id and an event type"
    );
    store.index(documents).await.unwrap();
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Tracing).await.unwrap();
    }

    let query = |filters: Vec<SearchFilter>| {
        let store = store.clone();
        async move {
            store
                .query_global(
                    SearchQuery::new(SearchIndex::Tracing)
                        .with_filter(id_ge(100u64))
                        .with_filters(filters),
                )
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>()
        }
    };
    // By queue id, the way x:Trace/query asks: the queue id column, or any
    // queue id in the keywords
    let by_queue_id = |queue_id: u64| {
        vec![
            SearchFilter::Or,
            SearchFilter::integer_eq(TracingSearchField::QueueId, queue_id),
            SearchFilter::has_text(
                TracingSearchField::Keywords,
                queue_id.to_string(),
                Language::None,
            ),
            SearchFilter::End,
        ]
    };
    assert_eq!(
        query(by_queue_id(9_000_000_001)).await,
        AHashSet::from_iter([100])
    );
    assert_eq!(
        query(by_queue_id(9_000_000_002)).await,
        AHashSet::from_iter([100])
    );
    assert_eq!(
        query(by_queue_id(9_000_000_003)).await,
        AHashSet::from_iter([101])
    );
    assert_eq!(query(by_queue_id(9_000_000_004)).await, AHashSet::new());
    assert_eq!(
        query(vec![SearchFilter::integer_eq(
            TracingSearchField::QueueId,
            9_000_000_003u64
        )])
        .await,
        AHashSet::from_iter([101])
    );
    // By opening event type
    assert_eq!(
        query(vec![SearchFilter::integer_eq(
            TracingSearchField::EventType,
            EventType::Delivery(DeliveryEvent::AttemptStart).to_id() as u64,
        )])
        .await,
        AHashSet::from_iter([101])
    );
    // By keyword: an address, lowercased, and its domain
    assert_eq!(
        query(vec![SearchFilter::has_text(
            TracingSearchField::Keywords,
            "example.org",
            Language::None,
        )])
        .await,
        AHashSet::from_iter([100])
    );
    assert_eq!(
        query(vec![SearchFilter::has_text(
            TracingSearchField::Keywords,
            "relay.example.net",
            Language::None,
        )])
        .await,
        AHashSet::from_iter([101])
    );

    // inbuxa: 1.0's built-in index drops traces only in whole id buckets
    if let Some(internal) = store.internal_fts() {
        internal.unindex_traces(u64::MAX).await.unwrap();
        return;
    }
    for id in [100u64, 101] {
        store
            .unindex(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::integer_eq(SearchField::Id, id)),
            )
            .await
            .unwrap();
    }
}

// inbuxa: the message indexer passes each display name and each address of
// From/To/Cc/Bcc as keyword text (Language::None). The built-in index splits
// that text into words, so an address is found by its full form, its local
// part, its domain or a display-name word; PostgreSQL kept the whole address
// as one token and MySQL dropped stopwords such as "com" and words under three
// characters. The expected results below are the built-in (RocksDB/SQLite)
// results and must be the same on every backend.
async fn test_address_search(store: SearchStore) {
    const ACCOUNT_ID: u32 = 7;
    let messages: [[&[(&str, &str)]; 4]; 5] = [
        // From, To, Cc, Bcc
        [
            &[("Amazon.com", "noreply@amazon.com")],
            &[("Jane Doe", "jane.doe@example.org")],
            &[],
            &[],
        ],
        [
            &[("", "shipment-tracking@amazon.com")],
            &[("", "jo@io.de")],
            &[("Jane Doe", "jane.doe@example.org")],
            &[],
        ],
        [
            &[("GitHub", "noreply@github.com")],
            &[("Jo Li", "jo@io.de")],
            &[],
            &[("Audit", "audit@example.org")],
        ],
        [
            &[("Jane Doe", "jane.doe@example.org")],
            &[("Amazon Web Services", "aws-marketing@amazon.com")],
            &[("Bob", "bob@example.net")],
            &[("", "noreply@amazon.com")],
        ],
        [
            &[("Newsletter", "news@www.example.com")],
            &[("", "undisclosed@example.org")],
            &[],
            &[],
        ],
    ];
    let fields = [
        EmailSearchField::From,
        EmailSearchField::To,
        EmailSearchField::Cc,
        EmailSearchField::Bcc,
    ];

    // inbuxa: 0.16 sorted by a received-at equal to the document id; 1.0
    // returns unsorted results in document id order, the same order.
    let mut documents = Vec::new();
    let mut mask = RoaringBitmap::new();
    for (document_id, message) in messages.iter().enumerate() {
        let mut document = IndexDocument::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_ID)
            .with_document_id(document_id as u32);
        for (field, addresses) in fields.iter().zip(message.iter()) {
            for (name, address) in addresses.iter() {
                if !name.is_empty() {
                    document.index_text(field.clone(), name, Language::None);
                }
                document.index_text(field.clone(), address, Language::None);
            }
        }
        documents.push(document);
        mask.insert(document_id as u32);
    }
    store.index(documents).await.unwrap();
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    for (field, text, expected) in [
        // full address
        (EmailSearchField::From, "noreply@amazon.com", vec![0u32]),
        (EmailSearchField::To, "jane.doe@example.org", vec![0]),
        (EmailSearchField::Cc, "jane.doe@example.org", vec![1]),
        (EmailSearchField::Bcc, "noreply@amazon.com", vec![3]),
        (EmailSearchField::To, "jo@io.de", vec![1, 2]),
        // local part
        (EmailSearchField::From, "noreply", vec![0, 2]),
        (EmailSearchField::To, "jo", vec![1, 2]),
        (EmailSearchField::Cc, "bob", vec![3]),
        (EmailSearchField::Bcc, "audit", vec![2]),
        // domain
        (EmailSearchField::From, "amazon.com", vec![0, 1]),
        (EmailSearchField::From, "amazon", vec![0, 1]),
        (EmailSearchField::To, "example.org", vec![0, 4]),
        (EmailSearchField::To, "io.de", vec![1, 2]),
        (EmailSearchField::Cc, "example.net", vec![3]),
        (EmailSearchField::Bcc, "example.org", vec![2]),
        (EmailSearchField::From, "www.example.com", vec![4]),
        (EmailSearchField::From, "com", vec![0, 1, 2, 4]),
        // display name
        (EmailSearchField::From, "Jane", vec![3]),
        (EmailSearchField::From, "jane doe", vec![3]),
        (EmailSearchField::To, "Web Services", vec![3]),
        (EmailSearchField::To, "Li", vec![2]),
        (EmailSearchField::Cc, "Doe", vec![1]),
        (EmailSearchField::Bcc, "Audit", vec![2]),
        // hyphenated local part
        (EmailSearchField::From, "shipment-tracking", vec![1]),
        (EmailSearchField::From, "tracking", vec![1]),
        // no match
        (EmailSearchField::From, "amazon.org", vec![]),
        (EmailSearchField::To, "noreply", vec![]),
        (EmailSearchField::Bcc, "jane", vec![]),
    ] {
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![
                        SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_ID),
                        SearchFilter::has_keyword(field.clone(), text),
                    ])
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();
        assert_eq!(ids, expected, "{field:?} {text:?}");
    }

    // TEXT-style search across all address fields
    let ids = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_filters(vec![
                    SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_ID),
                    SearchFilter::Or,
                    SearchFilter::has_keyword(EmailSearchField::From, "example.org"),
                    SearchFilter::has_keyword(EmailSearchField::To, "example.org"),
                    SearchFilter::has_keyword(EmailSearchField::Cc, "example.org"),
                    SearchFilter::has_keyword(EmailSearchField::Bcc, "example.org"),
                    SearchFilter::End,
                ])
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(ids, vec![0, 1, 2, 3, 4]);

    unindex_account(&store, SearchIndex::Email, ACCOUNT_ID).await;
}

async fn test_url_word_search(store: SearchStore) {
    const ACCOUNT_ID: u32 = 8;
    let bodies = [
        "Track your parcel here: https://x.example/shipping-support/ and reply.",
        "Reset it at https://mail.example.com/login/?password=reset&user=jane now.",
        "Attached is invoice-2024.pdf for your records.",
        "Shipping was fast, thanks again.",
        "Nothing to see at www.example.org/about-us, really.",
    ];

    let mut documents = Vec::new();
    let mut mask = RoaringBitmap::new();
    for (document_id, body) in bodies.iter().enumerate() {
        let mut document = IndexDocument::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_ID)
            .with_document_id(document_id as u32);
        document.index_text(EmailSearchField::Body, body, Language::English);
        documents.push(document);
        mask.insert(document_id as u32);
    }
    store.index(documents).await.unwrap();
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    for (text, expected) in [
        // only inside a URL path, a query string or a file name
        ("shipping", vec![0u32, 3]),
        ("support", vec![0]),
        ("password", vec![1]),
        ("login", vec![1]),
        ("jane", vec![1]),
        ("invoice", vec![2]),
        ("pdf", vec![2]),
        ("2024", vec![2]),
        // host names
        ("example", vec![0, 1, 4]),
        ("mail", vec![1]),
        // written as they appear
        ("https://x.example/shipping-support/", vec![0]),
        ("shipping-support", vec![0]),
        ("invoice-2024.pdf", vec![2]),
        ("mail.example.com", vec![1]),
        // plain words are unaffected
        ("parcel", vec![0]),
        ("records", vec![2]),
        ("thanks", vec![3]),
        // no match
        ("billing", vec![]),
        ("example.net", vec![]),
    ] {
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![
                        SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_ID),
                        SearchFilter::has_english_text(EmailSearchField::Body, text),
                    ])
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();
        assert_eq!(ids, expected, "Body {text:?}");
    }

    unindex_account(&store, SearchIndex::Email, ACCOUNT_ID).await;
}
