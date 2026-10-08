/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    backend::{
        MAX_TOKEN_LENGTH,
        postgres::{
            DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, PostgresStore, PsqlSearchField, bounded,
            into_error, into_pool_error, is_timeout_error,
        },
    },
    search::{
        IndexDocument, SearchComparator, SearchDocumentId, SearchField, SearchFilter,
        SearchOperator, SearchQuery, SearchValue,
    },
    write::SearchIndex,
};
use nlp::{language::Language, tokenizers::space::SpaceTokenizer};
use std::fmt::Write;
use tokio_postgres::{
    IsolationLevel,
    types::{FromSql, ToSql, Type, WrongType},
};

impl PostgresStore {
    fn ts_config(&self, language: &Language) -> &'static str {
        pg_lang(language)
            .filter(|config| self.ts_configs.contains(config))
            .unwrap_or(PG_UNSTEMMED_LANG)
    }

    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let trx = conn
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .start()
                .await
                .map_err(into_error)?;

            for document in documents {
                let index = document.index;
                let primary_keys = index.primary_keys();
                let all_fields = index.all_fields();
                let fields = document.fields;
                // inbuxa: keyword text (addresses, contact fields, ...) is split into
                // words before it reaches the text parser, see keyword_terms();
                // language text gets the words inside its URLs, host names and
                // file names added, see url_terms().
                let keywords = primary_keys
                    .iter()
                    .chain(all_fields)
                    .map(|field| match fields.get(field) {
                        Some(SearchValue::Text {
                            value,
                            language: Language::None,
                        }) if field.is_text() => Some(keyword_terms(value)),
                        Some(SearchValue::Text { value, .. }) if field.is_text() => {
                            url_terms(value)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let mut values = Vec::with_capacity(fields.len() + 2);
                let mut query = format!("INSERT INTO {} (", index.psql_table());

                for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                    if i > 0 {
                        query.push(',');
                    }
                    query.push_str(field.column());

                    if let Some(sort_column) = field.sort_column() {
                        query.push(',');
                        query.push_str(sort_column);
                    }
                }

                query.push_str(") VALUES (");

                for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                    if i > 0 {
                        query.push(',');
                    }

                    if let Some(value) = fields.get(field) {
                        let value_ref = format!("${}", values.len() + 1);
                        let (text_len, language) =
                            if let SearchValue::Text { value, language } = value {
                                (value.len(), self.ts_config(language))
                            } else {
                                (0, PG_UNSTEMMED_LANG)
                            };

                        if let Some(keywords) = &keywords[i] {
                            let _ = write!(&mut query, "to_tsvector('{language}',{value_ref})");
                            values.push(keywords as &(dyn ToSql + Sync));
                            if field.sort_column().is_some() {
                                let value_ref = format!("${}", values.len() + 1);
                                if text_len > 255 {
                                    let _ = write!(&mut query, ",left({value_ref},255)");
                                } else {
                                    let _ = write!(&mut query, ",{value_ref}");
                                }
                                values.push(value as &(dyn ToSql + Sync));
                            }
                            continue;
                        } else if field.is_text() {
                            let _ = write!(&mut query, "to_tsvector('{language}',{value_ref})");
                        } else if text_len > 512 {
                            query.push_str("left(");
                            query.push_str(&value_ref);
                            query.push_str(",512)");
                        } else {
                            query.push_str(&value_ref);
                        }

                        if field.sort_column().is_some() {
                            if text_len > 255 {
                                query.push_str(",left(");
                                query.push_str(&value_ref);
                                query.push_str(",255)");
                            } else {
                                query.push(',');
                                query.push_str(&value_ref);
                            }
                        }

                        values.push(value as &(dyn ToSql + Sync));
                    } else {
                        query.push_str("NULL");
                        if field.sort_column().is_some() {
                            query.push_str(",NULL");
                        }
                    }
                }

                query.push_str(") ON CONFLICT (");
                for (i, pkey) in primary_keys.iter().enumerate() {
                    if i > 0 {
                        query.push(',');
                    }
                    query.push_str(pkey.column());
                }
                query.push_str(") DO UPDATE SET ");
                for (i, field) in all_fields.iter().enumerate() {
                    if i > 0 {
                        query.push(',');
                    }
                    let column = field.column();
                    let _ = write!(&mut query, "{column} = EXCLUDED.{column}");
                }

                trx.execute(&query, &values).await.map_err(into_error)?;
            }

            trx.commit().await.map_err(into_error)
        })
        .await;
        bounded(conn, result, limit)
    }

    pub async fn query<R: SearchDocumentId>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<R>> {
        let mut query = format!("SELECT {} FROM {}", R::field().column(), index.psql_table());
        let params = self.build_filter(&mut query, filters);
        let params = params.iter().map(SqlParam::as_sql).collect::<Vec<_>>();
        if !sort.is_empty() {
            build_sort(&mut query, sort);
        }
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn.prepare_cached(&query).await.map_err(into_error)?;

            conn.query(&s, params.as_slice())
                .await
                .and_then(|rows| {
                    rows.into_iter()
                        .map(|row| row.try_get::<_, DocId>(0).map(|v| R::from_u64(v.0)))
                        .collect::<Result<Vec<R>, _>>()
                })
                .map_err(into_error)
        })
        .await;
        bounded(conn, result, limit)
    }

    /// inbuxa: every document's value of one unsigned field in an account,
    /// in one round trip. Feeds the message cache's received dates so
    /// sorting by receivedAt needs no query at all.
    pub async fn unsigned_values(
        &self,
        index: SearchIndex,
        field: SearchField,
        account_id: u32,
    ) -> trc::Result<Vec<(u32, u64)>> {
        let query = format!(
            "SELECT {}, {} FROM {} WHERE {} = $1",
            SearchField::DocumentId.column(),
            field.column(),
            index.psql_table(),
            SearchField::AccountId.column()
        );
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn.prepare_cached(&query).await.map_err(into_error)?;
            conn.query(&s, &[&(account_id as i32)])
                .await
                .and_then(|rows| {
                    rows.into_iter()
                        .map(|row| {
                            Ok((
                                row.try_get::<_, i32>(0)? as u32,
                                row.try_get::<_, i64>(1)? as u64,
                            ))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .map_err(into_error)
        })
        .await;
        bounded(conn, result, limit)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        debug_assert!(!filter.filters.is_empty());
        let table = filter.index.psql_table();
        let mut where_clause = String::new();
        let params = self.build_filter(&mut where_clause, &filter.filters);
        let params = params.iter().map(SqlParam::as_sql).collect::<Vec<_>>();
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.maintenance;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prepare_cached(&format!("DELETE FROM {table}{where_clause}"))
                .await
                .map_err(into_error)?;

            match conn.execute(&s, params.as_slice()).await {
                Ok(deleted) => return Ok(deleted),
                Err(err) if is_timeout_error(&err) => (),
                Err(err) => return Err(into_error(err)),
            }

            let mut chunk_size = DELETE_CHUNK_SIZE;
            let mut deleted = 0;

            loop {
                let s = conn
                    .prepare_cached(&format!(
                        "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table}{where_clause} LIMIT {chunk_size})"
                    ))
                    .await
                    .map_err(into_error)?;

                loop {
                    match conn.execute(&s, params.as_slice()).await {
                        Ok(0) => return Ok(deleted),
                        Ok(affected) => deleted += affected,
                        Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                            chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                            break;
                        }
                        Err(err) => return Err(into_error(err)),
                    }
                }
            }
        })
        .await;
        bounded(conn, result, limit)
    }

    fn build_filter<'x>(
        &self,
        query: &mut String,
        filters: &'x [SearchFilter],
    ) -> Vec<SqlParam<'x>> {
        if filters.is_empty() {
            return Vec::new();
        }
        query.push_str(" WHERE ");
        let mut operator_stack = Vec::new();
        let mut operator = &SearchFilter::And;
        let mut is_first = true;
        let mut values = Vec::new();

        for filter in filters {
            match filter {
                SearchFilter::Operator { field, op, value } => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }
                    let value_pos = values.len() + 1;
                    if field.is_text()
                        && matches!(op, SearchOperator::Equal | SearchOperator::Contains)
                    {
                        query.push_str(field.column());
                        query.push(' ');

                        let language = match &value {
                            SearchValue::Text { language, .. } => *language,
                            _ => Language::None,
                        };
                        let config = self.ts_config(&language);
                        let method = match op {
                            SearchOperator::Equal => "phraseto_tsquery",
                            _ => "plainto_tsquery",
                        };

                        if matches!(language, Language::None) {
                            let _ = write!(query, "@@ {method}('{config}', ${value_pos})");
                            if let SearchValue::Text { value, .. } = value {
                                values.push(SqlParam::Owned(keyword_terms(value)));
                                continue;
                            }
                        } else {
                            // inbuxa: a query word written as a URL, host,
                            // file or hyphenated word also matches as its word
                            // parts, which url_terms() indexes
                            let parts = match value {
                                SearchValue::Text { value, .. } => query_url_terms(value),
                                _ => None,
                            };
                            let parts_pos = value_pos + 1;
                            let _ = write!(query, "@@ ({method}('{config}', ${value_pos})");
                            if parts.is_some() {
                                let _ = write!(query, " || {method}('{config}', ${parts_pos})");
                            }
                            for fallback in [PG_FALLBACK_LANG, PG_UNSTEMMED_LANG] {
                                if fallback != config && self.ts_configs.contains(fallback) {
                                    let _ =
                                        write!(query, " || {method}('{fallback}', ${value_pos})");
                                    if parts.is_some() {
                                        let _ = write!(
                                            query,
                                            " || {method}('{fallback}', ${parts_pos})"
                                        );
                                    }
                                }
                            }
                            query.push(')');
                            values.push(SqlParam::Ref(value));
                            if let Some(parts) = parts {
                                values.push(SqlParam::Owned(parts));
                            }
                            continue;
                        }
                        values.push(SqlParam::Ref(value));
                    } else if let SearchValue::KeyValues(kv) = value {
                        query.push_str(field.column());
                        query.push(' ');

                        let (key, value) = kv.iter().next().unwrap();
                        values.push(SqlParam::Ref(key));

                        if !value.is_empty() {
                            let _ = write!(query, "->> ${value_pos} ");
                            op.write_pqsql(query, values.len() + 1);
                            values.push(SqlParam::Ref(value));
                        } else {
                            let _ = write!(query, " ? ${value_pos}");
                        }
                    } else {
                        query.push_str(field.sort_column().unwrap_or(field.column()));
                        query.push(' ');

                        op.write_pqsql(query, value_pos);
                        values.push(SqlParam::Ref(value));
                    }
                }
                SearchFilter::And | SearchFilter::Or => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }

                    operator_stack.push((operator, is_first));
                    operator = filter;
                    is_first = true;
                    query.push('(');
                }
                SearchFilter::Not => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }

                    operator_stack.push((operator, is_first));
                    operator = &SearchFilter::And;
                    is_first = true;
                    query.push_str("NOT (");
                }
                SearchFilter::End => {
                    let p = operator_stack.pop().unwrap_or((&SearchFilter::And, true));
                    operator = p.0;
                    is_first = p.1;
                    query.push(')');
                }
                SearchFilter::DocumentSet(_) => {
                    debug_assert!(
                        false,
                        "DocumentSet filters are not supported in Postgres backend"
                    )
                }
            }
        }

        values
    }
}

// inbuxa: PostgreSQL's text parser keeps "user@example.com" (and host names,
// URLs, file paths, ...) as a single token, so a search for "user" or
// "example.com" never matched an address. Keyword text is split into words the
// same way the built-in index splits it (SpaceTokenizer: lowercase runs of
// alphanumerics) on both the indexing and the query side, so a full address,
// its local part, its domain and the display-name words all match, as they do
// on the other backends.
pub(crate) fn keyword_terms(value: &str) -> String {
    let mut terms = String::with_capacity(value.len());
    for token in SpaceTokenizer::new(value, MAX_TOKEN_LENGTH) {
        if !terms.is_empty() {
            terms.push(' ');
        }
        terms.push_str(&token);
    }
    terms
}

// inbuxa: in language text (subject, body, attachments) PostgreSQL's parser
// keeps a URL, a host name, a path or a file name as tokens of its own:
// "https://x.example/shipping-support/" gives a url, a host and a url_path,
// "invoice-2024.pdf" a file, so a body search for "shipping" or "invoice"
// missed messages where the word appears only there, while the built-in index
// splits them into words. The text is indexed as it was, followed by the word
// parts of each such token (SpaceTokenizer, as keyword_terms() splits), so
// they go through the same configuration and stemming as the words around
// them. On sample mail the text vector grows by about 15% for a newsletter
// full of tracking links and 30% for a short order notice with three links.
// Plain words, and words that only carry punctuation ("end.", "(see"),
// add nothing; hyphenated words are already split by the parser. Returns None
// when there is nothing to add, so most text is indexed exactly as before.
/// Characters that join the parts of a URL, host, path, address or file name.
const URL_SEPARATORS: [char; 13] = [
    '/', '.', '@', ':', '?', '=', '&', '#', '_', '%', '+', '~', '\\',
];

pub(crate) fn url_terms(value: &str) -> Option<String> {
    let mut terms = String::new();
    // Each word is added once: a phrase search still finds the first URL it
    // is in, and a newsletter's hundred tracking links don't add a hundred
    // positions for "utm" and "campaign"
    let mut seen = std::collections::HashSet::new();
    for token in value.split(|c: char| {
        c.is_whitespace() || matches!(c, '<' | '>' | '"' | '(' | ')' | '[' | ']' | '{' | '}')
    }) {
        let token = token.trim_matches(|c: char| !c.is_alphanumeric());
        if token.contains(URL_SEPARATORS) {
            for word in SpaceTokenizer::new(token, MAX_TOKEN_LENGTH) {
                if !seen.insert(word.clone()) {
                    continue;
                }
                if terms.is_empty() {
                    terms.reserve(value.len() + 64);
                    terms.push_str(value);
                    terms.push('\n');
                } else {
                    terms.push(' ');
                }
                terms.push_str(&word);
            }
        }
    }
    (!terms.is_empty()).then_some(terms)
}

/// The query side of url_terms(): each query word that is a URL, host, file
/// name or hyphenated word replaced by its word parts, or None when there is
/// none. It is searched in addition to the query as written, so documents
/// indexed before url_terms() still match as they did.
pub(crate) fn query_url_terms(value: &str) -> Option<String> {
    let mut terms = String::with_capacity(value.len());
    let mut changed = false;
    for token in value.split_whitespace() {
        let word = token.trim_matches(|c: char| !c.is_alphanumeric());
        if !terms.is_empty() {
            terms.push(' ');
        }
        if word.contains(URL_SEPARATORS) || word.contains('-') {
            changed = true;
            terms.push_str(&keyword_terms(word));
        } else {
            terms.push_str(token);
        }
    }
    changed.then_some(terms)
}

pub(super) enum SqlParam<'x> {
    Ref(&'x (dyn ToSql + Sync)),
    Owned(String),
}

impl SqlParam<'_> {
    fn as_sql(&self) -> &(dyn ToSql + Sync) {
        match self {
            SqlParam::Ref(value) => *value,
            SqlParam::Owned(value) => value,
        }
    }
}

fn build_sort(query: &mut String, sort: &[SearchComparator]) {
    query.push_str(" ORDER BY ");
    for (i, comparator) in sort.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        match comparator {
            SearchComparator::Field { field, ascending } => {
                query.push_str(field.sort_column().unwrap_or(field.column()));
                if *ascending {
                    query.push_str(" ASC");
                } else {
                    query.push_str(" DESC");
                }
            }
            SearchComparator::DocumentSet { .. } | SearchComparator::SortedSet { .. } => {
                debug_assert!(
                    false,
                    "DocumentSet and SortedSet comparators are not supported "
                );
            }
        }
    }
}

impl ToSql for SearchValue {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        match self {
            SearchValue::Text { value, .. } => {
                // Truncate large text fields to avoid Postgres errors (see https://www.postgresql.org/docs/current/textsearch-limitations.html)

                if value.len() > 650_000 {
                    (&value[..value.floor_char_boundary(650_000)]).to_sql(ty, out)
                } else {
                    value.to_sql(ty, out)
                }
            }
            SearchValue::Int(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql(ty, out),
                _ => v.to_sql(ty, out),
            },
            SearchValue::Uint(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql(ty, out),
                _ => (*v as i64).to_sql(ty, out),
            },
            SearchValue::Boolean(v) => v.to_sql(ty, out),
            SearchValue::KeyValues(kv) => {
                serde_json::to_value(kv).unwrap_or_default().to_sql(ty, out)
            }
        }
    }

    fn accepts(_: &tokio_postgres::types::Type) -> bool
    where
        Self: Sized,
    {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            SearchValue::Text { value, .. } => {
                // Truncate large text fields to avoid Postgres errors (see https://www.postgresql.org/docs/current/textsearch-limitations.html)

                if value.len() > 650_000 {
                    (&value[..value.floor_char_boundary(650_000)]).to_sql_checked(ty, out)
                } else {
                    value.to_sql_checked(ty, out)
                }
            }
            SearchValue::Int(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql_checked(ty, out),
                _ => v.to_sql_checked(ty, out),
            },
            SearchValue::Uint(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql_checked(ty, out),
                _ => (*v as i64).to_sql_checked(ty, out),
            },
            SearchValue::Boolean(v) => v.to_sql_checked(ty, out),
            SearchValue::KeyValues(kv) => serde_json::to_value(kv)
                .unwrap_or_default()
                .to_sql_checked(ty, out),
        }
    }
}

struct DocId(u64);

impl FromSql<'_> for DocId {
    fn from_sql(
        ty: &tokio_postgres::types::Type,
        raw: &'_ [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match ty {
            &Type::INT4 => i32::from_sql(ty, raw).map(|v| DocId(v as u64)),
            &Type::INT8 | &Type::OID => i64::from_sql(ty, raw).map(|v| DocId(v as u64)),
            _ => Err(Box::new(WrongType::new::<DocId>(ty.clone()))),
        }
    }

    fn accepts(typ: &Type) -> bool {
        matches!(typ, &Type::INT4 | &Type::INT8 | &Type::OID)
    }
}

impl SearchOperator {
    fn write_pqsql(&self, query: &mut String, value_pos: usize) {
        match self {
            SearchOperator::LowerThan => {
                let _ = write!(query, "< ${value_pos}");
            }
            SearchOperator::LowerEqualThan => {
                let _ = write!(query, "<= ${value_pos}");
            }
            SearchOperator::GreaterThan => {
                let _ = write!(query, "> ${value_pos}");
            }
            SearchOperator::GreaterEqualThan => {
                let _ = write!(query, ">= ${value_pos}");
            }
            SearchOperator::Equal => {
                let _ = write!(query, "= ${value_pos}");
            }
            SearchOperator::Contains => {
                let _ = write!(query, "LIKE '%' || ${value_pos} || '%'");
            }
        }
    }
}

pub(super) const PG_FALLBACK_LANG: &str = "english";
pub(super) const PG_UNSTEMMED_LANG: &str = "simple";

pub(super) const PG_LANGS: &[&str] = &[
    "arabic",
    "armenian",
    "catalan",
    "danish",
    "dutch",
    "english",
    "finnish",
    "french",
    "german",
    "greek",
    "hindi",
    "hungarian",
    "indonesian",
    "italian",
    "lithuanian",
    "nepali",
    "norwegian",
    "portuguese",
    "romanian",
    "russian",
    "serbian",
    "spanish",
    "swedish",
    "tamil",
    "turkish",
    "yiddish",
];

#[inline(always)]
fn pg_lang(lang: &Language) -> Option<&'static str> {
    match lang {
        Language::Esperanto => None,
        Language::English => Some("english"),
        Language::Russian => Some("russian"),
        Language::Mandarin => None,
        Language::Spanish => Some("spanish"),
        Language::Portuguese => Some("portuguese"),
        Language::Italian => Some("italian"),
        Language::Bengali => None,
        Language::French => Some("french"),
        Language::German => Some("german"),
        Language::Ukrainian => None,
        Language::Georgian => None,
        Language::Arabic => Some("arabic"),
        Language::Hindi => Some("hindi"),
        Language::Japanese => None,
        Language::Hebrew => None,
        Language::Yiddish => Some("yiddish"),
        Language::Polish => None,
        Language::Amharic => None,
        Language::Javanese => None,
        Language::Korean => None,
        Language::Bokmal => Some("norwegian"), // Norwegian covers Bokmål
        Language::Danish => Some("danish"),
        Language::Swedish => Some("swedish"),
        Language::Finnish => Some("finnish"),
        Language::Turkish => Some("turkish"),
        Language::Dutch => Some("dutch"),
        Language::Hungarian => Some("hungarian"),
        Language::Czech => None,
        Language::Greek => Some("greek"),
        Language::Bulgarian => None,
        Language::Belarusian => None,
        Language::Marathi => None,
        Language::Kannada => None,
        Language::Romanian => Some("romanian"),
        Language::Slovene => None,
        Language::Croatian => None,
        Language::Serbian => Some("serbian"),
        Language::Macedonian => None,
        Language::Lithuanian => Some("lithuanian"),
        Language::Latvian => None,
        Language::Estonian => None,
        Language::Tamil => Some("tamil"),
        Language::Vietnamese => None,
        Language::Urdu => None,
        Language::Thai => None,
        Language::Gujarati => None,
        Language::Uzbek => None,
        Language::Punjabi => None,
        Language::Azerbaijani => None,
        Language::Indonesian => Some("indonesian"),
        Language::Telugu => None,
        Language::Persian => None,
        Language::Malayalam => None,
        Language::Oriya => None,
        Language::Burmese => None,
        Language::Nepali => Some("nepali"),
        Language::Sinhalese => None,
        Language::Khmer => None,
        Language::Turkmen => None,
        Language::Akan => None,
        Language::Zulu => None,
        Language::Shona => None,
        Language::Afrikaans => None,
        Language::Latin => None,
        Language::Slovak => None,
        Language::Catalan => Some("catalan"),
        Language::Tagalog => None,
        Language::Armenian => Some("armenian"),
        Language::Unknown | Language::None => None,
    }
}
