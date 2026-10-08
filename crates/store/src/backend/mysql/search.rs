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
        mysql::{
            DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, MysqlSearchField, MysqlStore, bounded,
            into_error, is_chunk_too_large_error,
        },
    },
    search::{
        IndexDocument, SearchComparator, SearchDocumentId, SearchField, SearchFilter,
        SearchOperator, SearchQuery, SearchValue,
    },
    write::SearchIndex,
};
use mysql_async::{IsolationLevel, TxOpts, Value, prelude::Queryable};
use nlp::{language::Language, tokenizers::word::WordTokenizer};
use std::fmt::Write;

impl MysqlStore {
    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let mut tx_opts = TxOpts::default();
            tx_opts
                .with_consistent_snapshot(false)
                .with_isolation_level(IsolationLevel::ReadCommitted);
            let mut trx = conn.start_transaction(tx_opts).await.map_err(into_error)?;

            for document in documents {
                let index = document.index;
                let primary_keys = index.primary_keys();
                let all_fields = index.all_fields();
                let mut fields = document.fields;
                let mut values = Vec::with_capacity(fields.len() + 2);
                let mut query = format!("INSERT INTO {} (", index.mysql_table());

                for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                    if i > 0 {
                        query.push(',');
                    }
                    query.push_str(field.column());
                }

                query.push_str(") VALUES (");

                for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                    if i > 0 {
                        query.push(',');
                    }

                    if let Some(value) = fields.remove(field) {
                        query.push('?');
                        values.push(value);
                    } else {
                        query.push_str("NULL");
                    }
                }

                query.push_str(") ON DUPLICATE KEY UPDATE ");
                for (i, field) in all_fields.iter().enumerate() {
                    if i > 0 {
                        query.push(',');
                    }
                    let column = field.column();
                    let _ = write!(&mut query, "{column} = VALUES({column})");
                }

                let s = trx.prep(&query).await.map_err(into_error)?;

                trx.exec_drop(&s, values).await.map_err(into_error)?;
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
        let mut query = format!(
            "SELECT {} FROM {}",
            R::field().column(),
            index.mysql_table()
        );
        let params = build_filter(&mut query, filters);
        if !sort.is_empty() {
            build_sort(&mut query, sort);
        }

        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn.prep(query).await.map_err(into_error)?;

            conn.exec::<i64, _, _>(s, params)
                .await
                .map(|r| r.into_iter().map(|r| R::from_u64(r as u64)).collect())
                .map_err(into_error)
        })
        .await;
        bounded(conn, result, limit)
    }

    /// inbuxa: every document's value of one unsigned field in an account,
    /// in one round trip (see the PostgreSQL backend).
    pub async fn unsigned_values(
        &self,
        index: SearchIndex,
        field: SearchField,
        account_id: u32,
    ) -> trc::Result<Vec<(u32, u64)>> {
        let query = format!(
            "SELECT {}, {} FROM {} WHERE {} = ?",
            SearchField::DocumentId.column(),
            field.column(),
            index.mysql_table(),
            SearchField::AccountId.column()
        );
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn.prep(query).await.map_err(into_error)?;
            conn.exec::<(i32, i64), _, _>(s, (account_id as i32,))
                .await
                .map(|rows| {
                    rows.into_iter()
                        .map(|(id, value)| (id as u32, value as u64))
                        .collect()
                })
                .map_err(into_error)
        })
        .await;
        bounded(conn, result, limit)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        let table = filter.index.mysql_table();
        let mut query = format!("DELETE FROM {table} ");
        let params = build_filter(&mut query, &filter.filters);

        let mut conn = self.conn().await?;
        let limit = self.timeouts.maintenance;
        let result = tokio::time::timeout(limit, async {
            let mut chunk_size = DELETE_CHUNK_SIZE;
            let mut deleted = 0;

            loop {
                let s = conn
                    .prep(format!("{query} LIMIT {chunk_size}"))
                    .await
                    .map_err(into_error)?;

                loop {
                    match conn.exec_drop(&s, params.clone()).await {
                        Ok(_) => {
                            let affected = conn.affected_rows();
                            deleted += affected;
                            if affected < chunk_size as u64 {
                                return Ok(deleted);
                            }
                        }
                        Err(err)
                            if is_chunk_too_large_error(&err)
                                && chunk_size > MIN_DELETE_CHUNK_SIZE =>
                        {
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
}

// inbuxa: InnoDB's default full-text stopword list
// (INFORMATION_SCHEMA.INNODB_FT_DEFAULT_STOPWORD) and innodb_ft_min_token_size
// default; words outside these are not in a FULLTEXT index.
const FT_STOPWORDS: &[&str] = &[
    "a", "about", "an", "are", "as", "at", "be", "by", "com", "de", "en", "for", "from", "how",
    "i", "in", "is", "it", "la", "of", "on", "or", "that", "the", "this", "to", "was", "what",
    "when", "where", "who", "will", "with", "und", "www",
];
const FT_MIN_TOKEN_SIZE: usize = 3;

fn is_ft_indexed(word: &str) -> bool {
    word.chars().count() >= FT_MIN_TOKEN_SIZE && !FT_STOPWORDS.contains(&word)
}

fn build_filter(query: &mut String, filters: &[SearchFilter]) -> Vec<Value> {
    if filters.is_empty() {
        return Vec::new();
    }
    query.push_str(" WHERE ");
    let mut operator_stack = Vec::new();
    let mut operator = &SearchFilter::And;
    let mut is_first = true;
    let mut values: Vec<Value> = Vec::new();

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

                if field.is_text() && matches!(op, SearchOperator::Equal | SearchOperator::Contains)
                {
                    let (value, mode, unindexed) = match (value, op) {
                        (SearchValue::Text { value, .. }, SearchOperator::Equal) => (
                            Value::Bytes(format!("{value:?}").into_bytes()),
                            "BOOLEAN",
                            Vec::new(),
                        ),
                        (SearchValue::Text { value, language }, ..) => {
                            let mut text_query = String::with_capacity(value.len() + 1);
                            let mut unindexed = Vec::new();

                            for item in WordTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                // inbuxa: InnoDB never indexes stopwords ("com",
                                // "de", "www", ...) or words under
                                // innodb_ft_min_token_size, and a required
                                // (+word) term it has not indexed matches no row,
                                // so "example.com" or "jo@example.org" found
                                // nothing. Such words are matched with a
                                // word-boundary REGEXP instead.
                                if is_ft_indexed(&item.word) {
                                    if !text_query.is_empty() {
                                        text_query.push(' ');
                                    }
                                    text_query.push('+');
                                    text_query.push_str(&item.word);
                                } else {
                                    unindexed.push(item.word);
                                }
                            }

                            // For language text (bodies, subjects) the unindexed
                            // words are noise words and only checked when nothing
                            // else is left to match; keyword text (addresses,
                            // contact fields) checks every word, as the other
                            // backends do.
                            if !text_query.is_empty() && !matches!(language, Language::None) {
                                unindexed.clear();
                            }

                            (Value::Bytes(text_query.into_bytes()), "BOOLEAN", unindexed)
                        }
                        _ => {
                            debug_assert!(false, "Invalid search value for text field");
                            continue;
                        }
                    };
                    if unindexed.is_empty() {
                        let _ =
                            write!(query, "MATCH({}) AGAINST(? IN {mode} MODE)", field.column());
                        values.push(value);
                    } else {
                        query.push('(');
                        let is_empty = matches!(&value, Value::Bytes(v) if v.is_empty());
                        if !is_empty {
                            let _ = write!(
                                query,
                                "MATCH({}) AGAINST(? IN {mode} MODE) AND ",
                                field.column()
                            );
                            values.push(value);
                        }
                        for (i, word) in unindexed.iter().enumerate() {
                            if i > 0 {
                                query.push_str(" AND ");
                            }
                            let _ = write!(query, "{} REGEXP ?", field.column());
                            values.push(Value::Bytes(
                                format!("(^|[^[:alnum:]]){word}([^[:alnum:]]|$)").into_bytes(),
                            ));
                        }
                        query.push(')');
                    }
                } else if let SearchValue::KeyValues(kv) = value {
                    let (key, value) = kv.iter().next().unwrap();

                    values.push(Value::Bytes(format!("$.{key:?}").into_bytes()));

                    if !value.is_empty() {
                        if op == &SearchOperator::Equal {
                            let _ = write!(query, "JSON_EXTRACT({}, ?) = ?", field.column());
                            values.push(Value::Bytes(value.as_bytes().to_vec()));
                        } else {
                            let _ = write!(query, "JSON_EXTRACT({}, ?) LIKE ?", field.column(),);
                            values.push(Value::Bytes(format!("%{value}%").into_bytes()));
                        }
                    } else {
                        let _ = write!(query, "JSON_CONTAINS_PATH({}, 'one', ?)", field.column(),);
                    }
                } else {
                    query.push_str(field.column());
                    query.push(' ');
                    op.write_mysql(query);
                    values.push(to_mysql(value));
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

fn build_sort(query: &mut String, sort: &[SearchComparator]) {
    query.push_str(" ORDER BY ");
    for (i, comparator) in sort.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        match comparator {
            SearchComparator::Field { field, ascending } => {
                query.push_str(field.column());
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

impl SearchOperator {
    fn write_mysql(&self, query: &mut String) {
        match self {
            SearchOperator::LowerThan => {
                let _ = write!(query, "< ?");
            }
            SearchOperator::LowerEqualThan => {
                let _ = write!(query, "<= ?");
            }
            SearchOperator::GreaterThan => {
                let _ = write!(query, "> ?");
            }
            SearchOperator::GreaterEqualThan => {
                let _ = write!(query, ">= ?");
            }
            SearchOperator::Equal => {
                let _ = write!(query, "= ?");
            }
            SearchOperator::Contains => {
                let _ = write!(query, "LIKE '%' CONCAT('%', ?, '%')");
            }
        }
    }
}

impl From<SearchValue> for Value {
    fn from(value: SearchValue) -> Self {
        match value {
            SearchValue::Text { mut value, .. } => {
                // Truncate values larger than 16MB to avoid MySQL errors
                if value.len() > 16_777_214 {
                    let pos = value.floor_char_boundary(16_777_214);
                    value.truncate(pos);
                }

                Value::Bytes(value.into_bytes())
            }
            SearchValue::KeyValues(vec_map) => serde_json::to_string(&vec_map)
                .map(|v| Value::Bytes(v.into_bytes()))
                .unwrap_or(Value::NULL),
            SearchValue::Int(i) => Value::Int(i),
            SearchValue::Uint(i) => Value::Int(i as i64),
            SearchValue::Boolean(b) => Value::Int(b as i64),
        }
    }
}

fn to_mysql(value: &SearchValue) -> Value {
    match value {
        SearchValue::Text { value, .. } => Value::Bytes(value.as_bytes().to_vec()),
        SearchValue::KeyValues(vec_map) => serde_json::to_string(&vec_map)
            .map(|v| Value::Bytes(v.into_bytes()))
            .unwrap_or(Value::NULL),
        SearchValue::Int(i) => Value::Int(*i),
        SearchValue::Uint(i) => Value::Int(*i as i64),
        SearchValue::Boolean(b) => Value::Int(*b as i64),
    }
}
