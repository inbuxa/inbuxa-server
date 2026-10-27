/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    U64_LEN,
    backend::{
        MAX_TOKEN_LENGTH,
        mysql::{
            DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, MysqlSearchField, MysqlStore, into_error,
            is_chunk_too_large_error,
            read::{MAX_POINT_KEYS, POINT_BUCKETS},
        },
    },
    search::{
        IndexDocument, KeyValueMatch, SearchFilter, SearchQuery, SearchResults, SearchValue,
        TextMatch,
    },
    write::SearchIndex,
};
use mysql_async::{TxOpts, Value, prelude::Queryable};
use nlp::tokenizers::word::WordTokenizer;
use roaring::RoaringBitmap;
use std::{cmp::Ordering, fmt::Write};

const ROW_BUCKETS: [usize; 5] = [256, 64, 16, 4, 1];
const MAX_BATCH_ROWS: usize = ROW_BUCKETS[0];
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

impl MysqlStore {
    pub async fn index(&self, mut documents: Vec<IndexDocument>) -> trc::Result<()> {
        documents.sort_by_key(|document| document.index as u8);
        let mut batches = row_batches(documents).into_iter();
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        match (batches.next(), batches.len()) {
            (Some(batch), 0) => conn
                .exec_drop(batch.statement(), batch.values)
                .await
                .map_err(into_error),
            (Some(batch), _) => {
                let mut trx = conn
                    .start_transaction(TxOpts::default())
                    .await
                    .map_err(into_error)?;
                for batch in std::iter::once(batch).chain(batches) {
                    trx.exec_drop(batch.statement(), batch.values)
                        .await
                        .map_err(into_error)?;
                }
                trx.commit().await.map_err(into_error)
            }
            (None, _) => Ok(()),
        }
    }

    pub async fn query<R: SearchResults>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
    ) -> trc::Result<R> {
        let mut query = format!(
            "SELECT {} FROM {}",
            R::field().column(),
            index.mysql_table()
        );
        let params = build_filter(&mut query, filters);
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn.prep(query).await.map_err(into_error)?;

        conn.exec::<i64, _, _>(s, params)
            .await
            .map(|r| {
                let mut results = R::default();
                for id in r {
                    results.insert(id as u64);
                }
                results
            })
            .map_err(into_error)
    }

    pub async fn filter_candidates(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        candidates: &[u32],
    ) -> trc::Result<RoaringBitmap> {
        let mut base = format!("SELECT docid FROM {}", index.mysql_table());
        let params = build_filter(&mut base, filters);
        base.push_str(if filters.is_empty() {
            " WHERE docid IN (?"
        } else {
            " AND docid IN (?"
        });
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let mut results = RoaringBitmap::new();
        let mut query = String::with_capacity(base.len() + 2 * MAX_POINT_KEYS);

        for chunk in candidates.chunks(MAX_POINT_KEYS) {
            let Some(&last) = chunk.last() else {
                continue;
            };
            let slots = POINT_BUCKETS
                .into_iter()
                .find(|bucket| *bucket >= chunk.len())
                .unwrap_or(MAX_POINT_KEYS);
            query.clear();
            query.push_str(&base);
            for _ in 1..slots {
                query.push_str(",?");
            }
            query.push(')');

            let mut values = Vec::with_capacity(params.len() + slots);
            values.extend(params.iter().cloned());
            values.extend(
                chunk
                    .iter()
                    .chain(std::iter::repeat_n(&last, slots - chunk.len()))
                    .map(|document_id| Value::Int(i64::from(*document_id))),
            );
            let s = conn.prep(&query).await.map_err(into_error)?;
            for document_id in conn
                .exec::<i64, _, _>(s, values)
                .await
                .map_err(into_error)?
            {
                if let Ok(document_id) = u32::try_from(document_id) {
                    results.insert(document_id);
                }
            }
        }

        Ok(results)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        let table = filter.index.mysql_table();
        let mut query = format!("DELETE FROM {table} ");
        let params = build_filter(&mut query, &filter.filters);

        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
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
                        if is_chunk_too_large_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE =>
                    {
                        chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                }
            }
        }
    }
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
            SearchFilter::Text {
                field,
                op,
                value,
                language: _,
            } => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }

                if field.is_text() {
                    let text_query = match op {
                        TextMatch::Exact => format!("{value:?}"),
                        TextMatch::Standard => {
                            let mut text_query = String::with_capacity(value.len() + 1);
                            for item in WordTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                if !text_query.is_empty() {
                                    text_query.push(' ');
                                }
                                text_query.push('+');
                                text_query.push_str(&item.word);
                            }
                            text_query
                        }
                        TextMatch::Prefix => {
                            let mut text_query = String::with_capacity(value.len() + 2);
                            for item in WordTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                if !text_query.is_empty() {
                                    text_query.push(' ');
                                }
                                text_query.push('+');
                                text_query.push_str(&item.word);
                                text_query.push('*');
                            }
                            text_query
                        }
                    };
                    let _ = write!(
                        query,
                        "MATCH({}) AGAINST(? IN BOOLEAN MODE)",
                        field.column()
                    );
                    values.push(Value::Bytes(text_query.into_bytes()));
                } else {
                    query.push_str(field.column());
                    match op {
                        TextMatch::Prefix => {
                            let _ = write!(query, " LIKE CONCAT(?, '%')");
                        }
                        _ => {
                            query.push_str(" = ?");
                        }
                    }
                    values.push(Value::Bytes(value.as_bytes().to_vec()));
                }
            }
            SearchFilter::KeyValue { field, key, op } => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }

                values.push(Value::Bytes(format!("$.{key:?}").into_bytes()));

                match op {
                    KeyValueMatch::Equals(value) => {
                        let _ = write!(query, "JSON_EXTRACT({}, ?) = ?", field.column());
                        values.push(Value::Bytes(value.as_bytes().to_vec()));
                    }
                    KeyValueMatch::Contains(value) => {
                        let _ = write!(
                            query,
                            "LOWER(JSON_UNQUOTE(JSON_EXTRACT({}, ?))) LIKE ?",
                            field.column()
                        );
                        values.push(Value::Bytes(
                            format!("%{}%", value.to_lowercase()).into_bytes(),
                        ));
                    }
                    KeyValueMatch::Exists => {
                        let _ = write!(query, "JSON_CONTAINS_PATH({}, 'one', ?)", field.column());
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }
                let cmp = match op {
                    Ordering::Less => "<",
                    Ordering::Equal => "=",
                    Ordering::Greater => ">",
                };
                let _ = write!(query, "{} {cmp} {value}", field.column());
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
                operator = &SearchFilter::Or;
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
                    "DocumentSet filters are not supported in MySQL backend"
                )
            }
        }
    }

    values
}

struct RowBatch {
    index: SearchIndex,
    rows: usize,
    values: Vec<Value>,
}

impl RowBatch {
    fn statement(&self) -> String {
        let index = self.index;
        let columns = index.primary_keys().iter().chain(index.all_fields());
        let num_columns = columns.clone().count();
        let mut query =
            String::with_capacity(64 + self.rows * (2 * num_columns + 3) + 32 * num_columns);
        let _ = write!(query, "INSERT INTO {} (", index.mysql_table());
        for (pos, field) in columns.enumerate() {
            if pos > 0 {
                query.push(',');
            }
            query.push_str(field.column());
        }
        query.push_str(") VALUES ");
        for row in 0..self.rows {
            if row > 0 {
                query.push(',');
            }
            query.push('(');
            for column in 0..num_columns {
                if column > 0 {
                    query.push(',');
                }
                query.push('?');
            }
            query.push(')');
        }
        query.push_str(" ON DUPLICATE KEY UPDATE ");
        for (pos, field) in index.all_fields().iter().enumerate() {
            if pos > 0 {
                query.push(',');
            }
            let column = field.column();
            let _ = write!(query, "{column} = VALUES({column})");
        }
        query
    }
}

fn row_batches(documents: Vec<IndexDocument>) -> Vec<RowBatch> {
    let mut batches = Vec::new();
    let mut values = Vec::new();
    let mut current = None;
    let mut rows = 0;
    let mut bytes = 0;

    for mut document in documents {
        let index = document.index;
        let row_bytes = document.fields.values().map(value_len).sum::<usize>();
        if let Some(current) = current
            && (current != index || rows == MAX_BATCH_ROWS || bytes + row_bytes > MAX_BATCH_BYTES)
        {
            split_rows(&mut batches, current, std::mem::take(&mut values), rows);
            rows = 0;
            bytes = 0;
        }

        for field in index.primary_keys().iter().chain(index.all_fields()) {
            values.push(
                document
                    .fields
                    .remove(field)
                    .map_or(Value::NULL, Value::from),
            );
        }
        current = Some(index);
        rows += 1;
        bytes += row_bytes;
    }

    if let Some(current) = current {
        split_rows(&mut batches, current, values, rows);
    }

    batches
}

fn split_rows(batches: &mut Vec<RowBatch>, index: SearchIndex, values: Vec<Value>, rows: usize) {
    let num_columns = values.len() / rows.max(1);
    let mut values = values.into_iter();
    let mut remaining = rows;
    for bucket in ROW_BUCKETS {
        while remaining >= bucket {
            batches.push(RowBatch {
                index,
                rows: bucket,
                values: values.by_ref().take(bucket * num_columns).collect(),
            });
            remaining -= bucket;
        }
    }
}

fn value_len(value: &SearchValue) -> usize {
    match value {
        SearchValue::Text { value, .. } => value.len(),
        SearchValue::KeyValues(values) => values
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum(),
        SearchValue::Int(_) | SearchValue::Uint(_) | SearchValue::Boolean(_) => U64_LEN,
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
