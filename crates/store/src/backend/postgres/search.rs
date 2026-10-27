/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::postgres::{
        DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, PostgresStore, PsqlSearchField, into_error,
        into_pool_error, is_timeout_error,
    },
    search::{
        IndexDocument, KeyValueMatch, SearchField, SearchFilter, SearchQuery, SearchResults,
        SearchValue, TextMatch, TracingSearchField,
    },
    write::SearchIndex,
};
use futures::{TryStreamExt, pin_mut};
use nlp::language::Language;
use roaring::RoaringBitmap;
use std::{cmp::Ordering, fmt::Write};
use tokio_postgres::{
    RowStream,
    types::{FromSql, IsNull, ToSql, Type, WrongType},
};

const MAX_TSVECTOR_CHARS: usize = 250_000;
const MAX_KEYWORD_CHARS: usize = 512;
pub const DENSE_ACCOUNT_DOCUMENTS: u64 = 32_768;
const ACCOUNT_FIRST_DOCUMENTS: u64 = 4_096;
const ACCOUNT_FIRST_COLUMNS_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsQueryForm {
    Inline,
    InitPlan,
    DenseInitPlan,
}

impl TsQueryForm {
    fn of(documents: u64) -> Self {
        if documents >= DENSE_ACCOUNT_DOCUMENTS {
            TsQueryForm::DenseInitPlan
        } else {
            TsQueryForm::InitPlan
        }
    }

    fn open(self) -> &'static str {
        match self {
            TsQueryForm::Inline => " @@ ",
            TsQueryForm::InitPlan | TsQueryForm::DenseInitPlan => " @@ (SELECT ",
        }
    }

    fn close(self) -> &'static str {
        match self {
            TsQueryForm::Inline => "",
            TsQueryForm::InitPlan | TsQueryForm::DenseInitPlan => ")",
        }
    }
}

#[cfg(stalwart_tests)]
pub static QUERY_LOG: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

impl PostgresStore {
    fn ts_config(&self, language: &Language) -> &'static str {
        pg_lang(language)
            .filter(|config| self.ts_configs.contains(config))
            .unwrap_or(PG_UNSTEMMED_LANG)
    }

    pub async fn index(&self, mut documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut buffer = String::new();
        for document in &mut documents {
            document.split_identifiers(&mut buffer);
        }
        documents.sort_by_key(DocumentKey::of);
        documents.dedup_by(|later, kept| {
            let is_duplicate = DocumentKey::of(later) == DocumentKey::of(kept);
            if is_duplicate {
                std::mem::swap(later, kept);
            }
            is_duplicate
        });
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for documents in documents.chunk_by(|a, b| a.index == b.index) {
            let Some(index) = documents.first().map(|document| document.index) else {
                continue;
            };
            let statement = conn
                .prepare_cached(&upsert_statement(index))
                .await
                .map_err(into_error)?;
            let params = self.upsert_params(index, documents);
            conn.execute_raw(&statement, params.iter())
                .await
                .map_err(into_error)?;
        }

        Ok(())
    }

    fn upsert_params<'x>(
        &self,
        index: SearchIndex,
        documents: &'x [IndexDocument],
    ) -> Vec<UpsertParam<'x>> {
        let (primary_keys, all_fields) = (index.primary_keys(), index.all_fields());
        let mut params = Vec::with_capacity(2 * (primary_keys.len() + all_fields.len()));

        for field in primary_keys.iter().chain(all_fields) {
            let values = documents.iter().map(|document| document.fields.get(field));
            if field.is_text() {
                let (values, configs) = values
                    .map(|value| {
                        let config = match value {
                            Some(SearchValue::Text { language, .. }) => self.ts_config(language),
                            _ => PG_UNSTEMMED_LANG,
                        };
                        (value, config)
                    })
                    .unzip();
                params.push(UpsertParam::Values(values));
                params.push(UpsertParam::Configs(configs));
            } else {
                params.push(UpsertParam::Values(values.collect()));
            }
        }

        params
    }

    pub async fn query<R: SearchResults>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
    ) -> trc::Result<R> {
        let mut query = format!("SELECT {} FROM {}", R::field().column(), index.psql_table());
        let params = self.build_filter(&mut query, filters, TsQueryForm::Inline);
        self.select(query, &params, TsQueryForm::Inline).await
    }

    pub async fn query_account<R: SearchResults>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        mask: &RoaringBitmap,
    ) -> trc::Result<R> {
        if index.reads_account_first()
            && let Some((first_id, last_id)) = mask.min().zip(mask.max())
            && u64::from(last_id - first_id) < ACCOUNT_FIRST_DOCUMENTS
            && IntegerColumn::Int4.binds(last_id.into())
            && let Some(account_id) = account_filter(filters)
            && let Some(columns) = account_first_columns(R::field(), filters)
        {
            return self
                .query_account_first(index, filters, &columns, account_id, first_id, last_id)
                .await;
        }

        let mut query = format!("SELECT {} FROM {}", R::field().column(), index.psql_table());
        let form = TsQueryForm::of(mask.len());
        let params = self.build_filter(&mut query, filters, form);
        self.select(query, &params, form).await
    }

    async fn query_account_first<R: SearchResults>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        columns: &[&str],
        account_id: u64,
        first_id: u32,
        last_id: u32,
    ) -> trc::Result<R> {
        let mut where_clause = String::new();
        let mut params = self.build_filter(&mut where_clause, filters, TsQueryForm::Inline);

        let mut query = String::with_capacity(where_clause.len() + 160);
        let _ = write!(query, "SELECT {} FROM (SELECT ", R::field().column());
        for (pos, column) in columns.iter().enumerate() {
            if pos > 0 {
                query.push_str(", ");
            }
            query.push_str(column);
        }
        let document_column = SearchField::DocumentId.column();
        let _ = write!(
            query,
            " FROM {} WHERE {} = ${} AND {document_column} >= ${} AND {document_column} <= ${} \
             OFFSET 0) c{where_clause}",
            index.psql_table(),
            SearchField::AccountId.column(),
            params.len() + 1,
            params.len() + 2,
            params.len() + 3,
        );
        params.push(FilterParam::Integer(account_id, IntegerColumn::Int4));
        params.push(FilterParam::Integer(first_id.into(), IntegerColumn::Int4));
        params.push(FilterParam::Integer(last_id.into(), IntegerColumn::Int4));
        self.select(query, &params, TsQueryForm::Inline).await
    }

    pub async fn filter_candidates(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        candidates: &[u32],
    ) -> trc::Result<RoaringBitmap> {
        let mut query = format!("SELECT docid FROM {}", index.psql_table());
        let mut params = self.build_filter(&mut query, filters, TsQueryForm::Inline);
        let candidates = candidates
            .iter()
            .map(|document_id| document_id.cast_signed())
            .collect::<Vec<_>>();
        let _ = write!(
            query,
            "{} docid = ANY(${}::int4[])",
            if filters.is_empty() { " WHERE" } else { " AND" },
            params.len() + 1
        );
        params.push(FilterParam::Ids(&candidates));
        self.select(query, &params, TsQueryForm::Inline).await
    }

    async fn select<R: SearchResults>(
        &self,
        query: String,
        params: &[FilterParam<'_>],
        form: TsQueryForm,
    ) -> trc::Result<R> {
        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let typed = params.iter().map(|param| (param, param.sql_type()));
        let (results, num_rows) = match form {
            TsQueryForm::Inline | TsQueryForm::InitPlan => {
                collect_ids::<R>(
                    conn.query_typed_raw(&query, typed)
                        .await
                        .map_err(into_error)?,
                )
                .await?
            }
            TsQueryForm::DenseInitPlan => {
                let trx = conn.transaction().await.map_err(into_error)?;
                trx.batch_execute("SET LOCAL jit = off")
                    .await
                    .map_err(into_error)?;
                let results = collect_ids::<R>(
                    trx.query_typed_raw(&query, typed)
                        .await
                        .map_err(into_error)?,
                )
                .await?;
                trx.commit().await.map_err(into_error)?;
                results
            }
        };

        #[cfg(stalwart_tests)]
        if let Ok(mut log) = QUERY_LOG.lock() {
            log.push((query, num_rows));
        }
        #[cfg(not(stalwart_tests))]
        let _ = num_rows;

        Ok(results)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        debug_assert!(!filter.filters.is_empty());
        let table = filter.index.psql_table();
        let mut where_clause = String::new();
        let params = self.build_filter(&mut where_clause, &filter.filters, TsQueryForm::Inline);
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&format!("DELETE FROM {table}{where_clause}"))
            .await
            .map_err(into_error)?;

        match conn.execute_raw(&s, params.iter()).await {
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
                match conn.execute_raw(&s, params.iter()).await {
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
    }

    fn build_filter<'x>(
        &self,
        query: &mut String,
        filters: &'x [SearchFilter],
        form: TsQueryForm,
    ) -> Vec<FilterParam<'x>> {
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
                SearchFilter::Text {
                    field,
                    op,
                    value,
                    language,
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
                    let value_pos = values.len() + 1;
                    query.push_str(field.column());
                    if field.is_text() {
                        query.push_str(form.open());
                        let config = self.ts_config(language);
                        match op {
                            TextMatch::Exact | TextMatch::Standard => {
                                let method = if matches!(op, TextMatch::Exact) {
                                    "phraseto_tsquery"
                                } else {
                                    "plainto_tsquery"
                                };

                                if matches!(language, Language::None) {
                                    let _ = write!(query, "{method}('{config}', ${value_pos})");
                                } else {
                                    let _ = write!(query, "({method}('{config}', ${value_pos})");
                                    for fallback in [PG_FALLBACK_LANG, PG_UNSTEMMED_LANG] {
                                        if fallback != config && self.ts_configs.contains(fallback)
                                        {
                                            let _ = write!(
                                                query,
                                                " || {method}('{fallback}', ${value_pos})"
                                            );
                                        }
                                    }
                                    query.push(')');
                                }
                            }
                            TextMatch::Prefix => {
                                let _ = write!(
                                    query,
                                    "to_tsquery('{PG_UNSTEMMED_LANG}', coalesce(nullif(array_to_string(tsvector_to_array(to_tsvector('{PG_UNSTEMMED_LANG}', ${value_pos})), ':* & '), '') || ':*', ''))"
                                );
                            }
                        }
                        query.push_str(form.close());
                    } else {
                        match op {
                            TextMatch::Prefix => {
                                let _ = write!(query, " LIKE ${value_pos} || '%'");
                            }
                            _ => {
                                let _ = write!(query, " = ${value_pos}");
                            }
                        }
                    }
                    values.push(FilterParam::Text(value));
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
                    query.push_str(field.column());
                    query.push(' ');
                    let key_pos = values.len() + 1;
                    values.push(FilterParam::Text(key));
                    match op {
                        KeyValueMatch::Equals(value) => {
                            let value_pos = values.len() + 1;
                            let _ = write!(query, "->> ${key_pos} = ${value_pos}");
                            values.push(FilterParam::Text(value));
                        }
                        KeyValueMatch::Contains(value) => {
                            let value_pos = values.len() + 1;
                            let _ =
                                write!(query, "->> ${key_pos} ILIKE '%' || ${value_pos} || '%'");
                            values.push(FilterParam::Text(value));
                        }
                        KeyValueMatch::Exists => {
                            let _ = write!(query, " ? ${key_pos}");
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
                    match IntegerColumn::of(field).filter(|column| column.binds(*value)) {
                        Some(column) => {
                            let _ = write!(query, "{} {cmp} ${}", field.column(), values.len() + 1);
                            values.push(FilterParam::Integer(*value, column));
                        }
                        None => {
                            let _ = write!(query, "{} {cmp} {value}", field.column());
                        }
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
                        "DocumentSet filters are not supported in Postgres backend"
                    )
                }
            }
        }

        values
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DocumentKey(u8, u64, u64);

impl DocumentKey {
    fn of(document: &IndexDocument) -> Self {
        let mut keys =
            document
                .index
                .primary_keys()
                .iter()
                .map(|field| match document.fields.get(field) {
                    Some(SearchValue::Uint(value)) => *value,
                    Some(SearchValue::Int(value)) => value.cast_unsigned(),
                    _ => 0,
                });
        DocumentKey(
            document.index as u8,
            keys.next().unwrap_or_default(),
            keys.next().unwrap_or_default(),
        )
    }
}

async fn collect_ids<R: SearchResults>(rows: RowStream) -> trc::Result<(R, usize)> {
    pin_mut!(rows);
    let mut results = R::default();
    let mut num_rows = 0;
    while let Some(row) = rows.try_next().await.map_err(into_error)? {
        results.insert(row.try_get::<_, DocId>(0).map_err(into_error)?.0);
        num_rows += 1;
    }
    Ok((results, num_rows))
}

fn upsert_statement(index: SearchIndex) -> String {
    let primary_keys = index.primary_keys();
    let all_fields = index.all_fields();
    let mut columns = String::with_capacity(128);
    let mut values = String::with_capacity(512);
    let mut arrays = String::with_capacity(256);
    let mut aliases = String::with_capacity(128);
    let mut param = 0;

    for (pos, field) in primary_keys.iter().chain(all_fields).enumerate() {
        if pos > 0 {
            columns.push(',');
            values.push(',');
            arrays.push(',');
            aliases.push(',');
        }
        param += 1;
        columns.push_str(field.column());
        let _ = write!(aliases, "v{pos}");

        if field.is_text() {
            let _ = write!(arrays, "${param}::text[],${}::text[]", param + 1);
            let _ = write!(
                values,
                "to_tsvector(c{pos}::regconfig,left(v{pos},{MAX_TSVECTOR_CHARS}))"
            );
            let _ = write!(aliases, ",c{pos}");
            param += 1;
        } else {
            let (array_type, value) = match IntegerColumn::of(field) {
                Some(column) => (column.type_name(), None),
                None if field.is_json() => ("jsonb", None),
                None => ("text", Some(MAX_KEYWORD_CHARS)),
            };
            let _ = write!(arrays, "${param}::{array_type}[]");
            match value {
                Some(max_chars) => {
                    let _ = write!(values, "left(v{pos},{max_chars})");
                }
                None => {
                    let _ = write!(values, "v{pos}");
                }
            }
        }
    }

    let mut statement = format!(
        "INSERT INTO {} ({columns}) SELECT {values} FROM unnest({arrays}) AS u({aliases}) ON CONFLICT (",
        index.psql_table()
    );
    for (pos, field) in primary_keys.iter().enumerate() {
        if pos > 0 {
            statement.push(',');
        }
        statement.push_str(field.column());
    }
    statement.push_str(") DO UPDATE SET ");
    for (pos, field) in all_fields.iter().enumerate() {
        if pos > 0 {
            statement.push(',');
        }
        let column = field.column();
        let _ = write!(statement, "{column} = EXCLUDED.{column}");
    }
    statement
}

enum UpsertParam<'x> {
    Values(Vec<Option<&'x SearchValue>>),
    Configs(Vec<&'static str>),
}

impl std::fmt::Debug for UpsertParam<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpsertParam::Values(values) => write!(f, "Values({})", values.len()),
            UpsertParam::Configs(configs) => write!(f, "Configs({configs:?})"),
        }
    }
}

impl ToSql for UpsertParam<'_> {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            UpsertParam::Values(values) => values.to_sql(ty, out),
            UpsertParam::Configs(configs) => configs.to_sql(ty, out),
        }
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            UpsertParam::Values(values) => values.to_sql_checked(ty, out),
            UpsertParam::Configs(configs) => configs.to_sql_checked(ty, out),
        }
    }
}

fn account_first_columns(
    result: SearchField,
    filters: &[SearchFilter],
) -> Option<Vec<&'static str>> {
    let mut columns = Vec::with_capacity(ACCOUNT_FIRST_COLUMNS_CAPACITY);
    columns.push(result.column());
    for filter in filters {
        if let SearchFilter::Text { field, .. }
        | SearchFilter::KeyValue { field, .. }
        | SearchFilter::Integer { field, .. } = filter
        {
            if field.holds_long_text() {
                return None;
            }
            if !columns.contains(&field.column()) {
                columns.push(field.column());
            }
        }
    }
    Some(columns)
}

fn account_filter(filters: &[SearchFilter]) -> Option<u64> {
    let mut depth = 0usize;
    for filter in filters {
        match filter {
            SearchFilter::And | SearchFilter::Or | SearchFilter::Not => depth += 1,
            SearchFilter::End => depth = depth.saturating_sub(1),
            SearchFilter::Integer {
                field: SearchField::AccountId,
                op: Ordering::Equal,
                value,
            } if depth == 0 && IntegerColumn::Int4.binds(*value) => return Some(*value),
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum IntegerColumn {
    Int4,
    Int8,
}

impl IntegerColumn {
    fn of(field: &SearchField) -> Option<Self> {
        match field {
            SearchField::AccountId | SearchField::DocumentId => Some(IntegerColumn::Int4),
            SearchField::Id
            | SearchField::Tracing(TracingSearchField::EventType | TracingSearchField::QueueId) => {
                Some(IntegerColumn::Int8)
            }
            _ => None,
        }
    }

    fn type_name(self) -> &'static str {
        match self {
            IntegerColumn::Int4 => "int4",
            IntegerColumn::Int8 => "int8",
        }
    }

    fn binds(self, value: u64) -> bool {
        match self {
            IntegerColumn::Int4 => i32::try_from(value).is_ok(),
            IntegerColumn::Int8 => i64::try_from(value).is_ok(),
        }
    }
}

#[derive(Debug)]
enum FilterParam<'x> {
    Text(&'x str),
    Integer(u64, IntegerColumn),
    Ids(&'x [i32]),
}

impl FilterParam<'_> {
    fn sql_type(&self) -> Type {
        match self {
            FilterParam::Text(_) => Type::TEXT,
            FilterParam::Integer(_, IntegerColumn::Int4) => Type::INT4,
            FilterParam::Integer(_, IntegerColumn::Int8) => Type::INT8,
            FilterParam::Ids(_) => Type::INT4_ARRAY,
        }
    }
}

impl ToSql for FilterParam<'_> {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            FilterParam::Text(value) => value.to_sql(ty, out),
            FilterParam::Integer(value, _) => match *ty {
                Type::INT4 => i32::try_from(*value)?.to_sql(ty, out),
                _ => i64::try_from(*value)?.to_sql(ty, out),
            },
            FilterParam::Ids(ids) => ids.to_sql(ty, out),
        }
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            FilterParam::Text(value) => value.to_sql_checked(ty, out),
            FilterParam::Integer(value, _) => match *ty {
                Type::INT4 => i32::try_from(*value)?.to_sql_checked(ty, out),
                _ => i64::try_from(*value)?.to_sql_checked(ty, out),
            },
            FilterParam::Ids(ids) => ids.to_sql_checked(ty, out),
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
