/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Queries (SCIM-45 to SCIM-50): `GET /Users`, `GET /Groups` and the
//! `.search` endpoints. Indexed clauses pick the candidates; the rest are
//! checked on at most 200 of them.

use crate::{
    CURSOR_TIMEOUT, DEFAULT_PAGE_SIZE, MAX_RESULTS, ResourceKind, ScimResponse,
    context::Ctx,
    cursor, groups,
    resource::{Projection, get, param},
    server_error,
    users::{self, display_of, is_active, split_address},
};
use registry::schema::{enums::Permission, prelude::Property, structs::Account};
use scim_proto::{
    AttrPath, Filter, MESSAGE_LIST_RESPONSE, MESSAGE_SEARCH_REQUEST, ScimError, filter::CompareOp,
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, str::FromStr};
use store::write::now;
use types::id::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attr {
    Id,
    ExternalId,
    UserName,
    Emails,
    Active,
    DisplayName,
    Groups,
    Members,
}

impl Attr {
    fn is_indexed(&self) -> bool {
        !matches!(self, Attr::Active | Attr::DisplayName)
    }
}

#[derive(Debug, Clone)]
struct Clause {
    attr: Attr,
    value: Value,
}

/// The query parameters, from the URL or a `SearchRequest`.
#[derive(Debug, Clone, Default)]
pub struct Params {
    pub filter: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub start_index: Option<i64>,
    pub count: Option<i64>,
    pub cursor: Option<String>,
    pub projection: Projection,
}

fn number(value: &str, name: &str) -> Result<i64, ScimError> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| ScimError::invalid_value(format!("'{name}' must be a number")))
}

impl Params {
    fn from_query(query: Option<&str>) -> Result<Params, ScimError> {
        Ok(Params {
            filter: param(query, "filter"),
            sort_by: param(query, "sortBy"),
            sort_order: param(query, "sortOrder"),
            start_index: param(query, "startIndex")
                .map(|v| number(&v, "startIndex"))
                .transpose()?,
            count: param(query, "count")
                .map(|v| number(&v, "count"))
                .transpose()?,
            cursor: param(query, "cursor"),
            projection: Projection::parse(
                param(query, "attributes").as_deref(),
                param(query, "excludedAttributes").as_deref(),
            ),
        })
    }

    fn from_body(body: &Map<String, Value>) -> Result<Params, ScimError> {
        let schemas = get(body, "schemas")
            .and_then(Value::as_array)
            .ok_or_else(|| ScimError::invalid_syntax("The 'schemas' attribute is missing"))?;
        if !schemas.iter().any(|s| {
            s.as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(MESSAGE_SEARCH_REQUEST))
        }) {
            return Err(ScimError::invalid_syntax(format!(
                "'schemas' must include '{MESSAGE_SEARCH_REQUEST}'"
            )));
        }
        let string = |name: &str| get(body, name).and_then(Value::as_str).map(str::to_string);
        let int = |name: &str| -> Result<Option<i64>, ScimError> {
            match get(body, name) {
                Some(Value::Number(n)) => Ok(n.as_i64()),
                Some(Value::String(s)) => number(s, name).map(Some),
                Some(_) => Err(ScimError::invalid_value(format!(
                    "'{name}' must be a number"
                ))),
                None => Ok(None),
            }
        };
        let list = |name: &str| match get(body, name) {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };
        Ok(Params {
            filter: string("filter"),
            sort_by: string("sortBy"),
            sort_order: string("sortOrder"),
            start_index: int("startIndex")?,
            count: int("count")?,
            cursor: get(body, "cursor").map(|c| c.as_str().unwrap_or_default().to_string()),
            projection: Projection::parse(
                list("attributes").as_deref(),
                list("excludedAttributes").as_deref(),
            ),
        })
    }
}

/// The first construct outside `eq` and `and`, named (SCIM-45).
fn unsupported(filter: &Filter) -> Option<String> {
    match filter {
        Filter::And(a, b) => unsupported(a).or_else(|| unsupported(b)),
        Filter::Or(..) => Some("The 'or' operator isn't supported: use 'eq' and 'and'".into()),
        Filter::Not(_) => Some("The 'not' operator isn't supported: use 'eq' and 'and'".into()),
        Filter::Present(path) => Some(format!("'{path} pr' isn't supported: use 'eq' and 'and'")),
        Filter::ValuePath { path, .. } => Some(format!(
            "Value filters such as '{path}[...]' aren't supported in 'filter'"
        )),
        Filter::Compare { op, .. } if *op != CompareOp::Eq => Some(format!(
            "The '{}' operator isn't supported: use 'eq' and 'and'",
            op.as_str()
        )),
        Filter::Compare { .. } => None,
    }
}

fn attr_of(kind: ResourceKind, path: &AttrPath) -> Result<Attr, ScimError> {
    if let Some(urn) = &path.urn
        && !urn.eq_ignore_ascii_case(kind.schema())
    {
        return Err(ScimError::invalid_filter(format!(
            "The schema '{urn}' can't be filtered on here"
        )));
    }
    let is = |name: &str, sub: Option<&str>| path.is(name, sub);
    let attr = match kind {
        ResourceKind::User => {
            if is("id", None) {
                Some(Attr::Id)
            } else if is("externalId", None) {
                Some(Attr::ExternalId)
            } else if is("userName", None) {
                Some(Attr::UserName)
            } else if is("emails", None) || is("emails", Some("value")) {
                Some(Attr::Emails)
            } else if is("active", None) {
                Some(Attr::Active)
            } else if is("displayName", None) || is("name", Some("formatted")) {
                Some(Attr::DisplayName)
            } else if is("groups", None) || is("groups", Some("value")) {
                Some(Attr::Groups)
            } else {
                None
            }
        }
        ResourceKind::Group => {
            if is("id", None) {
                Some(Attr::Id)
            } else if is("externalId", None) {
                Some(Attr::ExternalId)
            } else if is("displayName", None) {
                Some(Attr::DisplayName)
            } else if is("members", None) || is("members", Some("value")) {
                Some(Attr::Members)
            } else {
                None
            }
        }
    };
    attr.ok_or_else(|| {
        ScimError::invalid_filter(format!("The attribute '{path}' can't be filtered on"))
    })
}

fn clauses(kind: ResourceKind, filter: &Filter, out: &mut Vec<Clause>) -> Result<(), ScimError> {
    match filter {
        Filter::And(a, b) => {
            clauses(kind, a, out)?;
            clauses(kind, b, out)
        }
        Filter::Compare { path, value, .. } => {
            out.push(Clause {
                attr: attr_of(kind, path)?,
                value: value.clone(),
            });
            Ok(())
        }
        _ => unreachable!("checked by unsupported()"),
    }
}

fn parse_filter(kind: ResourceKind, text: Option<&str>) -> Result<Vec<Clause>, ScimError> {
    let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
        return Ok(vec![]);
    };
    let filter = Filter::parse(text)?;
    if let Some(detail) = unsupported(&filter) {
        return Err(ScimError::invalid_filter(detail));
    }
    let mut out = Vec::new();
    clauses(kind, &filter, &mut out)?;
    Ok(out)
}

fn as_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Every account of the kind in scope, by domain (SCIM-16).
async fn all_in_scope(ctx: &Ctx<'_>, kind: ResourceKind) -> Result<BTreeSet<u64>, ScimError> {
    let mut ids = BTreeSet::new();
    for domain in ctx.scoped_domains().await? {
        for id in ctx
            .query_ids(Ctx::accounts_query(kind).equal(Property::DomainId, domain.id as u64))
            .await?
        {
            ids.insert(id.id());
        }
    }
    Ok(ids)
}

/// Candidates for one indexed clause.
async fn candidates(
    ctx: &Ctx<'_>,
    kind: ResourceKind,
    clause: &Clause,
) -> Result<BTreeSet<u64>, ScimError> {
    let value = as_text(&clause.value);
    let mut out = BTreeSet::new();
    match clause.attr {
        Attr::Id => {
            if let Ok(id) = Id::from_str(&value) {
                out.insert(id.id());
            }
        }
        Attr::ExternalId => {
            for id in ctx
                .query_ids(Ctx::accounts_query(kind).equal(Property::ExternalId, value))
                .await?
            {
                out.insert(id.id());
            }
        }
        Attr::UserName => {
            if let Ok((local, domain)) = split_address(&value)
                && let Some(domain) = ctx.server.domain(&domain).await.map_err(server_error)?
            {
                for id in ctx
                    .query_ids(
                        Ctx::accounts_query(kind)
                            .equal(Property::Name, local)
                            .equal(Property::DomainId, domain.id as u64),
                    )
                    .await?
                {
                    out.insert(id.id());
                }
            }
        }
        Attr::Emails => {
            if let Some(common::auth::EmailCache::Account(id)) = ctx
                .server
                .rcpt_id_from_email(&value)
                .await
                .map_err(server_error)?
            {
                out.insert(id as u64);
            }
        }
        Attr::Groups => {
            if let Ok(group) = Id::from_str(&value) {
                for id in ctx
                    .query_ids(
                        Ctx::accounts_query(kind).equal(Property::MemberGroupIds, group.id()),
                    )
                    .await?
                {
                    out.insert(id.id());
                }
            }
        }
        Attr::Members => {
            if let Ok(user) = Id::from_str(&value)
                && let Some(Account::User(user)) = ctx.load_id(user).await?
            {
                out.extend(user.member_group_ids.iter().map(|id| id.id()));
            }
        }
        Attr::Active | Attr::DisplayName => {}
    }
    Ok(out)
}

/// Checks every clause exactly on a loaded account.
async fn holds(
    ctx: &Ctx<'_>,
    id: Id,
    account: &Account,
    clauses: &[Clause],
) -> Result<bool, ScimError> {
    for clause in clauses {
        let value = as_text(&clause.value);
        let ok = match (clause.attr, account) {
            (Attr::Id, _) => id.to_string() == value,
            (Attr::ExternalId, Account::User(u)) => u.external_id.as_deref() == Some(&value),
            (Attr::ExternalId, Account::Group(g)) => g.external_id.as_deref() == Some(&value),
            (Attr::UserName, Account::User(u)) => users::primary_address(ctx, u)
                .await?
                .eq_ignore_ascii_case(&value),
            (Attr::Emails, Account::User(u)) => {
                let rendered = users::render(ctx, id, account).await?;
                let _ = u;
                rendered
                    .get("emails")
                    .and_then(Value::as_array)
                    .is_some_and(|emails| {
                        emails.iter().any(|e| {
                            e.get("value")
                                .and_then(Value::as_str)
                                .is_some_and(|v| v.eq_ignore_ascii_case(&value))
                        })
                    })
            }
            (Attr::Active, Account::User(_)) => {
                let wanted = users::parse_bool(&clause.value);
                wanted.is_some() && Some(is_active(ctx, id).await?) == wanted
            }
            (Attr::DisplayName, account) => {
                display_of(account).is_some_and(|d| d.eq_ignore_ascii_case(&value))
            }
            (Attr::Groups, Account::User(u)) => {
                u.member_group_ids.iter().any(|g| g.to_string() == value)
            }
            (Attr::Members, Account::Group(_)) => match Id::from_str(&value) {
                Ok(user) => matches!(
                    ctx.load_id(user).await?,
                    Some(Account::User(u)) if u.member_group_ids.iter().any(|g| *g == id)
                ),
                Err(_) => false,
            },
            _ => false,
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The ids matching the filter, in scope, sorted (SCIM-45 to SCIM-47).
async fn matching(
    ctx: &Ctx<'_>,
    kind: ResourceKind,
    clauses: &[Clause],
    sort_by: Option<&str>,
    descending: bool,
) -> Result<Vec<Id>, ScimError> {
    let indexed = clauses
        .iter()
        .filter(|c| c.attr.is_indexed())
        .collect::<Vec<_>>();
    let mut ids: Vec<Id> = if indexed.is_empty() {
        let all = all_in_scope(ctx, kind).await?;
        if clauses.is_empty() {
            all.into_iter().map(Id::from).collect()
        } else {
            // SCIM-46: unindexed clauses on at most 200 candidates
            if all.len() > MAX_RESULTS {
                return Err(ScimError::too_many(format!(
                    "The filter leaves more than {MAX_RESULTS} candidates: narrow it with \
                     an indexed attribute such as userName or externalId"
                )));
            }
            let mut out = Vec::new();
            for id in all {
                let id = Id::from(id);
                if let Some(account) = ctx.load_id(id).await?
                    && holds(ctx, id, &account, clauses).await?
                {
                    out.push(id);
                }
            }
            out
        }
    } else {
        let mut set: Option<BTreeSet<u64>> = None;
        for clause in &indexed {
            let found = candidates(ctx, kind, clause).await?;
            set = Some(match set {
                Some(set) => set.intersection(&found).copied().collect(),
                None => found,
            });
        }
        let set = set.unwrap_or_default();
        if clauses.iter().any(|c| !c.attr.is_indexed()) && set.len() > MAX_RESULTS {
            return Err(ScimError::too_many(format!(
                "The filter leaves more than {MAX_RESULTS} candidates: narrow it"
            )));
        }
        let mut out = Vec::new();
        for id in set {
            let id = Id::from(id);
            if let Ok((id, account)) = ctx.load(kind, &id.to_string()).await
                && holds(ctx, id, &account, clauses).await?
            {
                out.push(id);
            }
        }
        out
    };

    // SCIM-47: by id unless told otherwise
    match sort_by {
        None => ids.sort_by_key(|id| id.id()),
        Some(attr) if attr.eq_ignore_ascii_case("id") => ids.sort_by_key(|id| id.id()),
        Some(attr) if kind == ResourceKind::User && attr.eq_ignore_ascii_case("userName") => {
            let mut keyed = Vec::with_capacity(ids.len());
            for id in ids {
                let name = match ctx.load_id(id).await? {
                    Some(Account::User(user)) => users::primary_address(ctx, &user).await?,
                    _ => String::new(),
                };
                keyed.push((name, id.id(), id));
            }
            keyed.sort();
            ids = keyed.into_iter().map(|(_, _, id)| id).collect();
        }
        Some(attr) => {
            return Err(ScimError::invalid_value(format!(
                "Results can't be sorted by '{attr}'"
            )));
        }
    }
    if descending {
        ids.reverse();
    }
    Ok(ids)
}

pub async fn list(
    ctx: &Ctx<'_>,
    kind: ResourceKind,
    query: Option<&str>,
) -> Result<ScimResponse, ScimError> {
    run(ctx, &[kind], Params::from_query(query)?).await
}

pub async fn search(
    ctx: &Ctx<'_>,
    kind: Option<ResourceKind>,
    body: &Map<String, Value>,
) -> Result<ScimResponse, ScimError> {
    let params = Params::from_body(body)?;
    match kind {
        Some(kind) => run(ctx, &[kind], params).await,
        // SCIM-50: users first, then groups
        None => run(ctx, &[ResourceKind::User, ResourceKind::Group], params).await,
    }
}

async fn run(
    ctx: &Ctx<'_>,
    kinds: &[ResourceKind],
    params: Params,
) -> Result<ScimResponse, ScimError> {
    ctx.require(Permission::SysAccountGet)?;

    let descending = match params.sort_order.as_deref() {
        None => false,
        Some(order) if order.eq_ignore_ascii_case("ascending") => false,
        Some(order) if order.eq_ignore_ascii_case("descending") => true,
        Some(order) => {
            return Err(ScimError::invalid_value(format!(
                "'{order}' isn't a sort order"
            )));
        }
    };
    if params.cursor.is_some() && params.start_index.is_some() {
        return Err(ScimError::invalid_value(
            "'startIndex' and 'cursor' can't be used together",
        ));
    }
    let count = params
        .count
        .map(|c| c.clamp(0, MAX_RESULTS as i64) as usize)
        .unwrap_or(DEFAULT_PAGE_SIZE);

    // Each kind's filter; one the kind can't answer matches none of it
    let mut all = Vec::new();
    let mut last_error = None;
    let mut answered = false;
    for kind in kinds {
        match parse_filter(*kind, params.filter.as_deref()) {
            Ok(clauses) => {
                answered = true;
                for id in
                    matching(ctx, *kind, &clauses, params.sort_by.as_deref(), descending).await?
                {
                    all.push((*kind, id));
                }
            }
            Err(err)
                if kinds.len() > 1
                    && err.scim_type == Some(scim_proto::ScimType::InvalidFilter) =>
            {
                last_error = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    if !answered && let Some(err) = last_error {
        return Err(err);
    }
    let total = all.len();

    // SCIM-48 and SCIM-49: pages by index or by cursor
    let key = ctx.server.core.oauth.oauth_key.as_bytes();
    let binding = cursor::binding(&[
        &ctx.principal_id().to_string(),
        &kinds.iter().map(|k| k.name()).collect::<Vec<_>>().join(","),
        params.filter.as_deref().unwrap_or_default(),
        params.sort_by.as_deref().unwrap_or_default(),
        params.sort_order.as_deref().unwrap_or_default(),
    ]);
    let start = match &params.cursor {
        Some(c) if c.is_empty() => 0,
        Some(c) => cursor::decode(key, c, count as u64, now(), binding)? as usize,
        None => params.start_index.unwrap_or(1).max(1) as usize - 1,
    };
    let page = all.iter().skip(start).take(count).collect::<Vec<_>>();

    let mut resources = Vec::with_capacity(page.len());
    for (kind, id) in &page {
        let (id, account) = ctx.load(*kind, &id.to_string()).await?;
        let doc = match kind {
            ResourceKind::User => users::render(ctx, id, &account).await?,
            ResourceKind::Group => {
                groups::render(ctx, id, &account, Some(&params.projection)).await?
            }
        };
        resources.push(params.projection.apply(doc));
    }

    let mut body = json!({
        "schemas": [MESSAGE_LIST_RESPONSE],
        "totalResults": total,
        "itemsPerPage": resources.len(),
    });
    if params.cursor.is_some() {
        let next = start + page.len();
        if next < total && count > 0 {
            body["nextCursor"] = json!(cursor::encode(
                key,
                next as u64,
                count as u64,
                now() + CURSOR_TIMEOUT,
                binding
            ));
        }
    } else {
        body["startIndex"] = json!(start + 1);
    }
    if count > 0 {
        body["Resources"] = Value::Array(resources);
    }
    Ok(ScimResponse::json(200, body))
}
