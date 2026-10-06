/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Groups (SCIM-34 to SCIM-38): an `x:GroupAccount` as a SCIM Group, with
//! membership kept on each member (`memberGroupIds`).

use crate::{
    MAX_RESULTS, ResourceKind,
    context::Ctx,
    resource::{Projection, WriteMode, audit, check_attributes, get, stamp},
    server_error,
    users::{check_external_id, display_of},
};
use registry::schema::{enums::Permission, prelude::Property, structs::Account};
use scim_proto::{SCHEMA_GROUP, ScimError};
use serde_json::{Map, Value, json};
use std::str::FromStr;
use types::id::Id;

const KNOWN: &[&str] = &[
    "schemas",
    "id",
    "externalId",
    "meta",
    "displayName",
    "members",
    "description",
];

/// Ids of the users in scope that are members of the group.
pub async fn member_ids(ctx: &Ctx<'_>, group_id: Id) -> Result<Vec<(Id, Account)>, ScimError> {
    let ids = ctx
        .query_ids(
            Ctx::accounts_query(ResourceKind::User).equal(Property::MemberGroupIds, group_id.id()),
        )
        .await?;
    let mut members = Vec::new();
    for id in ids {
        if let Some(account) = ctx.load_id(id).await?
            && ctx.in_scope(&account).await?
        {
            members.push((id, account));
        }
    }
    members.sort_by_key(|(id, _)| id.id());
    Ok(members)
}

pub async fn render(
    ctx: &Ctx<'_>,
    id: Id,
    account: &Account,
    projection: Option<&Projection>,
) -> Result<Value, ScimError> {
    let Account::Group(group) = account else {
        return Err(ScimError::not_found(format!("Group {id} not found")));
    };
    let members = member_ids(ctx, id).await?;
    // SCIM-37
    if members.len() > MAX_RESULTS && projection.is_some_and(|p| p.includes("members")) {
        return Err(ScimError::too_many(format!(
            "The group has more than {MAX_RESULTS} members: read it with \
             excludedAttributes=members, and membership from the users' 'groups'"
        )));
    }
    let mut doc = Map::new();
    doc.insert("schemas".into(), json!([SCHEMA_GROUP]));
    doc.insert("id".into(), json!(id.to_string()));
    if let Some(external_id) = &group.external_id {
        doc.insert("externalId".into(), json!(external_id));
    }
    doc.insert("displayName".into(), json!(display_of(account)));
    doc.insert(
        "members".into(),
        Value::Array(
            members
                .iter()
                .map(|(member_id, member)| {
                    json!({
                        "value": member_id.to_string(),
                        "display": display_of(member),
                        "type": "User",
                        "$ref": ctx.location(ResourceKind::User, *member_id),
                    })
                })
                .collect(),
        ),
    );
    doc.insert(
        "meta".into(),
        json!({
            "resourceType": "Group",
            "created": group.created_at.to_string(),
            "location": ctx.location(ResourceKind::Group, id),
        }),
    );
    Ok(stamp(Value::Object(doc)))
}

/// `Sales EMEA` becomes `sales-emea` (SCIM-35).
pub fn slug(display: &str) -> String {
    let mut out = String::new();
    let mut hyphen = false;
    for c in display.chars() {
        if c.is_ascii_alphanumeric() {
            if hyphen && !out.is_empty() {
                out.push('-');
            }
            hyphen = false;
            out.push(c.to_ascii_lowercase());
        } else {
            hyphen = true;
        }
    }
    if out.is_empty() {
        "group".to_string()
    } else {
        out
    }
}

/// `displayName` is unique among groups in scope, in any case (SCIM-34).
async fn check_display_name(
    ctx: &Ctx<'_>,
    display: &str,
    except: Option<Id>,
) -> Result<(), ScimError> {
    for domain in ctx.scoped_domains().await? {
        let ids = ctx
            .query_ids(
                Ctx::accounts_query(ResourceKind::Group)
                    .equal(Property::DomainId, domain.id as u64),
            )
            .await?;
        for id in ids {
            if Some(id) == except {
                continue;
            }
            if let Some(group) = ctx.load_id(id).await?
                && display_of(&group).is_some_and(|name| name.eq_ignore_ascii_case(display))
            {
                return Err(ScimError::conflict(format!(
                    "A group named '{display}' already exists"
                )));
            }
        }
    }
    Ok(())
}

/// The members sent, as ids of users in scope and in the group's tenant
/// (SCIM-19, SCIM-36).
async fn resolve_members(
    ctx: &Ctx<'_>,
    body: &Map<String, Value>,
    tenant: Option<u32>,
) -> Result<Vec<(Id, Account)>, ScimError> {
    let Some(members) = get(body, "members") else {
        return Ok(vec![]);
    };
    let members = members
        .as_array()
        .ok_or_else(|| ScimError::invalid_syntax("'members' must be a list"))?;
    let mut resolved: Vec<(Id, Account)> = Vec::new();
    for member in members {
        let value = member
            .as_object()
            .and_then(|m| get(m, "value"))
            .and_then(Value::as_str)
            .ok_or_else(|| ScimError::invalid_value("Each member needs a 'value'"))?;
        if resolved.iter().any(|(id, _)| id.to_string() == value) {
            continue;
        }
        let unknown =
            || ScimError::invalid_value(format!("The member '{value}' isn't a user in scope"));
        let id = Id::from_str(value).map_err(|_| unknown())?;
        let account = ctx.load_id(id).await?.ok_or_else(unknown)?;
        // Outside the caller's scope it doesn't exist (SCIM-17)
        if !ctx.in_scope(&account).await? {
            return Err(unknown());
        }
        if matches!(account, Account::Group(_)) {
            return Err(ScimError::invalid_value(format!(
                "The member '{value}' is a group: only users can be members"
            )));
        }
        let member_tenant = match &account {
            Account::User(user) => user.member_tenant_id.map(|t| t.document_id()),
            Account::Group(_) => None,
        };
        // In scope, it may still be in another tenant from the group's
        // (SCIM-19)
        if member_tenant != tenant {
            return Err(ScimError::invalid_value(format!(
                "The member '{value}' is in a different tenant from the group"
            )));
        }
        resolved.push((id, account));
    }
    Ok(resolved)
}

/// Adds or removes one membership, written on the user (SCIM-36).
async fn set_membership(
    ctx: &Ctx<'_>,
    user_id: Id,
    user: &Account,
    group_id: Id,
    member: bool,
) -> Result<(), ScimError> {
    let Account::User(user) = user else {
        return Ok(());
    };
    let mut groups = user
        .member_group_ids
        .iter()
        .copied()
        .filter(|id| *id != group_id)
        .collect::<Vec<_>>();
    if member {
        groups.push(group_id);
    }
    let map = groups
        .iter()
        .map(|id| (id.to_string(), Value::Bool(true)))
        .collect::<Map<_, _>>();
    ctx.update(user_id, json!({"memberGroupIds": map})).await
}

/// Removes every membership of the group, in scope or not, so it can be
/// destroyed (SCIM-53).
pub async fn remove_all_members(ctx: &Ctx<'_>, group_id: Id) -> Result<(), ScimError> {
    let ids = ctx
        .query_ids(
            Ctx::accounts_query(ResourceKind::User).equal(Property::MemberGroupIds, group_id.id()),
        )
        .await?;
    for id in ids {
        if let Some(account) = ctx.load_id(id).await? {
            set_membership(ctx, id, &account, group_id, false).await?;
        }
    }
    Ok(())
}

fn display_name(body: &Map<String, Value>) -> Result<String, ScimError> {
    get(body, "displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ScimError::invalid_value("'displayName' is required"))
}

fn external_id(body: &Map<String, Value>) -> Result<Option<String>, ScimError> {
    match get(body, "externalId") {
        Some(Value::String(id)) if id.is_empty() => {
            Err(ScimError::invalid_value("'externalId' can't be empty"))
        }
        Some(Value::String(id)) => Ok(Some(id.clone())),
        Some(_) => Err(ScimError::invalid_value("'externalId' must be a string")),
        None => Ok(None),
    }
}

/// `POST /Groups` (SCIM-18, SCIM-34 to SCIM-36, SCIM-39).
pub async fn create(ctx: &Ctx<'_>, body: &Map<String, Value>) -> Result<Id, ScimError> {
    check_attributes(body, ResourceKind::Group, KNOWN)?;
    let display = display_name(body)?;
    let external_id = external_id(body)?;

    // SCIM-18: on the service principal's own domain
    let principal = ctx
        .load_id(Id::from(ctx.principal_id()))
        .await?
        .ok_or_else(|| ScimError::forbidden("The service principal no longer exists"))?;
    let Account::User(principal) = principal else {
        return Err(ScimError::forbidden("The service principal isn't a user"));
    };
    let domain = match ctx.scoped_domain(principal.domain_id.document_id()).await? {
        Some(domain) => domain,
        None => {
            let name = ctx
                .server
                .domain_by_id(principal.domain_id.document_id())
                .await
                .map_err(server_error)?
                .map(|d| d.name().to_string())
                .unwrap_or_default();
            return Err(ScimError::invalid_value(format!(
                "Groups go on the service principal's domain '{name}', which isn't open to SCIM provisioning"
            )));
        }
    };
    let tenant = domain.id_tenant;

    let members = resolve_members(ctx, body, tenant).await?;
    if !members.is_empty() {
        ctx.require(Permission::SysAccountUpdate)?;
    }
    check_display_name(ctx, &display, None).await?;
    if let Some(external_id) = &external_id {
        check_external_id(ctx, ResourceKind::Group, external_id, tenant, None).await?;
    }

    // SCIM-35: the first free address from the display name
    let base = slug(&display);
    // Cut to 64 with room for a `-1000` suffix
    let base = base[..base.len().min(59)].trim_end_matches('-').to_string();
    let mut name = None;
    for n in 1..=1000 {
        let candidate = if n == 1 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        if ctx
            .server
            .rcpt_id_from_parts(&candidate, domain.id)
            .await
            .map_err(server_error)?
            .is_none()
        {
            name = Some(candidate);
            break;
        }
    }
    let name = name.ok_or_else(|| {
        ScimError::conflict(format!(
            "No free address was found for the group '{display}'"
        ))
    })?;

    let mut object = json!({
        "@type": "Group",
        "name": name,
        "domainId": Id::from(domain.id).to_string(),
        "description": display,
        "externalId": external_id,
    });
    // MT-7: in its domain's tenant; a tenant caller's writes get it anyway
    if let Some(tenant) = tenant
        && ctx.tenant_id().is_none()
    {
        object["memberTenantId"] = json!(Id::from(tenant).to_string());
    }
    let id = ctx.create(object).await?;
    for (member_id, member) in &members {
        set_membership(ctx, *member_id, member, id, true).await?;
    }
    audit(
        ctx,
        trc::ScimEvent::ResourceCreated,
        ResourceKind::Group,
        id,
        external_id.as_deref(),
    );
    Ok(id)
}

/// `PUT` and the result of `PATCH` (SCIM-36, SCIM-41, SCIM-42).
pub async fn replace(
    ctx: &Ctx<'_>,
    id: Id,
    account: &Account,
    _current: &Value,
    body: &Map<String, Value>,
    _mode: WriteMode,
) -> Result<(), ScimError> {
    let Account::Group(group) = account else {
        return Err(ScimError::not_found(format!("Group {id} not found")));
    };
    check_attributes(body, ResourceKind::Group, KNOWN)?;
    if let Some(sent) = get(body, "id").and_then(Value::as_str)
        && sent != id.to_string()
    {
        return Err(ScimError::mutability("'id' can't be changed"));
    }
    let display = display_name(body)?;
    let external_id = external_id(body)?;
    let tenant = group.member_tenant_id.map(|t| t.document_id());
    let wanted = resolve_members(ctx, body, tenant).await?;

    let mut patch = Map::new();
    if Some(&display) != display_of(account).as_ref() {
        check_display_name(ctx, &display, Some(id)).await?;
        patch.insert("description".into(), json!(display));
    }
    if external_id != group.external_id {
        if let Some(external_id) = &external_id {
            check_external_id(ctx, ResourceKind::Group, external_id, tenant, Some(id)).await?;
        }
        patch.insert("externalId".into(), json!(external_id));
    }

    // Membership: add the new, remove the gone (SCIM-36)
    let now = member_ids(ctx, id).await?;
    let changed = !patch.is_empty();
    if changed {
        ctx.update(id, Value::Object(patch)).await?;
    }
    let mut membership_changed = false;
    for (member_id, member) in &wanted {
        if !now.iter().any(|(id, _)| id == member_id) {
            set_membership(ctx, *member_id, member, id, true).await?;
            membership_changed = true;
        }
    }
    for (member_id, member) in &now {
        if !wanted.iter().any(|(id, _)| id == member_id) {
            set_membership(ctx, *member_id, member, id, false).await?;
            membership_changed = true;
        }
    }
    if changed || membership_changed {
        audit(
            ctx,
            trc::ScimEvent::ResourceUpdated,
            ResourceKind::Group,
            id,
            external_id.as_deref(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::slug;

    #[test]
    fn derives_addresses() {
        assert_eq!(slug("Sales EMEA"), "sales-emea");
        assert_eq!(slug("  --R&D / Ops!! "), "r-d-ops");
        assert_eq!(slug("日本"), "group");
    }
}
