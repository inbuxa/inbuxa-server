/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Users (SCIM-21 to SCIM-33): an `x:UserAccount` as a SCIM User, and a
//! SCIM User written back as one.

use crate::{
    ResourceKind,
    context::Ctx,
    resource::{WriteMode, audit, check_attributes, get, stamp},
    server_error,
};
use registry::{
    schema::{
        enums::{Locale, Permission, TimeZone},
        structs::{Account, Permissions, UserAccount},
    },
    types::EnumImpl,
};
use scim_proto::{SCHEMA_USER, ScimError};
use serde_json::{Map, Value, json};
use std::{collections::HashMap, sync::OnceLock};
use types::id::Id;

/// Every attribute a User body may carry. Those not in the mapping table
/// are accepted and discarded (SCIM-33).
const KNOWN: &[&str] = &[
    "schemas",
    "id",
    "externalId",
    "meta",
    "userName",
    "name",
    "displayName",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "preferredLanguage",
    "locale",
    "timezone",
    "active",
    "password",
    "emails",
    "phoneNumbers",
    "ims",
    "photos",
    "addresses",
    "groups",
    "entitlements",
    "roles",
    "x509Certificates",
];

/// A User as sent, reduced to what is stored.
#[derive(Debug, Clone)]
pub struct UserInput {
    pub user_name: String,
    pub local: String,
    pub domain: String,
    pub display: Option<String>,
    pub active: Option<bool>,
    pub aliases: Vec<String>,
    pub locale: Option<Locale>,
    pub time_zone: Option<TimeZone>,
    pub external_id: Option<String>,
    pub groups: Option<Vec<String>>,
}

fn text(value: &Value) -> Option<&str> {
    value.as_str().map(str::trim).filter(|s| !s.is_empty())
}

/// `userName` as a full address, lowercased (SCIM-15, SCIM-22).
pub fn split_address(address: &str) -> Result<(String, String), ScimError> {
    let address = address.trim().to_lowercase();
    let invalid = || {
        ScimError::invalid_value(format!(
            "The userName '{address}' is not a valid email address"
        ))
    };
    let (local, domain) = address.rsplit_once('@').ok_or_else(invalid)?;
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || local.chars().any(|c| c.is_whitespace() || c == '@')
        || domain
            .chars()
            .any(|c| !(c.is_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(invalid());
    }
    Ok((local.to_string(), domain.to_string()))
}

/// `true` and `false`, as JSON or as strings in any case (SCIM-27).
pub fn parse_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// A locale in SCIM's form (`en-US`, `ca-ES@valencia`), matched in any
/// case (SCIM-26).
pub fn parse_locale(value: &str) -> Option<Locale> {
    static LOCALES: OnceLock<HashMap<String, Locale>> = OnceLock::new();
    let key = value.trim().replace(['_', '@'], "-").to_lowercase();
    LOCALES
        .get_or_init(|| {
            (0..Locale::COUNT as u16)
                .filter_map(Locale::from_id)
                .map(|locale| (locale.as_str().to_lowercase(), locale))
                .collect()
        })
        .get(&key)
        .copied()
}

/// An IANA time zone, matched in any case (SCIM-26).
pub fn parse_time_zone(value: &str) -> Option<TimeZone> {
    static ZONES: OnceLock<HashMap<String, TimeZone>> = OnceLock::new();
    ZONES
        .get_or_init(|| {
            (0..TimeZone::COUNT as u16)
                .filter_map(TimeZone::from_id)
                .map(|zone| (zone.as_str().to_lowercase(), zone))
                .collect()
        })
        .get(&value.trim().to_lowercase())
        .copied()
}

/// The display name by precedence: `displayName`, `name.formatted`, then
/// the given and family names (SCIM-24).
fn display_name(body: &Map<String, Value>) -> Option<String> {
    if let Some(name) = get(body, "displayName").and_then(text) {
        return Some(name.to_string());
    }
    let name = get(body, "name").and_then(Value::as_object)?;
    if let Some(formatted) = get(name, "formatted").and_then(text) {
        return Some(formatted.to_string());
    }
    let parts = ["givenName", "familyName"]
        .into_iter()
        .filter_map(|part| get(name, part).and_then(text))
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" "))
}

pub fn parse(body: &Map<String, Value>) -> Result<UserInput, ScimError> {
    check_attributes(body, ResourceKind::User, KNOWN)?;

    let user_name = get(body, "userName")
        .and_then(Value::as_str)
        .ok_or_else(|| ScimError::invalid_value("'userName' is required"))?;
    let (local, domain) = split_address(user_name)?;
    let user_name = format!("{local}@{domain}");

    // SCIM-25: the primary comes from userName; every other entry is an alias
    let mut aliases: Vec<String> = Vec::new();
    if let Some(emails) = get(body, "emails") {
        let emails = emails
            .as_array()
            .ok_or_else(|| ScimError::invalid_syntax("'emails' must be a list"))?;
        for email in emails {
            let email = email
                .as_object()
                .ok_or_else(|| ScimError::invalid_syntax("Each email must be an object"))?;
            let value = get(email, "value")
                .and_then(text)
                .ok_or_else(|| ScimError::invalid_value("An email needs a 'value'"))?
                .to_lowercase();
            if value == user_name {
                let is_primary = get(email, "primary").and_then(parse_bool);
                let typ = get(email, "type").and_then(Value::as_str);
                if is_primary == Some(false) || typ.is_some_and(|t| !t.eq_ignore_ascii_case("work"))
                {
                    return Err(ScimError::mutability(
                        "The primary email is set by 'userName' and can't be changed through 'emails'",
                    ));
                }
                continue;
            }
            split_address(&value).map_err(|_| {
                ScimError::invalid_value(format!("The email '{value}' isn't a valid address"))
            })?;
            if !aliases.contains(&value) {
                aliases.push(value);
            }
        }
    }

    // SCIM-26: locale wins over preferredLanguage
    let locale = match get(body, "locale").or_else(|| get(body, "preferredLanguage")) {
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| ScimError::invalid_value("A locale must be a string"))?;
            Some(parse_locale(text).ok_or_else(|| {
                ScimError::invalid_value(format!("The locale '{text}' isn't supported"))
            })?)
        }
        None => None,
    };
    let time_zone = match get(body, "timezone") {
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| ScimError::invalid_value("'timezone' must be a string"))?;
            Some(parse_time_zone(text).ok_or_else(|| {
                ScimError::invalid_value(format!("The time zone '{text}' isn't known"))
            })?)
        }
        None => None,
    };

    // SCIM-29
    let external_id = match get(body, "externalId") {
        Some(Value::String(id)) if id.is_empty() => {
            return Err(ScimError::invalid_value("'externalId' can't be empty"));
        }
        Some(Value::String(id)) => Some(id.clone()),
        Some(_) => return Err(ScimError::invalid_value("'externalId' must be a string")),
        None => None,
    };

    let active = match get(body, "active") {
        Some(value) => Some(
            parse_bool(value)
                .ok_or_else(|| ScimError::invalid_value("'active' must be a boolean"))?,
        ),
        None => None,
    };

    let groups = match get(body, "groups") {
        Some(Value::Array(groups)) => Some(
            groups
                .iter()
                .filter_map(|g| g.get("value").and_then(Value::as_str).map(str::to_string))
                .collect::<Vec<_>>(),
        ),
        Some(_) => return Err(ScimError::invalid_syntax("'groups' must be a list")),
        None => None,
    };

    Ok(UserInput {
        user_name,
        local,
        domain,
        display: display_name(body),
        active,
        aliases,
        locale,
        time_zone,
        external_id,
        groups,
    })
}

/// A domain's first name.
async fn domain_name(ctx: &Ctx<'_>, domain_id: Id) -> Result<String, ScimError> {
    Ok(ctx
        .server
        .domain_by_id(domain_id.document_id())
        .await
        .map_err(server_error)?
        .map(|domain| domain.name().to_string())
        .unwrap_or_default())
}

/// The account's effective `authenticate` permission (SCIM-27).
pub async fn is_active(ctx: &Ctx<'_>, id: Id) -> Result<bool, ScimError> {
    Ok(ctx
        .server
        .access_token(id.document_id())
        .await
        .map_err(server_error)?
        .account_has_permission(Permission::Authenticate))
}

pub async fn primary_address(ctx: &Ctx<'_>, user: &UserAccount) -> Result<String, ScimError> {
    Ok(format!(
        "{}@{}",
        user.name,
        domain_name(ctx, user.domain_id).await?
    ))
}

/// The display name of a user or group, as SCIM shows it.
pub fn display_of(account: &Account) -> Option<String> {
    match account {
        Account::User(user) => user.description.clone(),
        Account::Group(group) => group
            .description
            .clone()
            .or_else(|| Some(group.name.clone())),
    }
}

pub async fn render(ctx: &Ctx<'_>, id: Id, account: &Account) -> Result<Value, ScimError> {
    let Account::User(user) = account else {
        return Err(ScimError::not_found(format!("User {id} not found")));
    };
    let user_name = primary_address(ctx, user).await?;
    let mut emails = vec![json!({"value": user_name, "type": "work", "primary": true})];
    for alias in user.aliases.values() {
        let address = format!(
            "{}@{}",
            alias.name,
            domain_name(ctx, alias.domain_id).await?
        );
        if address != user_name {
            emails.push(json!({"value": address, "primary": false}));
        }
    }
    let mut groups = Vec::new();
    for group_id in user.member_group_ids.iter() {
        if let Some(group) = ctx.load_id(*group_id).await?
            && matches!(group, Account::Group(_))
            && ctx.in_scope(&group).await?
        {
            groups.push(json!({
                "value": group_id.to_string(),
                "display": display_of(&group),
                "$ref": ctx.location(ResourceKind::Group, *group_id),
            }));
        }
    }

    let mut doc = Map::new();
    doc.insert("schemas".into(), json!([SCHEMA_USER]));
    doc.insert("id".into(), json!(id.to_string()));
    if let Some(external_id) = &user.external_id {
        doc.insert("externalId".into(), json!(external_id));
    }
    doc.insert("userName".into(), json!(user_name));
    if let Some(display) = &user.description {
        doc.insert("displayName".into(), json!(display));
        doc.insert("name".into(), json!({"formatted": display}));
    }
    doc.insert("active".into(), json!(is_active(ctx, id).await?));
    doc.insert("emails".into(), Value::Array(emails));
    doc.insert("locale".into(), json!(user.locale.as_str()));
    doc.insert("preferredLanguage".into(), json!(user.locale.as_str()));
    if let Some(zone) = &user.time_zone {
        doc.insert("timezone".into(), json!(zone.as_str()));
    }
    doc.insert("groups".into(), Value::Array(groups));
    doc.insert(
        "meta".into(),
        json!({
            "resourceType": "User",
            "created": user.created_at.to_string(),
            "location": ctx.location(ResourceKind::User, id),
        }),
    );
    Ok(stamp(Value::Object(doc)))
}

/// `permissions` with the `authenticate` entry that SCIM owns set or
/// cleared (SCIM-27). `None` when nothing changes.
fn with_active(permissions: &Permissions, active: bool) -> Option<Permissions> {
    let disabled = |permissions: &Permissions| match permissions {
        Permissions::Inherit => false,
        Permissions::Merge(list) | Permissions::Replace(list) => list
            .disabled_permissions
            .iter()
            .any(|p| *p == Permission::Authenticate),
    };
    let is_disabled = disabled(permissions);
    if is_disabled != active {
        return None;
    }
    let mut permissions = permissions.clone();
    if active {
        match &mut permissions {
            Permissions::Merge(list) | Permissions::Replace(list) => {
                list.disabled_permissions
                    .inner_mut()
                    .retain(|p| *p != Permission::Authenticate);
            }
            Permissions::Inherit => {}
        }
        // An account that was Inherit goes back to exactly Inherit
        if let Permissions::Merge(list) = &permissions
            && list.enabled_permissions.is_empty()
            && list.disabled_permissions.is_empty()
        {
            permissions = Permissions::Inherit;
        }
    } else {
        match &mut permissions {
            Permissions::Inherit => {
                permissions = Permissions::Merge(registry::schema::structs::PermissionsList {
                    enabled_permissions: Default::default(),
                    disabled_permissions: registry::types::map::Map::new(vec![
                        Permission::Authenticate,
                    ]),
                });
            }
            Permissions::Merge(list) | Permissions::Replace(list) => {
                list.disabled_permissions.push(Permission::Authenticate);
            }
        }
    }
    Some(permissions)
}

/// The aliases as `x:UserAccount.aliases`, each on a domain open to SCIM
/// in the account's tenant (SCIM-15, SCIM-25).
async fn alias_objects(
    ctx: &Ctx<'_>,
    aliases: &[String],
    tenant: Option<u32>,
) -> Result<Value, ScimError> {
    let mut objects = Map::new();
    for (index, alias) in aliases.iter().enumerate() {
        let (local, domain) = split_address(alias)?;
        let domain = ctx.writable_domain(&domain).await?;
        if domain.id_tenant != tenant {
            return Err(ScimError::invalid_value(format!(
                "The domain '{}' is in a different tenant from the account",
                domain.name()
            )));
        }
        objects.insert(
            index.to_string(),
            json!({
                "enabled": true,
                "name": local,
                "domainId": Id::from(domain.id).to_string(),
            }),
        );
    }
    Ok(Value::Object(objects))
}

/// SCIM-29: no other user in the same tenant holds that `externalId`.
pub async fn check_external_id(
    ctx: &Ctx<'_>,
    kind: ResourceKind,
    external_id: &str,
    tenant: Option<u32>,
    except: Option<Id>,
) -> Result<(), ScimError> {
    let ids = ctx
        .server
        .registry()
        .query::<Vec<Id>>(
            Ctx::accounts_query(kind)
                .equal(
                    registry::schema::prelude::Property::ExternalId,
                    external_id.to_string(),
                )
                .with_tenant(tenant),
        )
        .await
        .map_err(server_error)?;
    for id in ids {
        if Some(id) == except {
            continue;
        }
        if let Some(account) = ctx.load_id(id).await? {
            let (other_tenant, other_external) = match &account {
                Account::User(u) => (u.member_tenant_id, u.external_id.as_deref()),
                Account::Group(g) => (g.member_tenant_id, g.external_id.as_deref()),
            };
            if other_tenant.map(|t| t.document_id()) == tenant
                && other_external == Some(external_id)
            {
                return Err(ScimError::conflict(format!(
                    "The externalId '{external_id}' is already in use"
                )));
            }
        }
    }
    Ok(())
}

/// Checks a `groups` value is the current membership (SCIM-28 decision).
fn check_groups(input: &UserInput, current: &Value) -> Result<(), ScimError> {
    if let Some(groups) = &input.groups {
        let mut sent = groups.clone();
        sent.sort();
        let mut now = current
            .get("groups")
            .and_then(Value::as_array)
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|g| g.get("value").and_then(Value::as_str).map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        now.sort();
        if sent != now {
            return Err(ScimError::mutability(
                "'groups' is read-only: change membership through the Group",
            ));
        }
    }
    Ok(())
}

/// `POST /Users` (SCIM-31, SCIM-39).
pub async fn create(ctx: &Ctx<'_>, body: &Map<String, Value>) -> Result<Id, ScimError> {
    let input = parse(body)?;
    if input
        .groups
        .as_ref()
        .is_some_and(|groups| !groups.is_empty())
    {
        return Err(ScimError::mutability(
            "'groups' is read-only: add the user through the Group",
        ));
    }
    let domain = ctx.writable_domain(&input.domain).await?;
    let tenant = domain.id_tenant;
    let aliases = alias_objects(ctx, &input.aliases, tenant).await?;
    if let Some(external_id) = &input.external_id {
        check_external_id(ctx, ResourceKind::User, external_id, tenant, None).await?;
    }
    let permissions = if input.active == Some(false) {
        with_active(&Permissions::Inherit, false).unwrap_or(Permissions::Inherit)
    } else {
        Permissions::Inherit
    };
    let mut object = json!({
        "@type": "User",
        "name": input.local,
        "domainId": Id::from(domain.id).to_string(),
        "description": input.display,
        "aliases": aliases,
        "roles": {"@type": "User"},
        "permissions": permissions,
        "externalId": input.external_id,
    });
    // MT-7: in its domain's tenant; a tenant caller's writes get it anyway
    if let Some(tenant) = tenant
        && ctx.tenant_id().is_none()
    {
        object["memberTenantId"] = json!(Id::from(tenant).to_string());
    }
    if let Some(locale) = input.locale {
        object["locale"] = json!(locale.as_str());
    }
    if let Some(zone) = input.time_zone {
        object["timeZone"] = json!(zone.as_str());
    }
    let id = ctx.create(object).await?;
    audit(
        ctx,
        trc::ScimEvent::ResourceCreated,
        ResourceKind::User,
        id,
        input.external_id.as_deref(),
    );
    Ok(id)
}

/// `PUT` and the result of `PATCH` (SCIM-23, SCIM-41, SCIM-42): every
/// readWrite attribute takes the sent value or its default.
pub async fn replace(
    ctx: &Ctx<'_>,
    id: Id,
    account: &Account,
    current: &Value,
    body: &Map<String, Value>,
    mode: crate::resource::WriteMode,
) -> Result<(), ScimError> {
    let Account::User(user) = account else {
        return Err(ScimError::not_found(format!("User {id} not found")));
    };
    if let Some(sent) = get(body, "id").and_then(Value::as_str)
        && sent != id.to_string()
    {
        return Err(ScimError::mutability("'id' can't be changed"));
    }
    let input = parse(body)?;
    check_groups(&input, current)?;

    let is_self = id.document_id() == ctx.principal_id();
    let current_name = current
        .get("userName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tenant = user.member_tenant_id.map(|t| t.document_id());
    let mut patch = Map::new();

    // SCIM-23: a new userName moves the account, within its tenant
    if input.user_name != current_name {
        if is_self {
            return Err(ScimError::forbidden(
                "The service principal can't rename itself",
            ));
        }
        let domain = ctx.writable_domain(&input.domain).await?;
        if domain.id_tenant != tenant {
            return Err(ScimError::invalid_value(format!(
                "The domain '{}' is in a different tenant from the account",
                domain.name()
            )));
        }
        patch.insert("name".into(), json!(input.local));
        patch.insert("domainId".into(), json!(Id::from(domain.id).to_string()));
    }

    // SCIM-24
    if input.display != user.description {
        patch.insert("description".into(), json!(input.display));
    }

    // SCIM-25: PUT replaces the aliases; PATCH arrives with the full list
    let current_aliases = current
        .get("emails")
        .and_then(Value::as_array)
        .map(|emails| {
            emails
                .iter()
                .filter(|e| e.get("primary") != Some(&Value::Bool(true)))
                .filter_map(|e| e.get("value").and_then(Value::as_str).map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // A renamed account's old address isn't kept (SCIM-23)
    let aliases = input
        .aliases
        .iter()
        .filter(|a| **a != input.user_name)
        .cloned()
        .collect::<Vec<_>>();
    if aliases != current_aliases {
        patch.insert(
            "aliases".into(),
            alias_objects(ctx, &aliases, tenant).await?,
        );
    }

    // SCIM-26
    let locale = input.locale.unwrap_or_default();
    if locale != user.locale {
        patch.insert("locale".into(), json!(locale.as_str()));
    }
    if input.time_zone != user.time_zone {
        patch.insert(
            "timeZone".into(),
            json!(input.time_zone.map(|zone| zone.as_str())),
        );
    }

    // SCIM-29
    if input.external_id != user.external_id {
        if let Some(external_id) = &input.external_id {
            check_external_id(ctx, ResourceKind::User, external_id, tenant, Some(id)).await?;
        }
        patch.insert("externalId".into(), json!(input.external_id));
    }

    // SCIM-27: a PUT without active means true; a PATCH carries the current value
    let active = input.active.unwrap_or(match mode {
        WriteMode::Patch => current.get("active") != Some(&Value::Bool(false)),
        _ => true,
    });
    let active_change = with_active(&user.permissions, active);
    if !active && is_self && active_change.is_some() {
        return Err(ScimError::forbidden(
            "The service principal can't deactivate itself",
        ));
    }
    if let Some(permissions) = &active_change {
        patch.insert("permissions".into(), json!(permissions));
    }

    if patch.is_empty() {
        return Ok(());
    }
    ctx.update(id, Value::Object(patch)).await?;
    let external_id = input.external_id.as_deref();
    audit(
        ctx,
        trc::ScimEvent::ResourceUpdated,
        ResourceKind::User,
        id,
        external_id,
    );
    if active_change.is_some() {
        // SCIM-52: sessions the account has open are ended
        if !active {
            let _ = ctx
                .server
                .inner
                .ipc
                .push_tx
                .send(common::ipc::PushEvent::Revoke {
                    account_id: id.document_id(),
                })
                .await;
        }
        audit(
            ctx,
            if active {
                trc::ScimEvent::ResourceReactivated
            } else {
                trc::ScimEvent::ResourceSuspended
            },
            ResourceKind::User,
            id,
            external_id,
        );
    }
    Ok(())
}
