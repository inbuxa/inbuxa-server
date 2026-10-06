/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:AccountLock` (audit-hold-lock spec, AL-1 to AL-12): locking an
//! account, handing it to delegates, and unlocking it. The grants
//! themselves are `email::inbuxa_lock`'s.

use common::{
    Server,
    auth::AccessToken,
    ipc::{BroadcastEvent, PushEvent},
};
use email::inbuxa_lock::apply_grants;
use groupware::inbuxa_lock::invalidate;
use inbuxa_features::lock::{self, Access, Delegate, Kind, Lock};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_account_lock::{
        AccountLock, AccountLockProperty as P, AccountLockSetArguments, AccountLockValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use std::{borrow::Cow, str::FromStr};
use store::write::now;
use types::id::Id;

type LValue = Value<'static, P, AccountLockValue>;

const ALL: &[P] = &[
    P::Id,
    P::AccountId,
    P::Name,
    P::Kind,
    P::Reason,
    P::LockedAt,
    P::LockedBy,
    P::Delegates,
];

/// Whether the caller may lock, change or unlock `account_id` (AL-12): an
/// administrator for an account in reach, never its own, never a group.
async fn assert_reach(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> Result<(), SetError<P>> {
    if access_token.is_account_id(account_id) {
        return Err(SetError::forbidden().with_description("You can't lock your own account."));
    }
    let Ok(account) = server.account(account_id).await else {
        return Err(SetError::not_found());
    };
    if !account.is_user_account() {
        return Err(SetError::invalid_properties()
            .with_property(P::AccountId)
            .with_description("Only a person's account can be locked."));
    }
    match access_token.tenant_id() {
        // A tenant administrator reaches its own tenant's accounts only
        Some(tenant_id) if account.id_tenant != Some(tenant_id) => Err(SetError::not_found()),
        _ => Ok(()),
    }
}

/// Reads and checks the delegates asked for (AL-5, AL-6, AL-8).
async fn parse_delegates(
    server: &Server,
    access_token: &AccessToken,
    locked_id: u32,
    kind: Kind,
    value: LValue,
) -> Result<Vec<Delegate>, SetError<P>> {
    let invalid = |why: String| {
        SetError::invalid_properties()
            .with_property(P::Delegates)
            .with_description(why)
    };
    let json: serde_json::Value = value.into();
    let Some(items) = json.as_array() else {
        return Err(invalid("delegates must be a list.".into()));
    };
    // MA-S: a shared mailbox holds more people than a lock hands over
    let max = kind.max_delegates();
    if items.len() > max {
        return Err(invalid(format!("At most {max} delegates.")));
    }
    let locked_tenant = server.account(locked_id).await.ok().and_then(|a| a.id_tenant);
    let mut delegates: Vec<Delegate> = Vec::with_capacity(items.len());
    for item in items {
        let account_id = item["accountId"]
            .as_str()
            .and_then(|id| Id::from_str(id).ok())
            .map(|id| id.document_id())
            .ok_or_else(|| invalid("Each delegate needs an accountId.".into()))?;
        let access = item["access"]
            .as_str()
            .and_then(Access::parse)
            .ok_or_else(|| invalid("access must be read, organize or full.".into()))?;
        let send_as = item["sendAs"].as_bool().unwrap_or(false);
        let until = match item.get("until").filter(|v| !v.is_null()) {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(|d| UTCDate::from_str(d).ok())
                    .map(|d| d.timestamp().max(0) as u64)
                    .ok_or_else(|| invalid("until must be a UTC date.".into()))?,
            ),
        };
        if account_id == locked_id {
            return Err(invalid("An account can't be its own delegate.".into()));
        }
        if access_token.is_account_id(account_id) && access_token.tenant_id().is_some() {
            return Err(invalid(
                "Only a server administrator may make themselves a delegate.".into(),
            ));
        }
        if send_as && access == Access::Read {
            return Err(invalid(
                "Sending as the account needs organize or full access: the message is made in its Drafts first."
                    .into(),
            ));
        }
        let Ok(delegate) = server.account(account_id).await else {
            return Err(invalid(format!("No account {}.", Id::from(account_id))));
        };
        if !delegate.is_user_account() {
            return Err(invalid("A delegate must be a person, not a group.".into()));
        }
        // Delegates stay in the locked account's tenant, unless a server
        // administrator says otherwise (AL-5)
        if access_token.tenant_id().is_some() && delegate.id_tenant != locked_tenant {
            return Err(invalid("A delegate must be in the same organization.".into()));
        }
        if delegates.iter().any(|d| d.account_id == account_id) {
            return Err(invalid("A delegate is listed twice.".into()));
        }
        delegates.push(Delegate {
            account_id,
            access,
            send_as,
            until,
        });
    }
    Ok(delegates)
}

/// Ends the account's open sessions, here and on every node (AL-3).
async fn end_sessions(server: &Server, account_id: u32) {
    let _ = server
        .inner
        .ipc
        .push_tx
        .send(PushEvent::Revoke { account_id })
        .await;
    server
        .cluster_broadcast(BroadcastEvent::EndSessions(account_id))
        .await;
}

fn date(seconds: u64) -> LValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

async fn to_value(server: &Server, lock: &Lock, properties: &[P]) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id | P::AccountId => Value::Element(AccountLockValue::Id(Id::from(lock.account_id))),
            P::Name => Value::Str(server.audit_account_name(lock.account_id).await.into()),
            P::Kind => Value::Str(Cow::Borrowed(lock.kind.as_str())),
            P::Reason => Value::Str(lock.reason.clone().into()),
            P::LockedAt => date(lock.locked_at),
            P::LockedBy => Value::Str(lock.locked_by.clone().into()),
            P::Delegates => {
                let mut items = Vec::with_capacity(lock.delegates.len());
                for delegate in &lock.delegates {
                    let mut item = Map::with_capacity(5);
                    item.insert_unchecked(
                        Key::Borrowed("accountId"),
                        Value::Str(Id::from(delegate.account_id).to_string().into()),
                    );
                    item.insert_unchecked(
                        Key::Borrowed("name"),
                        Value::Str(server.audit_account_name(delegate.account_id).await.into()),
                    );
                    item.insert_unchecked(
                        Key::Borrowed("access"),
                        Value::Str(Cow::Borrowed(delegate.access.as_str())),
                    );
                    item.insert_unchecked(Key::Borrowed("sendAs"), Value::Bool(delegate.send_as));
                    item.insert_unchecked(
                        Key::Borrowed("until"),
                        delegate.until.map_or(Value::Null, date),
                    );
                    items.push(Value::Object(item));
                }
                Value::Array(items)
            }
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// Whether a lock is in the caller's reach: every lock at server level, the
/// tenant's own inside one.
async fn in_reach(server: &Server, access_token: &AccessToken, account_id: u32) -> bool {
    match access_token.tenant_id() {
        None => true,
        Some(tenant_id) => server
            .account(account_id)
            .await
            .is_ok_and(|a| a.id_tenant == Some(tenant_id)),
    }
}

/// `inbuxa:AccountLock/get`: the locks in reach.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<AccountLock>,
) -> trc::Result<GetResponse<AccountLock>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let data = server.store();
    match ids {
        None => {
            for current in lock::all(data).await? {
                if in_reach(server, access_token, current.account_id).await {
                    response.list.push(to_value(server, &current, &properties).await);
                }
            }
        }
        Some(ids) => {
            for id in ids {
                match lock::get(data, id.document_id()).await? {
                    Some(current) if in_reach(server, access_token, current.account_id).await => {
                        response.list.push(to_value(server, &current, &properties).await);
                    }
                    _ => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

fn reason_of(reason: Option<&str>) -> Option<String> {
    reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(500).collect())
}

fn reason_required() -> SetError<P> {
    SetError::invalid_properties()
        .with_property(P::Reason)
        .with_description("Say why: a reason is required and is kept in the audit log.")
}

/// `inbuxa:AccountLock/set`: create locks, update changes delegates or the
/// reason, destroy unlocks. The request layer records each.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, AccountLock>,
) -> trc::Result<SetResponse<AccountLock>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let arguments: AccountLockSetArguments = std::mem::take(&mut request.arguments);
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let mut account_id = None;
        let mut kind = Kind::Lock;
        let mut reason = None;
        let mut delegates_value = None;
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::AccountId), Value::Element(AccountLockValue::Id(id))) => {
                    account_id = Some(id.document_id())
                }
                (Key::Property(P::Kind), Value::Str(k)) => match Kind::parse(&k) {
                    Some(k) => kind = k,
                    None => {
                        invalid = Some(
                            SetError::invalid_properties()
                                .with_property(P::Kind)
                                .with_description("kind must be lock or sharedMailbox."),
                        );
                        break;
                    }
                },
                (Key::Property(P::Reason), Value::Str(r)) => reason = reason_of(Some(&r)),
                (Key::Property(P::Delegates), value) => delegates_value = Some(value.into_owned()),
                _ => {
                    invalid = Some(SetError::invalid_properties().with_property(key.into_owned()));
                    break;
                }
            }
        }
        if let Some(error) = invalid {
            response.not_created.append(client_id, error);
            continue;
        }
        let Some(account_id) = account_id else {
            response.not_created.append(
                client_id,
                SetError::invalid_properties().with_property(P::AccountId),
            );
            continue;
        };
        // MA-S: a shared mailbox needs no reason; a lock always does
        let reason = match reason.or_else(|| reason_of(arguments.reason.as_deref())) {
            Some(reason) => reason,
            None if kind == Kind::SharedMailbox => String::new(),
            None => {
                response.not_created.append(client_id, reason_required());
                continue;
            }
        };
        if let Err(error) = assert_reach(server, access_token, account_id).await {
            response.not_created.append(client_id, error);
            continue;
        }
        if lock::get(data, account_id).await?.is_some() {
            response.not_created.append(
                client_id,
                SetError::already_exists()
                    .with_description("That account is already locked or a shared mailbox."),
            );
            continue;
        }
        let delegates = match delegates_value {
            Some(value) => match parse_delegates(server, access_token, account_id, kind, value).await {
                Ok(delegates) => delegates,
                Err(error) => {
                    response.not_created.append(client_id, error);
                    continue;
                }
            },
            None => Vec::new(),
        };
        let mut created = Lock {
            account_id,
            kind,
            reason,
            locked_at: now(),
            locked_by: actor.name.clone(),
            locked_by_id: actor.account_id,
            delegates,
            replaced: Vec::new(),
        };
        // The lock is written first: from here the account can't sign in,
        // whatever happens to the grants
        lock::set(data, &created, None).await?;
        created.replaced = apply_grants(server, account_id, None, Some(&created)).await?;
        lock::set(data, &created, Some(&created)).await?;
        invalidate(server, account_id, None, Some(&created)).await?;
        end_sessions(server, account_id).await;

        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(AccountLockValue::Id(Id::from(account_id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let account_id = id.document_id();
        if let Err(error) = assert_reach(server, access_token, account_id).await {
            response.not_updated.append(id, error);
            continue;
        }
        let Some(current) = lock::get(data, account_id).await? else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        if current.kind.is_lock() && reason_of(arguments.reason.as_deref()).is_none() {
            response.not_updated.append(id, reason_required());
            continue;
        }
        let mut updated = current.clone();
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Delegates), value) => {
                    match parse_delegates(server, access_token, account_id, current.kind, value.into_owned())
                        .await
                    {
                        Ok(delegates) => updated.delegates = delegates,
                        Err(error) => {
                            invalid = Some(error);
                            break;
                        }
                    }
                }
                (Key::Property(P::Reason), Value::Str(r)) => match reason_of(Some(&r)) {
                    Some(r) => updated.reason = r,
                    None if !current.kind.is_lock() => updated.reason = String::new(),
                    None => {
                        invalid = Some(reason_required());
                        break;
                    }
                },
                _ => {
                    invalid = Some(SetError::invalid_properties().with_property(key.into_owned()));
                    break;
                }
            }
        }
        if let Some(error) = invalid {
            response.not_updated.append(id, error);
            continue;
        }
        updated.replaced = apply_grants(server, account_id, Some(&current), Some(&updated)).await?;
        lock::set(data, &updated, Some(&current)).await?;
        invalidate(server, account_id, Some(&current), Some(&updated)).await?;
        response.updated.append(id, None);
    }

    for id in request.unwrap_destroy().into_valid() {
        let account_id = id.document_id();
        if let Err(error) = assert_reach(server, access_token, account_id).await {
            response.not_destroyed.append(id, error);
            continue;
        }
        let Some(current) = lock::get(data, account_id).await? else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        if current.kind.is_lock() && reason_of(arguments.reason.as_deref()).is_none() {
            response.not_destroyed.append(id, reason_required());
            continue;
        }
        // Grants go first: an unlocked account never keeps its delegates
        apply_grants(server, account_id, Some(&current), None).await?;
        lock::remove(data, &current).await?;
        // Delegates lose the account on their next request: their tokens
        // are rebuilt without it, on every node
        invalidate(server, account_id, Some(&current), None).await?;
        response.destroyed.push(id);
    }

    Ok(response)
}
