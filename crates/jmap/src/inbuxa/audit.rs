/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The audit log's request layer (audit-hold-lock spec, AU-1.1 to AU-1.3,
//! AU-3). Before a set method changes anything, one pending record per
//! requested create, update and destroy is written, with what was asked
//! and, for registry objects, what each changed place held before. If that
//! write fails, nothing is changed. After the method, each record's outcome
//! follows. The method runs in a request scope, so the registry's write hook
//! doesn't record the same writes again.

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use inbuxa_features::audit::{Action, EntryId, Outcome, Record, Target, diff, scope};
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::JmapObject,
    request::{MaybeInvalid, reference::MaybeResultReference},
};
use registry::schema::enums::Permission;
use registry::{
    schema::prelude::{OBJ_FILTER_ACCOUNT, OBJ_SINGLETON, ObjectType},
    types::id::ObjectId,
};
use serde_json::Value;
use std::{cell::RefCell, future::Future};
use types::id::Id;

tokio::task_local! {
    /// Accounts a method call reached through impersonation (AU-1.6).
    static REACHED: RefCell<Vec<u32>>;
}

/// Runs one method call, collecting the accounts it reached through
/// `Impersonate` rather than as the caller's own, a group's or a share.
pub async fn collect_access<F: Future>(f: F) -> (F::Output, Vec<u32>) {
    REACHED
        .scope(RefCell::new(Vec::new()), async {
            let output = f.await;
            let reached = REACHED.with(|reached| std::mem::take(&mut *reached.borrow_mut()));
            (output, reached)
        })
        .await
}

/// Notes an account a method call is about to reach (AU-1.6).
pub fn note_access(account_id: u32, access_token: &AccessToken) {
    if !access_token.is_member_directly(account_id)
        && access_token.has_permission(Permission::Impersonate)
    {
        let _ = REACHED.try_with(|reached| {
            let mut reached = reached.borrow_mut();
            if !reached.contains(&account_id) {
                reached.push(account_id);
            }
        });
    }
}

enum Item {
    Create(String),
    Update(MaybeInvalid<Id>),
    Destroy(MaybeInvalid<Id>),
}

/// The pending records written for one set method.
pub struct Pending {
    items: Vec<(Item, EntryId)>,
}

fn ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Whether a set on this object isn't recorded: content a user manages for
/// themselves, which isn't the control plane.
pub fn is_exempt(object: &str, account_id: Id, access_token: &AccessToken) -> bool {
    let own = account_id.document_id() == access_token.account_id();
    match object {
        // Spam training is mail handling, and can come with every message
        "x:SpamTrainingSample" => true,
        // A user's own masks and archive are their own business; an
        // administrator reaching someone else's is recorded
        "x:MaskedEmail" | "MaskedEmail" | "x:ArchivedItem" => own,
        _ => false,
    }
}

/// `before`, boxed in a frame of its own (see `recorded`).
fn before_boxed<'a, T: JmapObject>(
    server: &'a Server,
    access_token: &'a AccessToken,
    session: &'a HttpSessionData,
    object: &'a str,
    registry: Option<ObjectType>,
    request: &'a SetRequest<'_, T>,
) -> std::pin::Pin<Box<dyn Future<Output = trc::Result<Pending>> + Send + 'a>> {
    Box::pin(before(
        server,
        access_token,
        session,
        object,
        registry,
        request,
    ))
}

/// Runs a set method with its requested changes recorded first and its
/// outcomes after (AU-3). `method` returns its future already boxed, so
/// this frame and the scope around it hold a pointer, not the method's
/// state.
pub async fn recorded<'x, T, F, Fut>(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    object: &str,
    registry: Option<ObjectType>,
    request: SetRequest<'x, T>,
    method: F,
) -> trc::Result<SetResponse<T>>
where
    T: JmapObject,
    F: FnOnce(SetRequest<'x, T>) -> std::pin::Pin<Box<Fut>>,
    Fut: Future<Output = trc::Result<SetResponse<T>>> + ?Sized,
{
    if is_exempt(object, request.account_id, access_token) {
        return method(request).await;
    }
    // Every inner future is boxed where it's made, never held in this
    // frame: a debug build's stack can't take a copy of registry_set's
    // state on top of the request's own
    let pending = before_boxed(server, access_token, session, object, registry, &request).await?;
    let result = scope::request(method(request)).await;
    after(server, pending, &result).await;
    result
}

async fn before<T: JmapObject>(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    object: &str,
    registry: Option<ObjectType>,
    request: &SetRequest<'_, T>,
) -> trc::Result<Pending> {
    let actor = server.audit_actor(access_token).await;
    let via = access_token.origin().cloned();
    // The request's account is the target's only for objects that belong
    // to an account; a domain created by an administrator isn't theirs
    let account_id = registry
        .is_none_or(|object_type| object_type.flags() & OBJ_FILTER_ACCOUNT != 0)
        .then(|| request.account_id.document_id());
    let mut records = Vec::new();

    for (client_id, value) in request.create.iter().flat_map(|c| c.iter()) {
        let after = serde_json::to_value(value).unwrap_or_default();
        let described = diff::describe(&after);
        let changes = after
            .as_object()
            .map(|patch| diff::patch(object, None, patch))
            .unwrap_or_default();
        records.push((
            Item::Create(client_id.clone()),
            Action::Create,
            Target {
                kind: object.to_string(),
                id: None,
                name: described.name,
                account_id: described.account_id.or(account_id),
                tenant_id: described.tenant_id.or(access_token.tenant_id()),
            },
            changes,
        ));
    }

    for (id, value) in request.update.iter().flat_map(|u| u.iter()) {
        let before = match registry {
            Some(_) => stored(server, registry, id).await,
            None => fork_current(server, object, id).await,
        };
        let patch = serde_json::to_value(value).unwrap_or_default();
        let described = before.as_ref().map(diff::describe).unwrap_or_default();
        let changes = patch
            .as_object()
            .map(|patch| diff::patch(object, before.as_ref(), patch))
            .unwrap_or_default();
        records.push((
            Item::Update(id.clone()),
            Action::Update,
            Target {
                kind: object.to_string(),
                id: Some(id_text(id)),
                name: described.name,
                account_id: described.account_id.or(account_id),
                tenant_id: described.tenant_id.or(access_token.tenant_id()),
            },
            changes,
        ));
    }

    if let Some(MaybeResultReference::Value(destroy)) = &request.destroy {
        for id in destroy {
            let before = stored(server, registry, id).await;
            let described = before.as_ref().map(diff::describe).unwrap_or_default();
            records.push((
                Item::Destroy(id.clone()),
                Action::Destroy,
                Target {
                    kind: object.to_string(),
                    id: Some(id_text(id)),
                    name: described.name,
                    account_id: described.account_id.or(account_id),
                    tenant_id: described.tenant_id.or(access_token.tenant_id()),
                },
                vec![],
            ));
        }
    }

    let mut pending = Pending {
        items: Vec::with_capacity(records.len()),
    };
    for (item, action, target, changes) in records {
        let record = Record {
            at: ms(),
            actor: actor.clone(),
            via: via.clone(),
            remote_ip: Some(session.remote_ip),
            action,
            target,
            changes,
            details: None,
            reason: None,
            outcome: Outcome::Pending,
        };
        match server.audit_append(&record).await {
            Ok(entry) => pending.items.push((item, entry)),
            Err(err) => {
                // Nothing is changed: the records already written say so
                for (_, entry) in pending.items {
                    let _ = server
                        .audit_finish(
                            entry,
                            Outcome::refused(
                                "serverFail",
                                Some("The audit log couldn't be written.".into()),
                            ),
                        )
                        .await;
                }
                return Err(
                    err.details("The audit log couldn't be written, so nothing was changed.")
                );
            }
        }
    }
    Ok(pending)
}

async fn after<T: JmapObject>(
    server: &Server,
    pending: Pending,
    result: &trc::Result<SetResponse<T>>,
) {
    for (item, entry) in pending.items {
        let outcome = match result {
            Err(err) => Outcome::refused(
                "serverFail",
                err.value_as_str(trc::Key::Details).map(str::to_string),
            ),
            Ok(response) => outcome(response, &item),
        };
        // The change is done: a failure here is reported, and the record
        // stays pending, which verify counts (AU-6)
        let _ = server.audit_finish(entry, outcome).await;
    }
}

fn outcome<T: JmapObject>(response: &SetResponse<T>, item: &Item) -> Outcome {
    let refused = |err: &SetError<T::Property>| {
        Outcome::refused(
            err.error_type().as_str(),
            err.description().map(str::to_string),
        )
    };
    match item {
        Item::Create(client_id) => {
            if let Some(created) = response.created.get(client_id) {
                Outcome::Success {
                    created_id: serde_json::to_value(created)
                        .ok()
                        .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string)),
                }
            } else if let Some(err) = response.not_created.get(client_id) {
                refused(err)
            } else {
                Outcome::refused("notProcessed", None)
            }
        }
        Item::Update(id) => {
            if let MaybeInvalid::Value(id) = id
                && response.updated.contains_key(id)
            {
                Outcome::success()
            } else if let Some(err) = response.not_updated.get(id) {
                refused(err)
            } else {
                Outcome::refused("notProcessed", None)
            }
        }
        Item::Destroy(id) => {
            if let MaybeInvalid::Value(id) = id
                && response.destroyed.contains(id)
            {
                Outcome::success()
            } else if let Some(err) = response.not_destroyed.get(id) {
                refused(err)
            } else {
                Outcome::refused("notProcessed", None)
            }
        }
    }
}

fn id_text(id: &MaybeInvalid<Id>) -> String {
    match id {
        MaybeInvalid::Value(id) => id.to_string(),
        MaybeInvalid::Invalid(text) => text.chars().take(100).collect(),
    }
}

/// The fork's own settings as they are now, as JSON, so their changes are
/// recorded with what they replaced. Their stored names are the JMAP
/// property names.
async fn fork_current(server: &Server, object: &str, id: &MaybeInvalid<Id>) -> Option<Value> {
    use inbuxa_features::{ai::limits, audit::log, security};
    let data = server.store();
    match object {
        "inbuxa:AuditSettings" => log::settings(data)
            .await
            .ok()
            .map(|settings| serde_json::json!({"keepForDays": settings.keep_for_secs / 86_400})),
        "inbuxa:AiLimits" => limits::get(data)
            .await
            .ok()
            .and_then(|limits| serde_json::to_value(limits).ok()),
        "inbuxa:ProtocolPolicy" => security::protocol_policy::get(data)
            .await
            .ok()
            .and_then(|policy| serde_json::to_value(policy).ok()),
        "inbuxa:TenantProtocolPolicy" => match id {
            MaybeInvalid::Value(id) => {
                security::tenant_protocol_policy::get(data, id.document_id())
                    .await
                    .ok()
                    .and_then(|policy| serde_json::to_value(policy).ok())
            }
            MaybeInvalid::Invalid(_) => None,
        },
        _ => None,
    }
}

/// A registry object as it is now, as JSON: what an update or destroy
/// starts from. A singleton never saved holds its defaults.
async fn stored(
    server: &Server,
    registry: Option<ObjectType>,
    id: &MaybeInvalid<Id>,
) -> Option<Value> {
    let (Some(object_type), MaybeInvalid::Value(id)) = (registry, id) else {
        return None;
    };
    let object = match server
        .registry()
        .get(ObjectId::new(object_type, *id))
        .await
        .ok()?
    {
        Some(object) => object,
        None if id.is_singleton() && object_type.flags() & OBJ_SINGLETON != 0 => {
            registry::schema::prelude::Object::from(object_type)
        }
        None => return None,
    };
    serde_json::to_value(registry::jmap::IntoValue::into_value(object)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_content_is_exempt() {
        let token = AccessToken::from_permissions(5, []);
        let own = Id::from(5u32);
        let other = Id::from(6u32);
        assert!(is_exempt("x:SpamTrainingSample", other, &token));
        assert!(is_exempt("x:MaskedEmail", own, &token));
        assert!(!is_exempt("x:MaskedEmail", other, &token));
        assert!(is_exempt("x:ArchivedItem", own, &token));
        assert!(!is_exempt("x:ArchivedItem", other, &token));
        assert!(!is_exempt("x:Domain", own, &token));
        assert!(!is_exempt("x:AppPassword", own, &token));
    }
}
