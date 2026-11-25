/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A shared mailbox's filters (#643, multi-account spec MA-S). Its full
//! members manage them as its owner would, sorting only: forwarding and
//! automatic replies are added, changed and turned on by an administrator,
//! and a member may keep or remove them (`SORT_ONLY` and
//! `ACTIVATE_ADMIN_ONLY` in `sieve/set.rs`). Every change to them made by anyone but the account
//! itself is in the audit log (AU-3): a create, update or destroy as
//! `recorded` writes it, and an activation or deactivation as one more
//! record, with the actor and the shared mailbox. Each is written before
//! the change, and if it can't be, nothing is changed.

use crate::sieve::set::SieveScriptSet;
use common::{Server, auth::AccessToken};
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use http_proto::HttpSessionData;
use inbuxa_features::audit::{Action, Change, EntryId, Outcome, Record, Target};
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::sieve::Sieve,
    request::reference::MaybeIdReference,
};
use serde_json::Value;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{collection::Collection, id::Id};

/// The kind the records name.
const KIND: &str = "SieveScript";

/// SieveScript/set, recorded when it changes a shared mailbox's scripts
/// and the caller isn't the shared mailbox itself.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    request: SetRequest<'_, Sieve>,
) -> trc::Result<SetResponse<Sieve>> {
    let account_id = request.account_id.document_id();
    if !is_recorded(server, access_token, account_id).await? {
        return Box::pin(server.sieve_script_set(request, access_token, session)).await;
    }

    let activation = Box::pin(activation_before(server, access_token, session, &request)).await?;
    let result = crate::inbuxa::audit::recorded(
        server,
        access_token,
        session,
        KIND,
        None,
        None,
        request,
        |request| Box::pin(server.sieve_script_set(request, access_token, session)),
    )
    .await;
    if let Some((entry, expected)) = activation {
        let outcome = match &result {
            Err(err) => Outcome::refused(
                "serverFail",
                err.value_as_str(trc::Key::Details).map(str::to_string),
            ),
            Ok(response) => expected.outcome(response),
        };
        // The change is done: a failure here is reported, and the record
        // stays pending, which verify counts (AU-6)
        let _ = server.audit_finish(entry, outcome).await;
    }
    result
}

/// Whether a change to `account_id`'s scripts is recorded: the account is
/// a shared mailbox and the caller isn't the account itself (a full
/// member, or an administrator reaching it).
async fn is_recorded(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<bool> {
    if access_token.is_account_id(account_id) {
        Ok(false)
    } else if access_token.delegated_shared_mailbox(account_id) {
        Ok(true)
    } else {
        Ok(inbuxa_features::lock::get(server.store(), account_id)
            .await
            .caused_by(trc::location!())?
            .is_some_and(|lock| lock.kind == inbuxa_features::lock::Kind::SharedMailbox))
    }
}

/// What a recorded activation expects to see in the response.
enum Expected {
    /// A script created in this call, by its creation id.
    ActivatedCreated(String),
    Activated(Id),
    Deactivated(Id),
}

impl Expected {
    /// Done, refused with the script's own error, or not done because
    /// something else in the call was refused.
    fn outcome(&self, response: &SetResponse<Sieve>) -> Outcome {
        let response = serde_json::to_value(response).unwrap_or_default();
        let (done, refused, is_active) = match self {
            Expected::ActivatedCreated(id) => {
                (format!("/created/{id}"), format!("/notCreated/{id}"), true)
            }
            Expected::Activated(id) => {
                (format!("/updated/{id}"), format!("/notUpdated/{id}"), true)
            }
            Expected::Deactivated(id) => {
                (format!("/updated/{id}"), format!("/notUpdated/{id}"), false)
            }
        };
        if let Some(error) = response.pointer(&refused) {
            Outcome::refused(
                error["type"].as_str().unwrap_or("forbidden"),
                error["description"].as_str().map(str::to_string),
            )
        } else if response
            .pointer(&format!("{done}/isActive"))
            .and_then(Value::as_bool)
            == Some(is_active)
        {
            Outcome::success()
        } else {
            Outcome::refused("notProcessed", None)
        }
    }
}

/// The pending record for `onSuccessActivateScript` or
/// `onSuccessDeactivateScript`, if the call asks for either. An `isActive`
/// set on a create or update is in that item's own record.
async fn activation_before(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    request: &SetRequest<'_, Sieve>,
) -> trc::Result<Option<(EntryId, Expected)>> {
    let account_id = request.account_id.document_id();
    let (expected, target_id, name, details, before, after) =
        match &request.arguments.on_success_activate_script {
            Some(MaybeIdReference::Id(id)) => (
                Expected::Activated(*id),
                id.to_string(),
                script_name(server, account_id, id.document_id()).await?,
                "Activated",
                false,
                true,
            ),
            Some(MaybeIdReference::Reference(reference)) => (
                Expected::ActivatedCreated(reference.clone()),
                format!("#{reference}"),
                request
                    .create
                    .as_ref()
                    .and_then(|create| create.get(reference))
                    .and_then(|value| serde_json::to_value(value).ok())
                    .and_then(|value| value.get("name")?.as_str().map(str::to_string)),
                "Activated",
                false,
                true,
            ),
            Some(MaybeIdReference::Invalid(_)) => return Ok(None),
            None if request.arguments.on_success_deactivate_script == Some(true) => {
                let Some(active_id) = server
                    .sieve_script_get_active_id(account_id)
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(None);
                };
                let id = Id::from(active_id);
                (
                    Expected::Deactivated(id),
                    id.to_string(),
                    script_name(server, account_id, active_id).await?,
                    "Deactivated",
                    true,
                    false,
                )
            }
            None => return Ok(None),
        };

    let record = Record {
        at: ms(),
        actor: server.audit_actor(access_token).await,
        via: access_token.origin().cloned(),
        remote_ip: Some(session.remote_ip),
        action: Action::Update,
        target: Target {
            kind: KIND.to_string(),
            id: Some(target_id),
            name,
            account_id: Some(account_id),
            tenant_id: access_token.tenant_id(),
        },
        changes: vec![Change::new(
            "isActive",
            Some(before.into()),
            Some(after.into()),
        )],
        details: Some(details.to_string()),
        reason: None,
        outcome: Outcome::Pending,
    };
    match server.audit_append(&record).await {
        Ok(entry) => Ok(Some((entry, expected))),
        Err(err) => Err(err.details("The audit log couldn't be written, so nothing was changed.")),
    }
}

async fn script_name(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<String>> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::SieveScript,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    Ok(Some(
        archive
            .to_unarchived::<SieveScript>()
            .caused_by(trc::location!())?
            .inner
            .name
            .to_string(),
    ))
}

fn ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
