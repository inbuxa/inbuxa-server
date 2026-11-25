/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{blob::download::BlobDownload, changes::state::StateManager};
use common::{
    Server,
    auth::{AccessToken, AccountCache},
    storage::index::ObjectIndexBuilder,
};
use email::sieve::{
    ArchivedSieveScript, SieveScript, delete::SieveScriptDelete, ingest::SieveScriptIngest,
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::sieve::{Sieve, SieveProperty, SieveValue},
    references::resolve::ResolveCreatedReference,
    request::{MaybeInvalid, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use rand::distr::Alphanumeric;
use registry::schema::enums::StorageQuota;
use sieve::compiler::ErrorType;
use std::future::Future;
use store::{
    Serialize, SerializeInfallible, ValueKey,
    rand::{RngExt, rng},
    write::{AlignedBytes, Archive, Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    collection::{Collection, SyncCollection},
    field::{PrincipalField, SieveField},
    id::Id,
};

pub struct SetContext<'x> {
    account_id: u32,
    access_token: &'x AccessToken,
    account_cache: &'x AccountCache,
    response: SetResponse<Sieve>,
    /// inbuxa: #643: saved by a shared mailbox's member who isn't an
    /// administrator, who may only sort
    sort_only: bool,
}

/// inbuxa: #643: why a shared mailbox's member can't add or change an
/// action that sends or answers mail.
pub const SORT_ONLY: &str =
    "Forwarding and automatic replies on a shared mailbox can only be saved by an administrator.";

/// inbuxa: #643: why a shared mailbox's member can't turn on a script that
/// sends or answers mail.
pub const ACTIVATE_ADMIN_ONLY: &str = "Filters that forward or answer mail on a shared mailbox can only be turned on by an administrator.";

pub trait SieveScriptSet: Sync + Send {
    fn sieve_script_set(
        &self,
        request: SetRequest<'_, Sieve>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<Sieve>>> + Send;

    #[allow(clippy::type_complexity)]
    fn sieve_set_item<'x>(
        &self,
        changes_: Value<'_, SieveProperty, SieveValue>,
        update: Option<(u32, Archive<&'x ArchivedSieveScript>)>,
        ctx: &SetContext,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<Result<SetItemResponse<'x>, SetError<SieveProperty>>>> + Send;
}

impl SieveScriptSet for Server {
    async fn sieve_script_set(
        &self,
        mut request: SetRequest<'_, Sieve>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse<Sieve>> {
        let account_id = request.account_id.document_id();
        let sieve_ids = self
            .document_ids(account_id, Collection::SieveScript, SieveField::Name)
            .await?;
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let mut ctx = SetContext {
            account_id,
            access_token,
            account_cache: &account,
            sort_only: !access_token.is_member(account_id),
            response: SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
                .with_state(
                    self.assert_state(
                        account_id,
                        SyncCollection::SieveScript,
                        &request.if_in_state,
                    )
                    .await?,
                ),
        };
        let will_destroy = ctx.response.collect_will_destroy(request.unwrap_destroy());

        // Validate active script id: one that doesn't exist, or that this
        // call destroys, is ignored (RFC 9661, 2.4)
        if let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_activate_script
            && (!sieve_ids.contains(id.document_id()) || will_destroy.contains(id))
        {
            request.arguments.on_success_activate_script = None;
        }

        // inbuxa: #643: a member may keep a script that sends mail active,
        // and may not turn one on
        let active_script_id = self.sieve_script_get_active_id(account_id).await?;
        let mut compiled_sends = Vec::new();

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut activations = Vec::new();
        let mut created_ids = Vec::new();
        for (id, object) in request.unwrap_create() {
            if sieve_ids.len()
                < self.object_quota(account.object_quotas(), StorageQuota::MaxSieveScripts) as u64
            {
                match self
                    .sieve_set_item(object, None, &ctx, session.session_id)
                    .await?
                {
                    Ok(mut result) => {
                        // Store blob
                        let sieve = &mut result.builder.changes_mut().unwrap();
                        let (blob_hash, blob_hold) = self
                            .put_temporary_blob(
                                account_id,
                                result.blob_update.as_ref().unwrap(),
                                60,
                            )
                            .await?;
                        sieve.blob_hash = blob_hash;
                        let blob_size = sieve.size as usize;
                        let blob_hash = sieve.blob_hash.clone();

                        // Write record
                        let document_id = self
                            .store()
                            .assign_document_ids(account_id, Collection::SieveScript, 1)
                            .await
                            .caused_by(trc::location!())?;
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::SieveScript)
                            .with_document(document_id)
                            .custom(
                                result
                                    .builder
                                    .with_changed_by(ctx.access_token.account_tenant_ids()),
                            )
                            .caused_by(trc::location!())?
                            .clear(blob_hold)
                            .commit_point();

                        // Set isActive if needed
                        if let Some(set_item) = result.set_item {
                            activations.push((document_id, set_item));
                        }

                        let result = Map::with_capacity(1)
                            .with_key_value(SieveProperty::Id, SieveValue::Id(document_id.into()))
                            .with_key_value(
                                SieveProperty::BlobId,
                                SieveValue::BlobId(BlobId {
                                    hash: blob_hash,
                                    class: BlobClass::Linked {
                                        account_id,
                                        collection: Collection::SieveScript.into(),
                                        document_id,
                                    },
                                    section: BlobSection {
                                        size: blob_size,
                                        ..Default::default()
                                    }
                                    .into(),
                                }),
                            );

                        // Update active script if needed
                        if let Some(MaybeIdReference::Reference(id_ref)) =
                            &request.arguments.on_success_activate_script
                            && id_ref == &id
                        {
                            request.arguments.on_success_activate_script =
                                Some(MaybeIdReference::Id(Id::from(document_id)));
                        }

                        // Add result with updated blobId
                        created_ids.push((document_id, id.clone()));
                        ctx.response.created.insert(id, result.into());
                    }
                    Err(err) => {
                        ctx.response.not_created.append(id, err);
                    }
                }
            } else {
                ctx.response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many sieve scripts, ",
                        "please delete some before adding a new one."
                    )),
                );
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    ctx.response
                        .not_updated
                        .append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                ctx.response
                    .not_updated
                    .append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain sieve script
            let document_id = id.document_id();
            if let Some(sieve_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                ))
                .await?
            {
                let sieve = sieve_
                    .to_unarchived::<SieveScript>()
                    .caused_by(trc::location!())?;

                match self
                    .sieve_set_item(
                        object,
                        (document_id, sieve).into(),
                        &ctx,
                        session.session_id,
                    )
                    .await?
                {
                    Ok(mut result) => {
                        // inbuxa: #643: isActive on a script that sends mail
                        if ctx.sort_only
                            && result.set_item == Some(true)
                            && active_script_id != Some(document_id)
                            && match result.sends_mail {
                                Some(sends_mail) => sends_mail,
                                None => !stored_sending_actions(self, account_id, document_id)
                                    .await?
                                    .is_empty(),
                            }
                        {
                            ctx.response.not_updated.append(
                                id,
                                SetError::forbidden()
                                    .with_property(SieveProperty::IsActive)
                                    .with_description(ACTIVATE_ADMIN_ONLY),
                            );
                            continue 'update;
                        }
                        if let Some(sends_mail) = result.sends_mail {
                            compiled_sends.push((document_id, sends_mail));
                        }

                        // Prepare write batch
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::SieveScript)
                            .with_document(document_id);

                        let blob_id = if let Some(blob) = result.blob_update.take() {
                            // Store blob
                            let sieve = &mut result.builder.changes_mut().unwrap();
                            let (blob_hash, blob_hold) =
                                self.put_temporary_blob(account_id, &blob, 60).await?;
                            sieve.blob_hash = blob_hash;
                            batch.clear(blob_hold);

                            BlobId {
                                hash: sieve.blob_hash.clone(),
                                class: BlobClass::Linked {
                                    account_id,
                                    collection: Collection::SieveScript.into(),
                                    document_id,
                                },
                                section: BlobSection {
                                    size: sieve.size as usize,
                                    ..Default::default()
                                }
                                .into(),
                            }
                            .into()
                        } else {
                            None
                        };

                        // Set isActive if needed
                        if let Some(set_item) = result.set_item {
                            activations.push((document_id, set_item));
                        }

                        // Write record
                        batch
                            .custom(
                                result
                                    .builder
                                    .with_changed_by(ctx.access_token.account_tenant_ids()),
                            )
                            .caused_by(trc::location!())?
                            .commit_point();

                        // Update blobId property if needed
                        let mut result = Map::with_capacity(1);
                        if let Some(blob_id) = blob_id {
                            result.insert_unchecked(
                                SieveProperty::BlobId,
                                SieveValue::BlobId(blob_id),
                            );
                        }

                        // Add result
                        ctx.response.updated.append(
                            id,
                            if !result.is_empty() {
                                Value::Object(result).into()
                            } else {
                                None
                            },
                        );
                    }
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                ctx.response.not_updated.append(id, SetError::not_found());
            }
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if sieve_ids.contains(document_id) {
                if active_script_id != Some(document_id) {
                    if self
                        .sieve_script_delete(account_id, document_id, ctx.access_token, &mut batch)
                        .await?
                    {
                        ctx.response.destroyed.push(id);
                    } else {
                        ctx.response.not_destroyed.append(id, SetError::not_found());
                    }
                } else {
                    ctx.response.not_destroyed.append(
                        id,
                        SetError::new(SetErrorType::SieveIsActive)
                            .with_description("Deactivate Sieve script before deletion."),
                    );
                }
            } else {
                ctx.response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Non-standard script activation handling
        let mut on_success_deactivate_script = request
            .arguments
            .on_success_deactivate_script
            .unwrap_or(false);
        if activations.len() == 1 {
            let (document_id, set_item) = activations[0];
            let is_active = active_script_id.is_some_and(|active_id| active_id == document_id);
            if set_item {
                if request.arguments.on_success_activate_script.is_none() && !is_active {
                    request.arguments.on_success_activate_script =
                        Some(MaybeIdReference::Id(document_id.into()));
                }
            } else if !on_success_deactivate_script && is_active {
                on_success_deactivate_script = true;
            }
        }

        // inbuxa: #643: a member doesn't turn on a script that sends mail;
        // an administrator does
        if ctx.sort_only
            && let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_activate_script
        {
            let id = *id;
            let document_id = id.document_id();
            if active_script_id != Some(document_id)
                && sieve_ids.contains(document_id)
                && match compiled_sends.iter().find(|(d, _)| *d == document_id) {
                    Some((_, sends_mail)) => *sends_mail,
                    None => !stored_sending_actions(self, account_id, document_id)
                        .await?
                        .is_empty(),
                }
            {
                ctx.response.not_updated.append(
                    id,
                    SetError::forbidden().with_description(ACTIVATE_ADMIN_ONLY),
                );
                request.arguments.on_success_activate_script = None;
            }
        }

        // Activate / deactivate scripts
        let mut activated = None;
        let mut deactivated = None;
        if ctx.response.not_created.is_empty()
            && ctx.response.not_updated.is_empty()
            && ctx.response.not_destroyed.is_empty()
        {
            let active_id = active_script_id.filter(|id| sieve_ids.contains(*id));
            if let Some(MaybeIdReference::Id(id)) = request.arguments.on_success_activate_script {
                let document_id = id.document_id();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .set(PrincipalField::ActiveScriptId, document_id.serialize());
                activated = Some(document_id);
                deactivated = active_id.filter(|id| *id != document_id);
            } else if on_success_deactivate_script {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .clear(PrincipalField::ActiveScriptId);
                deactivated = active_id;
            }

            // inbuxa: a script whose isActive changes is updated, for
            // SieveScript/changes (one created in this call is logged as
            // created already)
            for document_id in [activated.filter(|id| active_id != Some(*id)), deactivated]
                .into_iter()
                .flatten()
                .filter(|id| sieve_ids.contains(*id))
            {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::SieveScript)
                    .with_document(document_id)
                    .log_item_update(SyncCollection::SieveScript, None);
            }
        }

        // Write changes
        if !batch.is_empty()
            && let Ok(change_id) = self
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?
                .last_change_id(account_id)
        {
            ctx.response.new_state = State::Exact(change_id).into();
        }

        // inbuxa: isActive is reported once the change is committed, true for
        // the activated script (in created or updated) and false for the
        // deactivated one (RFC 9661, 2.4)
        for (document_id, is_active) in [(activated, true), (deactivated, false)]
            .into_iter()
            .filter_map(|(id, is_active)| id.map(|id| (id, is_active)))
        {
            if let Some((_, create_id)) = created_ids.iter().find(|(id, _)| *id == document_id) {
                if let Some(Value::Object(result)) = ctx.response.created.get_mut(create_id) {
                    result.insert_unchecked(SieveProperty::IsActive, is_active);
                }
            } else {
                let result = ctx
                    .response
                    .updated
                    .get_mut_or_insert_with(Id::from(document_id), || None);
                if let Some(Value::Object(result)) = result {
                    result.insert_unchecked(SieveProperty::IsActive, is_active);
                } else {
                    *result = Some(Value::Object(
                        Map::with_capacity(1).with_key_value(SieveProperty::IsActive, is_active),
                    ));
                }
            }
        }

        Ok(ctx.response)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn sieve_set_item<'x>(
        &self,
        changes_: Value<'_, SieveProperty, SieveValue>,
        update: Option<(u32, Archive<&'x ArchivedSieveScript>)>,
        ctx: &SetContext<'_>,
        session_id: u64,
    ) -> trc::Result<Result<SetItemResponse<'x>, SetError<SieveProperty>>> {
        // Vacation script cannot be modified
        if update
            .as_ref()
            .is_some_and(|(_, obj)| obj.inner.name.eq_ignore_ascii_case("vacation"))
        {
            return Ok(Err(SetError::forbidden().with_description(concat!(
                "The 'vacation' script cannot be modified, ",
                "use VacationResponse/set instead."
            ))));
        }

        // Parse properties
        let mut set_item = None;
        let mut changes = update
            .as_ref()
            .map(|(_, obj)| obj.deserialize().unwrap_or_default())
            .unwrap_or_default();
        let mut blob_id = None;
        for (property, mut value) in changes_.into_expanded_object() {
            if let Err(err) = ctx.response.resolve_self_references(&mut value, 0, false) {
                return Ok(Err(err));
            };
            match (&property, value) {
                (Key::Property(SieveProperty::Name), Value::Str(value)) => {
                    if value.len() > self.core.email.sieve_max_script_name {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(property.into_owned())
                            .with_description("Script name is too long.")));
                    } else if value.eq_ignore_ascii_case("vacation") {
                        return Ok(Err(SetError::forbidden()
                            .with_property(property.into_owned())
                            .with_description(
                                "The 'vacation' name is reserved, please use a different name.",
                            )));
                    } else if update
                        .as_ref()
                        .is_none_or(|(_, obj)| obj.inner.name != value.as_ref())
                        && let Some(id) = self
                            .document_ids_matching(
                                ctx.account_id,
                                Collection::SieveScript,
                                SieveField::Name,
                                value.as_bytes(),
                            )
                            .await?
                            .min()
                    {
                        return Ok(Err(SetError::already_exists()
                            .with_existing_id(id.into())
                            .with_description(format!(
                                "A sieve script with name '{}' already exists.",
                                value
                            ))));
                    }

                    changes.name = value.into_owned();
                }
                (
                    Key::Property(SieveProperty::BlobId),
                    Value::Element(SieveValue::BlobId(value)),
                ) => {
                    blob_id = value.into();
                    continue;
                }
                (Key::Property(SieveProperty::Name), Value::Null) => {
                    continue;
                }
                (Key::Property(SieveProperty::IsActive), Value::Bool(value)) => {
                    set_item = Some(value);
                    continue;
                }
                (Key::Property(SieveProperty::Id), value) => {
                    if update
                        .as_ref()
                        .map(|(document_id, _)| Id::from(*document_id))
                        .is_none_or(|expected| !crate::matches_id(&value, expected))
                    {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(SieveProperty::Id)
                            .with_description("The id property is immutable.".to_string())));
                    }
                }
                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property.into_owned())
                        .with_description("Invalid property or value.".to_string())));
                }
            }
        }

        if update.is_none() {
            // Add name if missing
            if changes.name.is_empty() {
                changes.name = rng()
                    .sample_iter(Alphanumeric)
                    .take(15)
                    .map(char::from)
                    .collect::<String>();
            }
        }

        let mut sends_mail = None;
        let blob_update = if let Some(blob_id) = blob_id {
            if update.as_ref().is_none_or( |(document_id, _)| {
                !matches!(blob_id.class, BlobClass::Linked { account_id, collection, document_id: d } if account_id == ctx.account_id && collection == u8::from(Collection::SieveScript) && *document_id == d)
            }) {
                // Check access
                if let Some(mut bytes) = self.blob_download(&blob_id, ctx.access_token).await? {
                    // Check quota
                    match self
                        .has_available_quota(ctx.account_cache, bytes.len() as u64)
                        .await
                    {
                        Ok(_) => (),
                        Err(err) => {
                            if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                                || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota))
                            {
                                trc::error!(err.account_id(ctx.account_id).span_id(session_id));
                                return Ok(Err(SetError::over_quota()));
                            } else {
                                return Err(err);
                            }
                        }
                    }

                    // Compile script
                    match self.core.sieve.untrusted_compiler.compile(&bytes) {
                        Ok(script) => {
                            // inbuxa: #643: a member may keep or remove the
                            // actions that send mail an administrator saved
                            // in this script, never add or change one. Read
                            // from what the script does, not what it requires
                            sends_mail = Some(script.sends_mail());
                            if ctx.sort_only
                                && sends_mail == Some(true)
                                && !is_sub_multiset(
                                    &script.sending_actions(),
                                    &match &update {
                                        Some((document_id, _)) => {
                                            stored_sending_actions(
                                                self,
                                                ctx.account_id,
                                                *document_id,
                                            )
                                            .await?
                                        }
                                        None => Vec::new(),
                                    },
                                )
                            {
                                return Ok(Err(SetError::forbidden()
                                    .with_property(SieveProperty::BlobId)
                                    .with_description(SORT_ONLY)));
                            }
                            changes.size = bytes.len() as u32;
                            bytes.extend(Archiver::new(script).untrusted().serialize().caused_by(trc::location!())?);
                            bytes.into()
                        }
                        Err(err) => {
                            return Ok(Err(SetError::new(
                                if let ErrorType::ScriptTooLong = &err.error_type() {
                                    SetErrorType::TooLarge
                                } else {
                                    SetErrorType::InvalidSieve
                                },
                            )
                            .with_description(err.to_string())));
                        }
                    }
                } else {
                    return Ok(Err(SetError::new(SetErrorType::BlobNotFound)
                        .with_property(SieveProperty::BlobId)
                        .with_description("Blob does not exist.")));
                }
            } else {
                None
            }
        } else if update.is_none() {
            return Ok(Err(SetError::invalid_properties()
                .with_property(SieveProperty::BlobId)
                .with_description("Missing blobId.")));
        } else {
            None
        };

        // Validate
        Ok(Ok(SetItemResponse {
            builder: ObjectIndexBuilder::new()
                .with_changes(changes)
                .with_current_opt(update.map(|(_, current)| current)),
            blob_update,
            set_item,
            sends_mail,
        }))
    }
}

pub struct SetItemResponse<'x> {
    builder: ObjectIndexBuilder<&'x ArchivedSieveScript, SieveScript>,
    blob_update: Option<Vec<u8>>,
    set_item: Option<bool>,
    /// inbuxa: #643: whether a new script sends mail, when one was compiled
    sends_mail: Option<bool>,
}

/// inbuxa: #643: the actions that send mail in a stored script, compiled
/// from its text. A script that no longer compiles has none, so nothing it
/// held counts as kept.
async fn stored_sending_actions(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Vec<String>> {
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
        return Ok(Vec::new());
    };
    let script = archive
        .unarchive::<SieveScript>()
        .caused_by(trc::location!())?;
    let size = u32::from(script.size) as usize;
    Ok(server
        .blob_store()
        .get_blob(script.blob_hash.0.as_ref(), 0..usize::MAX)
        .await
        .caused_by(trc::location!())?
        .and_then(|bytes| {
            server
                .core
                .sieve
                .untrusted_compiler
                .compile(bytes.get(..size)?)
                .ok()
        })
        .map(|script| script.sending_actions())
        .unwrap_or_default())
}

/// inbuxa: #643: every item of `new` is in `old`, as often or less; both
/// sorted.
fn is_sub_multiset(new: &[String], old: &[String]) -> bool {
    let mut old = old.iter();
    'new: for item in new {
        for candidate in old.by_ref() {
            match candidate.cmp(item) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => continue 'new,
                std::cmp::Ordering::Greater => return false,
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn sending_actions_may_be_kept_or_removed() {
        let list = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let old = list(&["redirect a", "redirect a", "vacation"]);
        for kept in [
            &[][..],
            &["redirect a"],
            &["redirect a", "redirect a"],
            &["redirect a", "vacation"],
            &["redirect a", "redirect a", "vacation"],
        ] {
            assert!(super::is_sub_multiset(&list(kept), &old), "{kept:?}");
        }
        for changed in [
            &["redirect b"][..],
            &["redirect a", "redirect a", "redirect a"],
            &["notify", "redirect a"],
            &["redirect a", "redirect a", "vacation", "vacation"],
            &["zzz"],
        ] {
            assert!(!super::is_sub_multiset(&list(changed), &old), "{changed:?}");
        }
    }
}
