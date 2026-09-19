/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Deleted accounts kept for their period (undelete spec, UD-15 to UD-17a):
//! kept at deletion, their addresses held, and listed, restored or
//! destroyed for good through `inbuxa:DeletedAccount/get` and `/set`.

use common::{
    Server,
    auth::AccessToken,
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
};
use directory::core::secret::hash_secret;
use inbuxa_features::undelete::{
    accounts,
    data::{self, KeptAccount},
    settings::retention,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_deleted_account::{
        DeletedAccount, DeletedAccountProperty as P, DeletedAccountValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use registry::{
    pickle::PickledStream,
    schema::{
        enums::{AccountType, Permission},
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{Account, Credential, Task, TaskDestroyAccount, TaskStatus},
    },
    types::{EnumImpl, datetime::UTCDateTime, id::ObjectId},
};
use std::borrow::Cow;
use store::{
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::{BatchBuilder, TaskQueueClass, ValueClass, now},
};
use trc::AddContext;
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

type DValue = Value<'static, P, DeletedAccountValue>;

const ALL: &[P] = &[
    P::Id,
    P::Name,
    P::Addresses,
    P::MemberTenantId,
    P::DeletedAt,
    P::KeptUntil,
];

/// The addresses an object answers to, with the property that names each.
async fn addresses_of(server: &Server, inner: &ObjectInner) -> trc::Result<Vec<(Property, String)>> {
    let (name, domain_id, aliases) = match inner {
        ObjectInner::Account(Account::User(account)) => {
            (&account.name, account.domain_id, &account.aliases)
        }
        ObjectInner::Account(Account::Group(account)) => {
            (&account.name, account.domain_id, &account.aliases)
        }
        ObjectInner::MailingList(list) => (&list.name, list.domain_id, &list.aliases),
        ObjectInner::MaskedEmail(mask) => {
            return Ok(vec![(Property::Email, mask.email.to_lowercase())]);
        }
        _ => return Ok(vec![]),
    };
    let mut addresses = Vec::new();
    for (property, local, domain_id) in std::iter::once((Property::Name, name, domain_id)).chain(
        aliases
            .values()
            .map(|alias| (Property::Aliases, &alias.name, alias.domain_id)),
    ) {
        if let Some(domain) = server.domain_by_id(domain_id.document_id()).await? {
            for domain in domain.names.iter() {
                addresses.push((property, format!("{local}@{domain}").to_lowercase()));
            }
        }
    }
    Ok(addresses)
}

/// UD-16: nothing new may take an address a kept account holds.
pub async fn reserved(
    server: &Server,
    old: Option<&Object>,
    new: &Object,
) -> trc::Result<Option<SetError<Property>>> {
    let before = match old {
        Some(old) => addresses_of(server, &old.inner).await?,
        None => vec![],
    };
    for (property, address) in addresses_of(server, &new.inner).await? {
        if before.iter().any(|(_, a)| *a == address) {
            continue;
        }
        if let Some(kept_id) = data::reserved_by(&server.core.storage.data, &address).await? {
            return Ok(Some(
                SetError::new(SetErrorType::PrimaryKeyViolation)
                    .with_property(property)
                    .with_object_id(ObjectId::new(ObjectType::Account, Id::from(kept_id)))
                    .with_description(format!(
                        "{address} is held by a deleted account until it's destroyed."
                    )),
            ));
        }
    }
    Ok(None)
}

/// UD-15: keeps a destroyed account for the period, if one is set, instead
/// of upstream's immediate destruction. Returns the other accounts whose
/// access changed, or `None` when nothing is kept.
pub async fn keep(server: &Server, id: Id, account: &Account) -> trc::Result<Option<Vec<u32>>> {
    let Some(period) = retention(server.registry()).await?.accounts else {
        return Ok(None);
    };
    let account_id = id.document_id();
    let deleted_at = now();
    let kept_until = deleted_at + period;
    let inner = ObjectInner::Account(account.clone());
    let addresses = addresses_of(server, &inner)
        .await?
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    let (domain_id, name, account_type, tenant) = match account {
        Account::User(a) => (a.domain_id, a.name.clone(), AccountType::User, a.member_tenant_id),
        Account::Group(a) => (a.domain_id, a.name.clone(), AccountType::Group, a.member_tenant_id),
    };

    // UD-17a: its shares are suspended both ways
    let data = &server.core.storage.data;
    let shares = accounts::suspend_shares(data, account_id).await?;
    let mut others = shares
        .iter()
        .flat_map(|share| [share.owner, share.grantee])
        .filter(|other| *other != account_id)
        .collect::<Vec<_>>();
    others.sort_unstable();
    others.dedup();

    // UD-15a: upstream's DestroyAccount task, due at the end of the period
    let task_id = SnowflakeIdGenerator::global_id().unwrap_or_default();
    let kept = KeptAccount {
        record: inner.to_pickled_vec(),
        name: name.clone(),
        addresses,
        member_tenant_id: tenant.map(|id| id.id()),
        deleted_at,
        kept_until,
        task_id,
        shares,
    };
    let mut batch = BatchBuilder::new();
    batch.schedule_task_with_id(
        task_id,
        Task::DestroyAccount(TaskDestroyAccount {
            account_domain_id: domain_id,
            account_id: id,
            account_name: name,
            account_type,
            status: TaskStatus::at(kept_until as i64),
        }),
    );
    data::set_kept_account(&mut batch, account_id, &kept)?;
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    server.notify_task_queue();
    Ok(Some(others))
}

/// Who may see or act on a kept account: server administrators, and tenant
/// administrators for their own tenant's (MT-1).
fn may_reach(access_token: &AccessToken, kept: &KeptAccount, permission: Permission) -> bool {
    access_token.has_permission(permission)
        && access_token
            .tenant_id()
            .is_none_or(|tenant| kept.member_tenant_id == Some(tenant as u64))
}

fn date(timestamp: u64) -> DValue {
    Value::Element(DeletedAccountValue::Date(UTCDate::from_timestamp(
        timestamp as i64,
    )))
}

fn to_value(account_id: u32, kept: &KeptAccount, properties: &[P]) -> DValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(DeletedAccountValue::Id(Id::from(account_id))),
            P::Name => Value::Str(Cow::Owned(kept.name.clone())),
            P::Addresses => Value::Array(
                kept.addresses
                    .iter()
                    .map(|a| Value::Str(Cow::Owned(a.clone())))
                    .collect(),
            ),
            P::MemberTenantId => match kept.member_tenant_id {
                Some(id) => Value::Element(DeletedAccountValue::Id(Id::from(id))),
                None => Value::Null,
            },
            P::DeletedAt => date(kept.deleted_at),
            P::KeptUntil => date(kept.kept_until),
            P::Restore | P::Password => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:DeletedAccount/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<DeletedAccount>,
) -> trc::Result<GetResponse<DeletedAccount>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let data = &server.core.storage.data;
    match ids {
        None => {
            for (account_id, kept) in data::kept_accounts(data).await? {
                if may_reach(access_token, &kept, Permission::SysAccountGet) {
                    response.list.push(to_value(account_id, &kept, &properties));
                }
            }
        }
        Some(ids) => {
            for id in ids {
                match data::kept_account(data, id.document_id()).await? {
                    Some(kept) if may_reach(access_token, &kept, Permission::SysAccountGet) => {
                        response
                            .list
                            .push(to_value(id.document_id(), &kept, &properties));
                    }
                    _ => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:DeletedAccount/set`: update `{"restore": true, "password": ...}`
/// restores; destroy destroys for good.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, DeletedAccount>,
) -> trc::Result<SetResponse<DeletedAccount>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
    let data = &server.core.storage.data;

    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description("Only a deleted account can be restored."),
        );
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let kept = match data::kept_account(data, id.document_id()).await? {
            Some(kept) if may_reach(access_token, &kept, Permission::SysAccountCreate) => kept,
            _ => {
                response.not_updated.append(id, SetError::not_found());
                continue;
            }
        };
        let (mut restore, mut password) = (false, None);
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Restore), Value::Bool(value)) => restore = value,
                (Key::Property(P::Password), Value::Str(value)) => password = Some(value.into_owned()),
                (Key::Property(P::Password), Value::Null) => password = None,
                _ => invalid = Some(key.into_owned()),
            }
        }
        if let Some(key) = invalid {
            response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(key)
                    .with_description("Only restore and password can be set."),
            );
            continue;
        }
        if !restore {
            response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(P::Restore)
                    .with_description("Set restore to true to restore the account."),
            );
            continue;
        }
        match restore_account(server, access_token, id, kept, password).await? {
            Ok(()) => response.updated.append(id, None),
            Err(err) => response.not_updated.append(id, err),
        }
    }

    for id in will_destroy {
        match data::kept_account(data, id.document_id()).await? {
            Some(kept) if may_reach(access_token, &kept, Permission::SysAccountDestroy) => {
                destroy_now(server, id, &kept).await?;
                response.destroyed.push(id);
            }
            _ => response.not_destroyed.append(id, SetError::not_found()),
        }
    }

    Ok(response)
}

fn failed(err: SetError<Property>) -> SetError<P> {
    let mut out = SetError::new(err.error_type().clone());
    if let Some(description) = err.description() {
        out = out.with_description(description.to_string());
    }
    out
}

/// UD-17: writes the record back with the same id and a new password,
/// cancels the pending destruction and reinstates its shares (UD-17a).
async fn restore_account(
    server: &Server,
    access_token: &AccessToken,
    id: Id,
    kept: KeptAccount,
    password: Option<String>,
) -> trc::Result<Result<(), SetError<P>>> {
    let account_id = id.document_id();
    let Some(ObjectInner::Account(mut account)) = PickledStream::new(&kept.record)
        .and_then(|mut stream| ObjectInner::unpickle(ObjectType::Account, &mut stream))
    else {
        return Ok(Err(SetError::forbidden().with_description("The kept record can't be read.")));
    };

    // A user comes back with a new password; its other credentials stay
    if let Account::User(user) = &mut account {
        let Some(password) = password else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(P::Password)
                .with_description("A restored account needs a new password.")));
        };
        if let Err(err) = server.is_secure_password(&password, &[]) {
            return Ok(Err(SetError::invalid_properties()
                .with_property(P::Password)
                .with_description(err)));
        }
        let secret = hash_secret(
            server.core.network.security.password_hash_algorithm,
            password.into_bytes(),
        )
        .await
        .caused_by(trc::location!())?;
        let expires_at = server
            .core
            .network
            .security
            .password_default_expiration
            .map(|expires| UTCDateTime::from_timestamp((now() + expires) as i64));
        match user
            .credentials
            .values_mut()
            .find_map(|credential| match credential {
                Credential::Password(credential) => Some(credential),
                _ => None,
            }) {
            Some(credential) => {
                credential.secret = secret;
                credential.expires_at = expires_at;
            }
            None => {
                return Ok(Err(SetError::forbidden()
                    .with_description("The kept account has no password credential.")));
            }
        }
    }

    // The restorer may only bring back what it could grant
    if server.can_set_permissions(access_token, &account).await?.is_err() {
        return Ok(Err(SetError::forbidden().with_description(
            "You can't grant the permissions this account holds.",
        )));
    }

    let object = Object {
        inner: ObjectInner::Account(account),
        revision: 0,
    };
    if let Err(err) =
        inbuxa_features::tenancy::writes::check(server.registry(), None, None, &object).await?
    {
        return Ok(Err(failed(err)));
    }

    // Its addresses are free for it alone
    let mut batch = BatchBuilder::new();
    data::clear_kept_account(&mut batch, account_id, &kept);
    let data = &server.core.storage.data;
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    match server
        .registry()
        .write(RegistryWrite::Insert {
            object: &object,
            id: Some(id),
        })
        .await?
    {
        RegistryWriteResult::Success(_) => {}
        err => {
            // Put the hold back
            let mut batch = BatchBuilder::new();
            data::set_kept_account(&mut batch, account_id, &kept)?;
            data.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            return Ok(Err(match err {
                RegistryWriteResult::PrimaryKeyConflict { property, .. } => {
                    SetError::new(SetErrorType::PrimaryKeyViolation).with_description(format!(
                        "Another object now has this account's {}.",
                        property.as_str()
                    ))
                }
                RegistryWriteResult::InvalidForeignKey { object_id } => {
                    SetError::new(SetErrorType::InvalidForeignKey).with_description(format!(
                        "{} {} no longer exists.",
                        object_id.object().as_str(),
                        object_id.id()
                    ))
                }
                _ => SetError::forbidden().with_description("The account can't be restored."),
            }));
        }
    }

    // Its destruction is off
    let mut batch = BatchBuilder::new();
    batch
        .clear(ValueClass::TaskQueue(TaskQueueClass::Task { id: kept.task_id }))
        .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: kept.task_id,
            due: kept.kept_until,
        }));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    // UD-17a: its shares come back where the other account still exists
    let mut existing = Vec::new();
    for share in &kept.shares {
        for other in [share.owner, share.grantee] {
            if other != account_id
                && !existing.contains(&other)
                && server
                    .registry()
                    .object::<Account>(Id::from(other))
                    .await?
                    .is_some()
            {
                existing.push(other);
            }
        }
    }
    let others =
        accounts::reinstate_shares(data, account_id, &kept.shares, |id| existing.contains(&id))
            .await?;

    let mut invalidator = CacheInvalidationBuilder::default();
    invalidator.process_create(&object);
    invalidator.invalidate(CacheInvalidation::AccessToken(account_id));
    for other in others {
        invalidator.invalidate(CacheInvalidation::AccessToken(other));
    }
    server.invalidate_caches(invalidator).await?;
    Ok(Ok(()))
}

/// Destroys a kept account for good: its `DestroyAccount` task runs now.
async fn destroy_now(server: &Server, id: Id, kept: &KeptAccount) -> trc::Result<()> {
    let data = &server.core.storage.data;
    let task_key = ValueClass::TaskQueue(TaskQueueClass::Task { id: kept.task_id });
    let mut batch = BatchBuilder::new();
    if let Some(mut task) = data
        .get_value::<Task>(store::ValueKey::from(task_key))
        .await?
    {
        task.set_status(TaskStatus::now());
        batch
            .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                id: kept.task_id,
                due: kept.kept_until,
            }))
            .schedule_task_with_id(kept.task_id, task);
    }
    data::clear_kept_account(&mut batch, id.document_id(), kept);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    server.notify_task_queue();
    Ok(())
}
