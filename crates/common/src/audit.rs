/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the audit log's server side (audit-hold-lock spec, AU-1 to
//! AU-11). The records, the chain and queries live in
//! `inbuxa_features::audit`; this is what needs the running server: the
//! node's id, account names, and the sign-in and access hooks.

use crate::{
    Server,
    auth::{AccessToken, AuthRequest, permissions::DefaultPermissions},
};
use directory::Credentials;
use inbuxa_features::hold::{self, Member};
use inbuxa_features::audit::{
    Action, Actor, AuditLog, EntryId, Outcome, Record, Target, Via, diff, log, scope,
};
use registry::{
    jmap::IntoValue,
    schema::{enums::Permission, prelude::ObjectType},
    types::EnumImpl,
};
use std::{future::Future, pin::Pin, sync::Arc, sync::OnceLock};
use store::{
    Store,
    registry::hook::{RegistryChange, RegistryWriteHook},
    write::now,
};
use types::id::Id;

/// What kind of recorded access a dedupe key is for (AU-1.4, AU-1.6).
const KIND_ACCOUNT_ACCESS: u8 = 0;
const KIND_BLOB_ACCESS: u8 = 1;
const KIND_SIGN_IN: u8 = 2;
const KIND_SIGN_IN_FAILED: u8 = 3;
const KIND_DELEGATE_ACCESS: u8 = 4;

/// The permissions that make an account an administrator for AU-1.4: every
/// `sys*` permission a plain user doesn't get by default, and impersonation.
fn admin_permissions() -> &'static [Permission] {
    static ADMIN: OnceLock<Vec<Permission>> = OnceLock::new();
    ADMIN.get_or_init(|| {
        let user = DefaultPermissions::default().user;
        (0..Permission::COUNT)
            .filter_map(|id| Permission::from_id(id as u16))
            .filter(|permission| {
                (permission.as_str().starts_with("sys") && !user.contains(permission))
                    || matches!(
                        permission,
                        Permission::Impersonate | Permission::FetchAnyBlob
                    )
            })
            .collect()
    })
}

/// Whether a session holds any administrator permission.
pub fn is_admin(token: &AccessToken) -> bool {
    admin_permissions()
        .iter()
        .any(|permission| token.has_permission(*permission))
}

fn ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A small, stable number for a sign-in's method and address, so repeated
/// sign-ins the same way are recorded once an hour (AU-1.4).
fn sign_in_key(via: Option<&Via>, ip: std::net::IpAddr) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    via.hash(&mut hasher);
    ip.hash(&mut hasher);
    hasher.finish() as u32
}

impl Server {
    fn audit(&self) -> &AuditLog {
        &self.inner.data.audit
    }

    /// This node's chain.
    pub fn audit_node(&self) -> u64 {
        self.core.network.node_id
    }

    /// An account as an actor, named as it is now, which the record keeps
    /// (AU-4).
    pub async fn audit_actor(&self, token: &AccessToken) -> Actor {
        let account_id = token.account_id();
        Actor::account(
            account_id,
            self.audit_account_name(account_id).await,
            token.tenant_id(),
        )
    }

    pub async fn audit_account_name(&self, account_id: u32) -> String {
        self.account(account_id)
            .await
            .map(|account| account.name.to_string())
            .unwrap_or_else(|_| format!("account {}", Id::from(account_id)))
    }

    /// Writes a record to this node's chain. An error means nothing was
    /// written: a change must then be refused (AU-3).
    pub async fn audit_append(&self, record: &Record) -> trc::Result<EntryId> {
        match self
            .audit()
            .append(self.store(), self.audit_node(), record)
            .await
        {
            Ok(id) => {
                trc::event!(
                    Security(trc::SecurityEvent::AuditRecorded),
                    Id = id.to_string(),
                    Type = record.action.as_str(),
                    AccountName = record.actor.name.clone(),
                    Details = describe_target(&record.target),
                    Result = record.outcome.as_str(),
                );
                Ok(id)
            }
            Err(err) => {
                trc::event!(
                    Security(trc::SecurityEvent::AuditWriteFailed),
                    Type = record.action.as_str(),
                    AccountName = record.actor.name.clone(),
                    Details = describe_target(&record.target),
                    Reason = err.to_string(),
                );
                Err(err)
            }
        }
    }

    /// Writes the outcome of a record written as pending.
    pub async fn audit_finish(&self, id: EntryId, outcome: Outcome) -> trc::Result<()> {
        let result = outcome.as_str();
        match self
            .audit()
            .finish(self.store(), self.audit_node(), id, ms(), outcome)
            .await
        {
            Ok(_) => {
                trc::event!(
                    Security(trc::SecurityEvent::AuditRecorded),
                    Id = id.to_string(),
                    Result = result,
                );
                Ok(())
            }
            Err(err) => {
                trc::event!(
                    Security(trc::SecurityEvent::AuditWriteFailed),
                    Id = id.to_string(),
                    Reason = err.to_string(),
                );
                Err(err)
            }
        }
    }

    /// Records something that isn't a change (a sign-in, an access), where
    /// a failed write is reported but stops nothing.
    pub async fn audit_note(&self, record: Record) -> bool {
        self.audit_append(&record).await.is_ok()
    }

    /// AU-1.4, AU-1.5: an administrator's sign-in, a master user's, or the
    /// recovery administrator's, at most once an hour per account, method
    /// and address. Using an OAuth or directory token isn't a sign-in: the
    /// sign-in was on the server's own page, with a password.
    pub async fn audit_sign_in(&self, req: &AuthRequest, token: &AccessToken) {
        let via = token.origin();
        let (actor, target) = match via {
            None | Some(Via::OAuth { .. }) | Some(Via::Directory) => return,
            Some(Via::Master { account_id, name }) => {
                let target_id = token.account_id();
                (
                    Actor {
                        account_id: *account_id,
                        name: name.clone(),
                        tenant_id: None,
                    },
                    Target {
                        kind: "account".into(),
                        id: Some(Id::from(target_id).to_string()),
                        name: Some(self.audit_account_name(target_id).await),
                        account_id: Some(target_id),
                        tenant_id: token.tenant_id(),
                    },
                )
            }
            // The recovery admin is an account for the log's purposes, as
            // its changes are: named, and signing in to itself
            Some(Via::Recovery) => {
                let actor = self.audit_actor(token).await;
                let target = Target {
                    kind: "account".into(),
                    id: Some(Id::from(token.account_id()).to_string()),
                    name: Some(actor.name.clone()),
                    account_id: Some(token.account_id()),
                    tenant_id: None,
                };
                (actor, target)
            }
            Some(_) if is_admin(token) => {
                let actor = self.audit_actor(token).await;
                let target = Target {
                    kind: "account".into(),
                    id: Some(Id::from(token.account_id()).to_string()),
                    name: Some(actor.name.clone()),
                    account_id: Some(token.account_id()),
                    tenant_id: token.tenant_id(),
                };
                (actor, target)
            }
            Some(_) => return,
        };
        let actor_key = actor.account_id.unwrap_or(u32::MAX);
        let key = sign_in_key(via, req.remote_ip);
        if !self
            .audit()
            .first_access_this_hour(actor_key, key, KIND_SIGN_IN, now())
        {
            return;
        }
        let recorded = self
            .audit_note(Record {
                at: ms(),
                actor,
                via: via.cloned(),
                remote_ip: Some(req.remote_ip),
                action: Action::SignIn,
                target,
                changes: vec![],
                details: None,
                reason: None,
                outcome: Outcome::success(),
            })
            .await;
        if !recorded {
            self.audit().forget_access(actor_key, key, KIND_SIGN_IN);
        }
    }

    /// AU-1.4: a failed password sign-in to an administrator's account, at
    /// most once an hour per account and address. Accounts that don't exist
    /// or aren't administrators aren't recorded, so guessing doesn't fill
    /// the log.
    pub async fn audit_sign_in_failed(&self, req: &AuthRequest) {
        let Credentials::Basic { username, .. } = &req.credentials else {
            return;
        };
        // `target%master` fails as the master
        let name = username.rsplit('%').next().unwrap_or(username);
        let Ok(Some(account_id)) = self.account_id_from_email(name, false).await else {
            return;
        };
        let Ok(token) = self.access_token(account_id).await else {
            return;
        };
        let token = AccessToken::new_maybe_invalid(token);
        if !is_admin(&token) {
            return;
        }
        let key = sign_in_key(None, req.remote_ip);
        if !self
            .audit()
            .first_access_this_hour(account_id, key, KIND_SIGN_IN_FAILED, now())
        {
            return;
        }
        let actor = self.audit_actor(&token).await;
        let target = Target {
            kind: "account".into(),
            id: Some(Id::from(account_id).to_string()),
            name: Some(actor.name.clone()),
            account_id: Some(account_id),
            tenant_id: token.tenant_id(),
        };
        if !self
            .audit_note(Record {
                at: ms(),
                actor,
                via: None,
                remote_ip: Some(req.remote_ip),
                action: Action::SignInFailed,
                target,
                changes: vec![],
                details: None,
                reason: None,
                outcome: Outcome::refused("authenticationFailed", None),
            })
            .await
        {
            self.audit()
                .forget_access(account_id, key, KIND_SIGN_IN_FAILED);
        }
    }

    /// AU-1.6: access to another account's data through `Impersonate` (or a
    /// blob through `FetchAnyBlob`), once an hour per session's account and
    /// target. Access through a share or group membership isn't this: the
    /// owner granted it.
    pub async fn audit_foreign_access(&self, token: &AccessToken, target_id: u32, blob: bool) {
        if target_id == token.account_id() || token.is_member_directly(target_id) {
            return;
        }
        let kind = if blob {
            KIND_BLOB_ACCESS
        } else {
            KIND_ACCOUNT_ACCESS
        };
        if !self
            .audit()
            .first_access_this_hour(token.account_id(), target_id, kind, now())
        {
            return;
        }
        let actor = self.audit_actor(token).await;
        let target_tenant = self
            .account(target_id)
            .await
            .ok()
            .and_then(|account| account.id_tenant);
        if !self
            .audit_note(Record {
                at: ms(),
                actor,
                via: token.origin().cloned(),
                remote_ip: None,
                action: if blob {
                    Action::BlobAccess
                } else {
                    Action::AccountAccess
                },
                target: Target {
                    kind: "account".into(),
                    id: Some(Id::from(target_id).to_string()),
                    name: Some(self.audit_account_name(target_id).await),
                    account_id: Some(target_id),
                    tenant_id: target_tenant,
                },
                changes: vec![],
                details: None,
                reason: None,
                outcome: Outcome::success(),
            })
            .await
        {
            self.audit()
                .forget_access(token.account_id(), target_id, kind);
        }
    }

    /// AU-1.10: from here on, registry writes the server makes on its own
    /// are recorded. Installed once boot has written its defaults.
    pub fn install_audit_hook(&self) {
        self.registry().set_write_hook(Arc::new(SystemWrites {
            data: self.store().clone(),
            log: AuditLog::new(),
            node: self.audit_node(),
        }));
    }

    /// AL-9: a delegate reaching a locked account: its access once an hour,
    /// and every change it makes there, one record per method call.
    pub async fn audit_delegate(
        &self,
        token: &AccessToken,
        locked_id: u32,
        access: &str,
        write: Option<&str>,
        error: Option<&trc::Error>,
    ) {
        let first = self.audit().first_access_this_hour(
            token.account_id(),
            locked_id,
            KIND_DELEGATE_ACCESS,
            now(),
        );
        if !first && write.is_none() {
            return;
        }
        let actor = self.audit_actor(token).await;
        let target = Target {
            kind: "account".into(),
            id: Some(Id::from(locked_id).to_string()),
            name: Some(self.audit_account_name(locked_id).await),
            account_id: Some(locked_id),
            tenant_id: self
                .account(locked_id)
                .await
                .ok()
                .and_then(|account| account.id_tenant),
        };
        let mut records = Vec::new();
        if first {
            records.push(Record {
                at: ms(),
                actor: actor.clone(),
                via: token.origin().cloned(),
                remote_ip: None,
                action: Action::AccountAccess,
                target: target.clone(),
                changes: vec![],
                details: Some(format!("As a delegate ({access})")),
                reason: None,
                outcome: Outcome::success(),
            });
        }
        if let Some(method) = write {
            records.push(Record {
                at: ms(),
                actor,
                via: token.origin().cloned(),
                remote_ip: None,
                action: Action::Update,
                target,
                changes: vec![],
                details: Some(format!("{method} as a delegate ({access})")),
                reason: None,
                outcome: match error {
                    None => Outcome::success(),
                    Some(err) => Outcome::refused(
                        "error",
                        err.value_as_str(trc::Key::Details).map(str::to_string),
                    ),
                },
            });
        }
        for record in records {
            if !self.audit_note(record).await && first {
                self.audit()
                    .forget_access(token.account_id(), locked_id, KIND_DELEGATE_ACCESS);
            }
        }
    }

    /// MA-D0a: a message sent from an address that isn't the sender's own:
    /// a group's or a shared mailbox's. The message itself only says
    /// `From:` that address, so the audit log is where the person who sent
    /// it is named. A locked account's delegate's send is AL-9's record, not
    /// this one.
    pub async fn audit_send_as(
        &self,
        token: &AccessToken,
        submission_account_id: u32,
        submission_id: u32,
        address: &str,
    ) {
        let Ok(Some(as_account_id)) = self.account_id_from_email(address, true).await else {
            return;
        };
        if as_account_id == token.account_id()
            || token
                .delegation(as_account_id)
                .is_some_and(|delegation| delegation.kind.is_lock())
        {
            return;
        }
        let actor = self.audit_actor(token).await;
        let tenant_id = self
            .account(as_account_id)
            .await
            .ok()
            .and_then(|account| account.id_tenant);
        let details = if submission_account_id == as_account_id {
            format!("Sent as {address}")
        } else {
            format!(
                "Sent as {address}, from {}",
                self.audit_account_name(submission_account_id).await
            )
        };
        self.audit_note(Record {
            at: ms(),
            actor,
            via: token.origin().cloned(),
            remote_ip: None,
            action: Action::Create,
            target: Target {
                kind: "EmailSubmission".into(),
                id: Some(Id::from(submission_id).to_string()),
                name: Some(address.to_string()),
                account_id: Some(as_account_id),
                tenant_id,
            },
            changes: vec![],
            details: Some(details),
            reason: None,
            outcome: Outcome::success(),
        })
        .await;
    }

    /// AU-7: removes entries past the retention period.
    pub async fn audit_purge(&self) -> trc::Result<usize> {
        let settings = log::settings(self.store()).await?;
        let cutoff = ms().saturating_sub(settings.keep_for_secs.saturating_mul(1000));
        // LH-6, AU-7: a record about a held account stays while it's held.
        // Worked out before the purge, which can't wait on lookups.
        let held = self.held_accounts().await?;
        log::purge(self.store(), cutoff, |record| {
            record
                .target
                .account_id
                .is_some_and(|account_id| held.contains(&account_id))
        })
        .await
    }
}

fn describe_target(target: &Target) -> String {
    match (&target.name, &target.id) {
        (Some(name), _) => format!("{} {name}", target.kind),
        (None, Some(id)) => format!("{} {id}", target.kind),
        (None, None) => target.kind.clone(),
    }
}

/// AU-1.10: records a registry write made outside any request, as the
/// server's own, under the subsystem its task runs in.
struct SystemWrites {
    data: Store,
    log: AuditLog,
    node: u64,
}

/// Objects whose writes aren't the control plane: telemetry and mail data
/// the registry also stores.
fn is_quiet_object(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::SpamTrainingSample
            | ObjectType::ArchivedItem
            | ObjectType::Trace
            | ObjectType::Metric
            | ObjectType::Log
            | ObjectType::ClusterNode
            | ObjectType::Task
            | ObjectType::QueuedMessage
            | ObjectType::ArfExternalReport
            | ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::DmarcInternalReport
            | ObjectType::TlsInternalReport
    )
}

impl RegistryWriteHook for SystemWrites {
    fn written<'a>(
        &'a self,
        change: RegistryChange<'a>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // LH-2: every change to an account, whoever makes it: one that
            // leaves a held domain, group or tenant stays held by name
            if change.object_type == ObjectType::Account
                && let (Some(before), Some(after)) = (change.before, change.after)
                && let (Some(before), Some(after)) = (
                    Member::of(change.id.document_id(), &before.inner),
                    Member::of(change.id.document_id(), &after.inner),
                )
                && let Err(err) = hold::keep_moved(&self.data, &before, &after).await
            {
                trc::error!(err
                    .account_id(after.account)
                    .details("Failed to keep a moved account under its legal hold"));
            }
            let subsystem = match scope::current() {
                Some(scope::Scope::Request | scope::Scope::Quiet) => return,
                Some(scope::Scope::System(subsystem)) => subsystem,
                None => "server",
            };
            if is_quiet_object(change.object_type) {
                return;
            }
            let kind = format!("x:{}", change.object_type.as_str());
            let json = |object: &registry::schema::prelude::Object| {
                serde_json::to_value(object.clone().into_value()).unwrap_or_default()
            };
            let before = change.before.map(json);
            let after = change.after.map(json);
            let described = after
                .as_ref()
                .or(before.as_ref())
                .map(diff::describe)
                .unwrap_or_default();
            let action = match (&before, &after) {
                (None, _) => Action::Create,
                (Some(_), Some(_)) => Action::Update,
                (Some(_), None) => Action::Destroy,
            };
            let changes = match action {
                Action::Destroy => vec![],
                _ => diff::diff(&kind, before.as_ref(), after.as_ref()),
            };
            let record = Record {
                at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64),
                actor: Actor::system(subsystem),
                via: None,
                remote_ip: None,
                action,
                target: Target {
                    kind,
                    id: Some(change.id.to_string()),
                    name: described.name,
                    account_id: described.account_id,
                    tenant_id: described.tenant_id,
                },
                changes,
                details: None,
                reason: None,
                outcome: Outcome::success(),
            };
            match self.log.append(&self.data, self.node, &record).await {
                Ok(id) => trc::event!(
                    Security(trc::SecurityEvent::AuditRecorded),
                    Id = id.to_string(),
                    Type = record.action.as_str(),
                    AccountName = record.actor.name.clone(),
                    Details = describe_target(&record.target),
                ),
                Err(err) => trc::event!(
                    Security(trc::SecurityEvent::AuditWriteFailed),
                    Type = record.action.as_str(),
                    AccountName = record.actor.name.clone(),
                    Details = describe_target(&record.target),
                    Reason = err.to_string(),
                ),
            }
        })
    }
}
