/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::{TaskFailureType, TaskResult};
use common::{
    Server,
    ipc::{BroadcastEvent, RegistryChange},
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY, fetch_resource, spam_rules},
};
use registry::{
    schema::{
        enums::TaskSpamFilterMaintenanceType,
        prelude::ObjectType,
        structs::{
            HttpLookup, MemoryLookupKey, SpamDnsblServer, SpamFileExtension, SpamRule, SpamTag,
            TaskSpamFilterMaintenance,
        },
    },
    types::EnumImpl,
};
use spam_filter::modules::classifier::SpamClassifier;
use std::time::{Duration, Instant};
use store::{
    ahash::AHashMap,
    registry::write::{RegistryWrite, RegistryWriteResult},
};
use trc::{SpamEvent, Value};

pub(crate) trait SpamFilterMaintenanceTask: Sync + Send {
    fn spam_filter_maintenance(
        &self,
        task: &TaskSpamFilterMaintenance,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl SpamFilterMaintenanceTask for Server {
    async fn spam_filter_maintenance(&self, task: &TaskSpamFilterMaintenance) -> TaskResult {
        match spam_filter_maintenance(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(err.details("Failed to perform spam filter maintenance task"));
                result
            }
        }
    }
}

async fn spam_filter_maintenance(
    server: &Server,
    task: &TaskSpamFilterMaintenance,
) -> trc::Result<TaskResult> {
    match task.maintenance_type {
        TaskSpamFilterMaintenanceType::Train => {
            if !server.inner.ipc.train_task_controller.is_running() {
                Box::pin(server.spam_train(false)).await?;
            }
        }
        TaskSpamFilterMaintenanceType::Retrain => {
            if !server.inner.ipc.train_task_controller.is_running() {
                Box::pin(server.spam_train(true)).await?;
            }
        }
        TaskSpamFilterMaintenanceType::Reset => {
            for key in [SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY] {
                server.blob_store().delete_blob(key).await?;
            }
        }
        TaskSpamFilterMaintenanceType::Abort => {
            if server.inner.ipc.train_task_controller.is_running() {
                server.inner.ipc.train_task_controller.stop();
            }
        }
        TaskSpamFilterMaintenanceType::UpdateRules => {
            // inbuxa: AU-1.10: one summary record, not one per rule
            return inbuxa_features::audit::scope::quiet(update_spam_rules(server)).await;
        }
    }

    Ok(TaskResult::Success(vec![]))
}

struct RuleUpdateError {
    typ: TaskFailureType,
    reason: String,
}

#[derive(Default)]
struct Rules {
    rules: Vec<SpamRule>,
    dnsbls: Vec<SpamDnsblServer>,
    tags: Vec<SpamTag>,
    http_lookups: Vec<HttpLookup>,
    key_lookups: Vec<MemoryLookupKey>,
    file_exts: Vec<SpamFileExtension>,
}

#[derive(Default)]
struct RuleUpdateResult {
    success: usize,
    already_exists: usize,
    failed: usize,
}

async fn update_spam_rules(server: &Server) -> trc::Result<TaskResult> {
    let started = Instant::now();
    let bundled = server.core.spam.spam_rules_url.is_none();
    let rules = match fetch_spam_rules(server).await {
        Ok(rules) => rules,
        Err(err) => {
            return Ok(TaskResult::Failure {
                typ: err.typ,
                message: err.reason,
                max_attempts: None,
            });
        }
    };

    let registry = server.registry();
    let mut stats: AHashMap<ObjectType, RuleUpdateResult> = AHashMap::new();

    let mut reload_settings = false;
    let mut reload_lookups = false;

    for rule in rules.rules {
        match registry.write(RegistryWrite::insert(&rule.into())).await? {
            RegistryWriteResult::Success(_) => {
                stats.entry(ObjectType::SpamRule).or_default().success += 1;
                reload_settings = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats
                    .entry(ObjectType::SpamRule)
                    .or_default()
                    .already_exists += 1;
            }
            _ => {
                stats.entry(ObjectType::SpamRule).or_default().failed += 1;
            }
        }
    }

    for dnsbl in rules.dnsbls {
        match registry.write(RegistryWrite::insert(&dnsbl.into())).await? {
            RegistryWriteResult::Success(_) => {
                stats
                    .entry(ObjectType::SpamDnsblServer)
                    .or_default()
                    .success += 1;
                reload_settings = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats
                    .entry(ObjectType::SpamDnsblServer)
                    .or_default()
                    .already_exists += 1;
            }
            _ => {
                stats.entry(ObjectType::SpamDnsblServer).or_default().failed += 1;
            }
        }
    }

    for tag in rules.tags {
        match registry.write(RegistryWrite::insert(&tag.into())).await? {
            RegistryWriteResult::Success(_) => {
                stats.entry(ObjectType::SpamTag).or_default().success += 1;
                reload_settings = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats.entry(ObjectType::SpamTag).or_default().already_exists += 1;
            }
            _ => {
                stats.entry(ObjectType::SpamTag).or_default().failed += 1;
            }
        }
    }

    for lookup in rules.http_lookups {
        match registry
            .write(RegistryWrite::insert(&lookup.into()))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                stats.entry(ObjectType::HttpLookup).or_default().success += 1;
                reload_lookups = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats
                    .entry(ObjectType::HttpLookup)
                    .or_default()
                    .already_exists += 1;
            }
            _ => {
                stats.entry(ObjectType::HttpLookup).or_default().failed += 1;
            }
        }
    }

    for key_lookup in rules.key_lookups {
        match registry
            .write(RegistryWrite::insert(&key_lookup.into()))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                stats
                    .entry(ObjectType::MemoryLookupKey)
                    .or_default()
                    .success += 1;
                reload_lookups = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats
                    .entry(ObjectType::MemoryLookupKey)
                    .or_default()
                    .already_exists += 1;
            }
            _ => {
                stats.entry(ObjectType::MemoryLookupKey).or_default().failed += 1;
            }
        }
    }

    for ext in rules.file_exts {
        match registry.write(RegistryWrite::insert(&ext.into())).await? {
            RegistryWriteResult::Success(_) => {
                stats
                    .entry(ObjectType::SpamFileExtension)
                    .or_default()
                    .success += 1;
                reload_settings = true;
            }
            RegistryWriteResult::PrimaryKeyConflict { .. } => {
                stats
                    .entry(ObjectType::SpamFileExtension)
                    .or_default()
                    .already_exists += 1;
            }
            _ => {
                stats
                    .entry(ObjectType::SpamFileExtension)
                    .or_default()
                    .failed += 1;
            }
        }
    }

    if reload_settings {
        if let Err(err) =
            Box::pin(server.reload_registry(RegistryChange::Reload(ObjectType::SpamRule))).await
        {
            trc::error!(err.details("Failed to reload registry after updating spam rules"));
        }
        server
            .cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Reload(
                ObjectType::SpamRule,
            )))
            .await;
    }

    if reload_lookups {
        if let Err(err) =
            Box::pin(server.reload_registry(RegistryChange::Reload(ObjectType::MemoryLookupKey)))
                .await
        {
            trc::error!(err.details("Failed to reload registry after updating spam rules"));
        }
        server
            .cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Reload(
                ObjectType::MemoryLookupKey,
            )))
            .await;
    }

    // inbuxa: AU-1.10: what the update added, as one audit record
    let added = stats
        .iter()
        .filter(|(_, result)| result.success > 0)
        .map(|(object_type, result)| format!("{} {}", result.success, object_type.as_str()))
        .collect::<Vec<_>>();
    if !added.is_empty() {
        let mut added = added;
        added.sort();
        server
            .audit_note(inbuxa_features::audit::Record {
                at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64),
                actor: inbuxa_features::audit::Actor::system("SpamFilterMaintenance"),
                via: None,
                remote_ip: None,
                action: inbuxa_features::audit::Action::Update,
                target: inbuxa_features::audit::Target {
                    kind: "x:SpamRule".into(),
                    name: Some("Spam filter rules".into()),
                    ..Default::default()
                },
                changes: vec![],
                details: Some(format!("Rules update added {}", added.join(", "))),
                reason: None,
                outcome: inbuxa_features::audit::Outcome::success(),
            })
            .await;
    }

    trc::event!(
        Spam(SpamEvent::RulesUpdated),
        Details = stats
            .into_iter()
            .map(|(object_type, result)| {
                Value::Array(vec![
                    Value::String(object_type.as_str().into()),
                    Value::from(result.success),
                    Value::from(result.already_exists),
                    Value::from(result.failed),
                ])
            })
            .collect::<Vec<_>>(),
        Elapsed = started.elapsed(),
    );

    // inbuxa: so the next start knows these bundled rules are in
    if bundled {
        spam_rules::set_applied_version(server.store(), spam_rules::BUNDLED_SPAM_RULES_VERSION)
            .await?;
    }

    Ok(TaskResult::Success(vec![]))
}

async fn fetch_spam_rules(server: &Server) -> Result<Rules, RuleUpdateError> {
    // inbuxa: no URL means the rules bundled with the server
    let bytes = match server.core.spam.spam_rules_url.as_ref() {
        Some(rules_url) => fetch_resource(rules_url, None, Duration::from_secs(60), 1024 * 500)
            .await
            .map_err(|reason| RuleUpdateError {
                typ: TaskFailureType::Temporary,
                reason,
            }),
        None => spam_rules::bundled_rules().map_err(|reason| RuleUpdateError {
            typ: TaskFailureType::Permanent,
            reason,
        }),
    };
    let rules_json: AHashMap<String, Vec<serde_json::Value>> =
        bytes.and_then(|bytes| {
            serde_json::from_slice(&bytes).map_err(|err| RuleUpdateError {
                typ: TaskFailureType::Permanent,
                reason: format!("Failed to parse spam rules JSON: {err}"),
            })
        })?;

    let mut rules = Rules::default();
    for (object_type, values) in rules_json {
        let Some(object_type) = ObjectType::parse(&object_type) else {
            return Err(RuleUpdateError {
                typ: TaskFailureType::Permanent,
                reason: format!("Invalid object type in spam rules JSON: {object_type}"),
            });
        };

        match object_type {
            ObjectType::SpamRule => {
                rules.rules = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse spam rule: {err}"),
                        })
                    })
                    .collect::<Result<Vec<SpamRule>, RuleUpdateError>>()?;
            }
            ObjectType::SpamDnsblServer => {
                rules.dnsbls = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse DNSBL server: {err}"),
                        })
                    })
                    .collect::<Result<Vec<SpamDnsblServer>, RuleUpdateError>>()?;
            }
            ObjectType::SpamTag => {
                rules.tags = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse spam tag: {err}"),
                        })
                    })
                    .collect::<Result<Vec<SpamTag>, RuleUpdateError>>()?;
            }
            ObjectType::HttpLookup => {
                rules.http_lookups = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse HTTP lookup: {err}"),
                        })
                    })
                    .collect::<Result<Vec<HttpLookup>, RuleUpdateError>>()?;
            }
            ObjectType::MemoryLookupKey => {
                rules.key_lookups = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse memory lookup key: {err}"),
                        })
                    })
                    .collect::<Result<Vec<MemoryLookupKey>, RuleUpdateError>>()?;
            }
            ObjectType::SpamFileExtension => {
                rules.file_exts = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: TaskFailureType::Permanent,
                            reason: format!("Failed to parse spam file extension: {err}"),
                        })
                    })
                    .collect::<Result<Vec<SpamFileExtension>, RuleUpdateError>>()?;
            }
            _ => {
                return Err(RuleUpdateError {
                    typ: TaskFailureType::Permanent,
                    reason: format!("Unsupported object type in spam rules: {object_type:?}"),
                });
            }
        }
    }

    Ok(rules)
}
