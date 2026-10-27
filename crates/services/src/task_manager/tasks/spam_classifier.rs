/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::outcome::{ErrorClass, Failure, Outcome, RetryClass};
use common::{
    Server,
    ipc::{BroadcastEvent, RegistryChange},
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY, fetch_resource, spam_rules},
};
use registry::{
    pickle::Pickle,
    schema::{
        enums::TaskSpamFilterMaintenanceType,
        prelude::{Object, ObjectInner, ObjectType},
        structs::{
            HttpLookup, MemoryLookupKey, SpamDnsblServer, SpamFileExtension, SpamRule, SpamTag,
            TaskSpamFilterMaintenance,
        },
    },
    types::{
        EnumImpl, ObjectImpl,
        index::{IndexBuilder, IndexKey},
    },
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
    ) -> impl Future<Output = Outcome> + Send;
}

impl SpamFilterMaintenanceTask for Server {
    async fn spam_filter_maintenance(&self, task: &TaskSpamFilterMaintenance) -> Outcome {
        match spam_filter_maintenance(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(err.details("Failed to perform spam filter maintenance task"));
                result
            }
        }
    }
}

async fn spam_filter_maintenance(
    server: &Server,
    task: &TaskSpamFilterMaintenance,
) -> trc::Result<Outcome> {
    match task.maintenance_type {
        TaskSpamFilterMaintenanceType::Train => {
            if !server.inner.ipc.train_task_controller.is_running() {
                server.spam_train(false).await?;
            }
        }
        TaskSpamFilterMaintenanceType::Retrain => {
            if !server.inner.ipc.train_task_controller.is_running() {
                server.spam_train(true).await?;
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

    Ok(Outcome::done())
}

struct RuleUpdateError {
    typ: ErrorClass,
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

trait UpstreamObject:
    ObjectImpl + Pickle + Clone + PartialEq + From<Object> + Into<ObjectInner>
{
    fn replacement_for(self, _local: &Self) -> Option<Self> {
        Some(self)
    }

    // inbuxa: the object as its fingerprint sees it. Switching a rule on or
    // off isn't an edit, so `enable` is left out.
    fn without_enable(self) -> Self {
        self
    }
}

impl UpstreamObject for SpamRule {
    fn replacement_for(mut self, local: &Self) -> Option<Self> {
        self.set_enable(local.enable());
        Some(self)
    }

    fn without_enable(mut self) -> Self {
        self.set_enable(true);
        self
    }
}

impl UpstreamObject for SpamDnsblServer {
    fn replacement_for(mut self, local: &Self) -> Option<Self> {
        self.set_enable(local.enable());
        Some(self)
    }

    fn without_enable(mut self) -> Self {
        self.set_enable(true);
        self
    }
}

impl UpstreamObject for HttpLookup {
    fn replacement_for(mut self, local: &Self) -> Option<Self> {
        self.enable = local.enable;
        Some(self)
    }

    fn without_enable(mut self) -> Self {
        self.enable = true;
        self
    }
}

impl UpstreamObject for SpamTag {
    fn replacement_for(self, _local: &Self) -> Option<Self> {
        None
    }
}

impl UpstreamObject for MemoryLookupKey {}

impl UpstreamObject for SpamFileExtension {}

struct RuleUpdateResult {
    object_type: ObjectType,
    added: usize,
    updated: usize,
    unchanged: usize,
    kept: usize,
    failed: usize,
}

impl RuleUpdateResult {
    fn new(object_type: ObjectType) -> Self {
        RuleUpdateResult {
            object_type,
            added: 0,
            updated: 0,
            unchanged: 0,
            kept: 0,
            failed: 0,
        }
    }

    fn has_changes(&self) -> bool {
        self.added + self.updated > 0
    }
}

async fn update_spam_rules(server: &Server) -> trc::Result<Outcome> {
    let started = Instant::now();
    let bundled = server.core.spam.spam_rules_url.is_none();
    let rules = match fetch_spam_rules(server).await {
        Ok(rules) => rules,
        Err(err) => {
            return Ok(match err.typ {
                ErrorClass::Retry(class) => Outcome::Retry(Failure::new(class, err.reason)),
                ErrorClass::Fatal => Outcome::Fatal(err.reason),
            });
        }
    };

    let settings = [
        apply_upstream(server, rules.rules).await?,
        apply_upstream(server, rules.dnsbls).await?,
        apply_upstream(server, rules.tags).await?,
        apply_upstream(server, rules.file_exts).await?,
    ];
    let lookups = [
        apply_upstream(server, rules.http_lookups).await?,
        apply_upstream(server, rules.key_lookups).await?,
    ];

    let mut reload_errors = Vec::new();
    for object in [
        settings
            .iter()
            .any(RuleUpdateResult::has_changes)
            .then_some(ObjectType::SpamRule),
        lookups
            .iter()
            .any(RuleUpdateResult::has_changes)
            .then_some(ObjectType::MemoryLookupKey),
    ]
    .into_iter()
    .flatten()
    {
        if let Err(reason) = reload_and_broadcast(server, object).await {
            reload_errors.push(reason);
        }
    }
    let failed: usize = settings
        .iter()
        .chain(&lookups)
        .map(|result| result.failed)
        .sum();

    // inbuxa: AU-1.10: what the update changed, as one audit record
    let summary = |count: fn(&RuleUpdateResult) -> usize| {
        let mut parts = settings
            .iter()
            .chain(&lookups)
            .filter(|result| count(result) > 0)
            .map(|result| format!("{} {}", count(result), result.object_type.as_str()))
            .collect::<Vec<_>>();
        parts.sort();
        parts.join(", ")
    };
    let details = [
        ("added", summary(|result| result.added)),
        ("replaced", summary(|result| result.updated)),
        ("kept as edited locally", summary(|result| result.kept)),
        ("failed", summary(|result| result.failed)),
    ]
    .into_iter()
    .filter(|(_, part)| !part.is_empty())
    .map(|(what, part)| format!("{what} {part}"))
    .collect::<Vec<_>>();
    if settings
        .iter()
        .chain(&lookups)
        .any(RuleUpdateResult::has_changes)
    {
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
                details: Some(format!("Rules update {}", details.join("; "))),
                reason: None,
                outcome: inbuxa_features::audit::Outcome::success(),
            })
            .await;
    }

    trc::event!(
        Spam(SpamEvent::RulesUpdated),
        Details = settings
            .into_iter()
            .chain(lookups)
            .map(|result| {
                Value::Array(vec![
                    Value::String(result.object_type.as_str().into()),
                    Value::from(result.added),
                    Value::from(result.updated),
                    Value::from(result.unchanged),
                    Value::from(result.failed),
                    Value::from(result.kept),
                ])
            })
            .collect::<Vec<_>>(),
        Elapsed = started.elapsed(),
    );

    if !reload_errors.is_empty() {
        Ok(Outcome::fatal(format!(
            "Spam rules were stored but not activated ({}); fix the logged errors and run Reload settings",
            reload_errors.join("; ")
        )))
    } else if failed > 0 {
        Ok(Outcome::fatal(format!(
            "{failed} spam filter objects failed to import or update"
        )))
    } else {
        // inbuxa: so the next start knows these bundled rules are in. Only
        // once they all are: a failed update runs again on the next start.
        if bundled {
            spam_rules::set_applied_version(server.store(), spam_rules::BUNDLED_SPAM_RULES_APPLIED)
                .await?;
        }
        // inbuxa: personal-data catalog, D5: a new install's first rules
        // leave the hashed-address blocklist off
        if spam_rules::apply_new_install(server.registry(), server.store()).await?
            && let Err(err) = reload_and_broadcast(server, ObjectType::SpamDnsblServer).await
        {
            return Ok(Outcome::fatal(format!(
                "Spam rules were stored but not activated ({err}); run Reload settings"
            )));
        }
        Ok(Outcome::done())
    }
}

async fn reload_and_broadcast(server: &Server, object: ObjectType) -> Result<(), String> {
    match server.reload_registry(RegistryChange::Reload(object)).await {
        Ok(result) => {
            result.log();
            if result.has_errors() {
                return Err(format!("{} configuration errors", result.errors.len()));
            }
            server
                .cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Reload(
                    object,
                )))
                .await;
            Ok(())
        }
        Err(err) => {
            let reason = err.to_string();
            trc::error!(err.details("Failed to reload registry after updating spam rules"));
            Err(reason)
        }
    }
}

async fn apply_upstream<T: UpstreamObject>(
    server: &Server,
    objects: Vec<T>,
) -> trc::Result<RuleUpdateResult> {
    let registry = server.registry();
    let mut result = RuleUpdateResult::new(T::OBJECT);
    let locals = registry.list::<T>().await?;
    let mut local_keys = IndexBuilder::default();
    let mut local_by_key = AHashMap::with_capacity(locals.len());
    for (index, local) in locals.iter().enumerate() {
        local.object.index(&mut local_keys);
        for key in local_keys.keys.drain().filter(is_unique_key) {
            local_by_key.insert(key, index);
        }
    }

    for upstream in objects {
        // inbuxa: every object the update writes is fingerprinted, and an
        // existing object is replaced only while it still matches: one an
        // admin edited is kept as it is.
        let upstream_print = fingerprint(&upstream);
        let existing = {
            let mut upstream_keys = IndexBuilder::default();
            upstream.index(&mut upstream_keys);
            upstream_keys
                .keys
                .iter()
                .filter(|key| is_unique_key(key))
                .find_map(|key| local_by_key.get(key))
                .and_then(|&index| locals.get(index))
        };

        let Some(local) = existing else {
            match registry
                .write(RegistryWrite::insert(&Object::from(upstream)))
                .await?
            {
                RegistryWriteResult::Success(id) => {
                    spam_rules::set_fingerprint(server.store(), T::OBJECT, id.id(), &upstream_print)
                        .await?;
                    result.added += 1
                }
                RegistryWriteResult::PrimaryKeyConflict { .. } => result.unchanged += 1,
                _ => result.failed += 1,
            }
            continue;
        };

        let local_id = local.id.id().id();
        let local_print = fingerprint(&local.object);
        let written_print = spam_rules::fingerprint(server.store(), T::OBJECT, local_id).await?;

        if local_print == upstream_print {
            // The same as upstream's. An install from before fingerprints
            // gets one here, so the next release can replace it.
            if written_print.as_deref() != Some(upstream_print.as_str()) {
                spam_rules::set_fingerprint(server.store(), T::OBJECT, local_id, &upstream_print)
                    .await?;
            }
            result.unchanged += 1;
            continue;
        }
        if written_print.as_deref() != Some(local_print.as_str()) {
            // Changed since the update wrote it, or never written by one.
            result.kept += 1;
            continue;
        }

        let Some(replacement) = upstream
            .replacement_for(&local.object)
            .filter(|replacement| replacement != &local.object)
        else {
            result.unchanged += 1;
            continue;
        };

        let replacement = Object::from(replacement);
        let current = Object::with_revision(local.object.clone().into(), local.revision);
        match registry
            .write(RegistryWrite::update(local.id.id(), &replacement, &current))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                spam_rules::set_fingerprint(server.store(), T::OBJECT, local_id, &upstream_print)
                    .await?;
                result.updated += 1
            }
            _ => result.failed += 1,
        }
    }

    Ok(result)
}

/// inbuxa: a digest of an object's content, `enable` aside, in hex.
fn fingerprint<T: UpstreamObject>(object: &T) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(serde_json::to_vec(&object.clone().without_enable()).unwrap_or_default())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_unique_key(key: &IndexKey<'_>) -> bool {
    matches!(key, IndexKey::Unique { .. })
}

async fn fetch_spam_rules(server: &Server) -> Result<Rules, RuleUpdateError> {
    // inbuxa: no URL means the rules bundled with the server
    let bytes = match server.core.spam.spam_rules_url.as_ref() {
        Some(rules_url) => {
            fetch_resource(rules_url, None, Duration::from_secs(60), 1024 * 500, false)
                .await
                .map_err(|reason| RuleUpdateError {
                    typ: ErrorClass::Retry(RetryClass::Transient),
                    reason,
                })
        }
        None => spam_rules::bundled_rules().map_err(|reason| RuleUpdateError {
            typ: ErrorClass::Fatal,
            reason,
        }),
    };
    let rules_json: AHashMap<String, Vec<serde_json::Value>> = bytes.and_then(|bytes| {
        serde_json::from_slice(&bytes).map_err(|err| RuleUpdateError {
            typ: ErrorClass::Fatal,
            reason: format!("Failed to parse spam rules JSON: {err}"),
        })
    })?;

    let mut rules = Rules::default();
    for (object_type, values) in rules_json {
        let Some(object_type) = ObjectType::parse(&object_type) else {
            return Err(RuleUpdateError {
                typ: ErrorClass::Fatal,
                reason: format!("Invalid object type in spam rules JSON: {object_type}"),
            });
        };

        match object_type {
            ObjectType::SpamRule => {
                rules.rules = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value(value).map_err(|err| RuleUpdateError {
                            typ: ErrorClass::Fatal,
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
                            typ: ErrorClass::Fatal,
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
                            typ: ErrorClass::Fatal,
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
                            typ: ErrorClass::Fatal,
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
                            typ: ErrorClass::Fatal,
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
                            typ: ErrorClass::Fatal,
                            reason: format!("Failed to parse spam file extension: {err}"),
                        })
                    })
                    .collect::<Result<Vec<SpamFileExtension>, RuleUpdateError>>()?;
            }
            _ => {
                return Err(RuleUpdateError {
                    typ: ErrorClass::Fatal,
                    reason: format!("Unsupported object type in spam rules: {object_type:?}"),
                });
            }
        }
    }

    Ok(rules)
}
