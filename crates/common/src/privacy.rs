/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The live facts the personal-data catalog is evaluated against
//! (personal-data catalog spec, §6): which sources are switched on, what
//! bounds each one's retention, which stores and endpoints are elsewhere.
//! Read from the registry on each request, so every node answers alike.

use crate::Server;
use inbuxa_features::privacy::{
    self, Days, Inventory, LiveFacts, is_loopback,
    snapshot::{self, Snapshot, Trigger},
};
use registry::schema::{
    prelude::Object,
    structs::{
        AiModel, BlobStore, DataRetention, DataStore, InMemoryStore, Jmap, MtaHook, MtaMilter,
        MtaRoute, Search, SearchStore, SpamClassifier, SpamClassifierModel, SpamDnsblServer,
        SpamLlm, SpamPyzor, Tracer, TracingStore, WebHook,
    },
};
use registry::types::duration::Duration;
use serde_json::Value;
use types::id::Id;

/// The objects [`Server::privacy_facts`] reads: a write to one may change
/// the inventory.
pub const INVENTORY_OBJECTS: &[&str] = &[
    "x:DataRetention",
    "x:SpamClassifier",
    "x:Jmap",
    "x:TracingStore",
    "x:Search",
    "x:Tracer",
    "x:WebHook",
    "x:AiModel",
    "x:SpamLlm",
    "x:SpamDnsblServer",
    "x:SpamPyzor",
    "x:MtaMilter",
    "x:MtaHook",
    "x:MtaRoute",
    "x:DataStore",
    "x:BlobStore",
    "x:SearchStore",
    "x:InMemoryStore",
    "inbuxa:AuditSettings",
    "inbuxa:LogSettings",
    "inbuxa:AiLimits",
];

/// A store or endpoint object's type and host, from its JSON: local types
/// stay on the host.
fn remote_host(value: &Value) -> Option<String> {
    let kind = value.get("@type").and_then(Value::as_str).unwrap_or_default();
    if matches!(kind, "" | "RocksDb" | "Sqlite" | "FileSystem" | "Default" | "Disabled") {
        return None;
    }
    for key in ["host", "url", "endpoint", "address", "hostname"] {
        if let Some(host) = value.get(key).and_then(Value::as_str).filter(|h| !h.is_empty()) {
            return Some(host.to_string());
        }
    }
    // A list of URLs, as an array or as a map keyed by URL
    match value.get("urls") {
        Some(Value::Array(urls)) => {
            if let Some(url) = urls.first().and_then(Value::as_str) {
                return Some(url.to_string());
            }
        }
        Some(Value::Object(urls)) => {
            if let Some(url) = urls.keys().next() {
                return Some(url.clone());
            }
        }
        _ => {}
    }
    Some(kind.to_string())
}

fn days(duration: Option<&Duration>) -> Days {
    match duration {
        Some(d) => Days::Days(d.into_inner().as_secs().div_ceil(86_400)),
        None => Days::Unbounded,
    }
}

/// An expression's text, if it is a plain constant (a zone, a switch).
fn expression_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("else").and_then(|v| v.as_str()).map(str::to_string),
        _ => None,
    }
}

impl Server {
    async fn singleton<T: registry::types::ObjectImpl + From<Object> + Default>(&self) -> trc::Result<T> {
        Ok(self.registry().object::<T>(Id::singleton()).await?.unwrap_or_default())
    }

    /// The facts the catalog is evaluated against, from the live settings.
    pub async fn privacy_facts(&self) -> trc::Result<LiveFacts> {
        let mut facts = LiveFacts::default();
        let data = &self.core.storage.data;
        let endpoint = |facts: &mut LiveFacts, id: &str, url: String| {
            if !url.is_empty() && !is_loopback(&url) {
                facts.endpoints.entry(id.to_string()).or_default().push(url);
            }
        };

        // Retention
        let retention = self.singleton::<DataRetention>().await?;
        for (name, value) in [
            ("x:DataRetention.holdTracesFor", &retention.hold_traces_for),
            ("x:DataRetention.holdMetricsFor", &retention.hold_metrics_for),
            ("x:DataRetention.holdMtaReportsFor", &retention.hold_mta_reports_for),
            ("x:DataRetention.archiveDeletedItemsFor", &retention.archive_deleted_items_for),
            ("x:DataRetention.archiveDeletedAccountsFor", &retention.archive_deleted_accounts_for),
            ("x:DataRetention.expungeTrashAfter", &retention.expunge_trash_after),
            ("x:DataRetention.expungeSubmissionsAfter", &retention.expunge_submissions_after),
        ] {
            facts.durations.insert(name.into(), days(value.as_ref()));
        }
        let classifier = self.singleton::<SpamClassifier>().await?;
        facts.durations.insert(
            "x:SpamClassifier.holdSamplesFor".into(),
            days(Some(&classifier.hold_samples_for)),
        );
        let jmap = self.singleton::<Jmap>().await?;
        facts
            .durations
            .insert("x:Jmap.uploadTtl".into(), days(Some(&jmap.upload_ttl)));
        let audit = inbuxa_features::audit::log::settings(data).await?;
        facts.durations.insert(
            "inbuxa:AuditSettings.keepForDays".into(),
            Days::Days(audit.keep_for_secs.div_ceil(86_400)),
        );
        let logs = inbuxa_features::security::log_files::get(data).await?;
        facts.durations.insert(
            "inbuxa:LogSettings.keepForDays".into(),
            logs.keep_for_days.map_or(Days::Unbounded, Days::Days),
        );

        // What's switched on
        let tracing = self.singleton::<TracingStore>().await?;
        let tracing_on = !matches!(tracing, TracingStore::Disabled);
        let search = self.singleton::<Search>().await?;
        for id in ["x:Trace", "x:TraceEvent", "x:TraceKeyValue", "x:TraceValueIpAddr", "x:TraceValueString"] {
            facts.collected.insert(id.into(), tracing_on);
        }
        facts
            .collected
            .insert("trace-index".into(), tracing_on && search.index_telemetry);
        facts.collected.insert(
            "full-text-index".into(),
            search.index_email || search.index_calendar || search.index_contacts,
        );
        let archive_on = retention.archive_deleted_items_for.is_some();
        for id in [
            "x:ArchivedEmail",
            "x:ArchivedFileNode",
            "x:ArchivedCalendarEvent",
            "x:ArchivedContactCard",
            "x:ArchivedSieveScript",
        ] {
            facts.collected.insert(id.into(), archive_on);
        }
        facts.collected.insert(
            "inbuxa:DeletedAccount".into(),
            retention.archive_deleted_accounts_for.is_some(),
        );
        let reports_on = retention.hold_mta_reports_for.is_some();
        for id in [
            "x:ArfExternalReport",
            "x:ArfFeedbackReport",
            "x:DmarcExternalReport",
            "x:DmarcReport",
            "x:DmarcReportRecord",
            "x:TlsExternalReport",
            "x:TlsReport",
            "x:TlsFailureDetails",
        ] {
            facts.collected.insert(id.into(), reports_on);
        }
        let classifier_on = !matches!(classifier.model, SpamClassifierModel::Disabled);
        facts
            .collected
            .insert("x:SpamTrainingSample".into(), classifier_on);
        facts
            .collected
            .insert("spam-trainer-state".into(), classifier_on);

        // Tracers
        let (mut log_on, mut console_on, mut otel_on) = (false, false, false);
        for tracer in self.registry().list::<Tracer>().await? {
            match tracer.object {
                Tracer::Log(t) => log_on |= t.enable,
                Tracer::Stdout(t) => console_on |= t.enable,
                Tracer::Journal(t) => console_on |= t.enable,
                Tracer::OtelHttp(t) if t.enable => {
                    otel_on = true;
                    endpoint(&mut facts, "otel-tracer", t.endpoint);
                }
                Tracer::OtelGrpc(t) if t.enable => {
                    otel_on = true;
                    endpoint(&mut facts, "otel-tracer", t.endpoint.unwrap_or_default());
                }
                _ => {}
            }
        }
        facts.collected.insert("log-file".into(), log_on);
        facts.collected.insert("x:Log".into(), log_on);
        facts.collected.insert("console-and-journal".into(), console_on);
        facts.collected.insert("otel-tracer".into(), otel_on);

        // Webhooks
        let mut hooks_on = false;
        for hook in self.registry().list::<WebHook>().await? {
            if hook.object.enable {
                hooks_on = true;
                endpoint(&mut facts, "webhooks", hook.object.url);
            }
        }
        facts.collected.insert("webhooks".into(), hooks_on);

        // AI: the classifier's model, and Explain's
        let models = self.registry().list::<AiModel>().await?;
        let model_url = |id: Id| {
            models
                .iter()
                .find(|m| Id::from(m.id.id()) == id)
                .map(|m| m.object.url.clone())
        };
        let llm_on = match self.singleton::<SpamLlm>().await? {
            SpamLlm::Enable(props) => {
                if let Some(url) = model_url(props.model_id) {
                    endpoint(&mut facts, "spam-llm", url);
                }
                true
            }
            SpamLlm::Disable => false,
        };
        facts.collected.insert("spam-llm".into(), llm_on);
        let limits = self.ai_limits().await;
        let explain = self.ai_explain_model(&limits).await;
        if let Some((_, model)) = &explain {
            endpoint(&mut facts, "inbuxa:Explanation", model.url.clone());
        }
        facts
            .collected
            .insert("explain-cache".into(), explain.is_some());
        facts
            .collected
            .insert("inbuxa:Explanation".into(), explain.is_some());

        // Spam lookups off the host
        let mut dnsbl_on = false;
        for server in self.registry().list::<SpamDnsblServer>().await? {
            let value = serde_json::to_value(&server.object).unwrap_or_default();
            if value.get("enable").and_then(Value::as_bool).unwrap_or(false) {
                dnsbl_on = true;
                if let Some(zone) = value.get("zone").and_then(expression_text) {
                    endpoint(&mut facts, "spam-dnsbl", zone);
                }
            }
        }
        facts.collected.insert("spam-dnsbl".into(), dnsbl_on);
        let pyzor = self.singleton::<SpamPyzor>().await?;
        if pyzor.enable {
            endpoint(&mut facts, "spam-pyzor", format!("{}:{}", pyzor.host, pyzor.port));
        }
        facts.collected.insert("spam-pyzor".into(), pyzor.enable);

        // Mail handed to others
        let mut hooks = false;
        for milter in self.registry().list::<MtaMilter>().await? {
            hooks = true;
            endpoint(
                &mut facts,
                "mta-milter-and-hooks",
                format!("{}:{}", milter.object.hostname, milter.object.port),
            );
        }
        for hook in self.registry().list::<MtaHook>().await? {
            hooks = true;
            endpoint(&mut facts, "mta-milter-and-hooks", hook.object.url);
        }
        facts.collected.insert("mta-milter-and-hooks".into(), hooks);
        let mut relays = false;
        for route in self.registry().list::<MtaRoute>().await? {
            if let MtaRoute::Relay(relay) = route.object {
                relays = true;
                endpoint(&mut facts, "relay", format!("{}:{}", relay.address, relay.port));
            }
        }
        facts.collected.insert("relay".into(), relays);

        // Stores elsewhere
        let stores = [
            ("data-store", serde_json::to_value(self.singleton::<DataStore>().await.ok()).unwrap_or_default()),
            ("blob-store", serde_json::to_value(self.singleton::<BlobStore>().await?).unwrap_or_default()),
            ("search-store", serde_json::to_value(self.singleton::<SearchStore>().await?).unwrap_or_default()),
            ("in-memory-store", serde_json::to_value(self.singleton::<InMemoryStore>().await?).unwrap_or_default()),
        ];
        for (place, value) in stores {
            if let Some(host) = remote_host(&value) {
                facts.remote_stores.insert(place.into(), host);
            }
        }
        if let Some(host) = remote_host(&serde_json::to_value(&tracing).unwrap_or_default()) {
            for id in ["x:Trace", "x:TraceEvent", "x:TraceKeyValue", "x:TraceValueIpAddr", "x:TraceValueString"] {
                endpoint(&mut facts, id, host.clone());
            }
        }

        Ok(facts)
    }

    /// The server's inventory, or a tenant's slice of it.
    pub async fn data_inventory(&self, tenant_only: bool) -> trc::Result<Inventory> {
        let facts = self.privacy_facts().await?;
        Ok(privacy::evaluate(privacy::catalog(), &facts, tenant_only))
    }

    /// Records a snapshot of the server's inventory if it differs from the
    /// newest one, or if there is none: the history shows when what the
    /// server holds changed, not a copy a day. Returns whether it recorded.
    pub async fn inventory_snapshot(&self, trigger: Trigger) -> trc::Result<bool> {
        let data = &self.core.storage.data;
        let inventory = self.data_inventory(false).await?;
        if let Some(latest) = snapshot::latest(data).await?
            && let Some(previous) = snapshot::get(data, latest).await?
            && previous.inventory == inventory
        {
            return Ok(false);
        }
        snapshot::record(
            data,
            &Snapshot {
                taken_at: store::write::now(),
                trigger,
                summary: inventory.summary(),
                inventory,
            },
        )
        .await?;
        Ok(true)
    }

    /// A snapshot after a registry write, when the object is one the
    /// inventory reads. Failures are logged: a snapshot is history, not
    /// worth failing the write over.
    pub async fn inventory_snapshot_after(&self, object: &str) {
        if !INVENTORY_OBJECTS.contains(&object) {
            return;
        }
        if let Err(err) = self
            .inventory_snapshot(Trigger::SettingChanged {
                setting: object.to_string(),
            })
            .await
        {
            trc::error!(err.details("Failed to record an inventory snapshot"));
        }
    }

    /// Removes snapshots past the audit log's retention (settled
    /// 2026-09-28: snapshots are kept as long as audit records).
    pub async fn purge_inventory_snapshots(&self) -> trc::Result<usize> {
        let data = &self.core.storage.data;
        let keep = inbuxa_features::audit::log::settings(data).await?.keep_for_secs;
        snapshot::purge(data, store::write::now().saturating_sub(keep)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_stores_stay_and_others_name_their_host() {
        assert_eq!(remote_host(&json!({"@type": "RocksDb", "path": "/var/lib"})), None);
        assert_eq!(remote_host(&json!({"@type": "Default"})), None);
        assert_eq!(
            remote_host(&json!({"@type": "PostgreSql", "host": "db.example.net"})),
            Some("db.example.net".into())
        );
        assert_eq!(
            remote_host(&json!({"@type": "ElasticSearch", "url": "https://es.example.net:9200"})),
            Some("https://es.example.net:9200".into())
        );
        assert_eq!(remote_host(&json!({"@type": "S3", "bucket": "mail"})), Some("S3".into()));
    }

    #[test]
    fn days_round_up() {
        assert_eq!(days(Some(&Duration::from_millis(86_400_000))), Days::Days(1));
        assert_eq!(days(Some(&Duration::from_millis(3_600_000))), Days::Days(1));
        assert_eq!(days(None), Days::Unbounded);
    }
}
