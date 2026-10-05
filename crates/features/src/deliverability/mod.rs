/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The deliverability check (deliverability spec): what other mail servers
//! see when this one sends. Not a rebuild of anything upstream ships.
//!
//! Every node that sends mail checks itself, because only it knows which
//! address it leaves from, and keeps one report. The report holds facts: an
//! address's reverse DNS, what each blocklist answered, what SPF said for
//! each address, whether a DKIM key in DNS matches the one signing. The
//! console grades them, so its wording can change without a server release.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `D`, then one byte for the kind:
//!
//! - `r` + node id (u64): that node's last report, as JSON.
//! - `s`: the settings, as JSON.
//!
//! Numbers are big-endian.

pub mod lists;

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

const FEATURE: u8 = b'D';
const KIND_REPORT: u8 = b'r';
const KIND_SETTINGS: u8 = b's';

/// DL-15: **Check now** runs a node again only this long after its last run.
pub const MIN_INTERVAL_SECS: u64 = 600;

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Report {
    /// The node's cluster id, as metric samples carry it.
    pub node_id: u64,
    pub hostname: String,
    /// Seconds since the epoch.
    pub checked_at: u64,
    pub addresses: Vec<Address>,
    pub domains: Vec<DomainReport>,
    pub certificates: Vec<Certificate>,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Address {
    pub ip: String,
    /// DL-2: how the node came by the address.
    pub source: AddressSource,
    /// The connection strategy that sends from it.
    pub strategy: String,
    /// The name the node greets with from this address.
    pub ehlo: String,
    /// The PTR names, empty when there's none.
    pub ptr: Vec<String>,
    /// Some PTR name resolves back to the address.
    pub forward_confirmed: bool,
    /// The forward-confirmed name is the EHLO name.
    pub ehlo_matches: bool,
    /// Set when the reverse lookup itself failed, rather than found nothing.
    pub ptr_error: Option<String>,
    pub listings: Vec<Listing>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressSource {
    /// Set in the connection strategy's source addresses.
    #[default]
    Configured,
    /// What the EHLO name resolves to.
    Ehlo,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Listing {
    /// The list's name, as in [`lists::LISTS`].
    pub list: String,
    pub state: ListingState,
    /// The address the list answered, when it answered one.
    pub code: Option<String>,
    /// What the list says the answer means.
    pub meaning: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum ListingState {
    #[default]
    Clean,
    Listed,
    /// The list wouldn't answer, or the lookup failed: neither listed nor clean.
    Refused,
    Error,
    /// Switched off in the settings, so not asked.
    Off,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DomainReport {
    pub domain: String,
    /// DL-20: a tenant administrator sees only their tenant's domains.
    pub tenant_id: Option<u32>,
    /// DL-7: what SPF says for each of the node's addresses.
    pub spf: Vec<SpfResult>,
    /// DL-8: each DKIM key the domain signs with.
    pub dkim: Vec<DkimKey>,
    /// DL-9: the DMARC record, if there's one.
    pub dmarc: Option<Dmarc>,
    /// DL-10.
    pub mta_sts: MtaSts,
    /// DL-11: there's a `_smtp._tls` record.
    pub tls_rpt: bool,
    /// DL-12.
    pub listings: Vec<Listing>,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SpfResult {
    pub ip: String,
    /// `pass`, `fail`, `softFail`, `neutral`, `none`, `tempError` or `permError`.
    pub result: String,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DkimKey {
    pub selector: String,
    pub state: DkimState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum DkimState {
    #[default]
    Matches,
    /// Nothing published at `<selector>._domainkey.<domain>`.
    Missing,
    /// Published, but a different key.
    Different,
    /// The lookup failed.
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Dmarc {
    /// `none`, `quarantine` or `reject`.
    pub policy: String,
    /// DKIM alignment: `relaxed` or `strict`.
    pub adkim: String,
    /// SPF alignment: `relaxed` or `strict`.
    pub aspf: String,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MtaSts {
    /// The `_mta-sts` record's id; None when there's no record.
    pub record_id: Option<String>,
    /// The policy was fetched and parsed. False with a record means the
    /// fetch or the parse failed, and `error` says why.
    pub fetched: bool,
    pub error: Option<String>,
    /// `enforce`, `testing` or `none`.
    pub mode: Option<String>,
    pub max_age: Option<u64>,
    /// The domain's MX names no `mx:` line matches.
    pub mx_not_covered: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Certificate {
    /// The EHLO name, or an MX name that points at this node.
    pub name: String,
    /// The node holds a certificate for the name.
    pub covered: bool,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// DL-6: lists not to ask, by name.
    pub disabled_lists: Vec<String>,
}

impl Settings {
    pub fn is_off(&self, list: &str) -> bool {
        self.disabled_lists.iter().any(|name| name == list)
    }

    /// Only the built-in lists' names, once each.
    pub fn validate(&self) -> Result<(), String> {
        for (i, name) in self.disabled_lists.iter().enumerate() {
            if lists::by_name(name).is_none() {
                return Err(format!("There's no list called {name:?}."));
            }
            if self.disabled_lists[..i].contains(name) {
                return Err(format!("{name:?} is named twice."));
            }
        }
        Ok(())
    }
}

impl Report {
    /// DL-20: what a tenant administrator may see: their tenant's domains
    /// and nothing about the node's addresses or certificates.
    pub fn for_tenant(&self, tenant_id: u32) -> Report {
        Report {
            node_id: self.node_id,
            hostname: self.hostname.clone(),
            checked_at: self.checked_at,
            addresses: Vec::new(),
            domains: self
                .domains
                .iter()
                .filter(|d| d.tenant_id == Some(tenant_id))
                .cloned()
                .collect(),
            certificates: Vec::new(),
        }
    }
}

// --- Storage --------------------------------------------------------------

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize deliverability data")
                .reason(err)
        })
    }
}

impl<T: for<'de> SerdeDeserialize<'de> + Send + Sync> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid deliverability data")
                .reason(err)
        })
    }
}

fn class(kind: u8, node_id: Option<u64>) -> ValueClass {
    let mut key = Vec::with_capacity(10);
    key.push(FEATURE);
    key.push(kind);
    if let Some(node_id) = node_id {
        key.extend_from_slice(&node_id.to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn report(data: &Store, node_id: u64) -> trc::Result<Option<Report>> {
    Ok(data
        .get_value::<Json<Report>>(ValueKey::from(class(KIND_REPORT, Some(node_id))))
        .await
        .caused_by(trc::location!())?
        .map(|Json(report)| report))
}

/// Every node's report, by node id.
pub async fn reports(data: &Store) -> trc::Result<Vec<Report>> {
    let mut out = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(class(KIND_REPORT, Some(0))),
            ValueKey::from(class(KIND_REPORT, Some(u64::MAX))),
        ),
        |_, value| {
            if let Ok(Json(report)) = Json::<Report>::deserialize(value) {
                out.push(report);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    out.sort_by_key(|r| r.node_id);
    Ok(out)
}

/// Replaces the node's report.
pub async fn put_report(data: &Store, report: &Report) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        class(KIND_REPORT, Some(report.node_id)),
        Json(report).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

pub async fn settings(data: &Store) -> trc::Result<Settings> {
    Ok(data
        .get_value::<Json<Settings>>(ValueKey::from(class(KIND_SETTINGS, None)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(settings)| settings)
        .unwrap_or_default())
}

pub async fn put_settings(data: &Store, settings: &Settings) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(KIND_SETTINGS, None), Json(settings).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_name_only_built_in_lists_once() {
        let ok = Settings {
            disabled_lists: vec!["Barracuda".into(), "URIBL".into()],
        };
        assert!(ok.validate().is_ok());
        assert!(ok.is_off("Barracuda"));
        assert!(!ok.is_off("SpamCop"));
        let unknown = Settings {
            disabled_lists: vec!["My list".into()],
        };
        assert!(unknown.validate().is_err());
        let twice = Settings {
            disabled_lists: vec!["URIBL".into(), "URIBL".into()],
        };
        assert!(twice.validate().is_err());
    }

    #[test]
    fn a_tenant_sees_only_its_domains() {
        let report = Report {
            node_id: 2,
            hostname: "mx2.example.org".into(),
            checked_at: 1,
            addresses: vec![Address {
                ip: "192.0.2.10".into(),
                ..Default::default()
            }],
            domains: vec![
                DomainReport {
                    domain: "a.example".into(),
                    tenant_id: Some(7),
                    ..Default::default()
                },
                DomainReport {
                    domain: "b.example".into(),
                    tenant_id: Some(8),
                    ..Default::default()
                },
                DomainReport {
                    domain: "server.example".into(),
                    tenant_id: None,
                    ..Default::default()
                },
            ],
            certificates: vec![Certificate {
                name: "mx2.example.org".into(),
                covered: true,
            }],
        };
        let seen = report.for_tenant(7);
        assert!(seen.addresses.is_empty());
        assert!(seen.certificates.is_empty());
        assert_eq!(
            seen.domains
                .iter()
                .map(|d| d.domain.as_str())
                .collect::<Vec<_>>(),
            ["a.example"]
        );
    }

    #[test]
    fn a_report_reads_back_with_missing_fields() {
        let report: Report = serde_json::from_str(r#"{"nodeId": 3}"#).unwrap();
        assert_eq!(report.node_id, 3);
        assert!(report.domains.is_empty());
    }
}
