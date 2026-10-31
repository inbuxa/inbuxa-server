/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Migrations into this server (docs/spec/features/migrations.md): the
//! `inbuxa:Migration` objects. The server runs the bundled inbuxa-migrate
//! on a migration's answers; this module keeps what a migration is and how
//! far it got, never a secret.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry. Every key starts with `I` (import), then one byte for the kind:
//!
//! - `m` + migration id (u32): a migration ([`Migration`]), as JSON.
//!
//! Numbers are big-endian. There are few migrations, so they're read whole.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'I';
const KIND_MIGRATION: u8 = b'm';
const CREATE_ATTEMPTS: usize = 5;

/// MG-3: at most this many accounts in one migration.
pub const MAX_ACCOUNTS: usize = 10_000;
/// MG-9: the failures a migration keeps, newest last.
pub const MAX_FAILURES: usize = 200;
const MAX_TEXT: usize = 2_000;

/// MG-2: where the mail is now. Maildir is left out: its folders would have
/// to be on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Imap,
    Jmap,
    Microsoft,
    Google,
}

impl SourceKind {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "imap" => SourceKind::Imap,
            "jmap" => SourceKind::Jmap,
            "microsoft" => SourceKind::Microsoft,
            "google" => SourceKind::Google,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Imap => "imap",
            SourceKind::Jmap => "jmap",
            SourceKind::Microsoft => "microsoft",
            SourceKind::Google => "google",
        }
    }
}

/// MG-2: the source, as the guide asks for it, without its secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Source {
    pub url: String,
    /// IMAP: the login for each account, such as `{email}*master`. JMAP:
    /// an administrator, or empty for an API key.
    pub login: String,
    /// IMAP: credentials on `imap://` without STARTTLS.
    pub cleartext: bool,
    /// Microsoft 365: the Entra tenant and the app's client id.
    pub tenant: String,
    pub client_id: String,
}

/// Which run a migration is doing, or did last (MG-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunKind {
    /// A dry run: signs in for each account and counts what would move.
    Preview,
    /// The move. Run again, it resumes.
    Move,
    /// The move again with `--again`, at cutover.
    FinalPass,
}

impl RunKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunKind::Preview => "preview",
            RunKind::Move => "move",
            RunKind::FinalPass => "finalPass",
        }
    }
}

/// How the last run ended (MG-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunResult {
    /// Every account finished.
    Done,
    /// Some account didn't finish; the report says which and why.
    Unfinished,
    /// The run couldn't start, or the engine stopped with an error.
    Failed,
    /// An administrator stopped it.
    Stopped,
    /// The server stopped while it ran. Resume carries on; the secret has
    /// to be given again (MG-12).
    Interrupted,
}

impl RunResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunResult::Done => "done",
            RunResult::Unfinished => "unfinished",
            RunResult::Failed => "failed",
            RunResult::Stopped => "stopped",
            RunResult::Interrupted => "interrupted",
        }
    }
}

/// Where a migration is in its life (MG-5, MG-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    /// Nothing is running.
    Idle,
    Running,
    /// Closed: its work directory, archives included, is gone. It stays
    /// listed.
    Closed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Idle => "idle",
            Status::Running => "running",
            Status::Closed => "closed",
        }
    }
}

/// What a run has done so far, from the engine's progress (MG-8).
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Progress {
    /// The accounts this run has.
    pub total: u64,
    /// The accounts it finished with, however they ended.
    pub finished: u64,
    /// Of those, the ones that didn't finish.
    pub unfinished: u64,
    /// Items read from the source, summed over the accounts so far.
    pub read: u64,
    /// Items written into this server: created and updated.
    pub written: u64,
    /// Items that failed, on either side.
    pub failed: u64,
}

/// An account that didn't finish, and why (MG-9).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    pub email: String,
    pub step: String,
    pub detail: String,
}

/// A migration into this server (MG-1).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Migration {
    pub id: u32,
    #[serde(default)]
    pub description: String,
    pub source_kind: SourceKind,
    #[serde(default)]
    pub source: Source,
    pub accounts: Vec<String>,
    /// Create on this server the accounts it doesn't have yet.
    #[serde(default)]
    pub create_accounts: bool,
    pub parallel: u32,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<RunResult>,
    /// Why a run failed, in the engine's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub progress: Progress,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
    /// The node the migration's work directory is on (MG-11). Set by the
    /// first run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<u64>,
    /// When the running node last said it was still at it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<u64>,
    /// Whether a move has finished at least once, so a final pass makes
    /// sense.
    #[serde(default)]
    pub moved: bool,
    /// The work directory's size, archives included, after the last run.
    #[serde(default)]
    pub disk_used: u64,
    /// Whether new accounts' passwords are waiting to be downloaded once
    /// (MG-13).
    #[serde(default)]
    pub passwords_waiting: bool,
    /// The last run's report, as a blob of whoever started the migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_blob_id: Option<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Whom the runs act as (MG-10).
    pub created_by_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
}

impl Migration {
    /// The answers `inbuxa-migrate plan` reads, for a target this server
    /// gives it (MG-4). The secret isn't among them.
    pub fn answers(&self, target_url: &str, allow_invalid_certs: bool) -> Value {
        let mut source = Map::new();
        source.insert("kind".into(), self.source_kind.as_str().into());
        source.insert("url".into(), self.source.url.clone().into());
        source.insert("login".into(), self.source.login.clone().into());
        source.insert("cleartext".into(), self.source.cleartext.into());
        source.insert("tenant".into(), self.source.tenant.clone().into());
        source.insert("clientId".into(), self.source.client_id.clone().into());
        serde_json::json!({
            "source": source,
            "accounts": self.accounts,
            "create": self.create_accounts,
            "target": {
                "url": target_url,
                "stayOnUrl": true,
                "allowInvalidCerts": allow_invalid_certs,
            },
            "parallel": self.parallel,
        })
    }

    /// Adds a failure, keeping the newest [`MAX_FAILURES`].
    pub fn add_failure(&mut self, failure: Failure) {
        self.failures.retain(|f| f.email != failure.email);
        self.failures.push(failure);
        let over = self.failures.len().saturating_sub(MAX_FAILURES);
        self.failures.drain(..over);
    }
}

/// Why a migration's answers were refused, for the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub property: &'static str,
    pub reason: String,
}

fn invalid(property: &'static str, reason: impl Into<String>) -> Result<(), Invalid> {
    Err(Invalid {
        property,
        reason: reason.into(),
    })
}

/// An address, as the engine takes it: lowercase, one `@`, no spaces.
pub fn account_email(value: &str) -> Option<String> {
    let email = value.trim().to_ascii_lowercase();
    let (local, domain) = email.split_once('@')?;
    (!local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && email.len() <= 320
        && !email.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then_some(email)
}

fn names_account(template: &str) -> bool {
    template.contains("{email}") || template.contains("{local}")
}

/// MG-2, MG-3: what a migration needs before anything runs. The engine
/// checks the rest when it writes the plans.
pub fn validate(migration: &Migration) -> Result<(), Invalid> {
    let s = &migration.source;
    for (property, text) in [
        ("description", &migration.description),
        ("source", &s.url),
        ("source", &s.login),
        ("source", &s.tenant),
        ("source", &s.client_id),
    ] {
        if text.len() > MAX_TEXT || text.chars().any(char::is_control) {
            return invalid(property, "Too long, or holds a control character.");
        }
    }
    match migration.source_kind {
        SourceKind::Imap => {
            if !(s.url.starts_with("imaps://") || s.url.starts_with("imap://")) {
                return invalid(
                    "source",
                    "Give the IMAP server as imaps://host or imap://host.",
                );
            }
            if !names_account(&s.login) {
                return invalid(
                    "source",
                    "The login for each account has to name it: {email} or {local}.",
                );
            }
        }
        SourceKind::Jmap => {
            if !(s.url.starts_with("https://") || s.url.starts_with("http://")) {
                return invalid("source", "Give the JMAP server's address, from https://.");
            }
        }
        SourceKind::Microsoft => {
            if s.tenant.trim().is_empty() || s.client_id.trim().is_empty() {
                return invalid(
                    "source",
                    "Give the Microsoft 365 tenant and the app's client id.",
                );
            }
        }
        SourceKind::Google => {}
    }
    if migration.accounts.is_empty() {
        return invalid("accounts", "List the accounts to move.");
    }
    if migration.accounts.len() > MAX_ACCOUNTS {
        return invalid(
            "accounts",
            format!("At most {MAX_ACCOUNTS} accounts in one migration; split it."),
        );
    }
    for email in &migration.accounts {
        if account_email(email).as_deref() != Some(email.as_str()) {
            return invalid("accounts", format!("{email} isn't an address."));
        }
    }
    if !(1..=16).contains(&migration.parallel) {
        return invalid("parallel", "Between 1 and 16 accounts at once.");
    }
    Ok(())
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<&T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Could not serialize a migration")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid migration")
                .reason(err)
        })
    }
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_MIGRATION);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Migration>> {
    Ok(data
        .get_value::<Json<Migration>>(ValueKey::from(class(id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(migration)| migration))
}

/// Every migration, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Migration>> {
    let mut migrations = Vec::new();
    data.iterate(
        IterateParams::new(ValueKey::from(class(0)), ValueKey::from(class(u32::MAX))),
        |_, value| {
            if let Ok(Json(migration)) = Json::<Migration>::deserialize(value) {
                migrations.push(migration);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    migrations.sort_by_key(|m| m.id);
    Ok(migrations)
}

/// Writes a new migration under the next free id, which it returns. Two
/// nodes creating migrations at once can't take the same id.
pub async fn create(data: &Store, migration: &Migration) -> trc::Result<u32> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = all(data).await?.iter().map(|m| m.id).max().unwrap_or(0) + 1;
        let stored = Migration {
            id,
            ..migration.clone()
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(id),
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// A migration as stored, with the version [`replace`] checks: a hash of
/// the stored bytes.
struct Versioned(Migration, u64);

impl Deserialize for Versioned {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(migration) = Json::<Migration>::deserialize(bytes)?;
        Ok(Versioned(migration, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

pub async fn get_versioned(data: &Store, id: u32) -> trc::Result<Option<(Migration, u64)>> {
    Ok(data
        .get_value::<Versioned>(ValueKey::from(class(id)))
        .await
        .caused_by(trc::location!())?
        .map(|Versioned(migration, version)| (migration, version)))
}

/// Replaces a stored migration if it is still at `version`. False if
/// something else changed it first, such as the running node saving
/// progress while an administrator stops it: read it again and retry.
pub async fn replace(data: &Store, migration: &Migration, version: u64) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(class(migration.id), AssertValue::Hash(version));
    batch.set(class(migration.id), Json(migration).serialize()?);
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(true),
        Err(err)
            if matches!(
                err.as_ref(),
                trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// Reads a migration, changes it with `change`, and writes it back, again
/// if something else wrote it in between. `change` returns false to leave
/// it as it is. None if there's no such migration.
pub async fn update<F>(data: &Store, id: u32, mut change: F) -> trc::Result<Option<Migration>>
where
    F: FnMut(&mut Migration) -> bool,
{
    loop {
        let Some((mut migration, version)) = get_versioned(data, id).await? else {
            return Ok(None);
        };
        if !change(&mut migration) {
            return Ok(Some(migration));
        }
        if replace(data, &migration, version).await? {
            return Ok(Some(migration));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration(kind: SourceKind) -> Migration {
        Migration {
            id: 1,
            description: String::new(),
            source_kind: kind,
            source: Source {
                url: "imaps://old.example.org".into(),
                login: "{email}*master".into(),
                ..Source::default()
            },
            accounts: vec!["ann@example.org".into()],
            create_accounts: true,
            parallel: 4,
            status: Status::Idle,
            run: None,
            result: None,
            error: None,
            progress: Progress::default(),
            failures: Vec::new(),
            node_id: None,
            heartbeat: None,
            moved: false,
            disk_used: 0,
            passwords_waiting: false,
            report_blob_id: None,
            created_at: 0,
            created_by: "admin".into(),
            created_by_id: 1,
            started_at: None,
            finished_at: None,
        }
    }

    #[test]
    fn answers_name_this_server_and_stay_on_its_address() {
        let answers = migration(SourceKind::Imap).answers("http://127.0.0.1:8080", false);
        assert_eq!(answers["source"]["kind"], "imap");
        assert_eq!(answers["source"]["login"], "{email}*master");
        assert_eq!(answers["target"]["url"], "http://127.0.0.1:8080");
        assert_eq!(answers["target"]["stayOnUrl"], true);
        assert_eq!(answers["create"], true);
        assert!(answers["target"].get("token").is_none());
        assert!(answers["source"].get("secret").is_none());
    }

    #[test]
    fn what_a_migration_needs() {
        assert_eq!(validate(&migration(SourceKind::Imap)), Ok(()));

        let mut m = migration(SourceKind::Imap);
        m.source.login = "master".into();
        assert_eq!(validate(&m).unwrap_err().property, "source");

        let mut m = migration(SourceKind::Microsoft);
        assert_eq!(validate(&m).unwrap_err().property, "source");
        m.source.tenant = "contoso.onmicrosoft.com".into();
        m.source.client_id = "1234".into();
        assert_eq!(validate(&m), Ok(()));

        let mut m = migration(SourceKind::Google);
        m.accounts.clear();
        assert_eq!(validate(&m).unwrap_err().property, "accounts");
        m.accounts = vec!["Ann@Example.org".into()];
        assert_eq!(validate(&m).unwrap_err().property, "accounts");
        m.accounts = vec!["ann@example.org".into()];
        m.parallel = 0;
        assert_eq!(validate(&m).unwrap_err().property, "parallel");
    }

    #[test]
    fn failures_keep_one_per_account_and_the_newest() {
        let mut m = migration(SourceKind::Imap);
        for n in 0..(MAX_FAILURES + 5) {
            m.add_failure(Failure {
                email: format!("u{n}@example.org"),
                step: "import".into(),
                detail: "no".into(),
            });
        }
        m.add_failure(Failure {
            email: format!("u{}@example.org", MAX_FAILURES + 4),
            step: "export".into(),
            detail: "again".into(),
        });
        assert_eq!(m.failures.len(), MAX_FAILURES);
        assert_eq!(m.failures.last().unwrap().step, "export");
        assert_eq!(m.failures[0].email, "u5@example.org");
    }
}
