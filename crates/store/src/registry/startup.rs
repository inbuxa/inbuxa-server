/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! inbuxa: K-S6, K-C5: why a part of the data layer couldn't be used.
//!
//! Each case has its own exit code (from sysexits.h) and its own words on the
//! error line, after the part's name, so a supervisor, a Kubernetes pre-flight
//! check or a person reading `kubectl describe` can tell them apart without
//! parsing a driver's message:
//!
//! | exit | line starts                     | meaning                                   |
//! |------|---------------------------------|-------------------------------------------|
//! | 78   | `<part>: bad configuration`     | the settings, a secret file they name, the database or bucket name |
//! | 69   | `<part>: unreachable`           | no answer: refused, unknown host, timed out, or the server is starting or full |
//! | 77   | `<part>: credentials refused`   | wrong user, password or key, or a permission it needs is missing |
//! | 76   | `<part>: TLS failed`            | the TLS handshake failed: an unknown CA, or TLS the server doesn't offer |
//! | 1    | `<part>: error`                 | anything else                             |
//!
//! The part is `data store` (at every start, and `--check`), `blob store` or
//! `coordinator` (`--check` only). PostgreSQL, S3 and NATS errors are told
//! apart; other stores report bad configuration and otherwise 1.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailure {
    Config,
    Unreachable,
    Credentials,
    Tls,
    Other,
}

/// Which part of the data layer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    DataStore,
    BlobStore,
    Coordinator,
}

impl Part {
    pub fn name(self) -> &'static str {
        match self {
            Part::DataStore => "data store",
            Part::BlobStore => "blob store",
            Part::Coordinator => "coordinator",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Part::DataStore => "the database",
            Part::BlobStore => "the blob store",
            Part::Coordinator => "NATS",
        }
    }
}

impl StartupFailure {
    pub fn exit_code(self) -> i32 {
        match self {
            StartupFailure::Config => 78,
            StartupFailure::Unreachable => 69,
            StartupFailure::Credentials => 77,
            StartupFailure::Tls => 76,
            StartupFailure::Other => 1,
        }
    }

    /// The case, in the words that follow the part's name.
    pub fn label(self) -> &'static str {
        match self {
            StartupFailure::Config => "bad configuration",
            StartupFailure::Unreachable => "unreachable",
            StartupFailure::Credentials => "credentials refused",
            StartupFailure::Tls => "TLS failed",
            StartupFailure::Other => "error",
        }
    }

    /// What to check, in a sentence.
    pub fn hint(self, part: Part) -> String {
        let what = part.what();
        match (self, part) {
            (StartupFailure::Config, Part::DataStore) => {
                "Check the data store settings file, the secret files it names and the database name."
                    .into()
            }
            (StartupFailure::Config, Part::BlobStore) => {
                "Check the blob store settings: the bucket, its region and endpoint, and the secret files they name."
                    .into()
            }
            (StartupFailure::Config, Part::Coordinator) => {
                "Check the coordinator settings and the secret files they name.".into()
            }
            (StartupFailure::Unreachable, _) => format!(
                "Check that {what} is running and that its host and port are reachable from here."
            ),
            (StartupFailure::Credentials, Part::BlobStore) => {
                "Check the access key and secret, and that they may write and delete in the bucket."
                    .into()
            }
            (StartupFailure::Credentials, Part::DataStore) => {
                "Check the user name and password, and that the user may use the database.".into()
            }
            (StartupFailure::Credentials, Part::Coordinator) => {
                "Check the user name and password, or the token.".into()
            }
            (StartupFailure::Tls, _) => {
                format!("Check that {what} offers TLS and that its certificate is trusted here.")
            }
            (StartupFailure::Other, _) => String::new(),
        }
    }

    /// What a data store error means.
    pub fn of(err: &trc::Error) -> Self {
        let code = err.value_as_str(trc::Key::Code);
        let reason = err.value_as_str(trc::Key::Reason).unwrap_or_default();
        if err.matches(trc::EventType::Store(trc::StoreEvent::PostgresqlError)) {
            Self::of_postgres(code, reason)
        } else if err.matches(trc::EventType::Store(trc::StoreEvent::S3Error)) {
            Self::of_s3(
                err.value(trc::Key::Code).and_then(|v| match v {
                    trc::Value::UInt(n) => Some(*n),
                    trc::Value::Int(n) => u64::try_from(*n).ok(),
                    _ => None,
                }),
                reason,
            )
        } else {
            StartupFailure::Other
        }
    }

    /// `code` is the SQLSTATE when the server answered; `reason` starts with
    /// tokio-postgres' or the pool's own words when it didn't.
    fn of_postgres(code: Option<&str>, reason: &str) -> Self {
        match code {
            // invalid_authorization_specification, invalid_password,
            // insufficient_privilege
            Some(code) if code.starts_with("28") || code == "42501" => StartupFailure::Credentials,
            // invalid_catalog_name: no such database
            Some("3D000") => StartupFailure::Config,
            // too_many_connections, admin_shutdown, cannot_connect_now
            Some("53300" | "57P01" | "57P03") => StartupFailure::Unreachable,
            Some(_) => StartupFailure::Other,
            None if reason.starts_with("error performing TLS handshake") => StartupFailure::Tls,
            None if reason.starts_with("error connecting to server")
                || reason.starts_with("Timeout occurred") =>
            {
                StartupFailure::Unreachable
            }
            None => StartupFailure::Other,
        }
    }

    /// `status` is the HTTP status when the service answered; otherwise
    /// `reason` is the HTTP client's chain of errors.
    fn of_s3(status: Option<u64>, reason: &str) -> Self {
        match status {
            // A key the service doesn't know, a bad signature, or a policy
            // that refuses the operation
            Some(401 | 403) => StartupFailure::Credentials,
            // No such bucket, or a bucket in another region or endpoint
            Some(301 | 307 | 400 | 404) => StartupFailure::Config,
            Some(429 | 500..=599) => StartupFailure::Unreachable,
            Some(_) => StartupFailure::Other,
            None => {
                let reason = reason.to_ascii_lowercase();
                if ["certificate", "tls", "ssl", "handshake"]
                    .iter()
                    .any(|w| reason.contains(w))
                {
                    StartupFailure::Tls
                } else if [
                    "connect",
                    "dns error",
                    "failed to lookup",
                    "timed out",
                    "connection refused",
                    "connection reset",
                ]
                .iter()
                .any(|w| reason.contains(w))
                {
                    StartupFailure::Unreachable
                } else {
                    StartupFailure::Other
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct StartupError {
    pub part: Part,
    pub kind: StartupFailure,
    pub message: String,
}

impl StartupError {
    /// A data store failure.
    pub fn new(kind: StartupFailure, message: impl Into<String>) -> Self {
        Self::of_part(Part::DataStore, kind, message)
    }

    pub fn of_part(part: Part, kind: StartupFailure, message: impl Into<String>) -> Self {
        StartupError {
            part,
            kind,
            message: message.into(),
        }
    }

    /// "data store: unreachable"
    pub fn headline(&self) -> String {
        format!("{}: {}", self.part.name(), self.kind.label())
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.headline(), self.message)?;
        let hint = self.kind.hint(self.part);
        if !hint.is_empty() {
            write!(f, "\n  {hint}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Part,
        StartupFailure::{self, *},
    };

    #[test]
    fn postgres_cases() {
        // As the lab's PostgreSQL and tokio-postgres reported them
        let cases: &[(Option<&str>, &str, StartupFailure)] = &[
            (
                None,
                "error connecting to server: Connection refused (os error 111)",
                Unreachable,
            ),
            (
                None,
                "error connecting to server: failed to lookup address information: Name or service not known",
                Unreachable,
            ),
            (
                None,
                "Timeout occurred while creating a new object",
                Unreachable,
            ),
            (
                Some("28P01"),
                "db error: FATAL: password authentication failed for user \"inbuxa\"",
                Credentials,
            ),
            (
                Some("28000"),
                "db error: FATAL: no pg_hba.conf entry",
                Credentials,
            ),
            (
                Some("42501"),
                "db error: ERROR: permission denied for schema public",
                Credentials,
            ),
            (
                Some("3D000"),
                "db error: FATAL: database \"nosuchdb\" does not exist",
                Config,
            ),
            (
                Some("57P03"),
                "db error: FATAL: the database system is starting up",
                Unreachable,
            ),
            (
                None,
                "error performing TLS handshake: invalid peer certificate: UnknownIssuer",
                Tls,
            ),
            (
                None,
                "error performing TLS handshake: server does not support TLS",
                Tls,
            ),
            (
                Some("42P01"),
                "db error: ERROR: relation does not exist",
                Other,
            ),
        ];
        for (code, reason, want) in cases {
            assert_eq!(
                StartupFailure::of_postgres(*code, reason),
                *want,
                "{reason}"
            );
        }
    }

    #[test]
    fn s3_cases() {
        let cases: &[(Option<u64>, &str, StartupFailure)] = &[
            (Some(403), "<Code>InvalidAccessKeyId</Code>", Credentials),
            (Some(403), "<Code>SignatureDoesNotMatch</Code>", Credentials),
            (Some(404), "<Code>NoSuchBucket</Code>", Config),
            (Some(301), "<Code>PermanentRedirect</Code>", Config),
            (Some(503), "<Code>SlowDown</Code>", Unreachable),
            (
                None,
                "error sending request: client error (Connect): tcp connect error: Connection refused (os error 111)",
                Unreachable,
            ),
            (
                None,
                "error sending request: client error (Connect): dns error: failed to lookup address information",
                Unreachable,
            ),
            (
                None,
                "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer",
                Tls,
            ),
            (Some(418), "", Other),
        ];
        for (status, reason, want) in cases {
            assert_eq!(StartupFailure::of_s3(*status, reason), *want, "{reason}");
        }
    }

    #[test]
    fn codes_and_words_are_distinct() {
        let all = [Config, Unreachable, Credentials, Tls, Other];
        for a in all {
            for b in all {
                if a != b {
                    assert_ne!(a.exit_code(), b.exit_code());
                    assert_ne!(a.label(), b.label());
                }
            }
            for part in [Part::DataStore, Part::BlobStore, Part::Coordinator] {
                assert_eq!(a.hint(part).is_empty(), a == Other);
            }
        }
    }
}
