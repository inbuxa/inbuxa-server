/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! inbuxa: K-S6: why the data store couldn't be opened at start-up.
//!
//! Each case has its own exit code (from sysexits.h) and its own first words
//! on the error line, so a supervisor, a Kubernetes pre-flight check or a
//! person reading `kubectl describe` can tell them apart without parsing a
//! database driver's message:
//!
//! | exit | line starts                                | meaning                                   |
//! |------|--------------------------------------------|-------------------------------------------|
//! | 78   | `data store: bad configuration`            | the settings file, a secret file it names, or the database name |
//! | 69   | `data store: unreachable`                  | no answer: refused, unknown host, timed out, or the server is starting or full |
//! | 77   | `data store: credentials refused`          | wrong user or password, or the role lacks a permission it needs |
//! | 76   | `data store: TLS failed`                   | the TLS handshake failed: an unknown CA, or TLS the server doesn't offer |
//! | 1    | `data store: error`                        | anything else                             |
//!
//! PostgreSQL errors are told apart fully. Other stores report bad
//! configuration (78) and otherwise 1.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailure {
    Config,
    Unreachable,
    Credentials,
    Tls,
    Other,
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

    pub fn label(self) -> &'static str {
        match self {
            StartupFailure::Config => "data store: bad configuration",
            StartupFailure::Unreachable => "data store: unreachable",
            StartupFailure::Credentials => "data store: credentials refused",
            StartupFailure::Tls => "data store: TLS failed",
            StartupFailure::Other => "data store: error",
        }
    }

    /// What to check, in a sentence.
    pub fn hint(self) -> &'static str {
        match self {
            StartupFailure::Config => {
                "Check the data store settings file, the secret files it names and the database name."
            }
            StartupFailure::Unreachable => {
                "Check that the database is running and that its host and port are reachable from here."
            }
            StartupFailure::Credentials => {
                "Check the user name and password, and that the user may use the database."
            }
            StartupFailure::Tls => {
                "Check that the database offers TLS and that its certificate is trusted here."
            }
            StartupFailure::Other => "",
        }
    }

    /// What a data store error at start-up means.
    pub fn of(err: &trc::Error) -> Self {
        if err.matches(trc::EventType::Store(trc::StoreEvent::PostgresqlError)) {
            Self::of_postgres(
                err.value_as_str(trc::Key::Code),
                err.value_as_str(trc::Key::Reason).unwrap_or_default(),
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
}

#[derive(Debug)]
pub struct StartupError {
    pub kind: StartupFailure,
    pub message: String,
}

impl StartupError {
    pub fn new(kind: StartupFailure, message: impl Into<String>) -> Self {
        StartupError {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.label(), self.message)?;
        let hint = self.kind.hint();
        if !hint.is_empty() {
            write!(f, "\n  {hint}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::StartupFailure::{self, *};

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
    fn codes_are_distinct() {
        let all = [Config, Unreachable, Credentials, Tls, Other];
        for a in all {
            for b in all {
                if a != b {
                    assert_ne!(a.exit_code(), b.exit_code());
                    assert!(!a.label().starts_with(b.label()), "{}", a.label());
                }
            }
        }
    }
}
