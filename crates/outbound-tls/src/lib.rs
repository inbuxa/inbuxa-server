/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

//! Outbound SMTP TLS policy, shared by the server's queue and inbuxa-relay
//! (RL-30): DANE (RFC 7672) and the DNSSEC lookups it needs, and MTA-STS
//! (RFC 8461) policies. Moved here from `crates/smtp` and
//! `crates/common`; caching, tracing and the policy fetch stay with each
//! caller.

pub mod dane;
pub mod dnssec;
pub mod mta_sts;

pub use mail_auth;

use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsaMatching {
    Full,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsaEntry {
    pub is_end_entity: bool,
    pub is_spki: bool,
    pub matching: TlsaMatching,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tlsa {
    pub entries: Vec<TlsaEntry>,
    pub has_end_entities: bool,
    pub has_intermediates: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Enforce,
    Testing,
    #[default]
    None,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Box<[MxPattern]>,
    pub max_age: u64,
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "testing" | "test" => Ok(Self::Testing),
            "none" => Ok(Self::None),
            _ => Err(format!("Invalid mode value {value:?}")),
        }
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("version: STSv1\r\n")?;
        f.write_str("mode: ")?;
        match self.mode {
            Mode::Enforce => f.write_str("enforce")?,
            Mode::Testing => f.write_str("testing")?,
            Mode::None => f.write_str("none")?,
        }
        f.write_str("\r\nmax_age: ")?;
        self.max_age.fmt(f)?;
        f.write_str("\r\n")?;

        for mx in &self.mx {
            f.write_str("mx: ")?;
            mx.fmt(f)?;
            f.write_str("\r\n")?;
        }

        Ok(())
    }
}

impl Display for MxPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MxPattern::Equals(mx) => f.write_str(mx),
            MxPattern::StartsWith(mx) => {
                f.write_str("*.")?;
                f.write_str(mx)
            }
        }
    }
}
