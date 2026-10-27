/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Error, Result};
use std::{env, path::PathBuf};

const DEFAULT_PROFILE: &str = "default";

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    access_key: Box<str>,
    secret_key: Box<str>,
    session_token: Option<Box<str>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileEntry {
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub session_token: Option<String>,
}

#[derive(Clone, Copy)]
enum ProfileField {
    AccessKey,
    SecretKey,
    SessionToken,
}

impl Credentials {
    pub fn new(access_key: &str, secret_key: &str, session_token: Option<&str>) -> Self {
        Credentials {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            session_token: session_token.map(Into::into),
        }
    }

    pub fn resolve(
        access_key: Option<&str>,
        secret_key: Option<&str>,
        session_token: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Self> {
        if let Some(access_key) = access_key {
            let secret_key = secret_key.ok_or_else(|| {
                Error::Credentials("an access key was given without a secret key".into())
            })?;
            return Ok(Credentials::new(access_key, secret_key, session_token));
        }
        if let Some(credentials) = Self::from_env() {
            return Ok(credentials);
        }
        Self::from_profile(profile)
    }

    fn from_env() -> Option<Self> {
        let access_key = env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_key = env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let session_token = env::var("AWS_SESSION_TOKEN")
            .or_else(|_| env::var("AWS_SECURITY_TOKEN"))
            .ok();
        Some(Credentials::new(
            &access_key,
            &secret_key,
            session_token.as_deref(),
        ))
    }

    fn from_profile(profile: Option<&str>) -> Result<Self> {
        let path = env::var_os("AWS_SHARED_CREDENTIALS_FILE")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| PathBuf::from(home).join(".aws").join("credentials"))
            })
            .ok_or_else(|| Error::Credentials("no credentials configured".into()))?;
        let contents = std::fs::read_to_string(&path).map_err(|err| {
            Error::Credentials(
                format!(
                    "no credentials configured and {} is not readable: {err}",
                    path.display()
                )
                .into(),
            )
        })?;
        let section = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = ProfileEntry::parse(&contents, section).ok_or_else(|| {
            Error::Credentials(
                format!("profile {section:?} not found in {}", path.display()).into(),
            )
        })?;
        match (entry.access_key, entry.secret_key) {
            (Some(access_key), Some(secret_key)) => Ok(Credentials::new(
                &access_key,
                &secret_key,
                entry.session_token.as_deref(),
            )),
            _ => Err(Error::Credentials(
                format!(
                    "profile {section:?} in {} lacks aws_access_key_id or aws_secret_access_key",
                    path.display()
                )
                .into(),
            )),
        }
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

impl ProfileEntry {
    pub(crate) fn parse(contents: &str, section: &str) -> Option<Self> {
        let mut entry = None;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                if entry.is_some() {
                    break;
                }
                if name.trim() == section {
                    entry = Some(ProfileEntry::default());
                }
                continue;
            }
            let (Some(entry), Some((name, value))) = (entry.as_mut(), line.split_once('=')) else {
                continue;
            };
            let field = hashify::map!(name.trim().as_bytes(), ProfileField,
                "aws_access_key_id" => ProfileField::AccessKey,
                "aws_secret_access_key" => ProfileField::SecretKey,
                "aws_session_token" => ProfileField::SessionToken,
                "aws_security_token" => ProfileField::SessionToken,
            )
            .copied();
            let value = Some(value.trim().to_string());
            match field {
                Some(ProfileField::AccessKey) => entry.access_key = value,
                Some(ProfileField::SecretKey) => entry.secret_key = value,
                Some(ProfileField::SessionToken) if entry.session_token.is_none() => {
                    entry.session_token = value;
                }
                Some(ProfileField::SessionToken) | None => {}
            }
        }
        entry
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

