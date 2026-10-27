/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Credentials;
use encodify::base64::URL_SAFE_NO_PAD;

impl Credentials {
    pub fn decode_sasl_challenge_plain(challenge: &[u8]) -> Option<Self> {
        let mut args = challenge.split(|&ch| ch == 0).skip(1);
        let username = args.next().filter(|username| !username.is_empty())?;
        let secret = args.next().filter(|secret| !secret.is_empty())?;

        Some(Credentials::Basic {
            username: std::str::from_utf8(username).ok()?.to_string(),
            secret: std::str::from_utf8(secret).ok()?.to_string(),
            mfa_token: None,
        })
    }

    pub fn decode_sasl_challenge_oauth(challenge: &[u8]) -> Option<Self> {
        extract_oauth_bearer(challenge)
            .map(|(token, username)| Credentials::Bearer { username, token })
    }
}

fn extract_oauth_bearer(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let mut start_pos = 0;
    let eof = bytes.len().saturating_sub(1);
    let mut iter = bytes.iter().enumerate();
    let mut a = None;

    while let Some((pos, ch)) = iter.next() {
        if *ch == b','
            && bytes
                .get(pos + 1..pos + 3)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"a="))
        {
            let from_pos = pos + 3;
            let mut to_pos = from_pos;
            for (pos, ch) in iter.by_ref() {
                if *ch == b',' || *ch == 1 {
                    to_pos = pos;
                    break;
                }
            }

            if to_pos > from_pos {
                a = bytes
                    .get(from_pos..to_pos)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .filter(|v| v.contains('@'));
            }
        } else {
            let is_separator = *ch == 1;
            if is_separator || pos == eof {
                if bytes
                    .get(start_pos..start_pos + 12)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"auth=Bearer "))
                {
                    return bytes
                        .get(start_pos + 12..if is_separator { pos } else { bytes.len() })
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .map(|token| {
                            (
                                token.to_string(),
                                a.map(|s| s.to_string())
                                    .or_else(|| extract_email_from_jwt(token)),
                            )
                        });
                }

                start_pos = pos + 1;
            }
        }
    }

    None
}

#[derive(Debug, serde::Deserialize)]
struct JwtClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    unique_name: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

fn extract_email_from_jwt(token: &str) -> Option<String> {
    let claims: JwtClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?).ok()?;
    [
        claims.email,
        claims.preferred_username,
        claims.upn,
        claims.unique_name,
        claims.sub,
    ]
    .into_iter()
    .flatten()
    .find(|v| v.contains('@'))
}

