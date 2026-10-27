/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::EncryptionKeys;
use encodify::base64::LENIENT;
use registry::schema::structs::PublicKey;
use sequoia_openpgp::{Cert, parse::Parse, policy::StandardPolicy, types::KeyFlags};
use std::{borrow::Cow, str::SplitInclusive};

const P: StandardPolicy<'static> = StandardPolicy::new();

const ARMOR_BEGIN: &str = "-----BEGIN ";
const ARMOR_END: &str = "-----END";
const ARMOR_DASHES: &str = "-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

pub struct EncryptionParams {
    pub certs: EncryptionKeys,
    pub method: EncryptionMethod,
}

pub fn parse_public_key(pk: &PublicKey) -> Result<Option<EncryptionParams>, Cow<'static, str>> {
    let mut method = None;
    let mut certs: Vec<Box<[u8]>> = Vec::new();
    let mut has_usable_pgp_key = false;

    for block in ArmoredBlocks::new(&pk.key) {
        let block = block?;
        if contains_ignore_ascii_case(block.label, "PRIVATE") {
            return Err("Private keys cannot be used as public keys".into());
        }
        let block_method = if contains_ignore_ascii_case(block.label, "CERTIFICATE") {
            EncryptionMethod::SMIME
        } else if contains_ignore_ascii_case(block.label, "PGP") {
            EncryptionMethod::PGP
        } else {
            continue;
        };

        match method {
            Some(method) if method != block_method => {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            }
            _ => method = Some(block_method),
        }

        match block_method {
            EncryptionMethod::PGP => {
                let cert = Cert::from_bytes(block.armored.as_bytes())
                    .map_err(|err| format!("Failed to decode OpenPGP public key: {err}"))?;
                if cert.is_tsk() {
                    return Err("Private keys cannot be used as public keys".into());
                }
                has_usable_pgp_key |= has_pgp_keys(&cert);
                certs.push(block.armored.as_bytes().into());
            }
            EncryptionMethod::SMIME => {
                let cert = LENIENT
                    .decode(block.body)
                    .map_err(|_| Cow::from("Failed to decode base64 certificate."))?;
                let is_complete = rasn::der::decode_with_remainder::<rasn_pkix::Certificate>(&cert)
                    .map_err(|err| format!("Failed to decode X509 certificate: {err}"))?
                    .1
                    .is_empty();
                if !is_complete {
                    return Err("Unexpected data after X509 certificate".into());
                }
                certs.push(cert.into_boxed_slice());
            }
        }
    }

    match method {
        Some(EncryptionMethod::PGP) if !has_usable_pgp_key => {
            Err("Could not find any suitable keys in OpenPGP public key".into())
        }
        Some(method) => Ok(Some(EncryptionParams {
            method,
            certs: certs.into_boxed_slice(),
        })),
        None if pk.key.trim().is_empty() => Ok(None),
        None => Err("No OpenPGP public key or X.509 certificate found".into()),
    }
}

struct ArmoredBlock<'x> {
    label: &'x str,
    armored: &'x str,
    body: &'x str,
}

struct ArmoredBlocks<'x> {
    text: &'x str,
    lines: SplitInclusive<'x, char>,
    offset: usize,
}

impl<'x> ArmoredBlocks<'x> {
    fn new(text: &'x str) -> Self {
        ArmoredBlocks {
            text,
            lines: text.split_inclusive('\n'),
            offset: 0,
        }
    }

    fn next_line(&mut self) -> Option<(usize, &'x str)> {
        let line = self.lines.next()?;
        let start = self.offset;
        self.offset += line.len();
        Some((start, line))
    }

    fn fail(
        &mut self,
        reason: &'static str,
    ) -> Option<Result<ArmoredBlock<'x>, Cow<'static, str>>> {
        self.lines = "".split_inclusive('\n');
        Some(Err(reason.into()))
    }
}

impl<'x> Iterator for ArmoredBlocks<'x> {
    type Item = Result<ArmoredBlock<'x>, Cow<'static, str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (block_start, label) = loop {
            let (line_start, line) = self.next_line()?;
            let begin = line.trim();
            if begin.is_empty() {
                continue;
            }
            let Some(label) = begin
                .strip_prefix(ARMOR_BEGIN)
                .and_then(|label| label.strip_suffix(ARMOR_DASHES))
                .filter(|label| !label.is_empty())
            else {
                return self.fail("Unexpected text outside of a PEM or OpenPGP armor block");
            };
            break (line_start + line.len() - line.trim_start().len(), label);
        };
        let body_start = self.offset;

        loop {
            let Some((line_start, line)) = self.next_line() else {
                return self.fail("PEM or OpenPGP armor block is missing its END line");
            };
            let line = line.trim();
            if let Some(end_label) = line.strip_prefix(ARMOR_END) {
                if end_label
                    .strip_prefix(' ')
                    .and_then(|end_label| end_label.strip_suffix(ARMOR_DASHES))
                    != Some(label)
                {
                    return self
                        .fail("PEM or OpenPGP armor END line does not match its BEGIN line");
                }
                return match (
                    self.text.get(block_start..self.offset),
                    self.text.get(body_start..line_start),
                ) {
                    (Some(armored), Some(body)) => Some(Ok(ArmoredBlock {
                        label,
                        armored,
                        body,
                    })),
                    _ => self.fail("Invalid PEM or OpenPGP armor block"),
                };
            } else if line.starts_with(ARMOR_BEGIN) {
                return self.fail("PEM or OpenPGP armor block is missing its END line");
            }
        }
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn has_pgp_keys(cert: &Cert) -> bool {
    cert.keys()
        .with_policy(&P, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .next()
        .is_some()
}

