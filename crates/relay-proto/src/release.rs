/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Signed relay releases (RL-29). Each release binary comes with a
//! signature file, `inbuxa-relay-<target>.sig`:
//!
//! ```text
//! inbuxa-relay release 1
//! version 27.1.0
//! target x86_64-linux-musl
//! sha256 <the binary's SHA-256, 64 hex digits>
//! signature <Ed25519 over the four lines above, newlines included; base64url>
//! ```
//!
//! The signature is by the inbuxa release key, whose public half is
//! compiled in here. The server checks it before handing a release over;
//! the relay checks it again, with its own target and version.

use crate::b64;
use aws_lc_rs::{
    digest,
    signature::{ED25519, UnparsedPublicKey},
};
use std::{cmp::Ordering, fmt};

/// The inbuxa release keys' public halves (raw Ed25519), as
/// `tools/release/new-relay-keys.sh` printed them on 2026-10-30. A build
/// without one refuses every upgrade.
pub const RELEASE_KEYS: &[[u8; 32]] = &[
    // ci: the RELAY_RELEASE_KEY secret, which signs every release
    // J0kY_vzXTC8T8gxErBMYI6cVk4Bwki65HlJGoDp15uw
    [
        0x27, 0x49, 0x18, 0xfe, 0xfc, 0xd7, 0x4c, 0x2f, 0x13, 0xf2, 0x0c, 0x44, 0xac, 0x13, 0x18,
        0x23, 0xa7, 0x15, 0x93, 0x80, 0x70, 0x92, 0x2e, 0xb9, 0x1e, 0x52, 0x46, 0xa0, 0x3a, 0x75,
        0xe6, 0xec,
    ],
    // offline: kept off any server, to sign by hand when the CI key has to
    // be replaced
    // vGsTE95CJ3vbGKVtfQctFEp0fOZ4wQ9QWTOFe0KF7_8
    [
        0xbc, 0x6b, 0x13, 0x13, 0xde, 0x42, 0x27, 0x7b, 0xdb, 0x18, 0xa5, 0x6d, 0x7d, 0x07, 0x2d,
        0x14, 0x4a, 0x74, 0x7c, 0xe6, 0x78, 0xc1, 0x0f, 0x50, 0x59, 0x33, 0x85, 0x7b, 0x42, 0x85,
        0xef, 0xff,
    ],
];

const HEADER: &str = "inbuxa-relay release 1";

/// What a signature file says of its binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub target: String,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// The signature file isn't one.
    Unreadable(&'static str),
    NoKey,
    BadSignature,
    /// The binary isn't the one the file was signed for.
    OtherBinary,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::Unreadable(why) => write!(f, "The signature file is unreadable: {why}"),
            ReleaseError::NoKey => f.write_str("This build has no inbuxa release key"),
            ReleaseError::BadSignature => {
                f.write_str("The signature isn't by the inbuxa release key")
            }
            ReleaseError::OtherBinary => f.write_str("The signature is for another binary"),
        }
    }
}

/// The target this build runs on, as signature files name it:
/// `<arch>-<os>-<libc>`, like `x86_64-linux-musl`.
pub fn target() -> String {
    let libc = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "gnu"
    } else {
        "other"
    };
    format!("{}-{}-{libc}", std::env::consts::ARCH, std::env::consts::OS)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The text a release key signs for `release`.
pub fn signed_text(release: &Release) -> String {
    format!(
        "{HEADER}\nversion {}\ntarget {}\nsha256 {}\n",
        release.version,
        release.target,
        hex(&release.sha256)
    )
}

/// Reads a signature file and checks its signature against `keys`, but not
/// the binary: what it says, if a key signed it.
pub fn verify_signature(signature_file: &str, keys: &[[u8; 32]]) -> Result<Release, ReleaseError> {
    let text = signature_file.replace("\r\n", "\n");
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(ReleaseError::Unreadable("it doesn't start as one"));
    }
    let mut field = |name: &'static str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(name))
            .and_then(|rest| rest.strip_prefix(' '))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(ReleaseError::Unreadable(name))
    };
    let version = field("version")?.to_string();
    let target = field("target")?.to_string();
    let sha256 = parse_sha256(field("sha256")?).ok_or(ReleaseError::Unreadable("sha256"))?;
    let signature = b64::decode(field("signature")?.trim_end_matches('='))
        .filter(|sig| sig.len() == 64)
        .ok_or(ReleaseError::Unreadable("signature"))?;
    if Version::parse(&version).is_none() {
        return Err(ReleaseError::Unreadable("version"));
    }
    if lines.any(|line| !line.trim().is_empty()) {
        return Err(ReleaseError::Unreadable("it goes on past the signature"));
    }
    let release = Release {
        version,
        target,
        sha256,
    };
    if keys.is_empty() {
        return Err(ReleaseError::NoKey);
    }
    let signed = signed_text(&release);
    if keys.iter().any(|key| {
        UnparsedPublicKey::new(&ED25519, key)
            .verify(signed.as_bytes(), &signature)
            .is_ok()
    }) {
        Ok(release)
    } else {
        Err(ReleaseError::BadSignature)
    }
}

/// Checks a release binary against its signature file: what it is, if a
/// key signed it and it is that binary.
pub fn verify(
    binary: &[u8],
    signature_file: &str,
    keys: &[[u8; 32]],
) -> Result<Release, ReleaseError> {
    let release = verify_signature(signature_file, keys)?;
    if digest::digest(&digest::SHA256, binary).as_ref() != release.sha256 {
        return Err(ReleaseError::OtherBinary);
    }
    Ok(release)
}

/// A release version, `MAJOR.MINOR.PATCH[-PRE][+BUILD]`, ordered as SemVer
/// §11 orders them: a pre-release comes before its release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<String>,
}

impl Version {
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim();
        let text = text.split_once('+').map_or(text, |(v, _)| v);
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let mut number = || parts.next()?.parse::<u64>().ok();
        let core = [number()?, number()?, number()?];
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            Some(pre) => {
                let ids: Vec<String> = pre.split('.').map(str::to_string).collect();
                if ids.iter().any(|id| {
                    id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) {
                    return None;
                }
                ids
            }
            None => Vec::new(),
        };
        Some(Version { core, pre })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(a), Ok(b)) => a.cmp(&b),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// How `a` compares with `b`, if both are versions.
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    Some(Version::parse(a)?.cmp(&Version::parse(b)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    /// A key pair for tests, and its public half.
    pub fn test_key() -> (Ed25519KeyPair, [u8; 32]) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        let public = pair.public_key().as_ref().try_into().unwrap();
        (pair, public)
    }

    pub fn sign(pair: &Ed25519KeyPair, binary: &[u8], version: &str, target: &str) -> String {
        let release = Release {
            version: version.into(),
            target: target.into(),
            sha256: digest::digest(&digest::SHA256, binary)
                .as_ref()
                .try_into()
                .unwrap(),
        };
        let signed = signed_text(&release);
        format!(
            "{signed}signature {}\n",
            b64::encode(pair.sign(signed.as_bytes()).as_ref())
        )
    }

    #[test]
    fn signed_releases() {
        let (pair, key) = test_key();
        let binary = b"a relay";
        let file = sign(&pair, binary, "27.1.0", "x86_64-linux-musl");
        let release = verify(binary, &file, &[key]).unwrap();
        assert_eq!(release.version, "27.1.0");
        assert_eq!(release.target, "x86_64-linux-musl");

        assert_eq!(
            verify(b"another", &file, &[key]),
            Err(ReleaseError::OtherBinary)
        );
        assert_eq!(verify(binary, &file, &[]), Err(ReleaseError::NoKey));
        let other = Ed25519KeyPair::from_seed_unchecked(&[8u8; 32]).unwrap();
        let other_key: [u8; 32] = other.public_key().as_ref().try_into().unwrap();
        assert_eq!(
            verify(binary, &file, &[other_key]),
            Err(ReleaseError::BadSignature)
        );
        // Any changed line breaks the signature
        let tampered = file.replace("version 27.1.0", "version 99.0.0");
        assert_eq!(
            verify(binary, &tampered, &[key]),
            Err(ReleaseError::BadSignature)
        );
        assert!(matches!(
            verify(binary, &format!("{file}more\n"), &[key]),
            Err(ReleaseError::Unreadable(_))
        ));
        assert!(matches!(
            verify(binary, "not a signature file", &[key]),
            Err(ReleaseError::Unreadable(_))
        ));
        // CRLF line ends, as a download on another system may have
        assert!(verify(binary, &file.replace('\n', "\r\n"), &[key]).is_ok());
    }

    /// A file made by tools/release/sign-relay.sh with openssl, from a key
    /// made for this test only: the script and this code agree.
    #[test]
    fn openssl_signature() {
        let key: [u8; 32] = b64::decode("VNaWnerWh2UXOrUMtSWPOKJHtigsUdIWUfzHmXbdgIU")
            .unwrap()
            .try_into()
            .unwrap();
        let file = "inbuxa-relay release 1\n\
                    version 27.1.0-rc.5\n\
                    target x86_64-linux-musl\n\
                    sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n\
                    signature SIG\n";
        let file = file.replace("SIG", OPENSSL_SIGNATURE);
        let release = verify(b"abc", &file, &[key]).unwrap();
        assert_eq!(release.version, "27.1.0-rc.5");
    }

    const OPENSSL_SIGNATURE: &str =
        "zRj90ByVN18fmW-GOZ9cvGBK1ZsYYoNvowGsbSBYcslJhgIgmKrYHgRgq1CSIy4G-EzR5uexCzAUoa3FEcluAA";

    /// The keys compiled in are the ones the comments name.
    #[test]
    fn release_keys_as_printed() {
        let printed: Vec<String> = RELEASE_KEYS.iter().map(|key| b64::encode(key)).collect();
        assert_eq!(
            printed,
            [
                "J0kY_vzXTC8T8gxErBMYI6cVk4Bwki65HlJGoDp15uw",
                "vGsTE95CJ3vbGKVtfQctFEp0fOZ4wQ9QWTOFe0KF7_8"
            ]
        );
        for key in RELEASE_KEYS {
            // Each is a key a signature can be checked against
            assert_eq!(
                verify_signature(
                    &format!(
                        "{HEADER}\nversion 1.0.0\ntarget t\nsha256 {}\nsignature {}\n",
                        "0".repeat(64),
                        "A".repeat(86)
                    ),
                    &[*key]
                ),
                Err(ReleaseError::BadSignature)
            );
        }
    }

    #[test]
    fn versions_in_order() {
        let less = |a: &str, b: &str| compare_versions(a, b) == Some(Ordering::Less);
        assert!(less("27.1.0-rc.4", "27.1.0-rc.5"));
        assert!(less("27.1.0-rc.9", "27.1.0-rc.10"));
        assert!(less("27.1.0-rc.5", "27.1.0"));
        assert!(less("27.1.0", "27.1.1"));
        assert!(less("27.1.9", "27.2.0"));
        assert!(less("27.2.0", "28.0.0"));
        assert!(less("1.0.0-alpha", "1.0.0-alpha.1"));
        assert!(less("1.0.0-alpha.1", "1.0.0-alpha.beta"));
        assert!(less("1.0.0-beta.11", "1.0.0-rc.1"));
        assert_eq!(
            compare_versions("27.1.0+abc", "27.1.0"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare_versions("27.1", "27.1.0"), None);
        assert_eq!(compare_versions("27.1.0-", "27.1.0"), None);
        assert!(target().contains(std::env::consts::ARCH));
    }
}
