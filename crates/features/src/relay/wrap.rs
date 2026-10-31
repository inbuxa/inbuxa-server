/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The downstream's relay keys, wrapped (RL-35): the link CA key, the
//! sealing key and each relay's recipient key are stored encrypted under a
//! key the store doesn't hold, from the file `INBUXA_RELAY_KEY_FILE` names.
//!
//! A [`Secret`] is stored as before, a string, while no file is named, and
//! as `{"wrapped": nonce || ciphertext}` once one is. A secret read in the
//! clear is wrapped the next time it is written, which [`wrap_stored`] does
//! for every one. Opening a wrapped secret without the file fails, saying
//! so: the link service then starts no link, and the node shows why.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, RwLock},
};

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use inbuxa_relay_proto::b64;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

/// Names the key file.
pub const ENV: &str = "INBUXA_RELAY_KEY_FILE";

/// Bound to every wrapped secret, so nothing else under the key opens as one.
const AAD: &[u8] = b"inbuxa relay key v1";

/// The key from the file, none when no file is named, or why it can't be
/// read.
type KeyFile = Result<Option<RandomizedNonceKey>, String>;

/// Read from [`ENV`] when first needed.
static KEY_FILE: LazyLock<RwLock<Option<Arc<KeyFile>>>> = LazyLock::new(|| RwLock::new(None));

fn key_file() -> Arc<KeyFile> {
    if let Some(loaded) = KEY_FILE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return loaded.clone();
    }
    let path = std::env::var_os(ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    set_key_file(path.as_deref())
}

/// Reads the key from `path`, or none, in place of what [`ENV`] names. The
/// server reads [`ENV`] itself; the tests use this to turn the file on and
/// off.
pub fn set_key_file(path: Option<&Path>) -> Arc<KeyFile> {
    let loaded = Arc::new(path.map_or(Ok(None), |path| load(path).map(Some)));
    if let Err(why) = loaded.as_ref() {
        trc::error!(trc::Error::from(KeyError(why.clone())));
    }
    *KEY_FILE.write().unwrap_or_else(|e| e.into_inner()) = Some(loaded.clone());
    loaded
}

/// 32 random bytes in base64, as `openssl rand -base64 32` writes them.
fn load(path: &Path) -> Result<RandomizedNonceKey, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("{ENV}: can't read {}: {err}", path.display()))?;
    let text = text.trim();
    let bytes = STANDARD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .or_else(|_| b64::decode(text).ok_or(()))
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            format!(
                "{ENV}: {} doesn't hold 32 bytes in base64, as `openssl rand -base64 32` writes them.",
                path.display()
            )
        })?;
    key(&bytes)
}

fn key(bytes: &[u8]) -> Result<RandomizedNonceKey, String> {
    RandomizedNonceKey::new(&AES_256_GCM, bytes).map_err(|_| format!("{ENV}: not a key."))
}

/// Whether a key file is named, and reads.
pub fn turned_on() -> bool {
    matches!(key_file().as_ref(), Ok(Some(_)))
}

/// A value that can be a [`Secret`]: how it is stored in the clear, and as
/// bytes to wrap.
pub trait SecretValue: Sized + Clone {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: Vec<u8>) -> Option<Self>;
    fn to_text(&self) -> String;
    fn from_text(text: String) -> Option<Self>;
}

/// A PEM private key.
impl SecretValue for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        String::from_utf8(bytes).ok()
    }

    fn to_text(&self) -> String {
        self.clone()
    }

    fn from_text(text: String) -> Option<Self> {
        Some(text)
    }
}

/// A key, in base64url.
impl SecretValue for [u8; 32] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }

    fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        bytes.try_into().ok()
    }

    fn to_text(&self) -> String {
        b64::encode(self)
    }

    fn from_text(text: String) -> Option<Self> {
        b64::decode(&text).and_then(|bytes| bytes.try_into().ok())
    }
}

/// A secret as the store holds it.
#[derive(Clone, PartialEq, Eq)]
pub enum Secret<T> {
    /// In the clear: no key file was named when it was written.
    Open(T),
    /// The nonce, then the ciphertext and its tag.
    Wrapped(Vec<u8>),
}

impl<T: SecretValue> Secret<T> {
    pub fn new(value: T) -> Self {
        Secret::Open(value)
    }

    /// The secret itself, or why it can't be opened.
    pub fn open(&self) -> Result<T, KeyError> {
        match self {
            Secret::Open(value) => Ok(value.clone()),
            Secret::Wrapped(wrapped) => match key_file().as_ref() {
                Ok(Some(key)) => unwrap_with(key, wrapped).ok_or_else(|| {
                    KeyError(format!(
                        "The relay keys were wrapped with another key than the one {ENV} names."
                    ))
                }),
                Ok(None) => Err(KeyError(format!(
                    "The relay keys are wrapped: set {ENV} to the key file they were wrapped with."
                ))),
                Err(why) => Err(KeyError(why.clone())),
            },
        }
    }

    /// In the clear, while a key file is named: written again, it is
    /// wrapped.
    pub fn needs_wrapping(&self) -> bool {
        matches!(self, Secret::Open(_)) && turned_on()
    }

    pub fn is_wrapped(&self) -> bool {
        matches!(self, Secret::Wrapped(_))
    }
}

impl<T: SecretValue + Default> Default for Secret<T> {
    fn default() -> Self {
        Secret::Open(T::default())
    }
}

/// Why a relay key can't be opened, or the key file read: in words for
/// the node's link status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub String);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<KeyError> for trc::Error {
    fn from(err: KeyError) -> Self {
        trc::EventType::Server(trc::ServerEvent::StartupError)
            .into_err()
            .details(err.0)
    }
}

fn wrap_with(key: &RandomizedNonceKey, value: &[u8]) -> Option<Vec<u8>> {
    let mut data = value.to_vec();
    let nonce = key
        .seal_in_place_append_tag(Aad::from(AAD), &mut data)
        .ok()?;
    let mut wrapped = nonce.as_ref().to_vec();
    wrapped.append(&mut data);
    Some(wrapped)
}

fn unwrap_with<T: SecretValue>(key: &RandomizedNonceKey, wrapped: &[u8]) -> Option<T> {
    let (nonce, data) = wrapped.split_at_checked(NONCE_LEN)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut data = data.to_vec();
    let len = key
        .open_in_place(nonce, Aad::from(AAD), &mut data)
        .ok()?
        .len();
    data.truncate(len);
    T::from_bytes(data)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Stored {
    Open(String),
    Wrapped { wrapped: String },
}

impl<T: SecretValue> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wrapped = match self {
            Secret::Wrapped(wrapped) => wrapped.clone(),
            Secret::Open(value) => match key_file().as_ref() {
                Ok(None) => return Stored::Open(value.to_text()).serialize(serializer),
                Ok(Some(key)) => wrap_with(key, &value.to_bytes())
                    .ok_or_else(|| ser::Error::custom("can't wrap a relay key"))?,
                // Never in the clear while a file is named
                Err(why) => return Err(ser::Error::custom(why)),
            },
        };
        Stored::Wrapped {
            wrapped: b64::encode(&wrapped),
        }
        .serialize(serializer)
    }
}

impl<'de, T: SecretValue> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Stored::deserialize(deserializer)? {
            Stored::Open(text) => T::from_text(text)
                .map(Secret::Open)
                .ok_or_else(|| de::Error::custom("not a relay key")),
            Stored::Wrapped { wrapped } => b64::decode(&wrapped)
                .map(Secret::Wrapped)
                .ok_or_else(|| de::Error::custom("not a wrapped relay key")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_opens() {
        let key = key(&[7; 32]).unwrap();
        let wrapped = wrap_with(&key, b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert!(!wrapped.windows(5).any(|w| w == b"BEGIN"));
        assert_eq!(
            unwrap_with::<String>(&key, &wrapped).as_deref(),
            Some("-----BEGIN PRIVATE KEY-----")
        );
        // A new nonce every time
        assert_ne!(
            wrap_with(&key, b"same").unwrap(),
            wrap_with(&key, b"same").unwrap()
        );
        // Another key, or a changed byte, opens nothing
        assert_eq!(
            unwrap_with::<String>(&self::key(&[8; 32]).unwrap(), &wrapped),
            None
        );
        let mut changed = wrapped.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(unwrap_with::<String>(&key, &changed), None);
        assert_eq!(unwrap_with::<String>(&key, &wrapped[..4]), None);
        // A 32-byte key comes back as one
        let wrapped = wrap_with(&key, &[3; 32]).unwrap();
        assert_eq!(unwrap_with::<[u8; 32]>(&key, &wrapped), Some([3; 32]));
    }

    #[test]
    fn stored_forms() {
        // In the clear, as before RL-35
        let open: Secret<[u8; 32]> =
            serde_json::from_str(&format!("\"{}\"", b64::encode(&[5; 32]))).unwrap();
        assert!(open == Secret::Open([5; 32]));
        let open: Secret<String> = serde_json::from_str("\"-----BEGIN\"").unwrap();
        assert!(open == Secret::Open("-----BEGIN".to_string()));
        // Wrapped stays as it was, whatever the key file
        let wrapped: Secret<String> = serde_json::from_str("{\"wrapped\":\"AAEC\"}").unwrap();
        assert!(wrapped == Secret::Wrapped(vec![0, 1, 2]));
        assert_eq!(
            serde_json::to_string(&wrapped).unwrap(),
            "{\"wrapped\":\"AAEC\"}"
        );
        assert!(serde_json::from_str::<Secret<[u8; 32]>>("\"short\"").is_err());
    }

    #[test]
    fn key_files() {
        let dir = std::env::temp_dir().join(format!("inbuxa-relay-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.key");
        for good in [
            STANDARD.encode([1; 32]) + "\n",
            URL_SAFE.encode([250; 32]),
            b64::encode(&[250; 32]),
        ] {
            std::fs::write(&path, good).unwrap();
            assert!(load(&path).is_ok());
        }
        for bad in [
            STANDARD.encode([1; 16]),
            "not base64".to_string(),
            String::new(),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(load(&path).unwrap_err().contains("32 bytes"));
        }
        assert!(
            load(&dir.join("missing"))
                .unwrap_err()
                .contains("can't read")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
