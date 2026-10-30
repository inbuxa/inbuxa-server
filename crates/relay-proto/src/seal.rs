/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Sealing held inbound mail to the downstream (RL-21).
//!
//! HPKE (RFC 9180) in base mode, with DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256 and ChaCha20-Poly1305: the suite of RFC 9180 Appendix A.2,
//! whose vectors the tests check. The relay holds only the downstream's
//! public key, so it can't read a message once it is sealed.
//!
//! The stream is a header, `"IXRS" 0x01 enc`, then chunks of up to 64 KiB of
//! plaintext, each `u32 frame || ciphertext`, where the frame's top bit marks
//! the last chunk and the rest is the ciphertext's length. Each chunk is
//! sealed with the next HPKE sequence number and the associated data
//! `aad || last`, where `aad` names the message (its `Inbound` id) and `last`
//! is 1 on the final chunk. So chunks can't be reordered, a stream can't be cut short, and one
//! message's file can't pass for another's.

use aws_lc_rs::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    agreement::{self, PrivateKey, UnparsedPublicKey, X25519},
    encoding::AsBigEndian,
    hmac,
};

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;
const TAG_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"IXRS";
const FORMAT: u8 = 1;
/// Header length: magic, format, encapsulated key.
pub const HEADER_LEN: usize = 4 + 1 + 32;
/// HPKE `info` for the relay's inbound spool.
pub const INFO: &[u8] = b"inbuxa-relay inbound v1";

const LAST_BIT: u32 = 1 << 31;

const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// A key that isn't a valid X25519 key.
    BadKey,
    /// Not a sealed stream, or one that fails authentication.
    Corrupt,
    /// The stream ends before its last chunk.
    Truncated,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SealError::BadKey => "not a valid X25519 key",
            SealError::Corrupt => "sealed data is corrupt or was altered",
            SealError::Truncated => "sealed data is cut short",
        })
    }
}

impl std::error::Error for SealError {}

/// A new sealing key pair: `(secret, public)`. The secret stays on the
/// downstream.
pub fn generate_keypair() -> (Box<[u8; 32]>, [u8; 32]) {
    let sk = PrivateKey::generate(&X25519).expect("X25519 key generation");
    let secret = secret_bytes(&sk);
    let public = public_bytes(&sk);
    (secret, public)
}

/// The public half of a secret sealing key.
pub fn public_key(secret: &[u8; 32]) -> Result<[u8; 32], SealError> {
    let sk = PrivateKey::from_private_key(&X25519, secret).map_err(|_| SealError::BadKey)?;
    Ok(public_bytes(&sk))
}

fn secret_bytes(sk: &PrivateKey) -> Box<[u8; 32]> {
    let seed: aws_lc_rs::encoding::Curve25519SeedBin<'_> =
        sk.as_be_bytes().expect("X25519 secret export");
    let mut out = Box::new([0u8; 32]);
    out.copy_from_slice(seed.as_ref());
    out
}

fn public_bytes(sk: &PrivateKey) -> [u8; 32] {
    let pk = sk.compute_public_key().expect("X25519 public key");
    let mut out = [0u8; 32];
    out.copy_from_slice(pk.as_ref());
    out
}

fn dh(sk: &PrivateKey, pk: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    agreement::agree(
        sk,
        UnparsedPublicKey::new(&X25519, pk),
        SealError::BadKey,
        |shared| Ok(shared.to_vec()),
    )
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
    for part in parts {
        ctx.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[b"HPKE-v1", suite, label, ikm])
}

fn labeled_expand(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    debug_assert!(len <= 255 * 32);
    let len_be = (len as u16).to_be_bytes();
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let block = hmac_sha256(
            prk,
            &[&t, &len_be, b"HPKE-v1", suite, label, info, &[counter]],
        );
        t = block.to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// An HPKE context in base mode: the AEAD key, base nonce and sequence.
struct Context {
    key: LessSafeKey,
    base_nonce: [u8; 12],
    seq: u64,
}

impl Context {
    fn new(shared_secret: &[u8; 32], info: &[u8]) -> Self {
        let psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info);
        let mut ksc = Vec::with_capacity(65);
        ksc.push(0u8);
        ksc.extend_from_slice(&psk_id_hash);
        ksc.extend_from_slice(&info_hash);
        let secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"");
        let key = labeled_expand(HPKE_SUITE, &secret, b"key", &ksc, 32);
        let nonce = labeled_expand(HPKE_SUITE, &secret, b"base_nonce", &ksc, 12);
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&nonce);
        Context {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("32-byte key")),
            base_nonce,
            seq: 0,
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = self.base_nonce;
        for (n, s) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        self.seq += 1;
        Nonce::assume_unique_for_key(nonce)
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
        buf.extend_from_slice(plaintext);
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .expect("ChaCha20-Poly1305 seal");
        buf
    }

    fn open(&mut self, aad: &[u8], mut ciphertext: Vec<u8>) -> Result<Vec<u8>, SealError> {
        let nonce = self.next_nonce();
        let len = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut ciphertext)
            .map_err(|_| SealError::Corrupt)?
            .len();
        ciphertext.truncate(len);
        Ok(ciphertext)
    }
}

fn shared_secret(dh: &[u8], enc: &[u8; 32], pk_r: &[u8; 32]) -> [u8; 32] {
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r);
    let eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh);
    let ss = labeled_expand(KEM_SUITE, &eae_prk, b"shared_secret", &kem_context, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ss);
    out
}

/// SetupBaseS with a given ephemeral key: returns `(enc, context)`.
fn setup_sender(
    sk_e: &PrivateKey,
    pk_r: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], Context), SealError> {
    let enc = public_bytes(sk_e);
    let dh = dh(sk_e, pk_r)?;
    Ok((enc, Context::new(&shared_secret(&dh, &enc, pk_r), info)))
}

/// SetupBaseR.
fn setup_receiver(enc: &[u8; 32], sk_r: &[u8; 32], info: &[u8]) -> Result<Context, SealError> {
    let sk = PrivateKey::from_private_key(&X25519, sk_r).map_err(|_| SealError::BadKey)?;
    let pk_r = public_bytes(&sk);
    let dh = dh(&sk, enc)?;
    Ok(Context::new(&shared_secret(&dh, enc, &pk_r), info))
}

fn chunk_aad(aad: &[u8], last: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + 1);
    out.extend_from_slice(aad);
    out.push(u8::from(last));
    out
}

/// Seals a stream, a chunk at a time, as the message arrives.
pub struct Sealer {
    ctx: Context,
    aad: Vec<u8>,
    pending: Vec<u8>,
}

impl Sealer {
    /// Starts a stream sealed to `recipient` (the downstream's public key),
    /// for the message named by `aad`. Returns the sealer and the header,
    /// which comes first in the output.
    pub fn new(recipient: &[u8; 32], aad: &[u8]) -> Result<(Self, Vec<u8>), SealError> {
        let sk_e = PrivateKey::generate(&X25519).map_err(|_| SealError::BadKey)?;
        let (enc, ctx) = setup_sender(&sk_e, recipient, INFO)?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT);
        header.extend_from_slice(&enc);
        Ok((
            Sealer {
                ctx,
                aad: aad.to_vec(),
                pending: Vec::with_capacity(CHUNK_SIZE),
            },
            header,
        ))
    }

    /// Takes more plaintext, and appends any whole chunks to `out`.
    pub fn update(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        while !data.is_empty() {
            let take = (CHUNK_SIZE - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            // A full chunk is held back until more arrives, so the final
            // chunk is never empty unless the whole message is.
            if self.pending.len() == CHUNK_SIZE && !data.is_empty() {
                self.emit(false, out);
            }
        }
    }

    /// Seals what is left as the last chunk.
    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.emit(true, out);
    }

    fn emit(&mut self, last: bool, out: &mut Vec<u8>) {
        let sealed = self.ctx.seal(&chunk_aad(&self.aad, last), &self.pending);
        let frame = sealed.len() as u32 | if last { LAST_BIT } else { 0 };
        out.extend_from_slice(&frame.to_be_bytes());
        out.extend_from_slice(&sealed);
        self.pending.clear();
    }
}

/// Opens a stream, as its bytes arrive.
pub struct Opener {
    ctx: Context,
    aad: Vec<u8>,
    buf: Vec<u8>,
    done: bool,
}

impl Opener {
    /// Starts opening a stream with the downstream's secret key. `header` is
    /// the stream's first `HEADER_LEN` bytes.
    pub fn new(secret: &[u8; 32], header: &[u8], aad: &[u8]) -> Result<Self, SealError> {
        if header.len() != HEADER_LEN || &header[..4] != MAGIC || header[4] != FORMAT {
            return Err(SealError::Corrupt);
        }
        let enc: [u8; 32] = header[5..].try_into().expect("32 bytes");
        Ok(Opener {
            ctx: setup_receiver(&enc, secret, INFO)?,
            aad: aad.to_vec(),
            buf: Vec::new(),
            done: false,
        })
    }

    /// Takes more sealed bytes, and appends the plaintext of each whole chunk
    /// to `out`.
    pub fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), SealError> {
        self.buf.extend_from_slice(data);
        loop {
            if self.buf.len() < 4 {
                return Ok(());
            }
            if self.done {
                return Err(SealError::Corrupt);
            }
            let frame = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes"));
            let last = frame & LAST_BIT != 0;
            let len = (frame & !LAST_BIT) as usize;
            if !(TAG_LEN..=CHUNK_SIZE + TAG_LEN).contains(&len) {
                return Err(SealError::Corrupt);
            }
            if self.buf.len() < 4 + len {
                return Ok(());
            }
            let chunk = self.buf[4..4 + len].to_vec();
            self.buf.drain(..4 + len);
            let plaintext = self.ctx.open(&chunk_aad(&self.aad, last), chunk)?;
            self.done = last;
            out.extend_from_slice(&plaintext);
        }
    }

    /// Checks the stream ended with its last chunk and nothing after it.
    pub fn finish(self) -> Result<(), SealError> {
        match (self.done, self.buf.is_empty()) {
            (true, true) => Ok(()),
            (true, false) => Err(SealError::Corrupt),
            (false, _) => Err(SealError::Truncated),
        }
    }
}

/// Seals a whole message at once.
pub fn seal(recipient: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let (mut sealer, mut out) = Sealer::new(recipient, aad)?;
    sealer.update(plaintext, &mut out);
    sealer.finish(&mut out);
    Ok(out)
}

/// Opens a whole sealed message at once.
pub fn open(secret: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < HEADER_LEN {
        return Err(SealError::Corrupt);
    }
    let mut opener = Opener::new(secret, &sealed[..HEADER_LEN], aad)?;
    let mut out = Vec::with_capacity(sealed.len());
    opener.update(&sealed[HEADER_LEN..], &mut out)?;
    opener.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    // RFC 9180, Appendix A.2.1.
    const INFO_A21: &str = "4f6465206f6e2061204772656369616e2055726e";
    const SK_EM: &str = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600";
    const PK_EM: &str = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
    const SK_RM: &str = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
    const PK_RM: &str = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const ENCRYPTIONS: [(u64, &str, &str); 3] = [
        (
            0,
            "436f756e742d30",
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db
             21993c62ce81883d2dd1b51a28",
        ),
        (
            1,
            "436f756e742d31",
            "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e
             85285337cc95ba5f59992dc98c",
        ),
        (
            2,
            "436f756e742d32",
            "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02
             b4f10ecac6f48c32f878fae86b",
        ),
    ];

    #[test]
    fn rfc9180_a21_vectors() {
        assert_eq!(public_key(&arr(SK_RM)).unwrap(), arr(PK_RM));
        let sk_e = PrivateKey::from_private_key(&X25519, &hex(SK_EM)).unwrap();
        let (enc, mut sender) = setup_sender(&sk_e, &arr(PK_RM), &hex(INFO_A21)).unwrap();
        assert_eq!(enc, arr(PK_EM));
        let mut receiver = setup_receiver(&enc, &arr(SK_RM), &hex(INFO_A21)).unwrap();
        for (seq, aad, ct) in ENCRYPTIONS {
            assert_eq!(sender.seq, seq);
            let sealed = sender.seal(&hex(aad), &hex(PT));
            assert_eq!(sealed, hex(ct), "sequence {seq}");
            assert_eq!(receiver.open(&hex(aad), sealed).unwrap(), hex(PT));
        }
    }

    #[test]
    fn stream_round_trips_at_every_size() {
        let (secret, public) = generate_keypair();
        for len in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            3 * CHUNK_SIZE + 7,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal(&public, b"id-1", &data).unwrap();
            assert_eq!(open(&secret, b"id-1", &sealed).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn stream_fed_in_pieces() {
        let (secret, public) = generate_keypair();
        let data: Vec<u8> = (0..200_000).map(|i| (i % 13) as u8).collect();
        let (mut sealer, mut sealed) = Sealer::new(&public, b"id").unwrap();
        for piece in data.chunks(977) {
            sealer.update(piece, &mut sealed);
        }
        sealer.finish(&mut sealed);
        let mut opener = Opener::new(&secret, &sealed[..HEADER_LEN], b"id").unwrap();
        let mut out = Vec::new();
        for piece in sealed[HEADER_LEN..].chunks(1013) {
            opener.update(piece, &mut out).unwrap();
        }
        opener.finish().unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn no_plaintext_in_the_sealed_bytes() {
        let (_, public) = generate_keypair();
        let marker = b"MARKER-7f3a-held-mail";
        let sealed = seal(&public, b"id", marker).unwrap();
        assert!(!sealed.windows(marker.len()).any(|w| w == marker));
    }

    #[test]
    fn tampering_is_caught() {
        let (secret, public) = generate_keypair();
        let data = vec![42u8; 2 * CHUNK_SIZE + 10];
        let sealed = seal(&public, b"id", &data).unwrap();

        // Another message's id.
        assert_eq!(open(&secret, b"other", &sealed), Err(SealError::Corrupt));
        // A flipped byte.
        let mut bad = sealed.clone();
        bad[HEADER_LEN + 100] ^= 1;
        assert_eq!(open(&secret, b"id", &bad), Err(SealError::Corrupt));
        // Cut after the first chunk.
        let first = HEADER_LEN + 4 + CHUNK_SIZE + TAG_LEN;
        assert_eq!(
            open(&secret, b"id", &sealed[..first]),
            Err(SealError::Truncated)
        );
        // Trailing bytes.
        let mut long = sealed.clone();
        long.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(open(&secret, b"id", &long), Err(SealError::Corrupt));
        // Chunks swapped.
        let c = 4 + CHUNK_SIZE + TAG_LEN;
        let mut swapped = sealed[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&sealed[HEADER_LEN + c..HEADER_LEN + 2 * c]);
        swapped.extend_from_slice(&sealed[HEADER_LEN..HEADER_LEN + c]);
        swapped.extend_from_slice(&sealed[HEADER_LEN + 2 * c..]);
        assert_eq!(open(&secret, b"id", &swapped), Err(SealError::Corrupt));
        // The wrong key.
        let (other, _) = generate_keypair();
        assert_eq!(open(&other, b"id", &sealed), Err(SealError::Corrupt));
        // Not a stream.
        assert_eq!(open(&secret, b"id", b"hello"), Err(SealError::Corrupt));
    }
}
