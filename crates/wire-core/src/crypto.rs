use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};

pub const SUITE_CLASSICAL: u16 = 1;
pub const SUITE_STUB: u16 = 2;

pub const KIND_EPHEMERAL: u8 = 1;
pub const KIND_LEDGER: u8 = 2;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let dig = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut b);
    b
}

pub fn random24() -> [u8; 24] {
    let mut b = [0u8; 24];
    rand::RngCore::fill_bytes(&mut OsRng, &mut b);
    b
}

pub struct RootSecret {
    sign: SigningKey,
}

impl RootSecret {
    pub fn generate() -> Self {
        Self {
            sign: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            sign: SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.sign.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    pub fn principal_id(&self) -> [u8; 32] {
        sha256(&self.public())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sign.sign(msg).to_bytes()
    }
}

pub struct AgreeSecret {
    secret: StaticSecret,
}

impl AgreeSecret {
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    fn shared(&self, peer_public: &[u8; 32]) -> Result<[u8; 32]> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        let bytes = *shared.as_bytes();
        if bytes == [0u8; 32] {
            return Err(Error::new("reject zero shared secret"));
        }
        Ok(bytes)
    }
}

pub struct SignSecret {
    sign: SigningKey,
}

impl SignSecret {
    pub fn generate() -> Self {
        Self {
            sign: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            sign: SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.sign.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sign.sign(msg).to_bytes()
    }
}

pub fn verify_sig(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| Error::new("bad verifying key"))?;
    let signature = Signature::from_slice(sig).map_err(|_| Error::new("bad signature"))?;
    vk.verify(msg, &signature)
        .map_err(|_| Error::new("signature rejected"))
}

pub fn require_suite(suite: u16) -> Result<()> {
    if suite == SUITE_CLASSICAL {
        Ok(())
    } else if suite == SUITE_STUB {
        Err(Error::new(
            "suite_id 2 is an agility stub and cannot seal or sign",
        ))
    } else {
        Err(Error::new(format!("unknown suite_id {suite}")))
    }
}

fn seal_key(shared: &[u8; 32], sender_x: &[u8; 32], recip_x: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wire-seal-v1");
    h.update(shared);
    h.update(sender_x);
    h.update(recip_x);
    let dig = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

pub struct Envelope {
    pub suite: u16,
    pub kind: u8,
    pub sender_cred_id: [u8; 32],
    pub recipient_cred_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub sender_x25519: [u8; 32],
    pub plaintext: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn seal(
    suite: u16,
    kind: u8,
    agree: &AgreeSecret,
    sender_cred_id: &[u8; 32],
    recipient_cred_id: &[u8; 32],
    recipient_x25519: &[u8; 32],
    channel_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    require_suite(suite)?;
    let sender_x = agree.public();
    let shared = agree.shared(recipient_x25519)?;
    let key = seal_key(&shared, &sender_x, recipient_x25519);
    let nonce = random24();
    let header = envelope_header(
        suite,
        kind,
        sender_cred_id,
        recipient_cred_id,
        channel_id,
        &sender_x,
        &nonce,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::new("bad aead key"))?;
    let nonce_ga = XNonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(
            nonce_ga,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::new("seal failed"))?;
    let mut w = Writer::new();
    w.bytes(&header);
    w.lp(&ct);
    Ok(w.finish())
}

pub struct ClearHeader {
    pub suite: u16,
    pub kind: u8,
    pub channel_id: [u8; 32],
}

/// Reads the clear envelope header only. Does not decrypt.
pub fn peek_clear(bytes: &[u8]) -> Result<ClearHeader> {
    let mut r = Reader::new(bytes);
    let magic = r.take(4)?;
    if magic != b"WENV" {
        return Err(Error::new("not an envelope"));
    }
    let version = r.u16()?;
    if version != 1 {
        return Err(Error::new("bad envelope version"));
    }
    Ok(ClearHeader {
        suite: r.u16()?,
        kind: r.u8()?,
        channel_id: {
            let _sender = r.arr32()?;
            let _recipient = r.arr32()?;
            r.arr32()?
        },
    })
}

pub fn open(agree: &AgreeSecret, my_cred_id: &[u8; 32], bytes: &[u8]) -> Result<Envelope> {
    let mut r = Reader::new(bytes);
    let magic = r.take(4)?;
    if magic != b"WENV" {
        return Err(Error::new("not an envelope"));
    }
    let version = r.u16()?;
    if version != 1 {
        return Err(Error::new("bad envelope version"));
    }
    let suite = r.u16()?;
    require_suite(suite)?;
    let kind = r.u8()?;
    let sender_cred_id = r.arr32()?;
    let recipient_cred_id = r.arr32()?;
    let channel_id = r.arr32()?;
    let sender_x25519 = r.arr32()?;
    let nonce = r.arr24()?;
    let ct = r.lp()?.to_vec();
    r.finish()?;
    if &recipient_cred_id != my_cred_id {
        return Err(Error::new("envelope is not for this credential"));
    }
    let header_len = bytes.len() - 4 - ct.len();
    let header = &bytes[..header_len];
    let my_x = agree.public();
    let shared = agree.shared(&sender_x25519)?;
    let key = seal_key(&shared, &sender_x25519, &my_x);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::new("bad aead key"))?;
    let nonce_ga = XNonce::from_slice(&nonce);
    let plaintext = cipher
        .decrypt(
            nonce_ga,
            Payload {
                msg: &ct,
                aad: header,
            },
        )
        .map_err(|_| Error::new("open failed"))?;
    Ok(Envelope {
        suite,
        kind,
        sender_cred_id,
        recipient_cred_id,
        channel_id,
        sender_x25519,
        plaintext,
    })
}

fn envelope_header(
    suite: u16,
    kind: u8,
    sender_cred_id: &[u8; 32],
    recipient_cred_id: &[u8; 32],
    channel_id: &[u8; 32],
    sender_x25519: &[u8; 32],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"WENV");
    w.u16(1);
    w.u16(suite);
    w.u8(kind);
    w.arr32(sender_cred_id);
    w.arr32(recipient_cred_id);
    w.arr32(channel_id);
    w.arr32(sender_x25519);
    w.bytes(nonce);
    w.finish()
}

/// Read the suite field without decrypting. Unknown suites stay visible so
/// callers can reject them instead of guessing.
pub fn peek_suite(bytes: &[u8]) -> Result<u16> {
    let mut r = Reader::new(bytes);
    let magic = r.take(4)?;
    if magic != b"WENV" {
        return Err(Error::new("not an envelope"));
    }
    let _version = r.u16()?;
    r.u16()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_suite_stub() {
        let a = AgreeSecret::generate();
        let b = AgreeSecret::generate();
        let sid = [1u8; 32];
        let rid = [2u8; 32];
        let ch = [3u8; 32];
        let env = seal(
            SUITE_CLASSICAL,
            KIND_EPHEMERAL,
            &a,
            &sid,
            &rid,
            &b.public(),
            &ch,
            b"WIRE-PIXEL-MARKER-v1",
        )
        .unwrap();
        assert!(!env.windows(19).any(|w| w == b"WIRE-PIXEL-MARKER-v1"));
        let opened = open(&b, &rid, &env).unwrap();
        assert_eq!(opened.plaintext, b"WIRE-PIXEL-MARKER-v1");
        assert!(seal(
            SUITE_STUB,
            KIND_EPHEMERAL,
            &a,
            &sid,
            &rid,
            &b.public(),
            &ch,
            b"x"
        )
        .is_err());
        let mut tagged = env.clone();
        tagged[6] = 0;
        tagged[7] = 2;
        assert_eq!(peek_suite(&tagged).unwrap(), SUITE_STUB);
        assert!(open(&b, &rid, &tagged).is_err());
    }

    #[test]
    fn flipped_ciphertext_fails() {
        let a = AgreeSecret::generate();
        let b = AgreeSecret::generate();
        let id = [9u8; 32];
        let mut env = seal(
            SUITE_CLASSICAL,
            KIND_EPHEMERAL,
            &a,
            &id,
            &id,
            &b.public(),
            &id,
            b"payload",
        )
        .unwrap();
        let last = env.len() - 1;
        env[last] ^= 0xff;
        assert!(open(&b, &id, &env).is_err());
    }
}
