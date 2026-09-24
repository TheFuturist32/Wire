use crate::codec::{to_hex, Reader, Writer};
use crate::crypto::{self, AgreeSecret, RootSecret, SignSecret};
use crate::error::{Error, Result};

pub const CAP_APPEND: u32 = 1 << 0;
pub const CAP_PROPOSE: u32 = 1 << 1;
pub const CAP_ACCEPT: u32 = 1 << 2;
pub const CAP_SPAWN: u32 = 1 << 3;
pub const CAP_ALL: u32 = CAP_APPEND | CAP_PROPOSE | CAP_ACCEPT | CAP_SPAWN;

pub const T_MEMBER_ADD: u16 = 1;
pub const T_MEMBER_CAP: u16 = 2;
pub const T_PROPOSE: u16 = 3;
pub const T_ACCEPT: u16 = 4;
pub const T_PROCEED: u16 = 5;
pub const T_PROPOSE_REVERT: u16 = 6;
pub const T_ACCEPT_REVERT: u16 = 7;
pub const T_SHARE: u16 = 8;
pub const T_SNAPSHOT: u16 = 9;
pub const T_ACK_SNAPSHOT: u16 = 10;
pub const T_HANDLE_ROTATE: u16 = 11;
pub const T_CRED_REVOKE: u16 = 12;

pub fn parse_caps(s: &str) -> Result<u32> {
    if s == "all" {
        return Ok(CAP_ALL);
    }
    let mut caps = 0u32;
    for part in s.split(',') {
        caps |= match part.trim() {
            "append_frame" => CAP_APPEND,
            "propose" => CAP_PROPOSE,
            "accept" => CAP_ACCEPT,
            "spawn_member" => CAP_SPAWN,
            "" => 0,
            other => return Err(Error::new(format!("unknown cap {other}"))),
        };
    }
    if caps == 0 {
        return Err(Error::new("empty caps"));
    }
    Ok(caps)
}

pub fn cap_for_event(typ: u16) -> Option<u32> {
    Some(match typ {
        T_MEMBER_ADD | T_MEMBER_CAP | T_CRED_REVOKE | T_HANDLE_ROTATE => CAP_SPAWN,
        T_PROPOSE | T_PROPOSE_REVERT | T_SHARE | T_SNAPSHOT => CAP_PROPOSE,
        T_ACCEPT | T_ACCEPT_REVERT | T_ACK_SNAPSHOT => CAP_ACCEPT,
        T_PROCEED => CAP_PROPOSE,
        _ => return None,
    })
}

#[derive(Clone)]
pub struct Credential {
    pub root_pub: [u8; 32],
    pub runtime_id: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub caps: u32,
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: [u8; 32],
    pub parent_sig: [u8; 64],
}

impl Credential {
    pub fn canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WCRD");
        w.u16(1);
        w.arr32(&self.root_pub);
        w.arr32(&self.runtime_id);
        w.u64(self.not_before);
        w.u64(self.not_after);
        w.u32(self.caps);
        w.arr32(&self.ed25519_pub);
        w.arr32(&self.x25519_pub);
        w.finish()
    }

    pub fn principal_id(&self) -> [u8; 32] {
        crypto::sha256(&self.root_pub)
    }

    pub fn id(&self) -> [u8; 32] {
        let mut buf = self.canonical();
        buf.extend_from_slice(&self.parent_sig);
        crypto::sha256(&buf)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.canonical();
        buf.extend_from_slice(&self.parent_sig);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WCRD" {
            return Err(Error::new("not a credential"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad credential version"));
        }
        let cred = Self {
            root_pub: r.arr32()?,
            runtime_id: r.arr32()?,
            not_before: r.u64()?,
            not_after: r.u64()?,
            caps: r.u32()?,
            ed25519_pub: r.arr32()?,
            x25519_pub: r.arr32()?,
            parent_sig: r.arr64()?,
        };
        r.finish()?;
        cred.verify_parent()?;
        Ok(cred)
    }

    pub fn verify_parent(&self) -> Result<()> {
        crypto::verify_sig(&self.root_pub, &self.canonical(), &self.parent_sig)
            .map_err(|_| Error::new("credential parent signature rejected"))?;
        if self.principal_id() != crypto::sha256(&self.root_pub) {
            return Err(Error::new("principal id mismatch"));
        }
        Ok(())
    }
}

pub struct RuntimeSecret {
    pub cred: Credential,
    pub sign: SignSecret,
    pub agree: AgreeSecret,
}

impl RuntimeSecret {
    pub fn issue(root: &RootSecret, ttl_secs: u64, caps: u32) -> Self {
        let sign = SignSecret::generate();
        let agree = AgreeSecret::generate();
        let now = crypto::now_unix();
        let not_after = if ttl_secs == 0 {
            0
        } else {
            now.saturating_add(ttl_secs)
        };
        let mut cred = Credential {
            root_pub: root.public(),
            runtime_id: crypto::random32(),
            not_before: now,
            not_after,
            caps,
            ed25519_pub: sign.public(),
            x25519_pub: agree.public(),
            parent_sig: [0u8; 64],
        };
        cred.parent_sig = root.sign(&cred.canonical());
        Self { cred, sign, agree }
    }

    pub fn cred_id(&self) -> [u8; 32] {
        self.cred.id()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WRUN");
        w.u16(1);
        w.arr32(&self.sign.to_bytes());
        w.arr32(&self.agree.to_bytes());
        let cred = self.cred.encode();
        w.lp(&cred);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WRUN" {
            return Err(Error::new("not a runtime file"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad runtime version"));
        }
        let sign_b = r.arr32()?;
        let agree_b = r.arr32()?;
        let cred_bytes = r.lp()?.to_vec();
        r.finish()?;
        let cred = Credential::decode(&cred_bytes)?;
        let sign = SignSecret::from_bytes(&sign_b);
        let agree = AgreeSecret::from_bytes(agree_b);
        if sign.public() != cred.ed25519_pub || agree.public() != cred.x25519_pub {
            return Err(Error::new("runtime secrets do not match credential"));
        }
        Ok(Self { cred, sign, agree })
    }
}

#[derive(Clone)]
pub struct Event {
    pub suite: u16,
    pub channel_id: [u8; 32],
    pub prev: [u8; 32],
    pub typ: u16,
    pub signer_cred_id: [u8; 32],
    pub signer_pub: [u8; 32],
    pub body: Vec<u8>,
    pub sig: [u8; 64],
}

impl Event {
    pub fn canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WEVT");
        w.u16(1);
        w.u16(self.suite);
        w.arr32(&self.channel_id);
        w.arr32(&self.prev);
        w.u16(self.typ);
        w.arr32(&self.signer_cred_id);
        w.arr32(&self.signer_pub);
        w.lp(&self.body);
        w.finish()
    }

    pub fn id(&self) -> [u8; 32] {
        crypto::sha256(&self.canonical())
    }

    pub fn sign(mut self, runtime: &RuntimeSecret) -> Result<Self> {
        crypto::require_suite(self.suite)?;
        if self.signer_pub != runtime.cred.ed25519_pub || self.signer_cred_id != runtime.cred.id() {
            return Err(Error::new("signer does not match runtime"));
        }
        if runtime.cred.ed25519_pub == runtime.cred.root_pub {
            return Err(Error::new("root key cannot sign channel events"));
        }
        self.sig = runtime.sign.sign(&self.canonical());
        Ok(self)
    }

    pub fn verify_sig(&self) -> Result<()> {
        crypto::require_suite(self.suite)?;
        crypto::verify_sig(&self.signer_pub, &self.canonical(), &self.sig)
            .map_err(|_| Error::new("event signature rejected"))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.canonical();
        buf.extend_from_slice(&self.sig);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WEVT" {
            return Err(Error::new("not an event"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad event version"));
        }
        let event = Self {
            suite: r.u16()?,
            channel_id: r.arr32()?,
            prev: r.arr32()?,
            typ: r.u16()?,
            signer_cred_id: r.arr32()?,
            signer_pub: r.arr32()?,
            body: r.lp()?.to_vec(),
            sig: r.arr64()?,
        };
        r.finish()?;
        Ok(event)
    }
}

pub fn member_add_body(cred: &Credential, caps: u32, token: &[u8; 32], handle_gen: u64) -> Vec<u8> {
    let encoded = cred.encode();
    let mut w = Writer::new();
    w.lp(&encoded);
    w.u32(caps);
    w.arr32(token);
    w.u64(handle_gen);
    w.finish()
}

pub fn parse_member_add(body: &[u8]) -> Result<(Credential, u32, [u8; 32], u64)> {
    let mut r = Reader::new(body);
    let cred = Credential::decode(r.lp()?)?;
    let caps = r.u32()?;
    let token = r.arr32()?;
    let gen = r.u64()?;
    r.finish()?;
    Ok((cred, caps, token, gen))
}

pub fn proposal_body(proposal_id: &[u8; 32], content_hash: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.arr32(proposal_id);
    w.arr32(content_hash);
    w.finish()
}

pub fn parse_proposal(body: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut r = Reader::new(body);
    let id = r.arr32()?;
    let hash = r.arr32()?;
    r.finish()?;
    Ok((id, hash))
}

pub fn id_body(id: &[u8; 32]) -> Vec<u8> {
    id.to_vec()
}

pub fn parse_id_body(body: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader::new(body);
    let id = r.arr32()?;
    r.finish()?;
    Ok(id)
}

#[derive(Clone)]
pub struct Invite {
    pub channel_id: [u8; 32],
    pub handle: String,
    pub handle_gen: u64,
    pub expires: u64,
    pub token: [u8; 32],
    pub genesis: Event,
    pub sig: [u8; 64],
}

impl Invite {
    pub fn canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WINV");
        w.u16(1);
        w.arr32(&self.channel_id);
        w.lp(self.handle.as_bytes());
        w.u64(self.handle_gen);
        w.u64(self.expires);
        w.arr32(&self.token);
        w.lp(&self.genesis.encode());
        w.finish()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.canonical();
        buf.extend_from_slice(&self.sig);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WINV" {
            return Err(Error::new("not an invite"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad invite version"));
        }
        let channel_id = r.arr32()?;
        let handle = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Error::new("handle utf8"))?;
        let invite = Self {
            channel_id,
            handle,
            handle_gen: r.u64()?,
            expires: r.u64()?,
            token: r.arr32()?,
            genesis: Event::decode(r.lp()?)?,
            sig: r.arr64()?,
        };
        r.finish()?;
        if invite.genesis.channel_id != invite.channel_id {
            return Err(Error::new("invite channel mismatch"));
        }
        invite.genesis.verify_sig()?;
        crypto::verify_sig(&invite.genesis.signer_pub, &invite.canonical(), &invite.sig)
            .map_err(|_| Error::new("invite signature rejected"))?;
        Ok(invite)
    }
}

pub fn sign_invite(mut invite: Invite, runtime: &RuntimeSecret) -> Result<Invite> {
    invite.sig = runtime.sign.sign(&invite.canonical());
    Ok(invite)
}

#[derive(Clone)]
pub struct Bundle {
    pub creds: Vec<Credential>,
    pub events: Vec<Event>,
}

impl Bundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WRCT");
        w.u16(1);
        w.u32(self.creds.len() as u32);
        for c in &self.creds {
            w.lp(&c.encode());
        }
        w.u32(self.events.len() as u32);
        for e in &self.events {
            w.lp(&e.encode());
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WRCT" {
            return Err(Error::new("not a receipt bundle"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad bundle version"));
        }
        let ncred = r.u32()? as usize;
        let mut creds = Vec::with_capacity(ncred);
        for _ in 0..ncred {
            creds.push(Credential::decode(r.lp()?)?);
        }
        let ne = r.u32()? as usize;
        let mut events = Vec::with_capacity(ne);
        for _ in 0..ne {
            let event = Event::decode(r.lp()?)?;
            event.verify_sig()?;
            events.push(event);
        }
        r.finish()?;
        Ok(Self { creds, events })
    }
}

pub fn verify_bundle(bundle: &Bundle, content: Option<&[u8]>) -> Result<()> {
    if bundle.events.len() != 3 {
        return Err(Error::new("bundle must contain propose, accept, proceed"));
    }
    let mut propose = None;
    let mut accept = None;
    let mut proceed = None;
    for event in &bundle.events {
        let cred = bundle
            .creds
            .iter()
            .find(|c| c.id() == event.signer_cred_id && c.ed25519_pub == event.signer_pub)
            .ok_or_else(|| Error::new("signer credential missing from bundle"))?;
        cred.verify_parent()?;
        match event.typ {
            T_PROPOSE => propose = Some(event),
            T_ACCEPT => accept = Some(event),
            T_PROCEED => proceed = Some(event),
            _ => return Err(Error::new("unexpected event in receipt bundle")),
        }
    }
    let propose = propose.ok_or_else(|| Error::new("missing propose"))?;
    let accept = accept.ok_or_else(|| Error::new("missing accept"))?;
    let proceed = proceed.ok_or_else(|| Error::new("missing proceed"))?;
    let (pid, hash) = parse_proposal(&propose.body)?;
    let ap = parse_id_body(&accept.body)?;
    let pp = parse_id_body(&proceed.body)?;
    if ap != pid || pp != pid {
        return Err(Error::new("proposal id mismatch"));
    }
    if propose.signer_cred_id == accept.signer_cred_id {
        return Err(Error::new("accept must be a second party"));
    }
    if proceed.signer_cred_id != propose.signer_cred_id {
        return Err(Error::new("proceed must be signed by the proposer"));
    }
    if let Some(bytes) = content {
        if crypto::sha256(bytes) != hash {
            return Err(Error::new("content hash mismatch"));
        }
    }
    let _ = to_hex(&pid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_does_not_match_runtime_signer_and_suite_stub_rejected() {
        let root = RootSecret::generate();
        let runtime = RuntimeSecret::issue(&root, 3600, CAP_ALL);
        assert_ne!(runtime.cred.ed25519_pub, root.public());
        let event = Event {
            suite: crypto::SUITE_STUB,
            channel_id: [1u8; 32],
            prev: [0u8; 32],
            typ: T_PROPOSE,
            signer_cred_id: runtime.cred_id(),
            signer_pub: runtime.cred.ed25519_pub,
            body: proposal_body(&[2u8; 32], &[3u8; 32]),
            sig: [0u8; 64],
        };
        assert!(event.sign(&runtime).is_err());
    }

    #[test]
    fn bundle_rejects_mismatched_proposal_and_bad_byte() {
        let root_a = RootSecret::generate();
        let root_b = RootSecret::generate();
        let a = RuntimeSecret::issue(&root_a, 3600, CAP_ALL);
        let b = RuntimeSecret::issue(&root_b, 3600, CAP_ALL);
        let channel = [7u8; 32];
        let proposal = [4u8; 32];
        let content = b"price-10";
        let hash = crypto::sha256(content);
        let propose = Event {
            suite: crypto::SUITE_CLASSICAL,
            channel_id: channel,
            prev: [0u8; 32],
            typ: T_PROPOSE,
            signer_cred_id: a.cred_id(),
            signer_pub: a.cred.ed25519_pub,
            body: proposal_body(&proposal, &hash),
            sig: [0u8; 64],
        }
        .sign(&a)
        .unwrap();
        let accept = Event {
            suite: crypto::SUITE_CLASSICAL,
            channel_id: channel,
            prev: propose.id(),
            typ: T_ACCEPT,
            signer_cred_id: b.cred_id(),
            signer_pub: b.cred.ed25519_pub,
            body: id_body(&proposal),
            sig: [0u8; 64],
        }
        .sign(&b)
        .unwrap();
        let proceed = Event {
            suite: crypto::SUITE_CLASSICAL,
            channel_id: channel,
            prev: accept.id(),
            typ: T_PROCEED,
            signer_cred_id: a.cred_id(),
            signer_pub: a.cred.ed25519_pub,
            body: id_body(&proposal),
            sig: [0u8; 64],
        }
        .sign(&a)
        .unwrap();
        let bundle = Bundle {
            creds: vec![a.cred.clone(), b.cred.clone()],
            events: vec![propose.clone(), accept.clone(), proceed.clone()],
        };
        verify_bundle(&bundle, Some(content)).unwrap();
        assert!(verify_bundle(&bundle, Some(b"other")).is_err());
        let mut bad = accept.clone();
        bad.body = id_body(&[9u8; 32]);
        bad = bad.sign(&b).unwrap();
        let mismatched = Bundle {
            creds: bundle.creds.clone(),
            events: vec![propose, bad, proceed],
        };
        assert!(verify_bundle(&mismatched, Some(content)).is_err());
        let mut bytes = bundle.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x5a;
        assert!(Bundle::decode(&bytes).is_err());
    }
}
