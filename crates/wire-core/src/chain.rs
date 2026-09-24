use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::model::{
    self, parse_id_body, parse_member_add, parse_proposal, Credential, Event, CAP_SPAWN, T_ACCEPT,
    T_ACCEPT_REVERT, T_CRED_REVOKE, T_MEMBER_ADD, T_PROCEED, T_PROPOSE, T_PROPOSE_REVERT,
};

#[derive(Clone)]
pub struct Chain {
    events: Vec<Event>,
    index: HashMap<[u8; 32], usize>,
    children: HashMap<[u8; 32], Vec<[u8; 32]>>,
    forks: Vec<([u8; 32], [u8; 32])>,
    truncated_tip: Option<[u8; 32]>,
}

impl Chain {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            index: HashMap::new(),
            children: HashMap::new(),
            forks: Vec::new(),
            truncated_tip: None,
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn fork_detected(&self) -> bool {
        !self.forks.is_empty() || self.tips().len() > 1
    }

    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.index.contains_key(id)
    }

    pub fn tips(&self) -> Vec<[u8; 32]> {
        self.events
            .iter()
            .map(|e| e.id())
            .filter(|id| self.children.get(id).map(|c| c.is_empty()).unwrap_or(true))
            .collect()
    }

    pub fn sole_tip(&self) -> Result<[u8; 32]> {
        let tips = self.tips();
        if tips.len() == 1 {
            Ok(tips[0])
        } else if tips.is_empty() {
            Err(Error::new("empty chain has no tip"))
        } else {
            Err(Error::new("fork: chain has more than one tip"))
        }
    }

    pub fn append(&mut self, event: Event) -> Result<[u8; 32]> {
        self.insert(event, true, true)
    }

    pub fn insert(&mut self, event: Event, strict_prev: bool, record_fork: bool) -> Result<[u8; 32]> {
        event.verify_sig()?;
        let id = event.id();
        if self.index.contains_key(&id) {
            return Ok(id);
        }
        let prev_known = event.prev == [0u8; 32] || self.index.contains_key(&event.prev);
        if strict_prev && !prev_known {
            return Err(Error::new("event prev is not in this chain"));
        }
        if record_fork {
            if let Some(kids) = self.children.get(&event.prev) {
                if !kids.is_empty() {
                    self.forks.push((kids[0], id));
                }
            }
        }
        self.children.entry(event.prev).or_default().push(id);
        self.index.insert(id, self.events.len());
        self.events.push(event);
        Ok(id)
    }

    pub fn members(&self) -> Result<HashMap<[u8; 32], (Credential, u32)>> {
        let mut out = HashMap::new();
        for event in &self.events {
            if event.typ != T_MEMBER_ADD {
                continue;
            }
            let (cred, caps, _token, _gen) = parse_member_add(&event.body)?;
            if caps & !cred.caps != 0 {
                return Err(Error::new("granted caps exceed credential"));
            }
            out.insert(cred.id(), (cred, caps));
        }
        Ok(out)
    }

    pub fn revoked(&self) -> Result<HashSet<[u8; 32]>> {
        let mut out = HashSet::new();
        for event in &self.events {
            if event.typ == T_CRED_REVOKE {
                out.insert(parse_id_body(&event.body)?);
            }
        }
        Ok(out)
    }

    pub fn screen(&self, event: &Event, now: u64) -> Result<()> {
        event.verify_sig()?;
        let members = self.members()?;
        let revoked = self.revoked()?;
        if revoked.contains(&event.signer_cred_id) {
            return Err(Error::new("credential revoked"));
        }
        if event.typ == T_MEMBER_ADD {
            let (cred, caps, _token, _gen) = parse_member_add(&event.body)?;
            if now >= cred.not_after {
                return Err(Error::new("credential expired"));
            }
            if caps & !cred.caps != 0 {
                return Err(Error::new("granted caps exceed credential"));
            }
            if cred.id() == event.signer_cred_id {
                if cred.ed25519_pub != event.signer_pub {
                    return Err(Error::new("member_add signer key mismatch"));
                }
                return Ok(());
            }
            let (sponsor, scaps) = members
                .get(&event.signer_cred_id)
                .ok_or_else(|| Error::new("sponsor is not a member"))?;
            if sponsor.ed25519_pub != event.signer_pub {
                return Err(Error::new("sponsor key mismatch"));
            }
            if now >= sponsor.not_after {
                return Err(Error::new("credential expired"));
            }
            if scaps & CAP_SPAWN == 0 {
                return Err(Error::new("capability denied"));
            }
            return Ok(());
        }
        let (cred, caps) = members
            .get(&event.signer_cred_id)
            .ok_or_else(|| Error::new("signer is not a member"))?;
        if cred.ed25519_pub != event.signer_pub {
            return Err(Error::new("signer key does not match membership"));
        }
        if now >= cred.not_after {
            return Err(Error::new("credential expired"));
        }
        if revoked.contains(&cred.id()) {
            return Err(Error::new("credential revoked"));
        }
        match model::cap_for_event(event.typ) {
            Some(need) if caps & need != 0 => Ok(()),
            Some(_) => Err(Error::new("capability denied")),
            None => Err(Error::new("unknown event type")),
        }
    }

    pub fn receipt_state(&self, proposal: &[u8; 32]) -> &'static str {
        let mut propose = false;
        let mut accept = false;
        let mut proceed = false;
        let mut prevert = false;
        let mut arevert = false;
        for event in &self.events {
            let matches = match event.typ {
                T_PROPOSE => parse_proposal(&event.body).ok().map(|p| p.0) == Some(*proposal),
                T_ACCEPT | T_PROCEED | T_PROPOSE_REVERT | T_ACCEPT_REVERT => {
                    parse_id_body(&event.body).ok() == Some(*proposal)
                }
                _ => false,
            };
            if !matches {
                continue;
            }
            match event.typ {
                T_PROPOSE => propose = true,
                T_ACCEPT => accept = true,
                T_PROCEED => proceed = true,
                T_PROPOSE_REVERT => prevert = true,
                T_ACCEPT_REVERT => arevert = true,
                _ => {}
            }
        }
        if prevert && arevert {
            "reverted"
        } else if prevert {
            "stuck"
        } else if propose && accept && proceed {
            "final"
        } else if propose {
            "proposed"
        } else {
            "absent"
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(b"WLOG");
        w.u16(1);
        w.u16(if self.truncated_tip.is_some() { 1 } else { 0 });
        if let Some(tip) = self.truncated_tip {
            w.arr32(&tip);
        }
        w.u32(self.events.len() as u32);
        for event in &self.events {
            w.lp(&event.encode());
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(4)?;
        if magic != b"WLOG" {
            return Err(Error::new("not a channel log"));
        }
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::new("bad log version"));
        }
        let flags = r.u16()?;
        let truncated_tip = if flags & 1 == 1 { Some(r.arr32()?) } else { None };
        let n = r.u32()? as usize;
        let mut chain = Chain::new();
        chain.truncated_tip = truncated_tip;
        let strict = truncated_tip.is_none();
        for _ in 0..n {
            let event = Event::decode(r.lp()?)?;
            chain.insert(event, strict, true)?;
        }
        r.finish()?;
        Ok(chain)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.encode())?;
        Ok(())
    }

    /// Rotated archive. Compressed only when the file shrinks.
    pub fn save_cold(&self, path: &Path) -> Result<()> {
        crate::pack::write_cold(path, &self.encode())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        Self::decode(&crate::pack::read_stored(path)?)
    }

    /// Ancestors of `covered_tip` move to the returned archive. The tip, its
    /// descendants, and any fork siblings stay hot so truncation cannot hide a fork.
    pub fn truncate_below(&mut self, covered_tip: [u8; 32]) -> Result<Chain> {
        if !self.index.contains_key(&covered_tip) {
            return Err(Error::new("covered tip is not in the hot log"));
        }
        let old_forks = self.forks.clone();
        let mut archive = Chain::new();
        let mut hot_events = Vec::new();
        for event in &self.events {
            let id = event.id();
            if id != covered_tip && is_ancestor(self, id, covered_tip) {
                archive.insert(event.clone(), true, false)?;
            } else {
                hot_events.push(event.clone());
            }
        }
        let mut hot = Chain::new();
        hot.truncated_tip = Some(covered_tip);
        for event in hot_events {
            hot.insert(event, false, false)?;
        }
        hot.forks = old_forks;
        *self = hot;
        Ok(archive)
    }
}

fn is_ancestor(chain: &Chain, maybe: [u8; 32], desc: [u8; 32]) -> bool {
    let mut cur = desc;
    for _ in 0..10_000 {
        let Some(idx) = chain.index.get(&cur) else {
            return false;
        };
        let prev = chain.events[*idx].prev;
        if prev == maybe {
            return true;
        }
        if prev == [0u8; 32] {
            return false;
        }
        cur = prev;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, RootSecret};
    use crate::model::{
        id_body, proposal_body, RuntimeSecret, CAP_ALL, CAP_APPEND, T_ACCEPT,
    };

    fn signed(
        runtime: &RuntimeSecret,
        channel: [u8; 32],
        prev: [u8; 32],
        typ: u16,
        body: Vec<u8>,
    ) -> Event {
        Event {
            suite: crypto::SUITE_CLASSICAL,
            channel_id: channel,
            prev,
            typ,
            signer_cred_id: runtime.cred_id(),
            signer_pub: runtime.cred.ed25519_pub,
            body,
            sig: [0u8; 64],
        }
        .sign(runtime)
        .unwrap()
    }

    fn genesis(runtime: &RuntimeSecret, channel: [u8; 32]) -> Event {
        let body = model::member_add_body(&runtime.cred, CAP_ALL, &[0u8; 32], 1);
        signed(runtime, channel, [0u8; 32], T_MEMBER_ADD, body)
    }

    #[test]
    fn chain_detects_fork_and_truncates_without_snapshot() {
        let a = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_ALL);
        let b = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_ALL);
        let channel = [1u8; 32];
        let g = genesis(&a, channel);
        let gid = g.id();
        let mut chain = Chain::new();
        chain.append(g).unwrap();
        let p1 = signed(
            &a,
            channel,
            gid,
            T_PROPOSE,
            proposal_body(&[2u8; 32], &[3u8; 32]),
        );
        let p2 = signed(
            &b,
            channel,
            gid,
            T_PROPOSE,
            proposal_body(&[4u8; 32], &[5u8; 32]),
        );
        assert!(chain.screen(&p2, crypto::now_unix()).is_err());
        let join = signed(
            &b,
            channel,
            gid,
            T_MEMBER_ADD,
            model::member_add_body(&b.cred, CAP_ALL, &[9u8; 32], 1),
        );
        chain.append(p1.clone()).unwrap();
        chain.append(join).unwrap();
        assert!(chain.fork_detected());
        let tip = p1.id();
        let archive = chain.truncate_below(tip).unwrap();
        assert!(archive.contains(&gid));
        assert!(chain.contains(&tip));
        assert!(chain.fork_detected());
        let loaded = Chain::decode(&chain.encode()).unwrap();
        assert!(loaded.fork_detected());
        assert!(loaded.contains(&tip));
    }

    #[test]
    fn flipped_log_byte_fails_and_sub_cannot_accept() {
        let a = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_ALL);
        let sub = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_APPEND);
        let channel = [8u8; 32];
        let g = genesis(&a, channel);
        let gid = g.id();
        let mut chain = Chain::new();
        chain.append(g).unwrap();
        let join = signed(
            &sub,
            channel,
            gid,
            T_MEMBER_ADD,
            model::member_add_body(&sub.cred, CAP_APPEND, &[1u8; 32], 1),
        );
        let jid = chain.append(join).unwrap();
        let accept = signed(&sub, channel, jid, T_ACCEPT, id_body(&[2u8; 32]));
        assert!(chain.screen(&accept, crypto::now_unix()).is_err());
        let mut bytes = chain.encode();
        bytes[20] ^= 0xff;
        assert!(Chain::decode(&bytes).is_err());
    }

    #[test]
    fn expired_and_revoked_cannot_append() {
        let root = RootSecret::generate();
        let a = RuntimeSecret::issue(&root, 3600, CAP_ALL);
        let dead = RuntimeSecret::issue(&root, 0, CAP_ALL);
        let channel = [3u8; 32];
        let g = genesis(&a, channel);
        let gid = g.id();
        let mut chain = Chain::new();
        chain.append(g).unwrap();
        let join = signed(
            &dead,
            channel,
            gid,
            T_MEMBER_ADD,
            model::member_add_body(&dead.cred, CAP_ALL, &[1u8; 32], 1),
        );
        assert!(chain.screen(&join, crypto::now_unix()).is_err());
        let b = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_ALL);
        let jb = signed(
            &b,
            channel,
            gid,
            T_MEMBER_ADD,
            model::member_add_body(&b.cred, CAP_ALL, &[1u8; 32], 1),
        );
        let jid = chain.append(jb).unwrap();
        let revoke = signed(&a, channel, jid, T_CRED_REVOKE, id_body(&b.cred_id()));
        chain.screen(&revoke, crypto::now_unix()).unwrap();
        let rid = chain.append(revoke).unwrap();
        let propose = signed(
            &b,
            channel,
            rid,
            T_PROPOSE,
            proposal_body(&[9u8; 32], &[1u8; 32]),
        );
        assert!(chain.screen(&propose, crypto::now_unix()).is_err());
        assert_eq!(chain.receipt_state(&[9u8; 32]), "absent");
    }
}
