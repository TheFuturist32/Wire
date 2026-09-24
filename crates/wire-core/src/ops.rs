use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::chain::Chain;
use crate::codec::{to_hex, Reader, Writer};
use crate::crypto::{self, RootSecret, KIND_EPHEMERAL, KIND_LEDGER, SUITE_CLASSICAL};
use crate::error::{Error, Result};
use crate::model::{
    self, member_add_body, parse_id_body, parse_member_add, parse_proposal, sign_invite, Bundle,
    Credential, Event, Invite, RuntimeSecret, CAP_APPEND, T_ACCEPT, T_ACCEPT_REVERT,
    T_CRED_REVOKE, T_MEMBER_ADD, T_PROCEED, T_PROPOSE, T_PROPOSE_REVERT, T_SHARE,
};
use crate::net;

pub struct VaultOut {
    pub principal: [u8; 32],
    pub handle: String,
}

struct Handles {
    gen: u64,
    current: String,
    retired: Vec<String>,
}

pub fn vault_init(path: &Path) -> Result<VaultOut> {
    let root_path = path.join("root.bin");
    if root_path.exists() {
        return Err(Error::new("vault already exists"));
    }
    fs::create_dir_all(path)?;
    let root = RootSecret::generate();
    fs::write(&root_path, root_bytes(&root))?;
    restrict_user(&root_path)?;
    let handle = to_hex(&crypto::random32()[..16]);
    write_handles(path, &Handles { gen: 1, current: handle.clone(), retired: Vec::new() })?;
    Ok(VaultOut { principal: root.principal_id(), handle })
}

pub fn vault_info(path: &Path) -> Result<VaultOut> {
    let root = load_root(path)?;
    let handles = read_handles(path)?;
    Ok(VaultOut { principal: root.principal_id(), handle: handles.current })
}

pub fn enroll(vault: &Path, ttl_secs: u64, caps: u32) -> Result<RuntimeSecret> {
    let root = load_root(vault)?;
    Ok(RuntimeSecret::issue(&root, ttl_secs, caps))
}

pub fn write_runtime(path: &Path, runtime: &RuntimeSecret) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, runtime.encode())?;
    restrict_user(path)?;
    Ok(())
}

pub fn rotate_handle(vault: &Path) -> Result<VaultOut> {
    let root = load_root(vault)?;
    let mut handles = read_handles(vault)?;
    handles.retired.push(handles.current);
    handles.gen = handles.gen.saturating_add(1);
    handles.current = to_hex(&crypto::random32()[..16]);
    write_handles(vault, &handles)?;
    Ok(VaultOut { principal: root.principal_id(), handle: handles.current })
}

pub fn invite_mint(vault: &Path, runtime_path: &Path, home: &Path, handle: &str) -> Result<([u8; 32], Vec<u8>)> {
    let handles = read_handles(vault)?;
    if handle != handles.current {
        return Err(Error::new("stale handle"));
    }
    let runtime = RuntimeSecret::decode(&fs::read(runtime_path)?)?;
    if runtime.cred.principal_id() != load_root(vault)?.principal_id() {
        return Err(Error::new("runtime is not from this vault"));
    }
    if crypto::now_unix() >= runtime.cred.not_after {
        return Err(Error::new("credential expired"));
    }
    let channel = crypto::random32();
    let token = crypto::random32();
    let body = member_add_body(&runtime.cred, runtime.cred.caps, &[0u8; 32], handles.gen);
    let event = sign_local(&runtime, channel, [0u8; 32], T_MEMBER_ADD, body)?;
    let mut chain = Chain::new();
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event.clone())?;
    chain.save(&log_path(home, &channel))?;
    fs::write(token_path(home, &channel), token)?;
    let invite = sign_invite(
        Invite {
            channel_id: channel,
            handle: handles.current,
            handle_gen: handles.gen,
            expires: crypto::now_unix().saturating_add(86_400),
            token,
            genesis: event,
            sig: [0u8; 64],
        },
        &runtime,
    )?;
    Ok((channel, invite.encode()))
}

pub fn invite_accept(runtime_path: &Path, home: &Path, invite_bytes: &[u8], relay: &str) -> Result<[u8; 32]> {
    let invite = Invite::decode(invite_bytes)?;
    if crypto::now_unix() >= invite.expires {
        return Err(Error::new("invite expired"));
    }
    let runtime = RuntimeSecret::decode(&fs::read(runtime_path)?)?;
    if crypto::now_unix() >= runtime.cred.not_after {
        return Err(Error::new("credential expired"));
    }
    let (inviter, _caps, _tok, _gen) = parse_member_add(&invite.genesis.body)?;
    let mut chain = Chain::new();
    chain.append(invite.genesis.clone())?;
    let body = member_add_body(&runtime.cred, runtime.cred.caps, &invite.token, invite.handle_gen);
    let join = sign_local(&runtime, invite.channel_id, invite.genesis.id(), T_MEMBER_ADD, body)?;
    chain.screen(&join, crypto::now_unix())?;
    chain.append(join.clone())?;
    chain.save(&log_path(home, &invite.channel_id))?;
    seal_push(relay, &runtime, &inviter, &invite.channel_id, &join.encode(), KIND_LEDGER)?;
    Ok(invite.channel_id)
}

pub fn send_frame(runtime_path: &Path, home: &Path, channel: &[u8; 32], payload: &[u8], relay: &str, retain: Option<&Path>) -> Result<()> {
    let runtime = load_runtime(runtime_path)?;
    let chain = Chain::load(&log_path(home, channel))?;
    let members = chain.members()?;
    let (_me, caps) = members.get(&runtime.cred_id()).ok_or_else(|| Error::new("not a member"))?;
    if caps & CAP_APPEND == 0 {
        return Err(Error::new("capability denied"));
    }
    let before = fs::read(log_path(home, channel)).unwrap_or_default();
    for (id, (cred, _)) in &members {
        if id == &runtime.cred_id() {
            continue;
        }
        seal_push(relay, &runtime, cred, channel, &crate::pack::pack_payload(payload), KIND_EPHEMERAL)?;
    }
    if let Some(dir) = retain {
        let file = dir.join(format!("{}.bin", to_hex(&crypto::random32())));
        crate::pack::write_cold(&file, payload)?;
    }
    let after = fs::read(log_path(home, channel)).unwrap_or_default();
    if before != after {
        return Err(Error::new("ephemeral send mutated the channel log"));
    }
    Ok(())
}

pub struct PollOut {
    pub ephemeral: usize,
    pub ledger: usize,
    pub payloads: Vec<Vec<u8>>,
}

pub fn poll(runtime_path: &Path, home: &Path, relay: &str, inbox: Option<&Path>) -> Result<PollOut> {
    let runtime = load_runtime(runtime_path)?;
    let batch = net::pull(relay, &runtime.cred_id())?;
    let mut out = PollOut { ephemeral: 0, ledger: 0, payloads: Vec::new() };
    let mut first_err: Option<Error> = None;
    for (env_id, bytes) in batch {
        match accept_envelope(home, &runtime, &bytes, inbox) {
            Ok(Some(plain)) => {
                out.ephemeral += 1;
                out.payloads.push(plain);
            }
            Ok(None) => {
                out.ledger += 1;
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        net::ack(relay, &runtime.cred_id(), &env_id)?;
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(out)
}

pub fn receipt(runtime_path: &Path, home: &Path, channel: &[u8; 32], action: &str, proposal: Option<[u8; 32]>, content: Option<&[u8]>, relay: &str) -> Result<([u8; 32], [u8; 32])> {
    let runtime = load_runtime(runtime_path)?;
    let typ = match action {
        "propose" => T_PROPOSE,
        "accept" => T_ACCEPT,
        "proceed" => T_PROCEED,
        "propose-revert" => T_PROPOSE_REVERT,
        "accept-revert" => T_ACCEPT_REVERT,
        other => return Err(Error::new(format!("unknown receipt action {other}"))),
    };
    let mut chain = Chain::load(&log_path(home, channel))?;
    if chain.fork_detected() {
        return Err(Error::new("fork: refusing new local event"));
    }
    let proposal = if typ == T_PROPOSE {
        proposal.unwrap_or_else(crypto::random32)
    } else {
        proposal.ok_or_else(|| Error::new("missing proposal"))?
    };
    let content_hash = if typ == T_PROPOSE {
        let bytes = content.ok_or_else(|| Error::new("propose requires content"))?;
        crypto::sha256(bytes)
    } else {
        [0u8; 32]
    };
    if typ != T_PROPOSE && !chain.events().iter().any(|e| e.typ == T_PROPOSE && parse_proposal(&e.body).ok().map(|p| p.0) == Some(proposal)) {
        return Err(Error::new("unknown proposal"));
    }
    if typ == T_PROCEED {
        let accept_ok = chain.events().iter().any(|e| e.typ == T_ACCEPT && parse_id_body(&e.body).ok() == Some(proposal));
        if !accept_ok {
            return Err(Error::new("proceed without accept"));
        }
        let proposer = chain.events().iter().find(|e| e.typ == T_PROPOSE && parse_proposal(&e.body).ok().map(|p| p.0) == Some(proposal));
        if proposer.map(|e| e.signer_cred_id) != Some(runtime.cred_id()) {
            return Err(Error::new("proceed must be signed by the proposer"));
        }
    }
    let body = if typ == T_PROPOSE {
        model::proposal_body(&proposal, &content_hash)
    } else {
        model::id_body(&proposal)
    };
    let prev = chain.sole_tip()?;
    let event = sign_local(&runtime, *channel, prev, typ, body)?;
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event.clone())?;
    chain.save(&log_path(home, channel))?;
    push_to_others(relay, &runtime, &chain, channel, &event.encode(), KIND_LEDGER)?;
    Ok((proposal, content_hash))
}

pub fn receipt_state(home: &Path, channel: &[u8; 32], proposal: &[u8; 32]) -> Result<&'static str> {
    let chain = load_combined(home, channel, true).or_else(|_| Chain::load(&log_path(home, channel)))?;
    Ok(state_of(&chain, proposal))
}

pub fn share_identity(runtime_path: &Path, home: &Path, channel: &[u8; 32], pii: &[u8], relay: &str) -> Result<()> {
    let runtime = load_runtime(runtime_path)?;
    let chain = Chain::load(&log_path(home, channel))?;
    if chain.fork_detected() {
        return Err(Error::new("fork: refusing new local event"));
    }
    let others = others(&chain, &runtime.cred_id())?;
    if others.len() != 1 {
        return Err(Error::new("share_identity expects one counterparty"));
    }
    let sealed = crypto::seal(SUITE_CLASSICAL, KIND_EPHEMERAL, &runtime.agree, &runtime.cred_id(), &others[0].id(), &others[0].x25519_pub, channel, pii)?;
    let prev = chain.sole_tip()?;
    let event = sign_local(&runtime, *channel, prev, T_SHARE, sealed)?;
    let mut chain = chain;
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event.clone())?;
    chain.save(&log_path(home, channel))?;
    push_to_others(relay, &runtime, &chain, channel, &event.encode(), KIND_LEDGER)?;
    Ok(())
}

pub fn show_share(runtime_path: &Path, home: &Path, channel: &[u8; 32]) -> Result<Vec<u8>> {
    let runtime = load_runtime(runtime_path)?;
    let chain = load_combined(home, channel, true).unwrap_or(Chain::load(&log_path(home, channel))?);
    for event in chain.events().iter().rev() {
        if event.typ != T_SHARE {
            continue;
        }
        if let Ok(opened) = crypto::open(&runtime.agree, &runtime.cred_id(), &event.body) {
            return Ok(opened.plaintext);
        }
    }
    Err(Error::new("no share_identity for this runtime"))
}

pub fn member_add(runtime_path: &Path, home: &Path, channel: &[u8; 32], sub: &RuntimeSecret, caps: u32, relay: &str) -> Result<()> {
    let runtime = load_runtime(runtime_path)?;
    let mut chain = Chain::load(&log_path(home, channel))?;
    if chain.fork_detected() {
        return Err(Error::new("fork: refusing new local event"));
    }
    let prev = chain.sole_tip()?;
    let body = member_add_body(&sub.cred, caps, &[0u8; 32], 0);
    let event = sign_local(&runtime, *channel, prev, T_MEMBER_ADD, body)?;
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event.clone())?;
    chain.save(&log_path(home, channel))?;
    for prior in chain.events() {
        seal_push(relay, &runtime, &sub.cred, channel, &prior.encode(), KIND_LEDGER)?;
    }
    push_to_others(relay, &runtime, &chain, channel, &event.encode(), KIND_LEDGER)?;
    Ok(())
}

pub fn cred_revoke(runtime_path: &Path, home: &Path, channel: &[u8; 32], cred_id: &[u8; 32], relay: &str) -> Result<()> {
    let runtime = load_runtime(runtime_path)?;
    let mut chain = Chain::load(&log_path(home, channel))?;
    if chain.fork_detected() {
        return Err(Error::new("fork: refusing new local event"));
    }
    let prev = chain.sole_tip()?;
    let event = sign_local(&runtime, *channel, prev, T_CRED_REVOKE, model::id_body(cred_id))?;
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event.clone())?;
    chain.save(&log_path(home, channel))?;
    push_to_others(relay, &runtime, &chain, channel, &event.encode(), KIND_LEDGER)?;
    Ok(())
}

pub fn truncate(home: &Path, channel: &[u8; 32]) -> Result<()> {
    let path = log_path(home, channel);
    let mut chain = Chain::load(&path)?;
    let tips = chain.tips();
    if tips.is_empty() {
        return Err(Error::new("empty chain"));
    }
    let tip = tips[0];
    let archive = chain.truncate_below(tip)?;
    let arch = archive_path(home, channel);
    if arch.exists() {
        return Err(Error::new("archive already exists"));
    }
    archive.save_cold(&arch)?;
    chain.save(&path)?;
    Ok(())
}

pub fn export_receipt(home: &Path, channel: &[u8; 32], proposal: &[u8; 32]) -> Result<Vec<u8>> {
    let chain = load_combined(home, channel, true)?;
    let mut propose = None;
    let mut accept = None;
    let mut proceed = None;
    for event in chain.events() {
        match event.typ {
            T_PROPOSE => {
                if parse_proposal(&event.body)?.0 == *proposal {
                    propose = Some(event.clone());
                }
            }
            T_ACCEPT => {
                if parse_id_body(&event.body)? == *proposal {
                    accept = Some(event.clone());
                }
            }
            T_PROCEED => {
                if parse_id_body(&event.body)? == *proposal {
                    proceed = Some(event.clone());
                }
            }
            _ => {}
        }
    }
    let propose = propose.ok_or_else(|| Error::new("archive required to verify this receipt"))?;
    let accept = accept.ok_or_else(|| Error::new("archive required to verify this receipt"))?;
    let proceed = proceed.ok_or_else(|| Error::new("archive required to verify this receipt"))?;
    let members = chain.members()?;
    let mut creds = Vec::new();
    for id in [propose.signer_cred_id, accept.signer_cred_id] {
        let (cred, _) = members.get(&id).ok_or_else(|| Error::new("signer cred missing from log"))?;
        if !creds.iter().any(|c: &Credential| c.id() == id) {
            creds.push(cred.clone());
        }
    }
    Ok(Bundle { creds, events: vec![propose, accept, proceed] }.encode())
}

pub fn verify_receipt(bundle: &[u8], content: Option<&[u8]>) -> Result<()> {
    let decoded = Bundle::decode(bundle)?;
    model::verify_bundle(&decoded, content)
}

pub fn explain_channel(home: &Path, channel: &[u8; 32]) -> Result<String> {
    let chain = load_combined(home, channel, true).or_else(|_| Chain::load(&log_path(home, channel)))?;
    Ok(crate::explain::events(chain.events()))
}

pub fn export_merge(home: &Path, channel: &[u8; 32], include_pii: bool) -> Result<String> {
    let chain = load_combined(home, channel, true).or_else(|_| Chain::load(&log_path(home, channel)))?;
    let mut out = String::new();
    for event in chain.events() {
        if event.typ == T_SHARE && !include_pii {
            continue;
        }
        out.push_str(type_name(event.typ));
        out.push('\n');
    }
    Ok(out)
}

pub fn fork_yes(home: &Path, channel: &[u8; 32], peer_log: Option<&Path>) -> Result<bool> {
    let local = Chain::load(&log_path(home, channel))?;
    let mut yes = local.fork_detected();
    if let Some(path) = peer_log {
        yes |= Chain::load(path)?.fork_detected();
    }
    Ok(yes)
}

fn state_of(chain: &Chain, proposal: &[u8; 32]) -> &'static str {
    chain.receipt_state(proposal)
}

fn accept_envelope(home: &Path, runtime: &RuntimeSecret, bytes: &[u8], inbox: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let opened = crypto::open(&runtime.agree, &runtime.cred_id(), bytes)?;
    if opened.kind == KIND_EPHEMERAL {
        let plain = crate::pack::unpack_payload(&opened.plaintext)?;
        if let Some(dir) = inbox {
            fs::create_dir_all(dir)?;
            fs::write(dir.join(format!("{}.bin", to_hex(&crypto::sha256(&plain)))), &plain)?;
        }
        return Ok(Some(plain));
    }
    if opened.kind != KIND_LEDGER {
        return Err(Error::new("unknown envelope kind"));
    }
    let event = Event::decode(&opened.plaintext)?;
    if event.channel_id != opened.channel_id {
        return Err(Error::new("channel mismatch"));
    }
    let path = log_path(home, &event.channel_id);
    let mut chain = Chain::load(&path)?;
    if chain.contains(&event.id()) {
        return Ok(None);
    }
    if event.typ == T_MEMBER_ADD {
        let token_file = token_path(home, &event.channel_id);
        if token_file.exists() {
            let (cred, _caps, token, _gen) = parse_member_add(&event.body)?;
            if cred.id() == event.signer_cred_id && token != [0u8; 32] {
                let expected = fs::read(&token_file)?;
                if expected.as_slice() != &token[..] {
                    return Err(Error::new("invite token rejected"));
                }
                let _ = fs::remove_file(&token_file);
            }
        }
    }
    chain.screen(&event, crypto::now_unix())?;
    chain.append(event)?;
    chain.save(&path)?;
    Ok(None)
}

fn push_to_others(relay: &str, runtime: &RuntimeSecret, chain: &Chain, channel: &[u8; 32], payload: &[u8], kind: u8) -> Result<()> {
    for cred in others(chain, &runtime.cred_id())? {
        seal_push(relay, runtime, &cred, channel, payload, kind)?;
    }
    Ok(())
}

fn others(chain: &Chain, me: &[u8; 32]) -> Result<Vec<Credential>> {
    let mut out = Vec::new();
    for (id, (cred, _)) in chain.members()? {
        if &id != me {
            out.push(cred);
        }
    }
    Ok(out)
}

fn seal_push(relay: &str, from: &RuntimeSecret, to: &Credential, channel: &[u8; 32], payload: &[u8], kind: u8) -> Result<()> {
    let env = crypto::seal(SUITE_CLASSICAL, kind, &from.agree, &from.cred_id(), &to.id(), &to.x25519_pub, channel, payload)?;
    net::push(relay, &from.cred_id(), &to.id(), &crypto::random32(), &env)?;
    Ok(())
}

fn sign_local(runtime: &RuntimeSecret, channel: [u8; 32], prev: [u8; 32], typ: u16, body: Vec<u8>) -> Result<Event> {
    Event {
        suite: SUITE_CLASSICAL,
        channel_id: channel,
        prev,
        typ,
        signer_cred_id: runtime.cred_id(),
        signer_pub: runtime.cred.ed25519_pub,
        body,
        sig: [0u8; 64],
    }
    .sign(runtime)
}

fn load_combined(home: &Path, channel: &[u8; 32], require_link: bool) -> Result<Chain> {
    let mut chain = Chain::new();
    let arch = archive_path(home, channel);
    if arch.exists() {
        for event in Chain::load(&arch)?.events().to_vec() {
            chain.insert(event, true, true)?;
        }
    }
    let hot = Chain::load(&log_path(home, channel))?;
    for event in hot.events().to_vec() {
        chain.insert(event, true, true).map_err(|_| Error::new("archive required to verify this receipt"))?;
    }
    let _ = require_link;
    Ok(chain)
}

fn load_runtime(path: &Path) -> Result<RuntimeSecret> {
    RuntimeSecret::decode(&fs::read(path)?)
}

fn log_path(home: &Path, channel: &[u8; 32]) -> PathBuf {
    home.join("channels").join(to_hex(channel)).join("log.bin")
}

fn archive_path(home: &Path, channel: &[u8; 32]) -> PathBuf {
    home.join("channels").join(to_hex(channel)).join("archive").join("log.bin")
}

fn token_path(home: &Path, channel: &[u8; 32]) -> PathBuf {
    home.join("channels").join(to_hex(channel)).join("token.bin")
}

fn type_name(typ: u16) -> &'static str {
    match typ {
        T_MEMBER_ADD => "member_add",
        T_PROPOSE => "propose",
        T_ACCEPT => "accept",
        T_PROCEED => "proceed",
        T_PROPOSE_REVERT => "propose_revert",
        T_ACCEPT_REVERT => "accept_revert",
        T_SHARE => "share_identity",
        T_CRED_REVOKE => "cred_revoke",
        _ => "event",
    }
}

fn root_bytes(root: &RootSecret) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"WROT");
    w.u16(1);
    w.arr32(&root.to_bytes());
    w.finish()
}

fn load_root(vault: &Path) -> Result<RootSecret> {
    let bytes = fs::read(vault.join("root.bin"))?;
    let mut r = Reader::new(&bytes);
    let magic = r.take(4)?;
    if magic != b"WROT" {
        return Err(Error::new("not a vault"));
    }
    if r.u16()? != 1 {
        return Err(Error::new("bad vault version"));
    }
    let secret = r.arr32()?;
    r.finish()?;
    Ok(RootSecret::from_bytes(&secret))
}

fn write_handles(vault: &Path, handles: &Handles) -> Result<()> {
    let mut w = Writer::new();
    w.bytes(b"WHND");
    w.u16(1);
    w.u64(handles.gen);
    w.lp(handles.current.as_bytes());
    w.u32(handles.retired.len() as u32);
    for item in &handles.retired {
        w.lp(item.as_bytes());
    }
    fs::write(vault.join("handles.bin"), w.finish())?;
    Ok(())
}

fn read_handles(vault: &Path) -> Result<Handles> {
    let bytes = fs::read(vault.join("handles.bin"))?;
    let mut r = Reader::new(&bytes);
    let magic = r.take(4)?;
    if magic != b"WHND" {
        return Err(Error::new("not a handle file"));
    }
    if r.u16()? != 1 {
        return Err(Error::new("bad handle version"));
    }
    let gen = r.u64()?;
    let current = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Error::new("handle utf8"))?;
    let n = r.u32()? as usize;
    let mut retired = Vec::with_capacity(n);
    for _ in 0..n {
        retired.push(String::from_utf8(r.lp()?.to_vec()).map_err(|_| Error::new("handle utf8"))?);
    }
    r.finish()?;
    Ok(Handles { gen, current, retired })
}

fn restrict_user(path: &Path) -> Result<()> {
    let who = Command::new("whoami").output()?;
    if !who.status.success() {
        return Err(Error::new("whoami failed"));
    }
    let user = String::from_utf8_lossy(&who.stdout).trim().to_string();
    let out = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:(R)"))
        .output()?;
    if !out.status.success() {
        return Err(Error::new(format!(
            "icacls failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CAP_ALL, CAP_APPEND};

    #[test]
    fn vault_refuses_overwrite_and_shares_principal() {
        let dir = std::env::temp_dir().join(format!("wire-vault-{}", to_hex(&crypto::random32())));
        let _ = fs::remove_dir_all(&dir);
        let first = vault_init(&dir).unwrap();
        assert!(vault_init(&dir).is_err());
        let a = enroll(&dir, 3600, CAP_ALL).unwrap();
        let b = enroll(&dir, 60, CAP_APPEND).unwrap();
        assert_eq!(a.cred.principal_id(), b.cred.principal_id());
        assert_eq!(a.cred.principal_id(), first.principal);
        assert_ne!(a.cred.runtime_id, b.cred.runtime_id);
        assert_ne!(a.cred.ed25519_pub, load_root(&dir).unwrap().public());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn root_acl_excludes_everyone() {
        let dir = std::env::temp_dir().join(format!("wire-acl-{}", to_hex(&crypto::random32())));
        let _ = fs::remove_dir_all(&dir);
        vault_init(&dir).unwrap();
        let out = Command::new("icacls").arg(dir.join("root.bin")).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        assert!(!text.contains("everyone"), "{text}");
        assert!(!text.contains("authenticated users"), "{text}");
        assert!(!text.contains("builtin\\users"), "{text}");
        let _ = fs::remove_dir_all(&dir);
    }
}
