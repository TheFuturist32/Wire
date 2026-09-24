#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use wire_core::codec::{parse_id, to_hex};
use wire_core::error::Error;
use wire_core::model::{self, RuntimeSecret};
use wire_core::ops;

mod serve;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(e) = dispatch(&args) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn dispatch(args: &[String]) -> Result<(), Error> {
    match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(args),
        Some("vault") => cmd_vault(args),
        Some("enroll") => cmd_enroll(args),
        Some("handle") => cmd_handle(args),
        Some("invite") => cmd_invite(args),
        Some("send-frame") => cmd_send(args),
        Some("poll") => cmd_poll(args),
        Some("receipt") => cmd_receipt(args),
        Some("share-identity") => cmd_share(args),
        Some("show-share") => cmd_show_share(args),
        Some("member-add") => cmd_member(args),
        Some("cred") => cmd_revoke(args),
        Some("compact") => cmd_truncate(args),
        Some("export-receipt") => cmd_export(args),
        Some("verify-receipt") => cmd_verify(args),
        Some("export-merge") => cmd_merge(args),
        Some("fork-status") => cmd_fork(args),
        Some("talk") => cmd_talk(args),
        Some("explain-talk") => cmd_explain_talk(args),
        Some("explain-log") => cmd_explain_log(args),
        _ => Err(Error::new("unknown command")),
    }
}

fn cmd_serve(args: &[String]) -> Result<(), Error> {
    let policy = optional(args, "policy");
    serve::run(
        Path::new(&require(args, "vault")?),
        Path::new(&require(args, "home")?),
        &require(args, "relay")?,
        policy.as_deref().map(Path::new),
    )
}

fn cmd_vault(args: &[String]) -> Result<(), Error> {
    if args.get(1).map(String::as_str) != Some("init") {
        return Err(Error::new("usage: vault init --path PATH"));
    }
    let out = ops::vault_init(Path::new(&require(args, "path")?))?;
    println!("principal {}", to_hex(&out.principal));
    println!("handle {}", out.handle);
    println!("ok");
    Ok(())
}

fn cmd_enroll(args: &[String]) -> Result<(), Error> {
    let ttl = parse_ttl(&require(args, "ttl")?)?;
    let caps = model::parse_caps(&optional(args, "caps").unwrap_or_else(|| "all".into()))?;
    let runtime = ops::enroll(Path::new(&require(args, "vault")?), ttl, caps)?;
    ops::write_runtime(Path::new(&require(args, "out")?), &runtime)?;
    println!("principal {}", to_hex(&runtime.cred.principal_id()));
    println!("runtime {}", to_hex(&runtime.cred.runtime_id));
    println!("cred {}", to_hex(&runtime.cred_id()));
    println!("ok");
    Ok(())
}

fn cmd_handle(args: &[String]) -> Result<(), Error> {
    if args.get(1).map(String::as_str) != Some("rotate") {
        return Err(Error::new("usage: handle rotate --vault PATH"));
    }
    let out = ops::rotate_handle(Path::new(&require(args, "vault")?))?;
    println!("principal {}", to_hex(&out.principal));
    println!("handle {}", out.handle);
    println!("ok");
    Ok(())
}

fn cmd_invite(args: &[String]) -> Result<(), Error> {
    match args.get(1).map(String::as_str) {
        Some("mint") => {
            let (channel, bytes) = ops::invite_mint(
                Path::new(&require(args, "vault")?),
                Path::new(&require(args, "runtime")?),
                Path::new(&require(args, "home")?),
                &require(args, "handle")?,
            )?;
            fs::write(require(args, "out")?, bytes)?;
            println!("channel {}", to_hex(&channel));
            println!("ok");
            Ok(())
        }
        Some("accept") => {
            let bytes = fs::read(require(args, "invite")?)?;
            let channel = ops::invite_accept(
                Path::new(&require(args, "runtime")?),
                Path::new(&require(args, "home")?),
                &bytes,
                &require(args, "relay")?,
            )?;
            println!("channel {}", to_hex(&channel));
            println!("ok");
            Ok(())
        }
        _ => Err(Error::new("usage: invite mint|accept")),
    }
}

fn cmd_send(args: &[String]) -> Result<(), Error> {
    let payload = fs::read(require(args, "data-file")?)?;
    let retain = optional(args, "retain");
    ops::send_frame(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        &payload,
        &require(args, "relay")?,
        retain.as_deref().map(Path::new),
    )?;
    println!("ok");
    Ok(())
}

fn cmd_poll(args: &[String]) -> Result<(), Error> {
    let inbox = optional(args, "inbox");
    let stats = ops::poll(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &require(args, "relay")?,
        inbox.as_deref().map(Path::new),
    )?;
    println!("ephemeral {}", stats.ephemeral);
    println!("ledger {}", stats.ledger);
    println!("ok");
    Ok(())
}

fn cmd_receipt(args: &[String]) -> Result<(), Error> {
    let action = args.get(1).ok_or_else(|| Error::new("missing receipt action"))?;
    let home = require(args, "home")?;
    let channel = parse_id(&require(args, "channel")?)?;
    if action == "status" {
        let proposal = parse_id(&require(args, "proposal")?)?;
        let state = ops::receipt_state(Path::new(&home), &channel, &proposal)?;
        println!("receipt {state}");
        println!("ok");
        return Ok(());
    }
    let proposal = optional(args, "proposal").map(|s| parse_id(&s)).transpose()?;
    let content = match optional(args, "content-file") {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    let (id, hash) = ops::receipt(
        Path::new(&require(args, "runtime")?),
        Path::new(&home),
        &channel,
        action,
        proposal,
        content.as_deref(),
        &require(args, "relay")?,
    )?;
    println!("proposal {}", to_hex(&id));
    println!("content {}", to_hex(&hash));
    println!("ok");
    Ok(())
}

fn cmd_share(args: &[String]) -> Result<(), Error> {
    let pii = fs::read(require(args, "file")?)?;
    ops::share_identity(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        &pii,
        &require(args, "relay")?,
    )?;
    println!("ok");
    Ok(())
}

fn cmd_show_share(args: &[String]) -> Result<(), Error> {
    let bytes = ops::show_share(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
    )?;
    fs::write(require(args, "out")?, bytes)?;
    println!("ok");
    Ok(())
}

fn cmd_member(args: &[String]) -> Result<(), Error> {
    let sub = RuntimeSecret::decode(&fs::read(require(args, "cred")?)?)?;
    let caps = model::parse_caps(&require(args, "caps")?)?;
    ops::member_add(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        &sub,
        caps,
        &require(args, "relay")?,
    )?;
    println!("ok");
    Ok(())
}

fn cmd_revoke(args: &[String]) -> Result<(), Error> {
    if args.get(1).map(String::as_str) != Some("revoke") {
        return Err(Error::new("usage: cred revoke ..."));
    }
    ops::cred_revoke(
        Path::new(&require(args, "runtime")?),
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        &parse_id(&require(args, "cred")?)?,
        &require(args, "relay")?,
    )?;
    println!("ok");
    Ok(())
}

fn cmd_truncate(args: &[String]) -> Result<(), Error> {
    if args.get(1).map(String::as_str) != Some("truncate-below") {
        return Err(Error::new("usage: compact truncate-below --home H --channel C"));
    }
    ops::truncate(Path::new(&require(args, "home")?), &parse_id(&require(args, "channel")?)?)?;
    println!("ok");
    Ok(())
}

fn cmd_export(args: &[String]) -> Result<(), Error> {
    let bytes = ops::export_receipt(
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        &parse_id(&require(args, "proposal")?)?,
    )?;
    fs::write(require(args, "out")?, bytes)?;
    println!("ok");
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), Error> {
    let bundle = fs::read(require(args, "bundle")?)?;
    let content = match optional(args, "content-file") {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    ops::verify_receipt(&bundle, content.as_deref())?;
    println!("ok");
    Ok(())
}

fn cmd_merge(args: &[String]) -> Result<(), Error> {
    let include = require(args, "include-pii")? == "true";
    let text = ops::export_merge(
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        include,
    )?;
    fs::write(require(args, "out")?, text)?;
    println!("ok");
    Ok(())
}

fn cmd_fork(args: &[String]) -> Result<(), Error> {
    let peer = optional(args, "peer-log");
    let yes = ops::fork_yes(
        Path::new(&require(args, "home")?),
        &parse_id(&require(args, "channel")?)?,
        peer.as_deref().map(Path::new),
    )?;
    println!("fork {}", if yes { "yes" } else { "no" });
    println!("ok");
    Ok(())
}

fn cmd_talk(args: &[String]) -> Result<(), Error> {
    let kind = args.get(1).ok_or_else(|| Error::new("usage: talk say|offer|counter|agree|blob-ref"))?;
    let talk = match kind.as_str() {
        "say" => wire_core::talk::Talk::Say(require(args, "text")?),
        "offer" | "counter" => {
            let minor: u32 = require(args, "minor")?.parse().map_err(|_| Error::new("bad minor"))?;
            let currency: u16 = require(args, "currency")?.parse().map_err(|_| Error::new("bad currency"))?;
            let terms = wire_core::talk::hash_bytes(&fs::read(require(args, "terms-file")?)?);
            if kind == "offer" {
                wire_core::talk::Talk::Offer { minor, currency, terms }
            } else {
                wire_core::talk::Talk::Counter { minor, currency, terms }
            }
        }
        "agree" => wire_core::talk::Talk::Agree {
            terms: wire_core::talk::hash_bytes(&fs::read(require(args, "terms-file")?)?),
        },
        "blob-ref" => {
            let size: u32 = require(args, "size")?.parse().map_err(|_| Error::new("bad size"))?;
            let hash = wire_core::talk::hash_bytes(&fs::read(require(args, "data-file")?)?);
            wire_core::talk::Talk::BlobRef { size, hash }
        }
        _ => return Err(Error::new("unknown talk kind")),
    };
    let bytes = talk.encode();
    fs::write(require(args, "out")?, &bytes)?;
    println!("bytes {}", bytes.len());
    println!("ok");
    Ok(())
}

fn cmd_explain_talk(args: &[String]) -> Result<(), Error> {
    let bytes = fs::read(require(args, "data-file")?)?;
    let talk = wire_core::talk::Talk::decode(&bytes)?;
    println!("{}", wire_core::talk::to_text(&talk));
    println!("ok");
    Ok(())
}

fn cmd_explain_log(args: &[String]) -> Result<(), Error> {
    let text = ops::explain_channel(Path::new(&require(args, "home")?), &parse_id(&require(args, "channel")?)?)?;
    print!("{text}");
    println!("ok");
    Ok(())
}

fn require(args: &[String], name: &str) -> Result<String, Error> {
    optional(args, name).ok_or_else(|| Error::new(format!("missing --{name}")))
}

fn optional(args: &[String], name: &str) -> Option<String> {
    let key = format!("--{name}");
    args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
}

fn parse_ttl(s: &str) -> Result<u64, Error> {
    let (num, mul) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num.parse().map_err(|_| Error::new("bad ttl"))?;
    Ok(n.saturating_mul(mul))
}
