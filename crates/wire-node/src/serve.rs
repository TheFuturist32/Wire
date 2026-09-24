use std::fs;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use wire_core::codec::{parse_id, to_hex};
use wire_core::crypto;
use wire_core::error::Error;
use wire_core::model::{self, RuntimeSecret};
use wire_core::net::{read_frame, write_frame};
use wire_core::ops;
use wire_core::plugin::{decode_request, encode_reply};

struct Policy {
    max_frame_bytes: usize,
    confirm: Vec<String>,
}

struct Ctx {
    vault: PathBuf,
    home: PathBuf,
    relay: String,
    policy: Policy,
}

pub fn run(
    vault: &Path,
    home: &Path,
    relay: &str,
    policy_path: Option<&Path>,
) -> Result<(), Error> {
    fs::create_dir_all(home)?;
    let info = if vault.join("root.bin").exists() {
        ops::vault_info(vault)?
    } else {
        ops::vault_init(vault)?
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    println!("bound {addr}");
    println!("principal {}", to_hex(&info.principal));
    println!("handle {}", info.handle);
    let _ = io::stdout().flush();
    let ctx = Arc::new(Mutex::new(Ctx {
        vault: vault.to_path_buf(),
        home: home.to_path_buf(),
        relay: relay.to_string(),
        policy: load_policy(policy_path)?,
    }));
    for conn in listener.incoming() {
        let Ok(sock) = conn else { continue };
        let ctx = Arc::clone(&ctx);
        thread::spawn(move || {
            let _ = handle_conn(sock, ctx);
        });
    }
    Ok(())
}

fn handle_conn(mut sock: TcpStream, ctx: Arc<Mutex<Ctx>>) -> Result<(), Error> {
    let _ = sock.set_nodelay(true);
    let timeout = Some(Duration::from_secs(30));
    let _ = sock.set_read_timeout(timeout);
    let _ = sock.set_write_timeout(timeout);
    let req = read_frame(&mut sock)?;
    let (args, blobs) = decode_request(&req)?;
    let reply = {
        let guard = ctx.lock().map_err(|_| Error::new("plugin lock"))?;
        match dispatch(&guard, &args, &blobs) {
            Ok((text, blobs)) => encode_reply(true, &text, &blobs),
            Err(e) => encode_reply(false, &e.to_string(), &[]),
        }
    };
    write_frame(&mut sock, &reply)?;
    Ok(())
}

fn dispatch(
    ctx: &Ctx,
    args: &[String],
    blobs: &[Vec<u8>],
) -> Result<(String, Vec<Vec<u8>>), Error> {
    match args.first().map(String::as_str) {
        Some("enroll") => enroll(ctx, args),
        Some("invite") => invite(ctx, args, blobs),
        Some("send-frame") => send_frame(ctx, args, blobs),
        Some("poll") => poll(ctx, args),
        Some("receipt") => receipt(ctx, args, blobs),
        Some("share-identity") => share(ctx, args, blobs),
        Some("show-share") => show_share(ctx, args),
        Some("export-receipt") => export_receipt(ctx, args),
        Some("verify-receipt") => verify(blobs),
        Some("handle") => rotate(ctx, args),
        _ => Err(Error::new("unknown plugin command")),
    }
}

fn enroll(ctx: &Ctx, args: &[String]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let name = require_name(args)?;
    let path = runtime_path(&ctx.home, &name);
    if path.exists() {
        let existing = RuntimeSecret::decode(&fs::read(&path)?)?;
        if crypto::now_unix() < existing.cred.not_after {
            return Ok((runtime_text(&existing), Vec::new()));
        }
    }
    let ttl = parse_ttl(&require(args, "ttl")?)?;
    let caps = model::parse_caps(&optional(args, "caps").unwrap_or_else(|| "all".into()))?;
    let runtime = ops::enroll(&ctx.vault, ttl, caps)?;
    ops::write_runtime(&path, &runtime)?;
    Ok((runtime_text(&runtime), Vec::new()))
}

fn invite(ctx: &Ctx, args: &[String], blobs: &[Vec<u8>]) -> Result<(String, Vec<Vec<u8>>), Error> {
    match args.get(1).map(String::as_str) {
        Some("mint") => {
            let name = require_name(args)?;
            let info = ops::vault_info(&ctx.vault)?;
            let (channel, bytes) = ops::invite_mint(
                &ctx.vault,
                &runtime_path(&ctx.home, &name),
                &ctx.home,
                &info.handle,
            )?;
            Ok((format!("channel {}\nok\n", to_hex(&channel)), vec![bytes]))
        }
        Some("accept") => {
            let name = require_name(args)?;
            let invite = blobs
                .first()
                .ok_or_else(|| Error::new("missing invite blob"))?;
            let channel = ops::invite_accept(
                &runtime_path(&ctx.home, &name),
                &ctx.home,
                invite,
                &ctx.relay,
            )?;
            Ok((format!("channel {}\nok\n", to_hex(&channel)), Vec::new()))
        }
        _ => Err(Error::new("usage: invite mint|accept")),
    }
}

fn send_frame(
    ctx: &Ctx,
    args: &[String],
    blobs: &[Vec<u8>],
) -> Result<(String, Vec<Vec<u8>>), Error> {
    let name = require_name(args)?;
    let channel = parse_id(&require(args, "channel")?)?;
    let payload = blobs
        .first()
        .ok_or_else(|| Error::new("missing payload blob"))?;
    if payload.len() > ctx.policy.max_frame_bytes {
        return Err(Error::new("payload exceeds max_frame_bytes"));
    }
    ops::send_frame(
        &runtime_path(&ctx.home, &name),
        &ctx.home,
        &channel,
        payload,
        &ctx.relay,
        None,
    )?;
    Ok(("ok\n".into(), Vec::new()))
}

fn poll(ctx: &Ctx, args: &[String]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let name = require_name(args)?;
    let stats = ops::poll(&runtime_path(&ctx.home, &name), &ctx.home, &ctx.relay, None)?;
    let text = format!(
        "ephemeral {}\nledger {}\nok\n",
        stats.ephemeral, stats.ledger
    );
    Ok((text, stats.payloads))
}

fn receipt(ctx: &Ctx, args: &[String], blobs: &[Vec<u8>]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let action = args
        .get(1)
        .ok_or_else(|| Error::new("missing receipt action"))?;
    let name = require_name(args)?;
    let channel = parse_id(&require(args, "channel")?)?;
    if action == "status" {
        let proposal = parse_id(&require(args, "proposal")?)?;
        let state = ops::receipt_state(&ctx.home, &channel, &proposal)?;
        return Ok((format!("receipt {state}\nok\n"), Vec::new()));
    }
    let gate = match action.as_str() {
        "proceed" => Some("receipt-proceed"),
        "propose-revert" => Some("receipt-propose-revert"),
        "accept" => Some("receipt-accept"),
        _ => None,
    };
    if let Some(gate) = gate {
        require_confirm(ctx, args, gate)?;
    }
    let proposal = optional(args, "proposal")
        .map(|s| parse_id(&s))
        .transpose()?;
    let content = if action == "propose" {
        Some(
            blobs
                .first()
                .ok_or_else(|| Error::new("missing content blob"))?
                .as_slice(),
        )
    } else {
        None
    };
    let (id, hash) = ops::receipt(
        &runtime_path(&ctx.home, &name),
        &ctx.home,
        &channel,
        action,
        proposal,
        content,
        &ctx.relay,
    )?;
    Ok((
        format!("proposal {}\ncontent {}\nok\n", to_hex(&id), to_hex(&hash)),
        Vec::new(),
    ))
}

fn share(ctx: &Ctx, args: &[String], blobs: &[Vec<u8>]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let name = require_name(args)?;
    let channel = parse_id(&require(args, "channel")?)?;
    let pii = blobs
        .first()
        .ok_or_else(|| Error::new("missing identity blob"))?;
    require_confirm(ctx, args, "share-identity")?;
    ops::share_identity(
        &runtime_path(&ctx.home, &name),
        &ctx.home,
        &channel,
        pii,
        &ctx.relay,
    )?;
    Ok(("ok\n".into(), Vec::new()))
}

fn show_share(ctx: &Ctx, args: &[String]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let name = require_name(args)?;
    let channel = parse_id(&require(args, "channel")?)?;
    let plain = ops::show_share(&runtime_path(&ctx.home, &name), &ctx.home, &channel)?;
    Ok(("ok\n".into(), vec![plain]))
}

fn export_receipt(ctx: &Ctx, args: &[String]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let channel = parse_id(&require(args, "channel")?)?;
    let proposal = parse_id(&require(args, "proposal")?)?;
    let bundle = ops::export_receipt(&ctx.home, &channel, &proposal)?;
    Ok(("ok\n".into(), vec![bundle]))
}

fn verify(blobs: &[Vec<u8>]) -> Result<(String, Vec<Vec<u8>>), Error> {
    let bundle = blobs
        .first()
        .ok_or_else(|| Error::new("missing bundle blob"))?;
    let content = blobs.get(1).map(Vec::as_slice);
    ops::verify_receipt(bundle, content)?;
    Ok(("ok\n".into(), Vec::new()))
}

fn rotate(ctx: &Ctx, args: &[String]) -> Result<(String, Vec<Vec<u8>>), Error> {
    if args.get(1).map(String::as_str) != Some("rotate") {
        return Err(Error::new("usage: handle rotate"));
    }
    let out = ops::rotate_handle(&ctx.vault)?;
    Ok((
        format!(
            "principal {}\nhandle {}\nok\n",
            to_hex(&out.principal),
            out.handle
        ),
        Vec::new(),
    ))
}

fn require_confirm(ctx: &Ctx, args: &[String], gate: &str) -> Result<(), Error> {
    if !ctx.policy.confirm.iter().any(|item| item == gate) {
        return Ok(());
    }
    let given = optional(args, "confirm").ok_or_else(|| Error::new("confirm required"))?;
    let path = ctx.vault.join("confirm.token");
    let expected = fs::read_to_string(&path).map_err(|_| Error::new("confirm token missing"))?;
    if given.trim() != expected.trim() {
        return Err(Error::new("confirm rejected"));
    }
    Ok(())
}

fn load_policy(path: Option<&Path>) -> Result<Policy, Error> {
    let mut policy = Policy {
        max_frame_bytes: 4 * 1024 * 1024,
        confirm: Vec::new(),
    };
    let Some(path) = path else {
        return Ok(policy);
    };
    let text = fs::read_to_string(path)?;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().ok_or_else(|| Error::new("bad policy line"))?;
        let value = parts
            .next()
            .ok_or_else(|| Error::new(format!("bad policy line {line}")))?;
        if parts.next().is_some() {
            return Err(Error::new(format!("bad policy line {line}")));
        }
        match key {
            "max_frame_bytes" => {
                policy.max_frame_bytes = value
                    .parse()
                    .map_err(|_| Error::new("bad max_frame_bytes"))?;
            }
            "confirm" => match value {
                "share-identity"
                | "receipt-proceed"
                | "receipt-propose-revert"
                | "receipt-accept" => {
                    policy.confirm.push(value.to_string());
                }
                _ => return Err(Error::new(format!("unknown confirm gate {value}"))),
            },
            _ => return Err(Error::new(format!("unknown policy key {key}"))),
        }
    }
    Ok(policy)
}

fn runtime_text(runtime: &RuntimeSecret) -> String {
    format!(
        "principal {}\nruntime {}\ncred {}\nok\n",
        to_hex(&runtime.cred.principal_id()),
        to_hex(&runtime.cred.runtime_id),
        to_hex(&runtime.cred_id())
    )
}

fn runtime_path(home: &Path, name: &str) -> PathBuf {
    home.join("runtimes").join(format!("{name}.bin"))
}

fn require_name(args: &[String]) -> Result<String, Error> {
    let name = require(args, "name")?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::new("bad runtime name"));
    }
    Ok(name)
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
