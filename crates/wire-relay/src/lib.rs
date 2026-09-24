#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use wire_core::codec::to_hex;
use wire_core::metrics::{self, Record, ACK, PUSH};
use wire_core::net::{self, read_frame, write_frame, OP_ACK, OP_PULL, OP_PUSH, ST_ERR, ST_OK};

struct Item {
    envelope: Vec<u8>,
    sender: [u8; 32],
    arrival_ms: u64,
    suite: u16,
    kind: u8,
    channel: [u8; 32],
}

struct State {
    root: PathBuf,
    pending: HashMap<[u8; 32], Vec<([u8; 32], Item)>>,
    metrics: Option<BufWriter<fs::File>>,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.first().map(String::as_str) != Some("bind") || args.len() < 2 {
        return Err("usage: wire-relay bind HOST:PORT --data DIR".into());
    }
    let bind = &args[1];
    let data = flag(args, "--data").ok_or("missing --data")?;
    let metrics = flag(args, "--metrics");
    serve_with(bind, Path::new(&data), metrics.as_deref().map(Path::new))?;
    Ok(())
}

pub fn serve(bind: &str, data: &Path) -> io::Result<()> {
    serve_with(bind, data, None)
}

pub fn serve_with(bind: &str, data: &Path, metrics: Option<&Path>) -> io::Result<()> {
    fs::create_dir_all(data.join("spool"))?;
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    println!("bound {addr}");
    let _ = io::stdout().flush();
    let state = Arc::new(Mutex::new(State {
        root: data.to_path_buf(),
        pending: HashMap::new(),
        metrics: open_metrics(metrics)?,
    }));
    for conn in listener.incoming() {
        let Ok(sock) = conn else { continue };
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let _ = handle(sock, state);
        });
    }
    Ok(())
}

fn handle(mut sock: TcpStream, state: Arc<Mutex<State>>) -> io::Result<()> {
    let req = read_frame(&mut sock).map_err(|e| io::Error::other(e.to_string()))?;
    let resp = {
        let mut guard = state.lock().expect("relay lock");
        dispatch(&mut guard, &req)
    };
    write_frame(&mut sock, &resp).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

fn dispatch(state: &mut State, req: &[u8]) -> Vec<u8> {
    if req.is_empty() {
        return err("empty");
    }
    match req[0] {
        OP_PUSH => push(state, req),
        OP_PULL => pull(state, req),
        OP_ACK => ack(state, req),
        net::OP_LIST => err("no directory"),
        _ => err("no directory"),
    }
}

fn push(state: &mut State, req: &[u8]) -> Vec<u8> {
    if req.len() < 1 + 96 {
        return err("short push");
    }
    let mut sender = [0u8; 32];
    let mut recipient = [0u8; 32];
    let mut env_id = [0u8; 32];
    sender.copy_from_slice(&req[1..33]);
    recipient.copy_from_slice(&req[33..65]);
    env_id.copy_from_slice(&req[65..97]);
    let envelope = req[97..].to_vec();
    if envelope.is_empty() {
        return err("empty envelope");
    }
    let path = spool_path(state, &recipient, &env_id);
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return err("spool mkdir");
        }
    }
    let mut blob = Vec::with_capacity(8 + 64 + envelope.len());
    let arrival = wire_core::crypto::now_unix().to_be_bytes();
    blob.extend_from_slice(&arrival);
    blob.extend_from_slice(&sender);
    blob.extend_from_slice(&recipient);
    blob.extend_from_slice(&envelope);
    if fs::write(&path, &blob).is_err() {
        return err("spool write");
    }
    let arrival_ms = metrics::now_ms();
    let peeked = wire_core::crypto::peek_clear(&envelope).ok();
    let suite = peeked.as_ref().map(|h| h.suite).unwrap_or(0);
    let kind = peeked.as_ref().map(|h| h.kind).unwrap_or(0);
    let channel = peeked.as_ref().map(|h| h.channel_id).unwrap_or([0u8; 32]);
    let cipher_len = envelope.len() as u32;
    if write_metric(
        state,
        &Record {
            tag: PUSH,
            time_ms: arrival_ms,
            sender,
            recipient,
            env_id,
            cipher_len,
            suite,
            kind,
            channel,
        },
    )
    .is_err()
    {
        return err("metrics write");
    }
    state.pending.entry(recipient).or_default().push((
        env_id,
        Item { envelope, sender, arrival_ms, suite, kind, channel },
    ));
    vec![ST_OK]
}

fn pull(state: &State, req: &[u8]) -> Vec<u8> {
    if req.len() != 33 {
        return err("short pull");
    }
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&req[1..33]);
    let items = state.pending.get(&recipient).map(Vec::as_slice).unwrap_or(&[]);
    let mut resp = Vec::new();
    resp.push(ST_OK);
    resp.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for (id, item) in items {
        resp.extend_from_slice(id);
        resp.extend_from_slice(&(item.envelope.len() as u32).to_be_bytes());
        resp.extend_from_slice(&item.envelope);
    }
    resp
}

fn ack(state: &mut State, req: &[u8]) -> Vec<u8> {
    if req.len() != 65 {
        return err("short ack");
    }
    let mut recipient = [0u8; 32];
    let mut env_id = [0u8; 32];
    recipient.copy_from_slice(&req[1..33]);
    env_id.copy_from_slice(&req[33..65]);
    let found = state.pending.get(&recipient).and_then(|queue| {
        queue.iter().find(|(id, _)| id == &env_id).map(|(_, item)| {
            (item.sender, item.arrival_ms, item.suite, item.kind, item.channel, item.envelope.len() as u32)
        })
    });
    if let Some(queue) = state.pending.get_mut(&recipient) {
        queue.retain(|(id, _)| id != &env_id);
        if queue.is_empty() {
            state.pending.remove(&recipient);
        }
    }
    if let Some((sender, _arrival, suite, kind, channel, cipher_len)) = found {
        if write_metric(
            state,
            &Record {
                tag: ACK,
                time_ms: metrics::now_ms(),
                sender,
                recipient,
                env_id,
                cipher_len,
                suite,
                kind,
                channel,
            },
        )
        .is_err()
        {
            return err("metrics write");
        }
    }
    let path = spool_path(state, &recipient, &env_id);
    let _ = fs::remove_file(&path);
    if let Some(parent) = path.parent() {
        if let Ok(mut dir) = fs::read_dir(parent) {
            if dir.next().is_none() {
                let _ = fs::remove_dir(parent);
            }
        }
    }
    vec![ST_OK]
}

fn spool_path(state: &State, recipient: &[u8; 32], env_id: &[u8; 32]) -> PathBuf {
    state
        .root
        .join("spool")
        .join(to_hex(recipient))
        .join(to_hex(env_id))
}

fn err(msg: &str) -> Vec<u8> {
    let mut v = vec![ST_ERR];
    v.extend_from_slice(msg.as_bytes());
    v
}

fn open_metrics(path: Option<&Path>) -> io::Result<Option<BufWriter<fs::File>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).read(true).open(path)?;
    if file.metadata()?.len() == 0 {
        file.write_all(metrics::header().as_bytes())?;
    }
    Ok(Some(BufWriter::new(file)))
}

fn write_metric(state: &mut State, rec: &Record) -> io::Result<()> {
    let Some(out) = state.metrics.as_mut() else {
        return Ok(());
    };
    out.write_all(metrics::format_record(rec).as_bytes())?;
    out.flush()?;
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
