use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::codec::{self, to_hex};
use crate::error::{Error, Result};

pub const PUSH: u8 = 1;
pub const ACK: u8 = 2;

#[derive(Clone)]
pub struct Record {
    pub tag: u8,
    pub time_ms: u64,
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub env_id: [u8; 32],
    pub cipher_len: u32,
    pub suite: u16,
    pub kind: u8,
    pub channel: [u8; 32],
}

pub struct Summary {
    pub ephemeral_transfers: u64,
    pub ephemeral_bytes: u64,
    pub persisted_transfers: u64,
    pub persisted_bytes: u64,
    pub in_flight: u64,
    pub window_ms: u64,
    pub ack_latency_ms_max: u64,
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn header() -> &'static str {
    "wire-metrics 1\n"
}

pub fn format_record(rec: &Record) -> String {
    let tag = if rec.tag == ACK { "ack" } else { "push" };
    format!(
        "{tag} time_ms={} sender={} recipient={} env={} bytes={} suite={} kind={} channel={}\n",
        rec.time_ms,
        to_hex(&rec.sender),
        to_hex(&rec.recipient),
        to_hex(&rec.env_id),
        rec.cipher_len,
        rec.suite,
        rec.kind,
        to_hex(&rec.channel)
    )
}

pub fn read_file(bytes: &[u8]) -> Result<Vec<Record>> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::new("metrics are not utf8"))?;
    let mut lines = text.lines();
    let head = lines.next().unwrap_or("");
    if head != "wire-metrics 1" {
        return Err(Error::new("not a metrics file"));
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        out.push(parse_line(line)?);
    }
    Ok(out)
}

fn parse_line(line: &str) -> Result<Record> {
    let mut parts = line.split_whitespace();
    let tag = match parts.next() {
        Some("push") => PUSH,
        Some("ack") => ACK,
        _ => return Err(Error::new("bad metrics line")),
    };
    let mut time_ms = None;
    let mut sender = None;
    let mut recipient = None;
    let mut env_id = None;
    let mut cipher_len = None;
    let mut suite = None;
    let mut kind = None;
    let mut channel = None;
    for part in parts {
        let (key, value) = part.split_once('=').ok_or_else(|| Error::new("bad metrics field"))?;
        match key {
            "time_ms" => time_ms = Some(value.parse().map_err(|_| Error::new("bad time_ms"))?),
            "sender" => sender = Some(parse_id_hex(value)?),
            "recipient" => recipient = Some(parse_id_hex(value)?),
            "env" => env_id = Some(parse_id_hex(value)?),
            "bytes" => cipher_len = Some(value.parse().map_err(|_| Error::new("bad bytes"))?),
            "suite" => suite = Some(value.parse().map_err(|_| Error::new("bad suite"))?),
            "kind" => kind = Some(value.parse().map_err(|_| Error::new("bad kind"))?),
            "channel" => channel = Some(parse_id_hex(value)?),
            _ => return Err(Error::new("unknown metrics field")),
        }
    }
    Ok(Record {
        tag,
        time_ms: time_ms.ok_or_else(|| Error::new("missing time_ms"))?,
        sender: sender.ok_or_else(|| Error::new("missing sender"))?,
        recipient: recipient.ok_or_else(|| Error::new("missing recipient"))?,
        env_id: env_id.ok_or_else(|| Error::new("missing env"))?,
        cipher_len: cipher_len.ok_or_else(|| Error::new("missing bytes"))?,
        suite: suite.ok_or_else(|| Error::new("missing suite"))?,
        kind: kind.ok_or_else(|| Error::new("missing kind"))?,
        channel: channel.ok_or_else(|| Error::new("missing channel"))?,
    })
}

fn parse_id_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = codec::from_hex(value)?;
    if bytes.len() != 32 {
        return Err(Error::new("bad metrics id"));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

pub fn summarize(records: &[Record]) -> Summary {
    let mut pushes: HashMap<[u8; 32], &Record> = HashMap::new();
    let mut acked = HashMap::new();
    let mut first = u64::MAX;
    let mut last = 0u64;
    for rec in records {
        first = first.min(rec.time_ms);
        last = last.max(rec.time_ms);
        match rec.tag {
            PUSH => {
                pushes.insert(rec.env_id, rec);
            }
            ACK => {
                acked.insert(rec.env_id, rec);
            }
            _ => {}
        }
    }
    let mut summary = Summary {
        ephemeral_transfers: 0,
        ephemeral_bytes: 0,
        persisted_transfers: 0,
        persisted_bytes: 0,
        in_flight: 0,
        window_ms: if records.is_empty() { 0 } else { last.saturating_sub(first) },
        ack_latency_ms_max: 0,
    };
    for (id, push) in &pushes {
        if let Some(ack) = acked.get(id) {
            let latency = ack.time_ms.saturating_sub(push.time_ms);
            summary.ack_latency_ms_max = summary.ack_latency_ms_max.max(latency);
            if push.kind == 1 {
                summary.ephemeral_transfers += 1;
                summary.ephemeral_bytes += push.cipher_len as u64;
            } else if push.kind == 2 {
                summary.persisted_transfers += 1;
                summary.persisted_bytes += push.cipher_len as u64;
            }
        } else {
            summary.in_flight += 1;
        }
    }
    summary
}

pub fn format_summary(summary: &Summary) -> String {
    let window = summary.window_ms;
    let eph_rate = rate(summary.ephemeral_bytes, window);
    let per_rate = rate(summary.persisted_bytes, window);
    format!(
        "ephemeral_transfers {}\nephemeral_bytes {}\nephemeral_bytes_per_sec {}\npersisted_transfers {}\npersisted_bytes {}\npersisted_bytes_per_sec {}\nin_flight {}\nwindow_ms {}\nack_latency_ms_max {}\n",
        summary.ephemeral_transfers,
        summary.ephemeral_bytes,
        eph_rate,
        summary.persisted_transfers,
        summary.persisted_bytes,
        per_rate,
        summary.in_flight,
        window,
        summary.ack_latency_ms_max
    )
}

fn rate(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        0
    } else {
        bytes.saturating_mul(1000) / window_ms
    }
}
