#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use wire_core::codec::to_hex;
use wire_core::crypto;

pub struct Tmp {
    path: PathBuf,
}

impl Tmp {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("wire-it-{}", to_hex(&crypto::random32())));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct Relay {
    child: Option<Child>,
    pub addr: String,
    pub data: PathBuf,
}

impl Relay {
    pub fn start(data: &Path) -> Self {
        fs::create_dir_all(data).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_wire-relay"))
            .args(["bind", "127.0.0.1:0", "--data", data.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn relay");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("relay did not print a bind line");
        let addr = line
            .trim()
            .strip_prefix("bound ")
            .unwrap_or_else(|| panic!("unexpected relay line: {line}"))
            .to_string();
        Self {
            child: Some(child),
            addr,
            data: data.to_path_buf(),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Party {
    pub vault: PathBuf,
    pub home: PathBuf,
    pub runtime: PathBuf,
    pub principal: String,
    pub handle: String,
    pub cred: String,
}

pub fn party(tmp: &Path, name: &str, ttl: &str, caps: &str) -> Party {
    let vault = tmp.join(format!("{name}-vault"));
    let home = tmp.join(format!("{name}-home"));
    fs::create_dir_all(&home).unwrap();
    let init = ok(&[
        "vault",
        "init",
        "--path",
        vault.to_str().unwrap(),
    ]);
    let runtime = home.join("runtime.bin");
    let enrolled = ok(&[
        "enroll",
        "--vault",
        vault.to_str().unwrap(),
        "--out",
        runtime.to_str().unwrap(),
        "--ttl",
        ttl,
        "--caps",
        caps,
    ]);
    Party {
        vault,
        home,
        runtime,
        principal: field(&init, "principal"),
        handle: field(&init, "handle"),
        cred: field(&enrolled, "cred"),
    }
}

pub fn join(a: &Party, b: &Party, relay: &str) -> String {
    let invite = a.home.join(format!("invite-{}.bin", to_hex(&crypto::random32())));
    let minted = ok(&[
        "invite",
        "mint",
        "--vault",
        a.vault.to_str().unwrap(),
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--handle",
        &a.handle,
        "--out",
        invite.to_str().unwrap(),
    ]);
    ok(&[
        "invite",
        "accept",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--invite",
        invite.to_str().unwrap(),
        "--relay",
        relay,
    ]);
    ok(&[
        "poll",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--relay",
        relay,
    ]);
    field(&minted, "channel")
}

pub fn node(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wire-node"))
        .args(args)
        .output()
        .expect("spawn wire-node")
}

pub fn ok(args: &[&str]) -> String {
    let out = node(args);
    if !out.status.success() {
        panic!(
            "command failed {args:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn fail(args: &[&str]) -> String {
    let out = node(args);
    assert!(
        !out.status.success(),
        "expected failure {args:?}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn field(text: &str, key: &str) -> String {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key} ")) {
            return rest.trim().to_string();
        }
    }
    panic!("missing {key} in:\n{text}");
}

pub fn log_file(home: &Path, channel_hex: &str) -> PathBuf {
    home.join("channels").join(channel_hex).join("log.bin")
}

pub fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

pub fn file_contains(path: &Path, needle: &[u8]) -> bool {
    fs::read(path)
        .map(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
        .unwrap_or(false)
}

pub const MARKER: &[u8] = b"WIRE-PIXEL-MARKER-v1";

pub fn payload(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        out.extend_from_slice(MARKER);
    }
    out.truncate(size);
    out
}
