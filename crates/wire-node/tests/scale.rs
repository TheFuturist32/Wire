mod common;

use std::fs;
use std::time::Instant;

use common::{
    field, file_contains, files_under, join, log_file, ok, party, payload, Relay, Tmp, MARKER,
};
use wire_core::codec::parse_id;

#[test]
fn scale_many_channels() {
    let started = Instant::now();
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let mut nodes = Vec::new();
    for i in 0..8 {
        nodes.push(party(tmp.path(), &format!("n{i}"), "1h", "all"));
    }
    let outsider = tmp.path().join("outsider");
    fs::create_dir_all(&outsider).unwrap();

    let mut channels = Vec::new();
    for k in 0..4 {
        for i in 0..8 {
            let a = i;
            let b = (i + 1 + k) % 8;
            let hex = join(&nodes[a], &nodes[b], &relay.addr);
            channels.push((a, b, hex));
        }
    }
    assert_eq!(channels.len(), 32);

    let mut payloads = Vec::new();
    for (n, (_a, _b, channel)) in channels.iter().enumerate() {
        let path = tmp.path().join(format!("pix-{n}.bin"));
        fs::write(&path, payload(256 * 1024)).unwrap();
        ok(&[
            "send-frame",
            "--runtime",
            nodes[*_a].runtime.to_str().unwrap(),
            "--home",
            nodes[*_a].home.to_str().unwrap(),
            "--channel",
            channel,
            "--data-file",
            path.to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
        payloads.push(path);
    }

    let mut spool = Vec::new();
    files_under(&relay.data.join("spool"), &mut spool);
    assert_eq!(spool.len(), 32, "one queued frame per channel");
    for file in &spool {
        assert!(!file_contains(file, MARKER));
    }

    for (_a, b, _channel) in &channels {
        ok(&[
            "poll",
            "--runtime",
            nodes[*b].runtime.to_str().unwrap(),
            "--home",
            nodes[*b].home.to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
    }
    let mut drained = Vec::new();
    files_under(&relay.data.join("spool"), &mut drained);
    assert!(drained.is_empty(), "spool should be empty after ack");

    let mut proposals = Vec::new();
    for (n, (a, b, channel)) in channels.iter().enumerate() {
        let proposed = ok(&[
            "receipt",
            "propose",
            "--runtime",
            nodes[*a].runtime.to_str().unwrap(),
            "--home",
            nodes[*a].home.to_str().unwrap(),
            "--channel",
            channel,
            "--content-file",
            payloads[n].to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
        let proposal = field(&proposed, "proposal");
        ok(&[
            "poll",
            "--runtime",
            nodes[*b].runtime.to_str().unwrap(),
            "--home",
            nodes[*b].home.to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
        ok(&[
            "receipt",
            "accept",
            "--runtime",
            nodes[*b].runtime.to_str().unwrap(),
            "--home",
            nodes[*b].home.to_str().unwrap(),
            "--channel",
            channel,
            "--proposal",
            &proposal,
            "--relay",
            &relay.addr,
        ]);
        ok(&[
            "poll",
            "--runtime",
            nodes[*a].runtime.to_str().unwrap(),
            "--home",
            nodes[*a].home.to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
        ok(&[
            "receipt",
            "proceed",
            "--runtime",
            nodes[*a].runtime.to_str().unwrap(),
            "--home",
            nodes[*a].home.to_str().unwrap(),
            "--channel",
            channel,
            "--proposal",
            &proposal,
            "--relay",
            &relay.addr,
        ]);
        ok(&[
            "poll",
            "--runtime",
            nodes[*b].runtime.to_str().unwrap(),
            "--home",
            nodes[*b].home.to_str().unwrap(),
            "--relay",
            &relay.addr,
        ]);
        let bundle = tmp.path().join(format!("bundle-{n}.bin"));
        ok(&[
            "export-receipt",
            "--home",
            nodes[*a].home.to_str().unwrap(),
            "--channel",
            channel,
            "--proposal",
            &proposal,
            "--out",
            bundle.to_str().unwrap(),
        ]);
        ok(&[
            "verify-receipt",
            "--bundle",
            bundle.to_str().unwrap(),
            "--content-file",
            payloads[n].to_str().unwrap(),
        ]);
        proposals.push(proposal);
    }

    let ids: Vec<[u8; 32]> = channels
        .iter()
        .map(|(_, _, hex)| parse_id(hex).unwrap())
        .collect();
    let mut total = 0u64;
    let mut logs = 0u32;
    for node in &nodes {
        for (idx, id) in ids.iter().enumerate() {
            let path = log_file(&node.home, &channels[idx].2);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            assert!(
                bytes.len() < 4096,
                "{} is {} bytes",
                path.display(),
                bytes.len()
            );
            assert!(bytes.windows(32).any(|w| w == id));
            for other in &ids {
                if other != id {
                    assert!(!bytes.windows(32).any(|w| w == other));
                }
            }
            assert!(!file_contains(&path, MARKER));
            total += bytes.len() as u64;
            logs += 1;
        }
    }
    assert_eq!(logs, 64, "each of 32 channels has two member logs");
    assert!(total < 32 * 4096, "total ledger bytes {total}");
    assert!(!outsider.join("channels").join(&channels[0].2).exists());
    assert!(!tmp.path().join("global.log").exists());
    let ephemeral = 32 * 256 * 1024u64;
    println!(
        "SCALE channels=32 nodes=8 ephemeral_bytes={ephemeral} ledger_bytes={total} log_files={logs} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
