mod common;

use std::fs;

use common::{field, file_contains, join, log_file, ok, party, payload, Relay, Tmp, MARKER};

#[test]
fn metrics_count_transfers_without_plaintext() {
    let tmp = Tmp::new();
    let metrics = tmp.path().join("metrics.bin");
    let relay = Relay::start_metrics(&tmp.path().join("relay"), &metrics);
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let data = tmp.path().join("offer.bin");
    fs::write(&data, payload(8192)).unwrap();
    ok(&[
        "send-frame",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--data-file",
        data.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let raw = fs::read_to_string(&metrics).unwrap();
    assert!(raw.starts_with("wire-metrics 1\n"), "{raw}");
    assert!(raw.contains(" kind=1 "), "{raw}");
    assert!(!file_contains(&metrics, MARKER));
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let report = ok(&["metrics", "--file", metrics.to_str().unwrap()]);
    assert!(report.contains("ephemeral_transfers 1\n"), "{report}");
    assert!(report.contains("in_flight 0\n"), "{report}");
    let bytes: u64 = field(&report, "ephemeral_bytes").parse().unwrap();
    assert!(bytes > 0 && bytes < 8192, "repetitive payload should shrink on the wire, got {bytes}");
    assert!(!report.contains("WIRE-PIXEL"));
    assert!(!file_contains(&log_file(&a.home, &channel), MARKER));
}

#[test]
fn explain_talk_and_log_are_views() {
    let tmp = Tmp::new();
    let terms = tmp.path().join("terms.bin");
    fs::write(&terms, b"net-30").unwrap();
    let offer = tmp.path().join("offer.talk");
    let encoded = ok(&[
        "talk",
        "offer",
        "--minor",
        "1000",
        "--currency",
        "840",
        "--terms-file",
        terms.to_str().unwrap(),
        "--out",
        offer.to_str().unwrap(),
    ]);
    assert!(encoded.contains("bytes 39"));
    let stored = fs::read(&offer).unwrap();
    assert!(!stored.windows(3).any(|w| w == b"USD"));
    let text = ok(&["explain-talk", "--data-file", offer.to_str().unwrap()]);
    assert!(text.starts_with("offer 10.00 USD terms sha256:"), "{text}");

    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    ok(&[
        "receipt",
        "propose",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--content-file",
        terms.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let explained = ok(&[
        "explain-log",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
    ]);
    assert!(explained.contains("member_add cred "), "{explained}");
    assert!(explained.contains("propose proposal "), "{explained}");
    let before = fs::read(log_file(&a.home, &channel)).unwrap();
    let _ = ok(&["explain-log", "--home", a.home.to_str().unwrap(), "--channel", &channel]);
    assert_eq!(fs::read(log_file(&a.home, &channel)).unwrap(), before);
}
