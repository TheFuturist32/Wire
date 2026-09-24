mod common;

use std::fs;

use common::{join, log_file, ok, party, Relay, Tmp};

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
