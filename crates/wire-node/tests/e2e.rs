mod common;

use std::fs;
use std::path::Path;

use common::{fail, field, file_contains, files_under, join, log_file, node, ok, party, payload, Relay, Tmp, MARKER};
use wire_core::net::{self, OP_LIST, ST_ERR};

fn deal(a: &common::Party, b: &common::Party, relay: &str, channel: &str, content: &Path) -> String {
    let proposed = ok(&[
        "receipt",
        "propose",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        channel,
        "--content-file",
        content.to_str().unwrap(),
        "--relay",
        relay,
    ]);
    let proposal = field(&proposed, "proposal");
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        relay,
    ]);
    ok(&[
        "receipt",
        "accept",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--channel",
        channel,
        "--proposal",
        &proposal,
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
    ok(&[
        "receipt",
        "proceed",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        channel,
        "--proposal",
        &proposal,
        "--relay",
        relay,
    ]);
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        relay,
    ]);
    proposal
}

#[test]
fn t1_relay_cannot_read_plaintext_and_frame_is_not_logged() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let data = tmp.path().join("offer.bin");
    fs::write(&data, payload(4096)).unwrap();
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
    let mut spool = Vec::new();
    files_under(&relay.data.join("spool"), &mut spool);
    assert!(!spool.is_empty(), "relay should be holding the frame");
    for file in &spool {
        assert!(!file_contains(file, MARKER), "plaintext leaked into spool");
    }
    let inbox = b.home.join("inbox");
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
        "--inbox",
        inbox.to_str().unwrap(),
    ]);
    let mut delivered = Vec::new();
    files_under(&inbox, &mut delivered);
    assert!(delivered.iter().any(|p| file_contains(p, MARKER)));
    assert!(!file_contains(&log_file(&a.home, &channel), MARKER));
    assert!(!file_contains(&log_file(&b.home, &channel), MARKER));
    let mut after = Vec::new();
    files_under(&relay.data.join("spool"), &mut after);
    assert!(after.is_empty(), "spool should drain after ack");
}

#[test]
fn t2_offline_delivery_waits_in_the_relay() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let data = tmp.path().join("later.bin");
    fs::write(&data, b"delivered-after-reconnect").unwrap();
    ok(&[
        "send-frame",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--data-file",
        data.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let inbox = a.home.join("inbox");
    assert!(!inbox.exists());
    ok(&[
        "poll",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
        "--inbox",
        inbox.to_str().unwrap(),
    ]);
    let mut delivered = Vec::new();
    files_under(&inbox, &mut delivered);
    assert!(delivered.iter().any(|p| file_contains(p, b"delivered-after-reconnect")));
}

#[test]
fn t3_invite_is_a_file_and_relay_has_no_directory() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let resp = net::exchange(&relay.addr, &[OP_LIST]).unwrap();
    assert_eq!(resp[0], ST_ERR);
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let _channel = join(&a, &b, &relay.addr);
}

#[test]
fn t4_and_t16_two_parties_finalize_and_a_stranger_verifies() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let content = tmp.path().join("terms.bin");
    fs::write(&content, b"price-10-usd").unwrap();
    let proposal = deal(&a, &b, &relay.addr, &channel, &content);
    let bundle = tmp.path().join("receipt.bin");
    ok(&[
        "export-receipt",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--proposal",
        &proposal,
        "--out",
        bundle.to_str().unwrap(),
    ]);
    let verified = node(&[
        "verify-receipt",
        "--bundle",
        bundle.to_str().unwrap(),
        "--content-file",
        content.to_str().unwrap(),
    ]);
    assert!(verified.status.success(), "{}", String::from_utf8_lossy(&verified.stderr));
    let wrong = tmp.path().join("wrong.bin");
    fs::write(&wrong, b"price-11-usd").unwrap();
    let rejected = fail(&[
        "verify-receipt",
        "--bundle",
        bundle.to_str().unwrap(),
        "--content-file",
        wrong.to_str().unwrap(),
    ]);
    assert!(rejected.contains("content hash"));
    let mut tampered = fs::read(&bundle).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x5a;
    let bad = tmp.path().join("bad.bin");
    fs::write(&bad, tampered).unwrap();
    assert!(!node(&["verify-receipt", "--bundle", bad.to_str().unwrap()]).status.success());
}

#[test]
fn t5_revert_without_accept_stays_stuck() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let content = tmp.path().join("terms.bin");
    fs::write(&content, b"barter-apples").unwrap();
    let proposal = deal(&a, &b, &relay.addr, &channel, &content);
    ok(&[
        "receipt",
        "propose-revert",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--proposal",
        &proposal,
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    for home in [&a.home, &b.home] {
        let status = ok(&[
            "receipt",
            "status",
            "--home",
            home.to_str().unwrap(),
            "--channel",
            &channel,
            "--proposal",
            &proposal,
        ]);
        assert!(status.contains("receipt stuck"), "{status}");
    }
}

#[test]
fn t6_blind_channel_then_explicit_share() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let data = tmp.path().join("chat.bin");
    fs::write(&data, b"offer-without-name").unwrap();
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
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
        "--inbox",
        b.home.join("inbox").to_str().unwrap(),
    ]);
    let secret = b"ssn-999-secret-wire";
    let pii = tmp.path().join("pii.bin");
    fs::write(&pii, secret).unwrap();
    ok(&[
        "share-identity",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--file",
        pii.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let out = tmp.path().join("seen.bin");
    ok(&[
        "show-share",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(fs::read(&out).unwrap(), secret);
    assert!(!file_contains(&log_file(&a.home, &channel), secret));
    assert!(!file_contains(&log_file(&b.home, &channel), secret));
}

#[test]
fn t7_sub_with_append_only_cannot_accept() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let sub = party(tmp.path(), "sub", "1h", "append_frame");
    let channel = join(&a, &b, &relay.addr);
    ok(&[
        "member-add",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--cred",
        sub.runtime.to_str().unwrap(),
        "--caps",
        "append_frame",
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        sub.runtime.to_str().unwrap(),
        "--home",
        sub.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let content = tmp.path().join("terms.bin");
    fs::write(&content, b"sub-deal").unwrap();
    let proposed = ok(&[
        "receipt",
        "propose",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--content-file",
        content.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        sub.runtime.to_str().unwrap(),
        "--home",
        sub.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let err = fail(&[
        "receipt",
        "accept",
        "--runtime",
        sub.runtime.to_str().unwrap(),
        "--home",
        sub.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--proposal",
        &field(&proposed, "proposal"),
        "--relay",
        &relay.addr,
    ]);
    assert!(err.contains("capability denied"), "{err}");
}

#[test]
fn t8_old_handle_cannot_mint() {
    let tmp = Tmp::new();
    let a = party(tmp.path(), "a", "1h", "all");
    let old = a.handle.clone();
    let rotated = ok(&["handle", "rotate", "--vault", a.vault.to_str().unwrap()]);
    assert_eq!(field(&rotated, "principal"), a.principal);
    let new_handle = field(&rotated, "handle");
    assert_ne!(new_handle, old);
    let err = fail(&[
        "invite",
        "mint",
        "--vault",
        a.vault.to_str().unwrap(),
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--handle",
        &old,
        "--out",
        tmp.path().join("old.bin").to_str().unwrap(),
    ]);
    assert!(err.contains("stale handle"), "{err}");
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
        &new_handle,
        "--out",
        tmp.path().join("new.bin").to_str().unwrap(),
    ]);
    assert_eq!(field(&minted, "channel").len(), 64);
}

#[test]
fn t9_expired_and_revoked_credentials_cannot_append() {
    let tmp = Tmp::new();
    let dead = party(tmp.path(), "dead", "0s", "all");
    let err = fail(&[
        "invite",
        "mint",
        "--vault",
        dead.vault.to_str().unwrap(),
        "--runtime",
        dead.runtime.to_str().unwrap(),
        "--home",
        dead.home.to_str().unwrap(),
        "--handle",
        &dead.handle,
        "--out",
        tmp.path().join("nope.bin").to_str().unwrap(),
    ]);
    assert!(err.contains("expired"), "{err}");

    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    ok(&[
        "cred",
        "revoke",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--cred",
        &b.cred,
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let content = tmp.path().join("terms.bin");
    fs::write(&content, b"after-revoke").unwrap();
    let err = fail(&[
        "receipt",
        "propose",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--content-file",
        content.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    assert!(err.contains("revoked"), "{err}");
}

#[test]
fn t10_truncate_verifies_from_archive_only() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let content = tmp.path().join("terms.bin");
    fs::write(&content, b"archive-me").unwrap();
    let proposal = deal(&a, &b, &relay.addr, &channel, &content);
    let b_before = fs::read(log_file(&b.home, &channel)).unwrap();
    ok(&[
        "compact",
        "truncate-below",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
    ]);
    let b_after = fs::read(log_file(&b.home, &channel)).unwrap();
    assert_eq!(b_before, b_after);
    let bundle = tmp.path().join("receipt.bin");
    ok(&[
        "export-receipt",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
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
        content.to_str().unwrap(),
    ]);
    fs::remove_dir_all(a.home.join("channels").join(&channel).join("archive")).unwrap();
    let err = fail(&[
        "export-receipt",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--proposal",
        &proposal,
        "--out",
        tmp.path().join("nope.bin").to_str().unwrap(),
    ]);
    assert!(err.contains("archive required"), "{err}");
}

#[test]
fn t11_fork_is_reported_and_truncate_still_works() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let left = tmp.path().join("left.bin");
    let right = tmp.path().join("right.bin");
    fs::write(&left, b"left-terms").unwrap();
    fs::write(&right, b"right-terms").unwrap();
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
        left.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "receipt",
        "propose",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--content-file",
        right.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    ok(&[
        "poll",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let b_before = fs::read(log_file(&b.home, &channel)).unwrap();
    let status = ok(&[
        "fork-status",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
    ]);
    assert!(status.contains("fork yes"), "{status}");
    ok(&[
        "compact",
        "truncate-below",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
    ]);
    let still = ok(&[
        "fork-status",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
    ]);
    assert!(still.contains("fork yes"), "{still}");
    assert_eq!(fs::read(log_file(&b.home, &channel)).unwrap(), b_before);
}

#[test]
fn t12_merge_can_omit_share_events() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let pii = tmp.path().join("pii.bin");
    fs::write(&pii, b"name-hidden").unwrap();
    ok(&[
        "share-identity",
        "--runtime",
        a.runtime.to_str().unwrap(),
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--file",
        pii.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let redacted = tmp.path().join("redacted.txt");
    ok(&[
        "export-merge",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--include-pii",
        "false",
        "--out",
        redacted.to_str().unwrap(),
    ]);
    let text = fs::read_to_string(&redacted).unwrap();
    assert!(!text.contains("share_identity"), "{text}");
    assert!(!text.contains("name-hidden"));
    let full = tmp.path().join("full.txt");
    ok(&[
        "export-merge",
        "--home",
        a.home.to_str().unwrap(),
        "--channel",
        &channel,
        "--include-pii",
        "true",
        "--out",
        full.to_str().unwrap(),
    ]);
    assert!(fs::read_to_string(&full).unwrap().contains("share_identity"));
}

#[test]
fn t15_retain_is_not_the_channel_log() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let a = party(tmp.path(), "a", "1h", "all");
    let b = party(tmp.path(), "b", "1h", "all");
    let channel = join(&a, &b, &relay.addr);
    let data = tmp.path().join("pixels.bin");
    fs::write(&data, payload(2048)).unwrap();
    let retain = a.home.join("retain");
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
        "--retain",
        retain.to_str().unwrap(),
    ]);
    ok(&[
        "poll",
        "--runtime",
        b.runtime.to_str().unwrap(),
        "--home",
        b.home.to_str().unwrap(),
        "--relay",
        &relay.addr,
    ]);
    let mut kept = Vec::new();
    files_under(&retain, &mut kept);
    assert!(kept.iter().any(|p| file_contains(p, MARKER)));
    assert!(!file_contains(&log_file(&a.home, &channel), MARKER));
    assert!(!file_contains(&log_file(&b.home, &channel), MARKER));
}
