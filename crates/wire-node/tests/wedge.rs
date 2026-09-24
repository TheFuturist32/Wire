mod common;

use std::fs;

use common::{
    field, file_contains, files_under, log_file, node, payload, plugin_call, plugin_ok, Plugin,
    Relay, Tmp, MARKER,
};
use wire_core::codec::parse_id;

#[test]
fn serve_creates_vault_once() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let first = Plugin::start(tmp.path(), "person", &relay.addr, None);
    let principal = first.principal.clone();
    let vault = first.vault.clone();
    drop(first);
    let second = Plugin::start(tmp.path(), "person", &relay.addr, None);
    assert_eq!(second.principal, principal);
    let enrolled = plugin_ok(
        &second.addr,
        &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    let root = fs::read(vault.join("root.bin")).unwrap();
    let secret = &root[6..38];
    assert!(!enrolled.text.as_bytes().windows(32).any(|w| w == secret));
    assert!(enrolled.blobs.is_empty());
}

#[test]
fn two_names_one_principal() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let plugin = Plugin::start(tmp.path(), "person", &relay.addr, None);
    let buyer = plugin_ok(
        &plugin.addr,
        &["enroll", "--name", "buyer", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    let other = plugin_ok(
        &plugin.addr,
        &[
            "enroll",
            "--name",
            "seller-agent",
            "--ttl",
            "1h",
            "--caps",
            "append_frame",
        ],
        &[],
    );
    assert_eq!(
        field(&buyer.text, "principal"),
        field(&other.text, "principal")
    );
    assert_ne!(field(&buyer.text, "cred"), field(&other.text, "cred"));
    let again = plugin_ok(
        &plugin.addr,
        &["enroll", "--name", "buyer", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    assert_eq!(field(&buyer.text, "cred"), field(&again.text, "cred"));
}

#[test]
fn wedge_buyer_seller() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let seller = Plugin::start(tmp.path(), "seller", &relay.addr, None);
    let buyer = Plugin::start(tmp.path(), "buyer", &relay.addr, None);
    plugin_ok(
        &seller.addr,
        &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    plugin_ok(
        &buyer.addr,
        &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    let invited = plugin_ok(&seller.addr, &["invite", "mint", "--name", "desk"], &[]);
    let channel = field(&invited.text, "channel");
    plugin_ok(
        &buyer.addr,
        &["invite", "accept", "--name", "desk"],
        &invited.blobs,
    );
    plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);

    let offer = payload(4096);
    plugin_ok(
        &buyer.addr,
        &["send-frame", "--name", "desk", "--channel", &channel],
        std::slice::from_ref(&offer),
    );
    let seen = plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);
    assert!(seen
        .blobs
        .iter()
        .any(|b| b.windows(MARKER.len()).any(|w| w == MARKER)));
    assert!(!file_contains(&log_file(&buyer.home, &channel), MARKER));
    assert!(!file_contains(&log_file(&seller.home, &channel), MARKER));

    let terms = b"agreed-price-10".to_vec();
    let proposed = plugin_ok(
        &buyer.addr,
        &[
            "receipt",
            "propose",
            "--name",
            "desk",
            "--channel",
            &channel,
        ],
        std::slice::from_ref(&terms),
    );
    let proposal = field(&proposed.text, "proposal");
    plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);
    plugin_ok(
        &seller.addr,
        &[
            "receipt",
            "accept",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--proposal",
            &proposal,
        ],
        &[],
    );
    plugin_ok(&buyer.addr, &["poll", "--name", "desk"], &[]);
    plugin_ok(
        &buyer.addr,
        &[
            "receipt",
            "proceed",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--proposal",
            &proposal,
        ],
        &[],
    );
    plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);

    let secret = b"name-ada-wire".to_vec();
    plugin_ok(
        &seller.addr,
        &["share-identity", "--name", "desk", "--channel", &channel],
        std::slice::from_ref(&secret),
    );
    plugin_ok(&buyer.addr, &["poll", "--name", "desk"], &[]);
    let revealed = plugin_ok(
        &buyer.addr,
        &["show-share", "--name", "desk", "--channel", &channel],
        &[],
    );
    assert_eq!(revealed.blobs[0], secret);
    assert!(!file_contains(&log_file(&buyer.home, &channel), &secret));
    assert!(!file_contains(&log_file(&seller.home, &channel), &secret));

    let exported = plugin_ok(
        &buyer.addr,
        &[
            "export-receipt",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--proposal",
            &proposal,
        ],
        &[],
    );
    let bundle = tmp.path().join("receipt.bin");
    let terms_path = tmp.path().join("terms.bin");
    fs::write(&bundle, &exported.blobs[0]).unwrap();
    fs::write(&terms_path, &terms).unwrap();
    let verified = node(&[
        "verify-receipt",
        "--bundle",
        bundle.to_str().unwrap(),
        "--content-file",
        terms_path.to_str().unwrap(),
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    plugin_ok(
        &buyer.addr,
        &[
            "receipt",
            "propose-revert",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--proposal",
            &proposal,
        ],
        &[],
    );
    plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);
    for addr in [&buyer.addr, &seller.addr] {
        let status = plugin_ok(
            addr,
            &[
                "receipt",
                "status",
                "--name",
                "desk",
                "--channel",
                &channel,
                "--proposal",
                &proposal,
            ],
            &[],
        );
        assert!(status.text.contains("receipt stuck"), "{}", status.text);
    }
}

#[test]
fn safeguard_confirm_and_size() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let policy = tmp.path().join("policy.txt");
    fs::write(
        &policy,
        "max_frame_bytes 32\nconfirm share-identity\nconfirm receipt-proceed\n",
    )
    .unwrap();
    let seller = Plugin::start(tmp.path(), "seller", &relay.addr, None);
    let buyer = Plugin::start(tmp.path(), "buyer", &relay.addr, Some(&policy));
    plugin_ok(
        &seller.addr,
        &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    plugin_ok(
        &buyer.addr,
        &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
        &[],
    );
    let invited = plugin_ok(&seller.addr, &["invite", "mint", "--name", "desk"], &[]);
    let channel = field(&invited.text, "channel");
    plugin_ok(
        &buyer.addr,
        &["invite", "accept", "--name", "desk"],
        &invited.blobs,
    );
    plugin_ok(&seller.addr, &["poll", "--name", "desk"], &[]);

    let too_big = plugin_call(
        &buyer.addr,
        &["send-frame", "--name", "desk", "--channel", &channel],
        &[vec![7u8; 33]],
    );
    assert!(!too_big.ok, "{}", too_big.text);
    assert!(too_big.text.contains("max_frame_bytes"), "{}", too_big.text);
    plugin_ok(
        &buyer.addr,
        &["send-frame", "--name", "desk", "--channel", &channel],
        &[vec![7u8; 16]],
    );

    let secret = b"hidden-name".to_vec();
    let denied = plugin_call(
        &buyer.addr,
        &["share-identity", "--name", "desk", "--channel", &channel],
        std::slice::from_ref(&secret),
    );
    assert!(
        !denied.ok && denied.text.contains("confirm required"),
        "{}",
        denied.text
    );
    fs::write(buyer.vault.join("confirm.token"), "host-only-token").unwrap();
    let guessed = plugin_call(
        &buyer.addr,
        &[
            "share-identity",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--confirm",
            "guess",
        ],
        std::slice::from_ref(&secret),
    );
    assert!(
        !guessed.ok && guessed.text.contains("confirm rejected"),
        "{}",
        guessed.text
    );
    plugin_ok(
        &buyer.addr,
        &[
            "share-identity",
            "--name",
            "desk",
            "--channel",
            &channel,
            "--confirm",
            "host-only-token",
        ],
        &[secret],
    );
}

#[test]
fn plugin_many_channels() {
    let tmp = Tmp::new();
    let relay = Relay::start(&tmp.path().join("relay"));
    let mut nodes = Vec::new();
    for i in 0..4 {
        let plugin = Plugin::start(tmp.path(), &format!("p{i}"), &relay.addr, None);
        plugin_ok(
            &plugin.addr,
            &["enroll", "--name", "desk", "--ttl", "1h", "--caps", "all"],
            &[],
        );
        nodes.push(plugin);
    }
    let mut channels = Vec::new();
    for k in 0..2 {
        for i in 0..4 {
            let a = i;
            let b = (i + 1 + k) % 4;
            let invited = plugin_ok(&nodes[a].addr, &["invite", "mint", "--name", "desk"], &[]);
            let channel = field(&invited.text, "channel");
            plugin_ok(
                &nodes[b].addr,
                &["invite", "accept", "--name", "desk"],
                &invited.blobs,
            );
            plugin_ok(&nodes[a].addr, &["poll", "--name", "desk"], &[]);
            channels.push((a, b, channel));
        }
    }
    assert_eq!(channels.len(), 8);
    let blob = payload(64 * 1024);
    for (_a, _b, channel) in &channels {
        plugin_ok(
            &nodes[*_a].addr,
            &["send-frame", "--name", "desk", "--channel", channel],
            std::slice::from_ref(&blob),
        );
    }
    let mut spool = Vec::new();
    files_under(&relay.data.join("spool"), &mut spool);
    assert_eq!(spool.len(), 8);
    for file in &spool {
        assert!(!file_contains(file, MARKER));
    }
    for (_a, b, _channel) in &channels {
        plugin_ok(&nodes[*b].addr, &["poll", "--name", "desk"], &[]);
    }
    let mut drained = Vec::new();
    files_under(&relay.data.join("spool"), &mut drained);
    assert!(drained.is_empty());

    let terms = b"plugin-deal".to_vec();
    let mut ids = Vec::new();
    for (n, (a, b, channel)) in channels.iter().enumerate() {
        let proposed = plugin_ok(
            &nodes[*a].addr,
            &["receipt", "propose", "--name", "desk", "--channel", channel],
            std::slice::from_ref(&terms),
        );
        let proposal = field(&proposed.text, "proposal");
        plugin_ok(&nodes[*b].addr, &["poll", "--name", "desk"], &[]);
        plugin_ok(
            &nodes[*b].addr,
            &[
                "receipt",
                "accept",
                "--name",
                "desk",
                "--channel",
                channel,
                "--proposal",
                &proposal,
            ],
            &[],
        );
        plugin_ok(&nodes[*a].addr, &["poll", "--name", "desk"], &[]);
        plugin_ok(
            &nodes[*a].addr,
            &[
                "receipt",
                "proceed",
                "--name",
                "desk",
                "--channel",
                channel,
                "--proposal",
                &proposal,
            ],
            &[],
        );
        plugin_ok(&nodes[*b].addr, &["poll", "--name", "desk"], &[]);
        let exported = plugin_ok(
            &nodes[*a].addr,
            &[
                "export-receipt",
                "--name",
                "desk",
                "--channel",
                channel,
                "--proposal",
                &proposal,
            ],
            &[],
        );
        let bundle = tmp.path().join(format!("b{n}.bin"));
        let content = tmp.path().join(format!("c{n}.bin"));
        fs::write(&bundle, &exported.blobs[0]).unwrap();
        fs::write(&content, &terms).unwrap();
        let verified = node(&[
            "verify-receipt",
            "--bundle",
            bundle.to_str().unwrap(),
            "--content-file",
            content.to_str().unwrap(),
        ]);
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        ids.push(parse_id(channel).unwrap());
    }
    let mut total = 0u64;
    for node in &nodes {
        for (idx, id) in ids.iter().enumerate() {
            let path = log_file(&node.home, &channels[idx].2);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            assert!(bytes.len() < 4096, "{} is {}", path.display(), bytes.len());
            assert!(bytes.windows(32).any(|w| w == id));
            assert!(!file_contains(&path, MARKER));
            total += bytes.len() as u64;
        }
    }
    assert!(total < 8 * 4096, "ledger {total}");
}
