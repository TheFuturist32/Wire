# Wire

Communication fabric for AI-to-AI exchange. Opaque encrypted frames are delivered and then dropped. Only commitment events (membership, bilateral receipts, explicit identity shares, revocations) go on a per-channel signed log. Two parties finalize a deal by both signing the same proposal hash. A later party can verify an exported receipt without having been on the channel.

The prototype is a Rust library plus two binaries. It does not host models or ship a UI.

Repo/brand: **TheFuturist** git only. Codename: **Wire**.

## Read order

1. **[docs/Wire-Prototype-Design-2026-09-24.md](docs/Wire-Prototype-Design-2026-09-24.md)** — implementation contract
2. **[docs/One-Pager-2026-09-23.md](docs/One-Pager-2026-09-23.md)** — vision and locked decisions
3. **[docs/Threat-Model-2026-09-24.md](docs/Threat-Model-2026-09-24.md)** — adversaries and trust boundaries
4. **[docs/Compaction-Policy-2026-09-24.md](docs/Compaction-Policy-2026-09-24.md)** — unilateral local truncate of the persisted log
5. **[docs/DEPS.md](docs/DEPS.md)** — dependency justifications

## Layout

```
crates/wire-core/     protocol library
crates/wire-relay/    TCP store-and-forward library
crates/wire-node/     binaries: wire-node, wire-relay
```

`suite_id = 1` is Ed25519, X25519, and XChaCha20-Poly1305. `suite_id = 2` is an agility stub and is rejected for seal and sign.

## Run the tests

```text
cargo test --workspace -- --nocapture
```

`scale_many_channels` is the scalability test: 8 node processes, 32 channels, a 256 KiB ephemeral payload on each channel, persisted receipt only. It passes only when each channel log stays under 4 KiB, total ledger bytes stay under 32 × 4 KiB, plaintext markers are absent from the relay spool and from every `log.bin`, a non-member stores nothing for that channel, and an offline `verify-receipt` process accepts every exported bundle. Elapsed time is printed and is not a pass/fail gate.

That test shows the scaling shape: work and storage follow the channels you belong to, and ephemeral bytes do not become history. It does not claim a multi-region relay. The relay bind address is configuration, so leaving localhost later is deployment, not a new protocol.

License placeholder: MIT OR Apache-2.0, pending a founder choice.
