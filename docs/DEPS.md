# Dependencies

Crypto primitives are libraries. Framing, the channel log, the CLI parser, and the relay spool are owned code. No Tokio, serde, or clap.

Exact versions and checksums are whatever `Cargo.lock` records after the build. Justifications:

Versions below are the ones `Cargo.lock` resolved.

| Crate | Version | Why | License | Maintainer note | Alternative considered |
|---|---|---|---|---|---|
| `ed25519-dalek` | 2.2.0 | Event and credential signatures. Root signs delegations; delegated keys sign events. | BSD-3-Clause | dalek-cryptography, widely reviewed Ed25519 | Hand-rolled signatures — rejected |
| `x25519-dalek` | 2.0.1 | Envelope key agreement for E2E seal | BSD-3-Clause | dalek-cryptography, same stack as the signature crate | A second KEM stack in the prototype — deferred with `suite_id` |
| `chacha20poly1305` | 0.10.1 | XChaCha20-Poly1305 AEAD for envelopes (`suite_id = 1`) | Apache-2.0 OR MIT | RustCrypto | Implementing AEAD — rejected |
| `sha2` | 0.10.9 | SHA-256 for event ids, content hashes, principal ids, seal-key derivation | Apache-2.0 OR MIT | RustCrypto | A non-crypto hash for ids — rejected |
| `rand` | 0.8.8 | Key generation and nonces via `OsRng` | MIT OR Apache-2.0 | RustCrypto | Calling `getrandom` directly — extra unsafe surface |
| `lz4_flex` | 0.11.6 | LZ4 for cold archives and large payloads, only when the output shrinks. Decode is a short memory pass. | MIT | Pure Rust, no C toolchain | zstd/xz — denser, slower to open when an AI needs the bytes again |

`suite_id = 2` has no implementation. Post-quantum hybrids are an upgrade of this table, not a change to the envelope version field.
