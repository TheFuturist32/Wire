# Wire — Prototype Design Doc (feed to Grok Build)
**Date:** 2026-09-24 (ET)  
**Codename:** Wire  
**Audience:** Grok Build (implementation) + founder (scope / AI test picks)  
**Repo:** Create under **TheFuturist** git only — not AG, Sale Spotted, or personal-name branding.  
**Language:** Rust, test-driven, minimal deps (prefer US/ally audited crypto; justify each dep).

**Companion docs (read-only context; this file wins on prototype scope conflicts):**
- `One-Pager-2026-09-23.md` — vision + locks  
- `Threat-Model-2026-09-24.md` — adversaries  
- `Compaction-Policy-2026-09-24.md` — unilateral truncate v0.1
- `Tool-Card-2026-09-24.md` — model-facing tool instructions and plugin safeguards
- `Observability-2026-09-24.md` — optional transfer-rate feed; not a ledger

---

## 0. How to use this doc

1. **Grok Build:** treat §1–§12 as the implementation contract. Do not expand into AI runtimes, UX, or public directory.  
2. **Founder:** use §13 to pick the post-prototype **2+ real AI** test clients; §14 is the suggested adoption wedge.  
3. Success = all acceptance tests in §11 green on localhost, not “integrated with ChatGPT.”

---

## 1. One-sentence product

**Wire** is a library + thin binaries for **AI↔AI communication**: E2E encrypted ephemeral frames, per-channel append-only commitment logs, bilateral receipts that two parties can finalize alone, an export any third party can verify, rotatable contact handles over one user-held principal, local-first storage, a localhost relay, and unilateral compaction of the persisted log.

It does not host AIs, define intents, or ship UX shells.

---

## 2. Locked decisions (do not reopen in prototype)

| Lock | Rule |
|---|---|
| Custody | User-held **root** keys; runtimes get **short-lived delegated** keys only. `vault init` creates a vault only if the path is empty and refuses to overwrite. |
| History | **Per-replica evidence** — not single global canonical truth. Storage is `channels/<id>/log.bin` only. No global log. |
| Discovery | **Out-of-band invite / capability** only — no public directory. Relay `LIST` is rejected. |
| Two planes | Ephemeral frames are sealed and deleted from the relay on ack. They are not hash-chained. Persisted types are listed in §7.2. |
| Receipts | **Bilateral only.** `propose` + `accept` + `proceed` on one proposal hash is final between those two principals. No third signature. |
| Offline verify | `verify-receipt` takes a bundle file and optional content file. It does not take a vault, a home, or a relay address. |
| Relay | **TCP store-and-forward stub in scope** (untrusted; metadata visible). Bind address is a flag. Tests use `127.0.0.1` and an ephemeral port. |
| Compaction | **Unilateral local hot truncate** of persisted events anytime. Snapshot is not a gate. Ephemeral frames are not compacted because they are not logged. |
| Client | `wire-node` is the plugin surface. One vault, many enrollments. Second AI = second delegated runtime, same principal. |
| Scale | Test `scale_many_channels`: 8 nodes, 32 channels, ≥256 KiB ephemeral each. See §11 T14. |
| Brand / git | **TheFuturist** account only |
| Quantum | `suite_id = 1` is Ed25519 + X25519 + XChaCha20-Poly1305. `suite_id = 2` round-trips as a tag and is rejected for seal and sign. |

---

## 3. Non-goals (explicit)

- Running or wrapping Claude/Grok/GPT/etc. inside this repo
- UX shells, intent taxonomy, AG watermark / bot-or-not
- An MCP server in this pass (the CLI is the tool list it will wrap)
- Production multi-tenant relays, DHT, public contact directory
- N-party receipts, automatic fork merge, global consensus
- Putting ephemeral frames, pixel streams, or chatter on the channel log
- GDPR erase-everywhere, content moderation of opaque payloads
- Latency bake-offs. The scale test is structural. Wall-clock time is printed and is not a pass/fail gate.

---

## 4. Suggested adoption wedge (prototype story)

**Wedge:** Two stand-in buyer and seller processes negotiate a fake purchase over Wire:

1. Blind channel (no PII).
2. Opaque offer bytes delivered as an ephemeral frame. Those bytes are not on the ledger. The receipt stores their SHA-256.
3. `propose` → `accept` → `proceed`. That is final. No third process is required.
4. Optional `share_identity` only at the end.
5. A separate process runs `verify-receipt` on the exported bundle and accepts it. A flipped bundle or a different content file is rejected.
6. One side unilaterally truncates its hot log and still verifies the old receipt from its archive.
7. One side proposes revert; the other refuses. State stays `stuck`.

The same binaries then run many of these deals at once (T14). Real AIs plug in later via the same library and CLI (§13).

---

## 5. Architecture (prototype)

```
┌─────────────────┐   sealed envelopes    ┌─────────────────┐
│ wire-node A     │◄────────────────────►│ relay (TCP)     │
│ delegated key   │   PUSH / PULL / ACK   │ spool = ciphertext
└────────┬────────┘                       │ delete on ACK   │
         │                                └────────▲────────┘
         │ ephemeral → inbox (not the log)         │
         │ commitment → channels/<id>/log.bin      │
         ▼                                         │
┌─────────────────┐                                │
│ wire-node B     │◄───────────────────────────────┘
└────────┬────────┘
         │ export bundle (no relay)
         ▼
┌─────────────────┐
│ verify-receipt  │  not a member, no vault, no relay
└─────────────────┘

Library:  wire-core (codec, vault, chain, receipts, invite)
          wire-relay (TCP spool)
Binaries: wire-node, wire-relay   (both targets of the wire-node package,
          so tests can spawn them; wire-relay crate is the library)
```

**Trust:** the relay never sees plaintext. Root keys stay in the vault directory. The runtime file holds only the delegated secret. On the wire, receipt events travel inside encrypted envelopes. The exported bundle is what a third party is allowed to see, and only if a party hands it over.

**Node directory:**

```
home/
  runtime.bin
  channels/<channel_id>/log.bin
  channels/<channel_id>/archive/log.bin
  retain/          # optional private copies, not evidence
  inbox/           # ephemeral deliveries the local AI just received
vault/             # root, shared by every runtime of this principal
```

---

## 6. Rust workspace layout

```
wire/
  Cargo.toml
  crates/wire-core/           # protocol library
  crates/wire-relay/          # relay library
  crates/wire-node/           # bins wire-node and wire-relay; tests/ e2e + scale
  docs/
  README.md
```

**Dependency policy:** the stack is `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `sha2`, and `rand`. Justifications are in [`DEPS.md`](./DEPS.md). No Tokio, serde, or clap. Framing, the log, and the fixed argv parser are owned. Relay I/O is `std::net` TCP plus threads.

---

## 7. Core types (conceptual)

Use explicit versioning: `WireVersion = 0`.

### 7.1 Identity

- `PrincipalId` — stable id derived from root verifying key  
- `RootKeypair` — only in principal vault  
- `DelegatedCredential` — `{ root_pub, runtime_id, caps, not_before, not_after, ed25519_pub, x25519_pub, parent_sig }`. `not_after = 0` is already expired.
- `ContactHandle` — rotatable string in the vault. Minting an invite for a retired handle fails. Principal id stays.
- `InviteCapability` — single-use token inside an invite file. The inviter consumes it when the joiner's `member_add` is polled.

### 7.2 Channel & events

- `ChannelId`  
- `EventId` — hash of event body  
- `Event` — `{ channel_id, prev: EventId|Genesis, type, body, signer: delegated_key_id, sig, suite_id }`  

**Event types (v0):**

| Type | Purpose |
|---|---|
| `member_add` | Add the signer, with caps, the invite token, and handle generation |
| `member_cap_update` | Restrict or expand caps |
| `share_identity` | Explicit PII blob, sealed to the counterparty, persisted |
| `propose` | `proposal_id` + SHA-256 content hash. Not the bytes. |
| `accept` / `proceed` | Same `proposal_id`. Proceed is signed by the proposer. |
| `propose_revert` / `accept_revert` | Compensating agreement. One side only → state `stuck`. |
| `snapshot` / `ack_snapshot` | Optional shared checkpoint. Not required to truncate. |
| `handle_rotate` | Announced handle change |
| `cred_revoke` | Channel-visible revoke of a delegated cred id |

There is no `frame` event. Opaque payloads are ephemeral envelopes (`kind = 1`). A local `--retain` path may store a private copy under `retain/`. That file is not the channel log. `poll --inbox` writes what the local AI just received, which is also not the log.

### 7.3 Capabilities (sub-AI)

`append_frame`, `propose`, `accept`, `spawn_member`. Default enroll is all four. The sub-member test enrolls `append_frame` only, and `accept` is rejected both locally and by `screen` on the chain.

### 7.4 Envelope

```
Envelope {
  magic "WENV", version 1,
  suite_id: u16,          # 1 = classical; anything else fails open
  kind: u8,               # 1 ephemeral plaintext, 2 persisted event bytes
  sender_cred_id, recipient_cred_id, channel_id, sender_x25519,
  nonce: 24 bytes,        # header is AEAD associated data
  ciphertext              # XChaCha20-Poly1305
}
```

The relay stores the envelope bytes plus arrival time and the two cred ids. It does not parse the plaintext. `suite_id = 2` can be read back off a header and is rejected by seal and open.

---

## 8. Module responsibilities (`wire-core`)

| Module | Responsibility |
|---|---|
| `codec` | Length-prefixed encode/decode, hex ids |
| `crypto` | Suite 1 seal/open and signatures. Suite 2 rejected. |
| `model` | Credentials, events, invites, receipt bundles |
| `chain` | Per-channel hash log, fork detect, caps screen, truncate |
| `ops` | Vault, enroll, invite, send, poll, receipts, export, merge |

`wire-relay`: TCP. Ops are `PUSH`, `PULL`, `ACK`. `LIST` is rejected. Spool key is recipient cred id. Files are deleted on `ACK`. No decrypt.

`wire-node`: one-shot CLI. Each command persists to disk and exits.

---

## 9. Feature build order (TDD)

Implement in this order; each step ends with failing→passing tests:

1. **Codec + hash chain** — append, verify, fork detect, flipped byte fails
2. **Vault + delegated creds** — refuse overwrite; two enrolls share a principal; root never signs events
3. **Crypto suite_id=1** — sign events; seal ephemeral frames; suite 2 rejected
4. **Invite file** — A mints, B consumes, single-use token
5. **Processes + relay** — offline delivery; spool has no plaintext; spool empty after ack
6. **Receipts** — two-party proceed; offline verify; stuck revert; content hash mismatch rejected
7. **share_identity** after the channel already worked without it
8. **Sub-member** with `append_frame` only cannot accept
9. **Handle rotate** — old handle cannot mint; new handle can; same principal
10. **Unilateral compact** — archive verifies; missing archive fails; peer log unchanged
11. **Scale** — 8×32 ephemeral payloads do not grow the logs
12. **Merge export** — `include_pii false` omits share events. Cut this before the scale test if time slips. Snapshot events are defined and are not a truncate gate.

---

## 10. CLI sketch (for E2E scripts)

```text
wire-node vault init --path ./vault-a
wire-node enroll --vault ./vault-a --out ./home-a/runtime.bin --ttl 1h --caps all
wire-node handle rotate --vault ./vault-a
wire-node invite mint --vault ./vault-a --runtime ./home-a/runtime.bin --home ./home-a --handle <handle> --out invite.bin
wire-node invite accept --runtime ./home-b/runtime.bin --home ./home-b --invite invite.bin --relay 127.0.0.1:PORT
wire-node send-frame --runtime ./home-a/runtime.bin --home ./home-a --channel <hex> --data-file offer.bin --relay 127.0.0.1:PORT [--retain ./home-a/retain]
wire-node poll --runtime ./home-b/runtime.bin --home ./home-b --relay 127.0.0.1:PORT [--inbox ./home-b/inbox]
wire-node receipt propose|accept|proceed|propose-revert|accept-revert|status --runtime ... --home ... --channel <hex> --relay ... [--proposal <hex>] [--content-file offer.bin]
wire-node share-identity --runtime ... --home ... --channel <hex> --file pii.bin --relay ...
wire-node show-share --runtime ... --home ... --channel <hex> --out pii.out
wire-node member-add --runtime ... --home ... --channel <hex> --cred ./sub.bin --caps append_frame --relay ...
wire-node cred revoke --runtime ... --home ... --channel <hex> --cred <hex> --relay ...
wire-node compact truncate-below --runtime ... --home ... --channel <hex>
wire-node export-receipt --runtime ... --home ... --channel <hex> --proposal <hex> --out receipt.bin
wire-node verify-receipt --bundle receipt.bin [--content-file offer.bin]
wire-node export-merge --runtime ... --home ... --channel <hex> --include-pii false --out view.txt
wire-node fork-status --home ... --channel <hex> [--peer-log ./other/log.bin]
wire-relay bind 127.0.0.1:0 --data ./relay-data
```

Runtime and invite files are length-prefixed binary, not JSON. `verify-receipt` is the third-party tool: bundle in, no home, no vault, no relay. `vault init` prints `principal` and `handle`. Successful commands print `ok` plus machine-readable `key value` lines.

---

## 11. Acceptance tests (definition of done)

All must pass in `cargo test --workspace` from this repo. End-to-end tests spawn `wire-node` and `wire-relay` as OS processes over TCP.

| ID | Test |
|---|---|
| T1 | Two nodes exchange opaque bytes via the relay. Spool files do not contain the plaintext marker. After ack the spool is gone. Neither `log.bin` contains the marker. |
| T2 | Offline delivery: B sends while A is not running. A polls later and receives the frame in `--inbox`. |
| T3 | Invite is a file. A `LIST` op to the relay is rejected. |
| T4 | propose/accept/proceed verifies offline. A different content file is rejected. A mismatched proposal id is rejected. |
| T5 | A `propose_revert`, B does not accept. `receipt status` is `stuck`. No completed revert event. |
| T6 | Channel works with no `share_identity`. After share, the peer's `show-share` writes the identity blob. |
| T7 | Sub-member with `append_frame` only cannot `accept`. |
| T8 | After rotate, mint with the old handle fails and mint with the new handle works. Principal id is unchanged. |
| T9 | `--ttl 0` cannot append. After a `cred_revoke` is polled, that cred cannot append. A valid signature from the revoked cred is still rejected by chain screening. |
| T10 | A truncates; B's log bytes are unchanged. A exports the old receipt while the archive exists, and export fails after the archive is removed. |
| T11 | Divergent tips report `fork yes`. A may still truncate. Fork status stays yes. |
| T12 | `export-merge --include-pii false` has no `share_identity` line. |
| T13 | `suite_id=1` seals. `suite_id=2` is readable as a header field and rejected for seal/open/sign. |
| T14 | `scale_many_channels`: 8 node processes, 32 channels, ≥256 KiB ephemeral payload each, then a receipt trio. Every `log.bin` is under 4 KiB. Sum of all `log.bin` files is under 32 × 4 KiB. No `global.log` and no file holds two channel ids. A home that never joined has no `channels/<id>/` directory. After acks the spool has no files. The plaintext marker is absent from spool files sampled before ack and from every `log.bin`. A process that only runs `verify-receipt` accepts all 32 bundles. Elapsed time is printed and is not the gate. If the machine cannot host 8 processes, drop to 4×8 but do not drop the byte ceilings, the empty spool, the missing global log, or offline verify. |
| T15 | `--retain` writes a private file. Both peers' `log.bin` files still lack the frame marker. |
| T16 | Proceed completes with exactly two signing principals. `verify-receipt` is invoked with `--bundle` only (plus the content file). A flipped bundle fails closed. |

**Cut line:** T12 may slip. Do not cut T1–T11, T13–T16. Snapshot acknowledgement is not a required test.

---

## 12. Security / engineering checklist for Build

- [ ] Root key file ACL limited to the current Windows user; secrets never printed
- [ ] Relay spool header is arrival time, sender cred id, recipient cred id, and ciphertext. No plaintext payload.
- [ ] `forbid(unsafe_code)` on the crates
- [ ] Truncation and flipped-byte tests on the codec and the log
- [ ] `DEPS.md` filled
- [ ] README: `cargo test --workspace -- --nocapture`
- [ ] License placeholder MIT OR Apache-2.0 until the founder chooses

---

## 13. Choosing 2+ real AIs for post-prototype testing

The product shape is a local plugin/daemon, not a model that speaks Wire. `wire-node` is that plugin for the prototype. On first run, if the vault path is empty, it creates one principal and a contact handle. If the vault exists, it refuses to overwrite. Each AI app is enrolled with `enroll` and receives a delegated credential. A second product on the same device uses the same vault. It does not mint a second person. A deliberate extra persona is a second vault the user asks for. The model never receives the root. An MCP adapter is P1 and must call this CLI, not invent another protocol.

Tool list the adapter will expose, matching the commands in §10:

- `send` — ephemeral frame
- `receipt` — persisted bilateral confirmation
- `share-identity` — explicit
- `verify-receipt` — offline check of an export
- vault init / enroll — daemon startup, not a step the model must remember

Prototype tests use OS processes as the stand-ins. After `wire-core` is stable, real AIs are runtimes under the same vault rules.

### 13.1 What “AI under test” means here

An AI is a valid Wire test client if it can:

1. Call the local plugin, which holds the delegated credential (not the user root),
2. Send and receive opaque bytes on a channel,
3. Call propose/accept when its own policy says so,
4. Run on a different trust domain than its peer (vendor or process isolation).

The model does not need to understand Wire natively. A tool adapter beside the model is the client.

### 13.2 Selection criteria (score each candidate 1–5)

| Criterion | Why |
|---|---|
| **Tool/function calling** | Adapter can mint frames/receipts without fine-tuning |
| **Local or controllable runtime** | Matches custody story (delegation from user vault) |
| **Different vendor/stack from peer** | Proves interop, not same-binary cheating |
| **Scriptable headless** | Repeatable e2e, not click-only chat UI |
| **Cost / rate limits** | Founder’s $0-until-funding bias — prefer free/local for soak tests |
| **Policy flexibility** | Can do blind commerce wedge without forced identity APIs |

### 13.3 Candidate matrix (starting point — founder picks)

| Candidate | Role fit | Notes |
|---|---|---|
| **Grok (xAI) via API or Grok Build agent** | Peer A or harness | Natural for founder workflow; good tool use |
| **Claude (Anthropic) via API** | Peer B | Strong tools; different vendor — good interop |
| **OpenAI GPT via API** | Alt peer B | Ubiquitous; compare against Claude |
| **Local llama.cpp / Ollama model** | Peer A or B | Best custody story; $0; weaker “agency” unless tool-wrapped |
| **Cursor / Grok Bot executor as “runtime”** | Harness | Good for driving `wire-node` CLI in tests — not a second product AI |
| **Google Gemini** | Optional 3rd | Extra vendor diversity later |

### 13.4 Recommended first pair (default if founder doesn’t override)

1. **Peer A:** Local tool-wrapped agent (Ollama or llama.cpp) holding delegated cred from a file vault — proves on-device custody path.  
2. **Peer B:** **Claude API** *or* **Grok API** tool-wrapped — proves cloud runtime with **delegated-only** keys (root stays on disk, never uploaded).

**Third (stretch):** opposite cloud vendor so A=local, B=Claude, C=Grok on a 3-member channel (membership + caps), still bilateral receipts between pairs.

### 13.5 Explicitly defer

- Training a model to speak Wire natively  
- In-browser extension UX  
- Phone on-device AI until desktop pair is green  

### 13.6 Founder decision checklist (fill before Phase 2)

- [ ] Peer A runtime: _______________  
- [ ] Peer B runtime: _______________  
- [ ] Optional Peer C: _______________  
- [ ] Vault location for roots (disk path / enclave later): _______________  
- [ ] Confirm: no root private key sent to any cloud API  

---

## 14. Phase plan

| Phase | Deliverable | Owner |
|---|---|---|
| **Phase 1 — PoC** | Library, one-shot node, relay, §11 tests including 8×32 scale | Landed |
| **Phase 2 — plugin** | `wire-node serve`, tool card, confirm/size policy, scripted buyer/seller wedge | Landed |
| **Observability** | Optional text metrics on the relay. Separate from channel storage. | This commit |
| **Later** | Real model adapters, PQ, production relay | After the wedge |

---

## 15. Open items Build must NOT block on

- Final public name/trademark vs “Wire” collisions  
- Production principal store (enclave) — file vault OK for P0  
- PQ hybrid implementation — suite_id stub enough  
- Adoption marketing  

---

## 16. Where the code lives

The git repo is `C:\Users\Zach\git\wire` on branch `develop`. Work there. Do not add AG or Sale Spotted remotes or branding. Keep this design doc beside the code under `docs/`.

---

## 17. Summary for the implementer

Build a Rust library, a node, and a TCP relay that prove: ephemeral E2E frames that never enter the log, OOB invite, two-party receipts including a stuck revert, offline verification by a non-member, delegated keys, handle rotate, sub-AI caps, fork detect, unilateral compact with archive, a merge PII filter, and the 8×32 scale assertions. Do not build the AIs. Real AI testing is Phase 1 adapters using the pair chosen in §13.
