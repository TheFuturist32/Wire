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

---

## 0. How to use this doc

1. **Grok Build:** treat §1–§12 as the implementation contract. Do not expand into AI runtimes, UX, or public directory.  
2. **Founder:** use §13 to pick the post-prototype **2+ real AI** test clients; §14 is the suggested adoption wedge.  
3. Success = all acceptance tests in §11 green on localhost, not “integrated with ChatGPT.”

---

## 1. One-sentence product

**Wire** is a library + thin binaries for **AI↔AI communication**: E2E encrypted opaque frames, per-channel append-only signed logs, bilateral agreement receipts, rotatable contact handles over a portable principal, local-first storage, optional localhost relay, and unilateral local compaction.

It does **not** host AIs, define intents, or ship UX shells.

---

## 2. Locked decisions (do not reopen in prototype)

| Lock | Rule |
|---|---|
| Custody | User-held **root** keys; runtimes get **short-lived delegated** keys only |
| History | **Per-replica evidence** — not single global canonical truth |
| Discovery | **Out-of-band invite / capability** only — no public directory |
| Receipts | **Bilateral only** (compose pairs for multi-party later) |
| Relay | **Localhost store-and-forward stub in scope** (untrusted; metadata visible) |
| Compaction | **Unilateral local hot truncate** anytime; optional bilateral snapshot = shared checkpoint only |
| Brand / git | **TheFuturist** account only |
| Quantum | Envelope has `suite_id`; classical now; stub second suite id for agility — no full PQC required in week 2 |

---

## 3. Non-goals (explicit)

- Running or wrapping Claude/Grok/GPT/etc. inside this repo  
- UX shells, intent taxonomy, AG watermark / bot-or-not  
- Production multi-tenant relays, DHT, public contact directory  
- N-party receipts, automatic fork merge, global consensus  
- GDPR erase-everywhere, content moderation of opaque payloads  
- “Faster than the internet” marketing claims in code comments

---

## 4. Suggested adoption wedge (prototype story)

**Wedge:** Two stand-in “buyer” and “seller” agents negotiate a fake purchase over Wire:

1. Blind channel (no PII).  
2. Opaque offer/counter bytes.  
3. Bilateral `propose` → `accept` → `proceed` on a price hash.  
4. Optional `share_identity` only at the end.  
5. One side unilaterally truncates hot log; still verifies an old receipt from archive.  
6. One side proposes revert; other accepts (happy) **and** a second test where other refuses (stuck — expected).

Stand-ins are **two OS processes** in the prototype. Real AIs plug in later via the same client library (§13).

---

## 5. Architecture (prototype)

```
┌─────────────────┐     envelopes      ┌─────────────────┐
│ wire-node A     │◄──────────────────►│ localhost relay │
│ (principal A,   │   store & forward  │ (ciphertext +   │
│  delegated key) │◄──────────────────►│  metadata only) │
└────────┬────────┘                    └────────▲────────┘
         │ local hot log + optional archive     │
         ▼                                      │
┌─────────────────┐                             │
│ wire-node B     │◄────────────────────────────┘
│ (principal B)   │
└─────────────────┘

Library: wire-core (types, crypto envelope, log, receipts, invite, compact)
Bins:    wire-node (one participant), wire-relay (stub)
```

**Trust:** relay never sees plaintext. Root keys never enter `wire-node` long-term store beyond an explicit test “principal vault” file on disk (simulating user-held store).

---

## 6. Rust workspace layout

```
wire/
  Cargo.toml                  # workspace
  crates/
    wire-core/                # library: all protocol logic
    wire-node/                # binary: one participant process
    wire-relay/               # binary: localhost store-and-forward
  tests/
    e2e/                      # multi-process tests
  docs/                       # copy or submodule of design notes (optional)
  README.md
```

**Dependency policy:**
- Prefer `rustls` / well-known US or ally-maintained crypto (`ring`, `ed25519-dalek`, `chacha20poly1305`, or equivalent — **pick one stack and justify in README**).  
- No heavy frameworks (no Tokio-everything app server unless needed for relay; prefer simple TCP + length-prefixed frames).  
- Do **not** reinvent signatures/AEAD; do reinvent as little “channel ledger” logic as possible but keep it small and owned.  
- Every dep: one line in `docs/DEPS.md` — why, license, country/maintainer note, alternative considered.

---

## 7. Core types (conceptual)

Use explicit versioning: `WireVersion = 0`.

### 7.1 Identity

- `PrincipalId` — stable id derived from root verifying key  
- `RootKeypair` — only in principal vault  
- `DelegatedCredential` — `{ principal_id, runtime_id, scope, not_before, not_after, parent_sig }`  
- `ContactHandle` — rotatable; maps to `PrincipalId` in local handle table  
- `InviteCapability` — single-use or limited-use token/URL material to join/create channel (OOB)

### 7.2 Channel & events

- `ChannelId`  
- `EventId` — hash of event body  
- `Event` — `{ channel_id, prev: EventId|Genesis, type, body, signer: delegated_key_id, sig, suite_id }`  

**Event types (v0):**

| Type | Purpose |
|---|---|
| `member_add` | Add principal or sub-participant with capabilities |
| `member_cap_update` | Restrict/expand caps |
| `frame` | Opaque payload ciphertext (or inner plaintext only in test suite with fake suite) |
| `share_identity` | Explicit PII/identity share blob (still encrypted to members) |
| `propose` / `accept` / `proceed` | Bilateral agreement |
| `propose_revert` / `accept_revert` | Compensating agreement |
| `snapshot` / `ack_snapshot` | Optional shared checkpoint |
| `handle_rotate` | Local+announced handle change (as needed) |

### 7.3 Capabilities (sub-AI)

Bitflags or string set, e.g. `append_frame`, `propose`, `accept`, `spawn_member`, `compaction_ack` (default off for subs). Prototype: parent full; one sub with `append_frame` only.

### 7.4 Envelope

```
EnvelopeV0 {
  suite_id: u16,
  sender_cred_id,
  channel_id?,
  ciphertext,
  aead_nonce,
  // relay-visible: length, timestamps at relay — not inside AEAD
}
```

Start `suite_id = 1` (classical). Stub `suite_id = 2` rejected or round-trip tagged only.

---

## 8. Module responsibilities (`wire-core`)

| Module | Responsibility |
|---|---|
| `vault` | Create principal, enroll delegated cred, rotate/revoke |
| `handles` | Multiple handles → principal; rotate |
| `invite` | Mint/consume OOB capability |
| `log` | Append-only hash-linked store; tip; fork detect |
| `membership` | Caps; sub-AI add |
| `crypto` | Suite registry; sign/verify; seal/open |
| `receipts` | propose/accept/proceed/revert helpers + verify |
| `compact` | Unilateral truncate_below; optional snapshot helpers; archive I/O |
| `merge_index` | Stub group index + `include_pii: bool` |
| `wire_codec` | Length-prefixed encode/decode |

`wire-relay`: accept TCP connections; queue envelopes by `channel_id` + recipient handle/cred; deliver when recipient polls or reconnects; **no decrypt**.

`wire-node`: CLI or simple RPC: vault path, relay addr, send frame, receipt flows, truncate, export archive.

---

## 9. Feature build order (TDD)

Implement in this order; each step ends with failing→passing tests:

1. **Log + hash chain** (no crypto) — append, verify chain, fork detect  
2. **Vault + delegated creds** — root never used to sign frames directly in happy path  
3. **Crypto suite_id=1** — sign events; seal opaque frames  
4. **Invite capability** — A mints, B consumes, channel created  
5. **Dual-process + relay** — A offline, B sends, A comes online, receives  
6. **Bilateral receipts** — happy proceed + refuse-revert stuck path  
7. **share_identity** optional after proceed  
8. **member_add** sub with reduced caps; sub cannot accept receipt  
9. **Handle rotate** — old handle stops resolving for *new* invites  
10. **Unilateral compact** — truncate hot; verify from archive; peer unaffected  
11. **Optional snapshot/ack** — does not gate truncate  
12. **merge_index stub** — `include_pii false` omits share events from export view  

---

## 10. CLI sketch (for E2E scripts)

```text
wire-node vault init --path ./vault-a
wire-node enroll --vault ./vault-a --out ./runtime-a.json --ttl 1h
wire-node invite mint --runtime ./runtime-a.json --out invite.txt
wire-node invite accept --runtime ./runtime-b.json --invite invite.txt
wire-node send-frame --runtime ./runtime-a.json --channel C --data-file offer.bin
wire-node receipt propose|accept|proceed|propose-revert|accept-revert ...
wire-node share-identity --runtime ./runtime-a.json --channel C --file pii.json
wire-node compact truncate-below --runtime ./runtime-a.json --channel C --tip T --archive ./arch-a
wire-node fork-status --runtime ./runtime-a.json --channel C
wire-relay bind 127.0.0.1:7700 --data ./relay-data
```

Exact flags may vary; keep scriptable for `tests/e2e`.

---

## 11. Acceptance tests (definition of done)

All must pass in CI / local `cargo test` + e2e script:

| ID | Test |
|---|---|
| T1 | Two nodes exchange opaque bytes via relay with E2E seal (relay cannot read plaintext — assert relay store ≠ plaintext) |
| T2 | Offline delivery: B sends while A down; A receives after reconnect |
| T3 | Invite OOB only; no directory API exists |
| T4 | Receipts: propose/accept/proceed verify; mismatched proposal hash rejected |
| T5 | Revert refuse: A propose_revert, B does not accept → no proceed_revert; both logs consistent with stuck state |
| T6 | Blind then share: channel works without share; after share, peer can read identity blob |
| T7 | Sub-member with `append_frame` only cannot `accept` |
| T8 | Handle rotate: invite to old handle fails; new handle works |
| T9 | Delegated key expiry/revoke: expired cred cannot append |
| T10 | Unilateral truncate on A; B full; A verifies old receipt from archive; without archive verify fails |
| T11 | Fork detect: diverge tips → `ForkDetected`; truncate still allowed locally |
| T12 | merge export `include_pii=false` excludes `share_identity` bodies |
| T13 | `suite_id` round-trip; unknown suite rejected |

**Timebox:** ~2 weeks solo AI-assisted. If slipping, cut T12 and optional snapshot/ack first; do **not** cut T1–T6, T9–T11.

---

## 12. Security / engineering checklist for Build

- [ ] Root key file mode restricted; never logged  
- [ ] Relay logs metadata only (document fields)  
- [ ] No `unsafe` without comment + review note  
- [ ] Fuzz or at least proptest property tests on codec + chain  
- [ ] `DEPS.md` filled  
- [ ] README: how to run e2e in 10 minutes  
- [ ] License placeholder (founder chooses later; MIT/Apache dual common)

---

## 13. Choosing 2+ real AIs for post-prototype testing

Prototype uses **process stand-ins**. After `wire-core` is stable, wrap thin **clients** that call the same APIs from real AI stacks.

### 13.1 What “AI under test” means here

An AI is a valid Wire test client if it can:

1. Hold or call out to a **delegated credential** (not the user root),  
2. Send/receive **opaque bytes** on a channel,  
3. Call propose/accept when its policy says so,  
4. Run on a different trust domain than its peer (vendor/process isolation).

Wire does **not** need the model to “understand” Wire natively — a **tool/adapter** beside the model is enough (and preferred).

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
| **P0 — this prototype** | `wire` repo, §11 tests green | Grok Build |
| **P1 — adapters** | Thin adapters for chosen 2 AIs calling `wire-node` or linking `wire-core` | Build + founder picks from §13 |
| **P2 — wedge demo** | Scripted buyer/seller blind→share→receipt on real AIs | Founder watches |
| **P3+** | PQ hybrid suite, real relay hardening, multi-party receipts — only after P2 |

---

## 15. Open items Build must NOT block on

- Final public name/trademark vs “Wire” collisions  
- Production principal store (enclave) — file vault OK for P0  
- PQ hybrid implementation — suite_id stub enough  
- Adoption marketing  

---

## 16. First commit instructions (for Grok Build)

1. Create private repo under **TheFuturist** named `wire` (or `wire-protocol`).  
2. Scaffold workspace + empty `wire-core` with a failing `log` test.  
3. Follow §9 order; pause for founder review after T1–T6 green.  
4. Do not add AG/Sale Spotted remotes or branding.  
5. Keep this design doc in `docs/Wire-Prototype-Design.md` (copy on first commit).

---

## 17. Summary for the implementer

Build a **Rust library + node + localhost relay** that proves: opaque E2E frames, OOB invite, bilateral receipts (including stuck revert), delegated keys, handle rotate, sub-AI caps, fork detect, unilateral compact with archive, and merge PII filter — all with TDD. **Do not build the AIs.** Real AI testing is Phase 1 adapters using the pair chosen in §13.
