# Wire — Threat Model
**Date:** 2026-09-24 (ET)  
**Status:** v0 — paired with one-pager §2b locks  
**Codename:** Wire  
**Non-goal:** This is not a formal Common Criteria evaluation. It is the working adversary model for design and for an honest prototype.

---

## 1. What Wire is protecting (assets)

| Asset | Why it matters |
|---|---|
| **Principal root keys** | Long-lived identity; compromise = permanent impersonation until rotation (and rotation may not convince past counterparties). |
| **Delegated runtime keys** | Let a specific AI/device speak *as* the principal for a limited time/scope. |
| **Channel commitment log (local replica)** | Persisted history the principal relies on for receipts and continuity. Ephemeral frames are not this asset. |
| **Payload confidentiality in flight** | Opaque AI↔AI content, including pixel streams. Confidential while queued and on the wire. Not retained by the fabric after ack. |
| **Explicit share events (PII)** | Identity/payment/etc. only after intentional share — high sensitivity once present, and these events are persisted. |
| **Contact handles → principal binding** | Reachability without burning the principal; rotation must actually cut spam. |
| **Agreement receipts** | Evidence that both parties signed the same proposal / revert. |
| **Membership / capability grants** | Who may append, spawn sub-AIs, or read sealed material. |

**Non-assets (out of Wire’s job):** correctness of AI decisions, UX safety filters, business logic, “was this a fair price,” legal enforceability of a receipt.

---

## 2. Trust boundaries

```
[ User-held principal store ]  ← ROOT TRUST (user device / HSM / offline vault)
         │ short-lived delegation only
         ▼
[ Runtime / AI process ]       ← SEMI-TRUSTED (can abuse delegation until expiry/revoke)
         │ Wire protocol
         ▼
[ Channel peers ]              ← UNTRUSTED (other principals / their runtimes)
         │ optional
         ▼
[ Relay / store-and-forward ]  ← UNTRUSTED-BUT-USEFUL (sees metadata)
         │
         ▼
[ Network path ]               ← UNTRUSTED (passive + active attackers)
```

**Locked custody rule:** root keys never leave user-held storage. Cloud AI vendors are **untrusted for root custody**. A runtime that needs to speak Wire receives a **delegated** credential with expiry and scope.

**Plugin:** the local daemon creates a vault only when the path is empty, and it must refuse to overwrite an existing vault. A compromised AI runtime is adversary B (delegated-key window). It is not, by itself, a root compromise. Each additional AI on the device enrolls against the same vault.

---

## 3. Adversaries (in scope)

### A. Malicious peer (other principal on the channel)
Goals: learn private payloads; coerce or forge agreement; trap the other party with refuse-to-revert; inject spam events; lie about “what you agreed.”

### B. Compromised or malicious runtime
Goals: use a still-valid delegated key to impersonate the principal; exfiltrate channel keys or PII share events; enroll itself persistently.

### C. Compromised sub-AI member
Goals: spam the shared channel; exfiltrate what it can decrypt; abuse over-broad capabilities granted at spawn.

### D. Relay operator (honest-but-curious or malicious)
Goals: map who talks to whom; timing/volume analysis; drop, delay, or reorder ciphertext; substitute invite capabilities if discovery is relay-mediated (v0 avoids public directory; invites may still transit relays).

### E. Global passive network observer
Goals: traffic analysis (sizes, timing, graph); harvest ciphertext for later cryptanalysis (“harvest now, decrypt later”).

### F. Active network attacker (MITM on path)
Goals: terminate TLS-to-relay if any; block delivery; attempt downgrade of crypto suite negotiation.

### G. Thief of user device / principal store
Goals: steal root keys; clone identity; read local ledgers.

### H. Spammer with a leaked contact handle
Goals: unsolicited channel opens / invite floods after a handle is posted publicly.

**Out of scope for v0 modeling (acknowledge, don’t design away yet):** nation-state with unbroken PQC-hostile quantum computer *today*; supply-chain compromise of the Rust toolchain; physical TEMPEST; legal compulsion of a party to reveal keys (Wire cannot stop that).

---

## 4. Assumptions (v0)

1. User can keep a **principal store** somewhere they control (device secure enclave, password-encrypted vault, hardware key — exact mechanism TBD).  
2. Counterparties’ runtimes may be hostile or buggy.  
3. Relays, when used, see **metadata** even when payloads are E2E encrypted.  
4. Discovery v0 is **out-of-band invite / capability URL** — no public directory.  
5. History is **per-replica evidence**, not single canonical global truth. Forks are possible; Wire does not silently pick a winner.  
6. Receipts v1 are **bilateral** only.  
7. Crypto suites are agile; initial classical is not the forever suite (PQC hybrid path exists).  
8. Opaque payloads are **not inspected** by Wire — content safety is a client/runtime concern.

---

## 5. Threats → mitigations (by adversary)

### A. Malicious peer

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Read payloads | E2E encryption; keys only among members | Compromised member still reads |
| Forge your signature | Signatures under your keys only | Stolen delegated key |
| Fake “you accepted” | Receipts require **both** signed accepts bound to proposal hash | Social engineering outside protocol |
| Refuse revert | Document: dual-consent undo ≠ dispute court | Stuck dispute (accepted) |
| Equivocate (two histories) | Per-replica evidence; compare hashes out-of-band or via future sync rules | No automatic global truth |
| Spam append | Rate/capability limits; member remove (append tombstone, not silent delete) | Cost of retaining spam in log |

### B. Compromised runtime

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Impersonate principal | Short-lived delegated keys; scope limits; revoke/rotate | Window until expiry |
| Persist after revoke | Delegation must be **verifiable** by peers (epoch / revoke list / parent sig) | Offline peers may accept stale until sync |
| Exfiltrate PII shares | Minimize what’s in runtime memory; client hygiene | Runtime malware wins if it sees plaintext |
| Enroll evil twin device | Enrollment requires **user presence** / principal store approval | User phished into approving |

### C. Compromised sub-AI

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Channel spam / cost DoS | Least-privilege capabilities; separate child channels for noisy work; membership caps | Parent must design grants carefully |
| Read everything on channel | Default: sub-AI gets **subset** capabilities / sealed subsets — not full channel keys | Easy to over-grant in practice |
| Spawn infinite further subs | Depth/breadth limits on grants | Misconfiguration |

### D. Relay

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Traffic graph | Minimize stable identifiers on the wire; rotate handles; optional padding (later) | Timing/volume still leak |
| Drop / delay | Multi-relay or peer retry; detect stall via timeouts | Availability attack works |
| Tamper ciphertext | AEAD / signed envelopes — tamper detected | Drop still works |
| Store forever for later decrypt | Ephemeral spool deleted on ack. Crypto agility + re-key for persisted envelopes still at rest on peers | A relay that ignores delete, or old ciphertext under a weak suite, remains a risk. Metadata (who, when, size) is unchanged. |

### E. Global passive observer

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Harvest ciphertext | Strong E2E + PQ-hybrid path for channel keys | Past sessions under classical-only |
| Flow correlation | Handle rotation; avoid public directory (v0) | Invite links and direct IPs still correlate |

### F. Active path MITM

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Downgrade suite | Pin / negotiate with signed suite lists; reject known-weak | Bugs in negotiation |
| Impersonate relay | Authenticate relay if used; don’t put trust for confidentiality in relay | Availability |

### G. Device / principal-store thief

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Steal root | OS enclave / hardware key / strong unlock; optional duress (later) | Physical + unlocked device loses |
| Clone identity | Detect multi-use anomalies (optional); rotate principal (painful) | Counterparties may not know |

### H. Handle spam

| Threat | Mitigation in Wire | Residual risk |
|---|---|---|
| Flood after leak | **Rotate handle** without changing principal; capability invites are single-use or scoped | Old handle still printed on the internet briefly |

---

## 6. Privacy / “blind until share” — precise claim

**Wire claims (v0):**  
- The protocol does **not require** legal name, payment instrument, or similar PII to open a channel or exchange opaque frames.  
- Such fields appear on the channel only via an **explicit share event**.  
- Merge/group operations can **omit or separately seal** PII-bearing events (`include_pii` policy).

**Wire does not claim (v0):**  
- Unlinkability from a global passive adversary.  
- That ephemeral keys are anonymous against a malicious peer who shares a long channel history.  
- That relays learn nothing.  
- That selective disclosure on merge cryptographically erases past ciphertext (it doesn’t — see one-pager H6).

---

## 7. History / forks — precise claim

**Wire claims:** A replica can show a hash-linked, signed sequence of **commitment** events it holds, and can prove which receipts it signed. Two valid signatures on the same proposal hash (`propose` and `accept`, closed by the proposer's `proceed`) are final between those two principals. A third party who did not sign is not required and cannot block finality. Anyone later given the exported bundle can check those signatures and the content hash without joining the channel, without a relay, and without the ephemeral payloads. They learn identity only if the exporter included a `share_identity` event.

**Wire does not claim:** There is always one true channel history everyone converges to. A verifier is not a trusted role and is not a member.

**Fork handling (v0):** Detect divergence (conflicting tips / membership). Surface to clients. Resolution is **out of band or future sync policy** — not silent rewrite. Agreed reverts are new events on a shared tip both parties append to *when they still share a tip*.

---

## 8. Safety stance

Wire is **safety-capable** only in the envelope sense: membership control, capability limits, rate limits, revoke, handle rotation, receipt evidence.

Wire is **not** a content moderator. Opaque payloads are the point. Abuse content is a **runtime/client** responsibility; Wire may expose hooks (ban member, close channel) but will not inspect bytes.

---

## 9. Implications for the prototype

Must exercise:
1. User-held root + delegated runtime key (root is a local file for tests). A second enroll shares the principal. Vault init refuses to overwrite.
2. Two replicas that can diverge and report fork. Do not silently merge.
3. Invite capability create/consume (no directory). Relay `LIST` is rejected.
4. Bilateral propose/accept/proceed is final with two parties. A non-member verifies the export offline. Revert path stays **stuck** when one side refuses.
5. Explicit `share_identity` vs a channel that already worked with only ephemeral frames.
6. Sub-member with reduced capability vs parent.
7. Envelope `suite_id` (classical now; stub second suite rejected for seal and sign).
8. Ephemeral payload absent from channel logs and from the relay spool after ack. Scale fixture: 8 nodes, 32 channels, ≥256 KiB ephemeral each.

Must also stub:
- TCP relay (metadata visible) — locked in prototype scope. Ephemeral spool deleted on ack.
- Unilateral local hot truncate of persisted events + archive re-verify — see Compaction-Policy. Snapshot does not gate truncate.
- Revoke delegated key and show rejection after the revoke event is delivered.

---

## 10. Open residual risks (accepted for now)

- Dispute with no dual-consent revert.  
- Metadata leakage via relays and traffic analysis.  
- Over-broad sub-AI grants in real deployments.  
- GDPR-style erasure vs append-only peer copies.  
- Adoption chicken-and-egg vs lab agent protocols.  
- Name collision (“Wire”) at public launch.

---

## 11. Next design choices still open

1. ~~Relay stub in prototype scope?~~ → yes.  
2. ~~Compaction / snapshot policy~~ → Compaction-Policy-2026-09-24.md.  
3. ~~Adoption wedge~~ → blind buyer/seller, two-party close, optional offline verify.
4. Concrete principal-store mechanism for real devices (enclave vs encrypted file vs hardware key).  
5. First classical crypto suite + PQ hybrid candidates (US/ally libs).
