# Wire — Compaction & Snapshot Policy
**Date:** 2026-09-24 (ET)  
**Status:** v0.1 sketch — **unilateral local hot truncate** (revised 2026-09-24)  
**Pairs with:** one-pager §2b, threat model §7 (forks / per-replica evidence)

---

## 1. Problem

Append-only + “no silent delete” + long-lived AI channels + hundreds of sub-AI events ⇒ **disk and sync cost grow without bound**.

We need a way to **shrink what a live replica must hold** without:

- pretending history never happened,
- breaking receipt verification,
- creating a crypto-wallet “gone forever” footgun,
- or silently picking a winner across forks.

---

## 2. Goals

| Goal | Meaning |
|---|---|
| **Bounded hot storage** | Active replicas can drop old event bodies under clear rules. |
| **Evidence preserved** | Receipts and membership decisions remain *provable* — either still local or retrievable from archive. |
| **No silent delete** | Nothing disappears without a signed, policy-visible act (snapshot + ack, or explicit discard of a *local* archive copy). |
| **Fork-safe** | Compaction never papers over divergent tips. |
| **PII-aware** | Compaction/merge respects sealed / `include_pii` boundaries. |
| **Local autonomy** | Each replica may shrink **its own** hot storage anytime (unilateral). Peer consent is not required to manage your disk. |
| **Shared checkpoint (optional)** | Bilateral `snapshot`/`ack_snapshot` is optional — useful when parties want a *joint* checkpoint for sync/dispute, not a gate on local truncate. |

## 3. Non-goals (v0)

- Global garbage collection across all peers enforced by Wire.
- GDPR “erase from everyone’s disk” as a protocol guarantee (impossible with honest peer copies — legal process stays outside).
- Automatic compression of encrypted blobs that rewrites ciphertext in place.
- CRDT-style silent merge of conflicting histories.

---

## 4. Core objects

### 4.1 Event log (unchanged)

Hash-linked, signed events. Tip = latest event id(s). Fork = two incompatible tips for the same channel id.

### 4.2 Local truncate mark (primary path)

A replica may record a **local-only** `truncate_below` mark (not necessarily a channel event):

- `covered_tip` — drop hot payloads strictly below this tip **on this replica**
- `archived` — whether bodies were moved to local cold archive vs discarded
- timestamp / runtime id that performed it

This mark is **not** consensus and **not** sent as “the channel compacted.” Other parties keep whatever they keep.

### 4.3 Snapshot + ack (optional shared checkpoint)

A signed **channel** `snapshot` event (optional) asserts a joint summary others can sync to:

- `channel_id`, `snapshot_id`, `covered_tip`
- `membership_epoch` / capability root
- `receipts_root`
- `pii_policy`, `suite_id` / crypto epoch
- Optional `archive_hint`

**A snapshot is a checkpoint, not a rewrite, and not a prerequisite for local truncate.**

`ack_snapshot` (bilateral in v1) means “we both treat this checkpoint as a shared reference.” Useful for:

- aligning sync (“start from snapshot S”),
- dispute framing (“both acknowledged state at S”),
- optional coordinated archive hints.

It does **not** gate whether you may free your own hot disk.

### 4.4 Archive

Storage tier that still holds full events (or encrypted blobs + keys under separate policy):

- local cold directory,
- optional relay archive (untrusted; ciphertext only),
- peer-fetch on demand.

Truncation **without** an archive path is allowed only as an explicit **local discard** (“I no longer keep evidence”) — never implied to delete the peer’s copy.

---

## 5. Compaction rules (v0.1)

### Allowed unilaterally (any time, per replica)

A replica MAY, for **its own** storage:

1. Drop event **payloads** below a chosen `covered_tip` from **hot** storage.
2. Move those payloads to **local cold archive**, or **discard** them entirely (user choice — “I no longer keep this evidence”).
3. Keep a local `truncate_below` mark so the runtime knows what it still has.
4. Optionally retain hash skeletons or a `prior_root` so the tip still chains — **recommended default**, not mandatory if the user accepts weaker local verify.

**Consequence (honest):** If you discard without archive, *you* may be unable to re-prove old receipts later. The peer may still have them. Wire will not invent missing bytes.

### Optional: after bilateral `ack_snapshot`

Parties MAY additionally treat snapshot S as a **shared sync checkpoint** (fetch-from-S, dispute anchor). This does not unlock or restrict unilateral truncate — it only adds a joint reference.

### Never allowed

| Action | Why |
|---|---|
| Broadcast “channel was compacted” as if peers must drop | Truncation is local; peers choose independently |
| Hide a fork by truncating away conflicting tips you still owe honesty about | Fork reporting still required for tips you advertise |
| Rewrite or mutate old event bytes / hashes | Breaks verification; use drop or crypto-shred instead |
| “Redact” PII by editing old events | Use sealed-ref + key discard |
| Imply peer lost evidence because you truncated | False; their replica is independent |

### Crypto-shredding (related, not the same)

To reduce PII exposure without deleting ciphertext bytes: **destroy decryption keys** for sealed segments after a bilateral `shred_keys` receipt. Ciphertext may remain; content becomes unavailable. This is optional and separate from log truncation.

---

## 6. Interaction with forks (per-replica evidence)

1. **Unilateral truncate is still allowed** during a fork — you may drop *your* old payloads.
2. You MUST NOT use truncation to pretend a fork did not occur for tips you still publish/sync. If you advertise a tip, Wire still reports `ForkDetected` when peers disagree.
3. Optional shared `snapshot`/`ack` SHOULD target a tip both parties share (e.g. last common ancestor); do not bilateral-ack across unresolved divergent tips.
4. Your local discard never rewrites the peer’s evidence.

---

## 7. Interaction with reverts

`propose_revert` / `accept_revert` are normal events. They can sit **above** a snapshot.

If *you* still care about proving an old receipt (e.g. a later revert refers to it), **you** must keep it in hot storage, local archive, or be willing to ask the peer/relay archive. Unilateral truncate means that risk is yours.

Optional shared snapshots may list live `receipts_root` for joint reference — helpful, not required for truncate.

**Stuck disputes** (one side refuses revert) are unchanged: Wire still isn’t a court. Truncating your copy can make *you* weaker in a dispute — deliberate tradeoff.

---

## 8. Sub-AIs and scale

- Prefer **child channels** for high-churn sub-AI chatter; compact or drop child channels wholesale when the parent bilateral closes them.
- Parent channel stays small: membership grants, receipts, shares, snapshots.
- Snapshot cadence: policy hint only (e.g. every N events or M MB) — clients choose; Wire defines validity rules, not forced timers.

---

## 9. Relay role

Relay stub MAY store ciphertext envelopes for offline delivery and OPTIONAL cold archive blobs.

Relay MUST NOT be required to:

- understand snapshots,
- enforce truncation,
- see plaintext.

Threat model D still applies: relay sees metadata (who, when, sizes).

---

## 10. Prototype stub (minimal)

Enough to prove the policy isn’t fiction:

1. Process A **unilaterally** truncates hot payloads below tip (no B ack); B keeps full log.  
2. A verifies an old receipt via **local archive fixture**; without archive, verify fails honestly.  
3. Optional path: `snapshot` + bilateral `ack_snapshot` as shared checkpoint (does not gate A’s truncate).  
4. Under fork: A may still truncate locally; sync layer still reports `ForkDetected`.  
5. Tests: no silent channel-wide delete; peer B unaffected by A’s truncate; “I discarded” ≠ “they discarded.”

---

## 11. Open edges (defer)

- N-party snapshot acks (when receipts go beyond bilateral).  
- Partial snapshots (compact payloads but keep headers).  
- Cross-channel group indexes after child-channel drop.  
- Legal hold flags that pin events against truncation.  
- Exact merkle shape for `receipts_root`.

---

## 12. One-line summary

**Your hot log is yours to shrink unilaterally; optional bilateral snapshots are shared checkpoints only; archives preserve *your* evidence if you want it; forks don’t require peer permission to truncate; nothing is silently deleted channel-wide.**
