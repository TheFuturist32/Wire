# Wire — Observability

**Date:** 2026-09-24 (ET)
**Status:** Relay metrics feed is in this repo. It is still not a ledger and it does not decrypt.
**Codename of the fabric:** Wire
**Reads with:** [`Threat-Model-2026-09-24.md`](./Threat-Model-2026-09-24.md) (relay metadata), [`Wire-Prototype-Design-2026-09-24.md`](./Wire-Prototype-Design-2026-09-24.md) (two planes, scale bar)

---

## 1. What this is

Observability is a separate project that sits on top of Wire. It answers two questions the fabric itself does not answer:

- Did a transfer happen?
- At what rate are transfers happening?

That is the signal used to judge performance while the network scales: many independent channels, large ephemeral payloads, small commitment logs.

Wire carries encrypted bytes. This project does not decrypt them, does not join channels, and does not become a directory of people or deals.

## 2. Two observers

| Observer | What they can see | What stays hidden |
|---|---|---|
| **A party on the channel** | Their own sends and receives, including plaintext they already decrypted, plus their own rates. A local retain or inbox copy is their configuration, not the shared log. | The other party's private retain files. Payloads they were not a recipient of. |
| **Anyone on the path** (relay operator, a later metrics collector, a third party watching the network) | That a transfer occurred, who the envelope was routed between, when, how big the ciphertext was, and the resulting rates. | Plaintext, the agreed bytes behind a content hash, identity shares, and anything inside the AEAD ciphertext. |

A party who wants the network view uses the same feed as everyone else. Holding keys does not turn the network feed into a plaintext feed. Decryption stays in the party's own plugin.

## 3. What counts as a transfer

A transfer is one store-and-forward hop of an encrypted envelope:

1. `PUSH` accepted by a relay.
2. `PULL` delivered to the recipient credential.
3. `ACK`, after which the relay deletes that spool file.

Both planes show up as transfers. The difference is only the envelope `kind` byte in the clear header:

- **Ephemeral** (`kind = 1`): offers, chatter, pixel stand-ins. Deleted on ack. Not in any channel log. This is the volume that dominates a scale run.
- **Persisted** (`kind = 2`): a commitment event (membership, receipt, share, revoke) traveling inside an envelope. Peers append it after they open it. The observer still sees only the envelope, not the event body.

Invite files, exported receipt bundles, and `verify-receipt` are out of band. They are not relay transfers. A third party who is handed a bundle can verify it. That is receipt verification, not this feed.

## 4. Fields the network feed may record

Taken from what the relay already stores, plus the clear envelope header (`WENV`). No decryption.

| Field | Source | Use |
|---|---|---|
| Arrival time | Spool header | When the transfer started waiting |
| Ack time | When the spool file is removed | Latency and in-flight time |
| Sender cred id | Spool header and envelope | Edge of the transfer. A cred id is a runtime, not a display name. |
| Recipient cred id | Spool header and envelope | Edge of the transfer |
| Ciphertext length | Byte length of the envelope | Throughput. Not the plaintext length, which is close but not identical. |
| Envelope id | `PUSH` id | Joins push, pull, and ack into one transfer |
| `suite_id` | Envelope header | Which crypto suite, not the payload |
| `kind` | Envelope header | Ephemeral volume vs commitment volume |
| `channel_id` | Envelope header (outside the AEAD) | Rate per channel. Channels are the unit of scale. |

The feed does not record plaintext, content hashes' preimages, `share_identity` contents, root keys, or contact handles. Cred ids and channel ids are routing metadata. They are not a public directory: the relay still rejects `LIST`.

## 5. Rates that matter for scaling

Counters are computed by the observability project from the feed. Wire's own tests stay structural (ledger bytes vs ephemeral bytes). This project adds the time dimension.

| Rate | Meaning |
|---|---|
| **Transfers / sec** | Envelopes acked per second, split by `kind` |
| **Ciphertext bytes / sec** | Sum of envelope lengths per second, split by `kind` |
| **In flight** | Pushed and not yet acked. This is spool depth. |
| **Ack latency** | Ack time minus arrival time, per transfer |
| **Per channel** | The same rates grouped by `channel_id` |
| **Per edge** | The same rates grouped by sender cred → recipient cred |

A healthy scale shape, matching the phase 1 bar:

- Ephemeral bytes/sec can be large. Those bytes are not retained after ack.
- Persisted transfers stay few and small (membership and receipts).
- In flight returns to zero after the recipients poll. A spool that grows without bound is a relay problem, not a ledger problem.
- Per-channel rates add up. There is no single global series that every transfer must pass through for consensus. A collector may sum rates for a dashboard. That sum is a view, not a Wire ledger.

Phase 1 already checked the byte outcome on one run: 32 channels, 8,388,608 ephemeral bytes, 110,208 ledger bytes. Observability is how you watch the next run while it is moving, and how you compare runs as node count and channel count grow.

## 6. Where the feed comes from

Two exports, both outside `wire-core`:

1. **Relay export.** A future relay flag writes one record per push and one per ack to a local sink (file or a localhost socket). The record is the fields in §4. The relay still cannot open the ciphertext. The current prototype only has the spool files; the export is the productization of those headers, not a new trust role.
2. **Party export.** `wire-node` may later count its own sends, polls, and local plaintext rates for the person who holds that vault. That stream stays on the device. It is not uploaded and it is not merged into anyone else's feed.

The observability project is the process that tails those exports, computes the rates in §5, and keeps them for as long as the operator chooses. Wire does not store that history. Retention of metrics is that project's problem, and it should be short by default: rates do not require a permanent log of every envelope id.

## 7. What this project must not become

- A decoder. No keys, no trial decryption, no storing envelopes "just in case."
- A directory. No lookup from cred id to a name, handle, or principal. Handles stay in the user-held vault.
- A second ledger. Metrics are not channel events and are not evidence of what was agreed. Agreement evidence remains the exported receipt.
- A content monitor. Abuse handling stays in the party's runtime, as in the threat model.
- A reason to put ephemeral frames on the commitment log so they are easier to count. Counting happens on the relay hop, then the bytes are deleted.

## 8. What is implemented

`wire-relay bind … --data DIR --metrics FILE` appends one UTF-8 line on each push and each ack. The file starts with `wire-metrics 1`. Each line names the time in milliseconds, sender cred id, recipient cred id, envelope id, ciphertext length, `suite_id`, `kind`, and `channel_id`. The last three come from the clear envelope header. The ciphertext is not copied into the file and is not decrypted. The file is text because this process is optional and a person reads it. It is not a channel log, so it is not held to the ledger's size budget.

```text
wire-node metrics --file metrics.bin
```

prints transfer counts, ciphertext bytes, bytes/sec when the window is at least 1 ms, in-flight (pushed and not yet acked), the window, and max ack latency. Bytes/sec is `bytes * 1000 / window_ms`. A zero window prints `0` rather than a made-up rate.

This build flushes each line so a reader sees it immediately. A later collector can batch those writes if the metrics file itself becomes the hot path. The lines stay text either way.

Party-local counters on `wire-node serve` are still off. Turn them on only on that device, in a later change. They are not part of the relay feed.

The structural scale evidence is still `cargo test -p wire-node --test scale`. The metrics feed is how you watch a run while it moves.
