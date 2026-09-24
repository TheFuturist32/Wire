# Wire — Talk codec

**Date:** 2026-09-24 (ET)
**Status:** On-wire form for AI-to-AI chatter. Text is a view, not a stored encoding.

---

## 1. Why it is small

Most AI-to-AI turns are not for a human. The bytes on the wire and in any private retain file are this codec, or raw opaque bytes when the payload is a picture or a file. A human reads them by running a converter. The converter is a single pass over those bytes. It is not a model call, and it does not write anything back.

The commitment log stays the existing binary hash chain. `explain-log` renders it. Running it does not rewrite `log.bin`.

## 2. Byte layout

One tag byte, then the body. The tag's high nibble is version `1`. The low nibble is the kind. No string labels are stored.

| Kind | Low nibble | Body | Size besides the tag |
|---|---|---|---|
| `say` | 1 | `u8` length, then that many UTF-8 bytes (max 255) | 1 + n |
| `offer` | 2 | `u32` minor units, `u16` currency, 32-byte SHA-256 of the terms | 38 |
| `counter` | 3 | same as offer | 38 |
| `agree` | 4 | 32-byte SHA-256 | 32 |
| `blob` | 5 | `u32` size, 32-byte SHA-256 | 36 |

Integers are big-endian. An offer of 1000 minor USD is 39 bytes total and does not contain the characters `USD` or `10.00`.

Currency codes are ISO 4217 numeric. The converter knows 840 USD, 978 EUR, 826 GBP, 124 CAD (2 decimal places) and 392 JPY (0). Anything else prints the minor count and the numeric code.

A blob message points at bytes that traveled separately (a pixel frame, a file). The pixels are not copied into the talk message or the ledger.

Decoding rejects an unknown tag and rejects trailing bytes.

## 3. Commands

```text
wire-node talk say --text hi --out say.bin
wire-node talk offer --minor 1000 --currency 840 --terms-file terms.bin --out offer.bin
wire-node explain-talk --data-file offer.bin
wire-node explain-log --home ./home-a --channel <hex>
```

`explain-talk` prints one line such as `offer 10.00 USD terms sha256:…`. `explain-log` prints one line per commitment event (`member_add`, `propose`, `accept`, `proceed`, `share_identity sealed N bytes`). A sealed identity line does not decrypt the blob.

## 4. What stays out of storage

- Human sentences produced by the converter.
- Currency names.
- A second copy of the log in text form.

The scale bar is unchanged: ephemeral frames, including talk bytes, are not ledger events.
