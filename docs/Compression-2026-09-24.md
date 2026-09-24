# Wire — Compression

**Date:** 2026-09-24 (ET)
**Codec:** LZ4 (`lz4_flex`), used only when it shrinks the bytes and only off the hot path where that is possible.

---

## 1. Rule

Compress where the bytes sit still. Leave the hot path alone.

An AI reading or appending the live channel log does no decompression. A small talk message is not wrapped. A large payload is compressed only when the LZ4 output is smaller than the original, then sealed. After a log rotates into an archive, that file is compressed. Reading it back is one LZ4 decode and then the normal parser.

LZ4 is the choice because decode is a straight memory copy with small matches. Higher-ratio codecs (xz, zstd at high levels) save more disk and cost more time when an AI needs the bytes again. That cost would sit on the path Wire is not allowed to slow down.

## 2. What is compressed

| Data | When | Form |
|---|---|---|
| Live `log.bin` | Never | `WLOG` bytes |
| Ephemeral payload under 256 bytes | Never | One `0` byte, then the raw payload, then encryption |
| Ephemeral payload at or above 256 bytes | Only if LZ4 shrinks it | One `1` byte, then an LZ4 block with the original size prepended, then encryption. Otherwise the raw form |
| Inbox after delivery | Decompressed once on receive | Plain payload, ready for the AI |
| `--retain` copy and rotated archive | After the bytes leave the hot log | `WLZ4` plus LZ4 when that file is smaller; otherwise the raw bytes |
| Relay spool | The ciphertext of whatever was sealed | The relay does not compress or decompress |
| Metrics file | Never | UTF-8 lines. Optional process, read by a person |

Incompressible payloads (a JPEG, random bytes) stay raw. The extra flag byte is the only overhead.

## 3. Commands are unchanged

`send-frame`, `poll`, `compact truncate-below`, and `explain-log` hide this. `explain-log` still only prints. It does not rewrite `log.bin`.
