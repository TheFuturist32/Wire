use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

/// Payloads smaller than this stay raw. LZ4 would not pay for itself.
pub const MIN_PACK: usize = 256;
const RAW: u8 = 0;
const LZ4: u8 = 1;
const COLD: &[u8] = b"WLZ4";

/// Pack an ephemeral payload. Uses LZ4 only when the result is smaller.
pub fn pack_payload(raw: &[u8]) -> Vec<u8> {
    if raw.len() < MIN_PACK {
        return prefix(RAW, raw);
    }
    let compressed = lz4_flex::compress_prepend_size(raw);
    if compressed.len() >= raw.len() {
        return prefix(RAW, raw);
    }
    prefix(LZ4, &compressed)
}

pub fn unpack_payload(packed: &[u8]) -> Result<Vec<u8>> {
    if packed.is_empty() {
        return Err(Error::new("empty packed payload"));
    }
    match packed[0] {
        RAW => Ok(packed[1..].to_vec()),
        LZ4 => lz4_flex::decompress_size_prepended(&packed[1..])
            .map_err(|_| Error::new("lz4 decompress failed")),
        _ => Err(Error::new("bad payload packing")),
    }
}

/// Cold storage (rotated archive, retain). Hot logs do not use this.
pub fn write_cold(path: &Path, raw: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let compressed = lz4_flex::compress_prepend_size(raw);
    if compressed.len() + COLD.len() < raw.len() {
        let mut out = Vec::with_capacity(COLD.len() + compressed.len());
        out.extend_from_slice(COLD);
        out.extend_from_slice(&compressed);
        fs::write(path, out)?;
    } else {
        fs::write(path, raw)?;
    }
    Ok(())
}

pub fn read_stored(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(COLD) {
        lz4_flex::decompress_size_prepended(&bytes[COLD.len()..])
            .map_err(|_| Error::new("lz4 decompress failed"))
    } else {
        Ok(bytes)
    }
}

fn prefix(flag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(flag);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn small_stays_raw_and_repetitive_shrinks() {
        let small = b"offer-39-bytes-are-left-alone!!";
        assert!(small.len() < MIN_PACK);
        let packed = pack_payload(small);
        assert_eq!(packed[0], RAW);
        assert_eq!(unpack_payload(&packed).unwrap(), small);

        let big = vec![b'A'; 8 * 1024];
        let packed = pack_payload(&big);
        assert_eq!(packed[0], LZ4);
        assert!(packed.len() < big.len());
        let started = Instant::now();
        let plain = unpack_payload(&packed).unwrap();
        assert!(started.elapsed().as_millis() < 20);
        assert_eq!(plain, big);
    }

    #[test]
    fn incompressible_is_not_wrapped() {
        let mut raw = vec![0u8; MIN_PACK];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i.wrapping_mul(17)) as u8;
        }
        let packed = pack_payload(&raw);
        assert_eq!(unpack_payload(&packed).unwrap(), raw);
        assert!(packed.len() <= raw.len() + 1);
    }
}
