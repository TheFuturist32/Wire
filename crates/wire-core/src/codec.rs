use crate::error::{Error, Result};

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn arr32(&mut self, b: &[u8; 32]) {
        self.buf.extend_from_slice(b);
    }

    pub fn lp(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, i: 0 }
    }

    pub fn rest(&self) -> usize {
        self.data.len().saturating_sub(self.i)
    }

    pub fn u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        Ok(b[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    pub fn arr32(&mut self) -> Result<[u8; 32]> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub fn arr64(&mut self) -> Result<[u8; 64]> {
        let b = self.take(64)?;
        let mut a = [0u8; 64];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub fn arr24(&mut self) -> Result<[u8; 24]> {
        let b = self.take(24)?;
        let mut a = [0u8; 24];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub fn lp(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.i + n > self.data.len() {
            return Err(Error::new("truncated"));
        }
        let s = &self.data[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    pub fn finish(&self) -> Result<()> {
        if self.i != self.data.len() {
            return Err(Error::new("trailing bytes"));
        }
        Ok(())
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::new("odd hex"));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub fn parse_id(s: &str) -> Result<[u8; 32]> {
    let v = from_hex(s)?;
    if v.len() != 32 {
        return Err(Error::new("expected 32-byte hex id"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::new("bad hex")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let raw = [0u8, 1, 255, 16, 10];
        assert_eq!(from_hex(&to_hex(&raw)).unwrap(), raw);
    }

    #[test]
    fn truncated_lp_fails() {
        let mut w = Writer::new();
        w.lp(b"hello");
        let buf = w.finish();
        for n in 0..buf.len() {
            let mut r = Reader::new(&buf[..n]);
            assert!(r.lp().is_err());
        }
    }
}
