use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};

pub const OP_PUSH: u8 = 1;
pub const OP_PULL: u8 = 2;
pub const OP_ACK: u8 = 3;
pub const OP_LIST: u8 = 9;
pub const ST_OK: u8 = 0;
pub const ST_ERR: u8 = 1;

const MAX_FRAME: usize = 8 * 1024 * 1024;

pub fn write_frame(sock: &mut impl Write, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME {
        return Err(Error::new("frame too large"));
    }
    let n = (body.len() as u32).to_be_bytes();
    sock.write_all(&n)?;
    sock.write_all(body)?;
    sock.flush()?;
    Ok(())
}

pub fn read_frame(sock: &mut impl Read) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf)?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > MAX_FRAME {
        return Err(Error::new("frame too large"));
    }
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body)?;
    Ok(body)
}

pub fn exchange(addr: &str, request: &[u8]) -> Result<Vec<u8>> {
    let mut sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    let timeout = Some(Duration::from_secs(30));
    sock.set_read_timeout(timeout)?;
    sock.set_write_timeout(timeout)?;
    write_frame(&mut sock, request)?;
    read_frame(&mut sock)
}

pub fn push(addr: &str, sender: &[u8; 32], recipient: &[u8; 32], env_id: &[u8; 32], envelope: &[u8]) -> Result<()> {
    let mut req = Vec::with_capacity(1 + 96 + envelope.len());
    req.push(OP_PUSH);
    req.extend_from_slice(sender);
    req.extend_from_slice(recipient);
    req.extend_from_slice(env_id);
    req.extend_from_slice(envelope);
    let resp = exchange(addr, &req)?;
    status_ok(&resp)
}

pub fn pull(addr: &str, recipient: &[u8; 32]) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let mut req = Vec::with_capacity(33);
    req.push(OP_PULL);
    req.extend_from_slice(recipient);
    let resp = exchange(addr, &req)?;
    if resp.first().copied() != Some(ST_OK) {
        return Err(Error::new("relay pull rejected"));
    }
    if resp.len() < 5 {
        return Err(Error::new("short pull response"));
    }
    let count = u32::from_be_bytes(resp[1..5].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    let mut i = 5;
    for _ in 0..count {
        if i + 36 > resp.len() {
            return Err(Error::new("truncated pull item"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&resp[i..i + 32]);
        i += 32;
        let n = u32::from_be_bytes(resp[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + n > resp.len() {
            return Err(Error::new("truncated pull envelope"));
        }
        out.push((id, resp[i..i + n].to_vec()));
        i += n;
    }
    Ok(out)
}

pub fn ack(addr: &str, recipient: &[u8; 32], env_id: &[u8; 32]) -> Result<()> {
    let mut req = Vec::with_capacity(65);
    req.push(OP_ACK);
    req.extend_from_slice(recipient);
    req.extend_from_slice(env_id);
    status_ok(&exchange(addr, &req)?)
}

fn status_ok(resp: &[u8]) -> Result<()> {
    if resp.first().copied() == Some(ST_OK) {
        Ok(())
    } else {
        Err(Error::new(format!(
            "relay error: {}",
            String::from_utf8_lossy(resp.get(1..).unwrap_or(&[]))
        )))
    }
}
