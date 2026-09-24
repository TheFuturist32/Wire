use std::net::TcpStream;
use std::time::Duration;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::net::{read_frame, write_frame};

pub struct Reply {
    pub ok: bool,
    pub text: String,
    pub blobs: Vec<Vec<u8>>,
}

pub fn encode_request(args: &[String], blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(1);
    w.u32(args.len() as u32);
    for arg in args {
        w.lp(arg.as_bytes());
    }
    w.u32(blobs.len() as u32);
    for blob in blobs {
        w.lp(blob);
    }
    w.finish()
}

pub fn decode_request(bytes: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
    let mut r = Reader::new(bytes);
    let version = r.u16()?;
    if version != 1 {
        return Err(Error::new("bad plugin request"));
    }
    let argc = r.u32()? as usize;
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        let arg = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Error::new("plugin arg utf8"))?;
        args.push(arg);
    }
    let n = r.u32()? as usize;
    let mut blobs = Vec::with_capacity(n);
    for _ in 0..n {
        blobs.push(r.lp()?.to_vec());
    }
    r.finish()?;
    Ok((args, blobs))
}

pub fn encode_reply(ok: bool, text: &str, blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(if ok { 0 } else { 1 });
    w.lp(text.as_bytes());
    w.u32(blobs.len() as u32);
    for blob in blobs {
        w.lp(blob);
    }
    w.finish()
}

pub fn decode_reply(bytes: &[u8]) -> Result<Reply> {
    let mut r = Reader::new(bytes);
    let status = r.u8()?;
    let text = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Error::new("plugin reply utf8"))?;
    let n = r.u32()? as usize;
    let mut blobs = Vec::with_capacity(n);
    for _ in 0..n {
        blobs.push(r.lp()?.to_vec());
    }
    r.finish()?;
    Ok(Reply { ok: status == 0, text, blobs })
}

pub fn call(addr: &str, args: &[String], blobs: &[Vec<u8>]) -> Result<Reply> {
    let mut sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    let timeout = Some(Duration::from_secs(30));
    sock.set_read_timeout(timeout)?;
    sock.set_write_timeout(timeout)?;
    write_frame(&mut sock, &encode_request(args, blobs))?;
    let body = read_frame(&mut sock)?;
    decode_reply(&body)
}
