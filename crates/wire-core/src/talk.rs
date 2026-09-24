use crate::codec::{Reader, Writer};
use crate::crypto;
use crate::error::{Error, Result};

/// One-byte tag: high nibble is version 1, low nibble is the message kind.
const VER: u8 = 1 << 4;
const SAY: u8 = VER | 1;
const OFFER: u8 = VER | 2;
const COUNTER: u8 = VER | 3;
const AGREE: u8 = VER | 4;
const BLOB: u8 = VER | 5;

/// Compact AI-to-AI message. The bytes are the stored form. [`to_text`] is a view.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Talk {
    Say(String),
    Offer { minor: u32, currency: u16, terms: [u8; 32] },
    Counter { minor: u32, currency: u16, terms: [u8; 32] },
    Agree { terms: [u8; 32] },
    BlobRef { size: u32, hash: [u8; 32] },
}

impl Talk {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Talk::Say(text) => {
                let bytes = text.as_bytes();
                let n = bytes.len().min(255);
                w.u8(SAY);
                w.u8(n as u8);
                w.bytes(&bytes[..n]);
            }
            Talk::Offer { minor, currency, terms } => write_money(&mut w, OFFER, *minor, *currency, terms),
            Talk::Counter { minor, currency, terms } => write_money(&mut w, COUNTER, *minor, *currency, terms),
            Talk::Agree { terms } => {
                w.u8(AGREE);
                w.arr32(terms);
            }
            Talk::BlobRef { size, hash } => {
                w.u8(BLOB);
                w.u32(*size);
                w.arr32(hash);
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let talk = match tag {
            SAY => {
                let n = r.u8()? as usize;
                let text = std::str::from_utf8(r.take(n)?).map_err(|_| Error::new("talk say utf8"))?;
                Talk::Say(text.to_string())
            }
            OFFER | COUNTER => {
                let minor = r.u32()?;
                let currency = r.u16()?;
                let terms = r.arr32()?;
                if tag == OFFER {
                    Talk::Offer { minor, currency, terms }
                } else {
                    Talk::Counter { minor, currency, terms }
                }
            }
            AGREE => Talk::Agree { terms: r.arr32()? },
            BLOB => Talk::BlobRef { size: r.u32()?, hash: r.arr32()? },
            _ => return Err(Error::new("unknown talk tag")),
        };
        r.finish()?;
        Ok(talk)
    }
}

fn write_money(w: &mut Writer, tag: u8, minor: u32, currency: u16, terms: &[u8; 32]) {
    w.u8(tag);
    w.u32(minor);
    w.u16(currency);
    w.arr32(terms);
}

/// Human view. Does not allocate beyond the output string.
pub fn to_text(talk: &Talk) -> String {
    match talk {
        Talk::Say(text) => format!("say {text}"),
        Talk::Offer { minor, currency, terms } => {
            format!("offer {} terms {}", money(*minor, *currency), hex_hash(terms))
        }
        Talk::Counter { minor, currency, terms } => {
            format!("counter {} terms {}", money(*minor, *currency), hex_hash(terms))
        }
        Talk::Agree { terms } => format!("agree terms {}", hex_hash(terms)),
        Talk::BlobRef { size, hash } => format!("blob {size} bytes {}", hex_hash(hash)),
    }
}

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    crypto::sha256(bytes)
}

fn money(minor: u32, currency: u16) -> String {
    let (name, scale) = match currency {
        840 => ("USD", 100u32),
        978 => ("EUR", 100),
        826 => ("GBP", 100),
        124 => ("CAD", 100),
        392 => ("JPY", 1),
        _ => return format!("{minor} currency {currency}"),
    };
    if scale == 1 {
        format!("{minor} {name}")
    } else {
        format!("{}.{:02} {name}", minor / scale, minor % scale)
    }
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    s.push_str(&crate::codec::to_hex(bytes));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_stay_minimal_and_text_is_not_stored() {
        let say = Talk::Say("hi".into()).encode();
        assert_eq!(say, vec![0x11, 2, b'h', b'i']);
        let terms = hash_bytes(b"net-30");
        let offer = Talk::Offer { minor: 1000, currency: 840, terms }.encode();
        assert_eq!(offer.len(), 39);
        assert!(!offer.windows(3).any(|w| w == b"USD"));
        assert!(!offer.windows(4).any(|w| w == b"10.00"));
        let text = to_text(&Talk::decode(&offer).unwrap());
        assert_eq!(text, format!("offer 10.00 USD terms {}", hex_hash(&terms)));
        assert!(Talk::decode(&offer[..offer.len() - 1]).is_err());
    }
}
