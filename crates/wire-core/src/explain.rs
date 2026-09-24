use crate::codec::to_hex;
use crate::model::{
    parse_id_body, parse_member_add, parse_proposal, Event, CAP_ACCEPT, CAP_APPEND, CAP_PROPOSE,
    CAP_SPAWN, T_ACCEPT, T_ACCEPT_REVERT, T_CRED_REVOKE, T_MEMBER_ADD, T_PROCEED, T_PROPOSE,
    T_PROPOSE_REVERT, T_SHARE,
};

/// One linear pass over commitment events. The log file is not rewritten.
pub fn events(list: &[Event]) -> String {
    let mut out = String::new();
    for event in list {
        out.push_str(&line(event));
        out.push('\n');
    }
    out
}

fn line(event: &Event) -> String {
    match event.typ {
        T_MEMBER_ADD => match parse_member_add(&event.body) {
            Ok((cred, caps, _token, _gen)) => {
                format!("member_add cred {} caps {}", short(&cred.id()), caps_text(caps))
            }
            Err(_) => "member_add unparsed".to_string(),
        },
        T_PROPOSE => match parse_proposal(&event.body) {
            Ok((id, hash)) => format!("propose proposal {} content {}", short(&id), short(&hash)),
            Err(_) => "propose unparsed".to_string(),
        },
        T_ACCEPT => id_line("accept", &event.body),
        T_PROCEED => id_line("proceed", &event.body),
        T_PROPOSE_REVERT => id_line("propose_revert", &event.body),
        T_ACCEPT_REVERT => id_line("accept_revert", &event.body),
        T_SHARE => format!("share_identity sealed {} bytes", event.body.len()),
        T_CRED_REVOKE => id_line("cred_revoke", &event.body),
        other => format!("event {other}"),
    }
}

fn id_line(name: &str, body: &[u8]) -> String {
    match parse_id_body(body) {
        Ok(id) => format!("{name} {}", short(&id)),
        Err(_) => format!("{name} unparsed"),
    }
}

fn short(id: &[u8; 32]) -> String {
    to_hex(id)
}

fn caps_text(caps: u32) -> String {
    let mut names = Vec::new();
    if caps & CAP_APPEND != 0 {
        names.push("append_frame");
    }
    if caps & CAP_PROPOSE != 0 {
        names.push("propose");
    }
    if caps & CAP_ACCEPT != 0 {
        names.push("accept");
    }
    if caps & CAP_SPAWN != 0 {
        names.push("spawn_member");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, RootSecret};
    use crate::model::{proposal_body, RuntimeSecret, CAP_ALL, T_PROPOSE};
    use std::time::Instant;

    #[test]
    fn explain_is_a_view_and_stays_fast() {
        let runtime = RuntimeSecret::issue(&RootSecret::generate(), 3600, CAP_ALL);
        let mut list = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            let id = crypto::sha256(&i.to_be_bytes());
            let hash = crypto::sha256(&[i as u8]);
            list.push(Event {
                suite: 1,
                channel_id: [1u8; 32],
                prev: [0u8; 32],
                typ: T_PROPOSE,
                signer_cred_id: runtime.cred_id(),
                signer_pub: runtime.cred.ed25519_pub,
                body: proposal_body(&id, &hash),
                sig: [0u8; 64],
            });
        }
        let started = Instant::now();
        let text = events(&list);
        let elapsed = started.elapsed();
        assert!(text.lines().count() == 1000);
        assert!(text.contains("propose proposal"));
        assert!(elapsed.as_millis() < 200, "explain took {}ms", elapsed.as_millis());
    }
}
