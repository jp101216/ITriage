//! Just enough of the DNS wire format to ask a server for an A record and
//! read whether it answered: used to time each configured DNS server
//! directly, bypassing the resolver cache.

/// A standard recursive query for `name`'s A record.
pub fn query(id: u16, name: &str) -> Option<Vec<u8>> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut packet = Vec::with_capacity(18 + name.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // recursion desired
    packet.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
    Some(packet)
}

/// What came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub rcode: u8,
    pub answers: u16,
}

impl Reply {
    /// The server did its job: an answer, or an authoritative "no such name".
    pub fn answered(&self) -> bool {
        self.rcode == 0 || self.rcode == 3
    }
}

/// Check a reply belongs to query `id` and read its result code.
pub fn parse_reply(id: u16, buf: &[u8]) -> Result<Reply, String> {
    if buf.len() < 12 {
        return Err("reply too short".into());
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        return Err("reply to a different query".into());
    }
    if buf[2] & 0x80 == 0 {
        return Err("not a reply".into());
    }
    Ok(Reply {
        rcode: buf[3] & 0x0F,
        answers: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "answered",
        1 => "format error",
        2 => "server failure (SERVFAIL)",
        3 => "no such name (NXDOMAIN)",
        4 => "not implemented",
        5 => "refused",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_query() {
        let q = query(0xBEEF, "www.example.org.").unwrap();
        assert_eq!(&q[..4], &[0xBE, 0xEF, 0x01, 0x00]);
        assert_eq!(&q[12..17], &[3, b'w', b'w', b'w', 7]);
        assert_eq!(&q[q.len() - 5..], &[0, 0, 1, 0, 1]);
        assert!(query(1, "").is_none());
        assert!(query(1, "bad..name").is_none());
        assert!(query(1, &format!("{}.org", "x".repeat(64))).is_none());
    }

    #[test]
    fn reads_replies() {
        let mut reply = query(7, "example.org").unwrap();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 2;
        let r = parse_reply(7, &reply).unwrap();
        assert_eq!(r, Reply { rcode: 0, answers: 2 });
        assert!(r.answered());
        reply[3] = 0x82;
        let failed = parse_reply(7, &reply).unwrap();
        assert!(!failed.answered());
        assert_eq!(rcode_name(failed.rcode), "server failure (SERVFAIL)");
        assert!(parse_reply(8, &reply).is_err());
        assert!(parse_reply(7, &reply[..5]).is_err());
        assert!(parse_reply(7, &query(7, "example.org").unwrap()).is_err(), "a query isn't a reply");
    }
}
