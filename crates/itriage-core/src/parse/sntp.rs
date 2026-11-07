//! SNTP (RFC 4330), just enough to measure this machine's clock against a
//! time server. The packet building and the offset arithmetic live here so
//! they're testable; the UDP exchange is in `desk::time`.

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;

/// One measurement. `offset` is server time minus local time, in seconds:
/// positive means this clock is behind ("slow").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub offset: f64,
    /// Round-trip network delay, in seconds.
    pub delay: f64,
    pub stratum: u8,
}

/// A client request: leap indicator 0, version 4, mode 3 (client), with our
/// send time in the Transmit Timestamp. Servers echo it back as Originate,
/// which is how a reply is matched to its request.
pub fn request(now_unix: f64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 0b00_100_011;
    write_ts(&mut p[40..48], now_unix);
    p
}

/// Parse a server reply. `t1` is when the request left and `t4` when the
/// reply arrived, both Unix seconds on the local clock.
pub fn parse_reply(reply: &[u8], request: &[u8; 48], t1: f64, t4: f64) -> Result<Sample, String> {
    if reply.len() < 48 {
        return Err("the reply was too short to be NTP".into());
    }
    let mode = reply[0] & 0x07;
    if mode != 4 && mode != 5 {
        return Err(format!("not a server reply (mode {mode})"));
    }
    if reply[24..32] != request[40..48] {
        return Err("the reply doesn't match the request".into());
    }
    let stratum = reply[1];
    if stratum == 0 {
        let code: String = reply[12..16]
            .iter()
            .map(|&b| b as char)
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        return Err(format!("the server refused the request (kiss code {code})"));
    }
    if reply[0] >> 6 == 3 {
        return Err("the server says its own clock isn't synchronised".into());
    }
    let t2 = read_ts(&reply[32..40]);
    let t3 = read_ts(&reply[40..48]);
    if t3 <= 0.0 {
        return Err("the reply has no transmit time".into());
    }
    Ok(Sample {
        offset: ((t2 - t1) + (t3 - t4)) / 2.0,
        delay: (t4 - t1) - (t3 - t2),
        stratum,
    })
}

/// "3.2 s slow", "412 ms fast", "in sync": how far off this clock is.
pub fn describe_offset(offset: f64) -> String {
    let magnitude = offset.abs();
    if magnitude < 0.0005 {
        return "in sync".into();
    }
    let amount = if magnitude < 1.0 {
        format!("{:.0} ms", magnitude * 1000.0)
    } else if magnitude < 120.0 {
        format!("{magnitude:.1} s")
    } else {
        format!("{:.1} min", magnitude / 60.0)
    };
    format!("{amount} {}", if offset > 0.0 { "slow" } else { "fast" })
}

fn write_ts(b: &mut [u8], unix: f64) {
    let ntp = unix + NTP_UNIX_OFFSET;
    let secs = ntp.trunc() as u64 as u32; // wraps into the current NTP era
    let frac = (ntp.fract() * 4_294_967_296.0) as u32;
    b[..4].copy_from_slice(&secs.to_be_bytes());
    b[4..8].copy_from_slice(&frac.to_be_bytes());
}

fn read_ts(b: &[u8]) -> f64 {
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    if secs == 0 && frac == 0 {
        return 0.0;
    }
    // Era 1 starts in February 2036; values below 2^31 belong to it.
    let era = if secs < 0x8000_0000 { 4_294_967_296.0 } else { 0.0 };
    f64::from(secs) + era + f64::from(frac) / 4_294_967_296.0 - NTP_UNIX_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(req: &[u8; 48], t2: f64, t3: f64, stratum: u8) -> [u8; 48] {
        let mut p = [0u8; 48];
        p[0] = 0b00_100_100; // LI 0, v4, mode 4 (server)
        p[1] = stratum;
        p[24..32].copy_from_slice(&req[40..48]);
        write_ts(&mut p[32..40], t2);
        write_ts(&mut p[40..48], t3);
        p
    }

    #[test]
    fn computes_offset_and_delay() {
        let t1 = 1_794_000_000.25;
        let req = request(t1);
        // Server is 10 s ahead; 0.5 s each way; 10 ms processing.
        let t2 = t1 + 0.5 + 10.0;
        let t3 = t2 + 0.01;
        let t4 = t1 + 1.01;
        let s = parse_reply(&reply(&req, t2, t3, 2), &req, t1, t4).unwrap();
        assert!((s.offset - 10.0).abs() < 1e-3, "{s:?}");
        assert!((s.delay - 1.0).abs() < 1e-3, "{s:?}");
        assert_eq!(s.stratum, 2);
    }

    #[test]
    fn timestamps_round_trip() {
        let mut b = [0u8; 8];
        for t in [1_700_000_000.5, 1_794_000_000.125, 2_200_000_000.75] {
            write_ts(&mut b, t);
            assert!((read_ts(&b) - t).abs() < 1e-6, "{t}");
        }
    }

    #[test]
    fn rejects_bad_replies() {
        let req = request(1_794_000_000.0);
        let good = reply(&req, 1_794_000_000.1, 1_794_000_000.1, 3);
        assert!(parse_reply(&good[..40], &req, 0.0, 0.0).is_err(), "short");

        let mut kiss = good;
        kiss[1] = 0;
        kiss[12..16].copy_from_slice(b"RATE");
        assert!(parse_reply(&kiss, &req, 0.0, 0.0).unwrap_err().contains("RATE"));

        let other = request(1_794_000_999.0);
        assert!(parse_reply(&good, &other, 0.0, 0.0).unwrap_err().contains("match"));

        let mut alarm = good;
        alarm[0] |= 0b11 << 6;
        assert!(parse_reply(&alarm, &req, 0.0, 0.0).is_err());
    }

    #[test]
    fn describes_offsets() {
        assert_eq!(describe_offset(0.0001), "in sync");
        assert_eq!(describe_offset(0.412), "412 ms slow");
        assert_eq!(describe_offset(-3.24), "3.2 s fast");
        assert_eq!(describe_offset(412.0), "6.9 min slow");
    }
}
